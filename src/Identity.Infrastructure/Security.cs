using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Identity.Application;
using Identity.Domain;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

namespace Identity.Infrastructure;

public sealed class Pbkdf2PasswordVerifier : IPasswordVerifier
{
    private const int SaltSize = 16; private const int KeySize = 32; private const int Iterations = 210_000;
    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize); var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA512, KeySize);
        return $"pbkdf2-sha512:{Iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(key)}";
    }
    public bool Verify(string encodedHash, string password)
    {
        try
        {
            var parts = encodedHash.Split(':'); if (parts.Length != 4 || parts[0] != "pbkdf2-sha512") return false;
            var iterations = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture); var salt = Convert.FromBase64String(parts[2]); var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, expected.Length); return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }
}

public sealed class JwtAccessTokenIssuer(JwtSigningKeyProvider keys, ISystemClock clock) : IAccessTokenIssuer
{
    public Task<AccessTokenResult> IssueAsync(User user, IReadOnlyCollection<string> permissions, Guid sessionId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow; var expires = now.AddMinutes(10); var credentials = new SigningCredentials(keys.Key, SecurityAlgorithms.RsaSha256);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.Value.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.Username),
            new(ClaimTypes.Name, user.Username),
            new("name", user.DisplayName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("sid", sessionId.ToString()),
            new("ver", user.SecurityStamp)
        };
        claims.AddRange(permissions.Select(x => new Claim("permission", x)));
        var token = new JwtSecurityToken(keys.Issuer, keys.Audience, claims, now.UtcDateTime, expires.UtcDateTime, credentials);
        token.Header["kid"] = keys.KeyId;
        return Task.FromResult(new AccessTokenResult(new JwtSecurityTokenHandler().WriteToken(token), expires, keys.KeyId));
    }
}

public sealed class JwtSigningKeyOptions
{
    public const string SectionName = "Identity:Tokens";
    public string StoragePath { get; init; } = "identity-signing-keys.json";
    public string KeyId { get; init; } = "development-key-1";
    public int KeySize { get; init; } = 2048;
    public TimeSpan ActiveKeyLifetime { get; init; } = TimeSpan.FromDays(30);
    public TimeSpan KeyOverlapLifetime { get; init; } = TimeSpan.FromDays(14);
    public bool AutomaticRotation { get; init; } = true;
}

public sealed class JwtSigningKeyProvider : IDisposable
{
    private readonly List<RSA> rsaKeys = [];

    public JwtSigningKeyProvider(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        Issuer = configuration["Identity:Tokens:Issuer"] ?? "https://localhost:7001";
        Audience = configuration["Identity:Tokens:Audience"] ?? "identity-api";
        var options = new JwtSigningKeyOptions
        {
            StoragePath = configuration["Identity:Tokens:StoragePath"] ?? "identity-signing-keys.json",
            KeyId = configuration["Identity:Tokens:KeyId"] ?? "development-key-1",
            KeySize = ParsePositiveInt(configuration["Identity:Tokens:KeySize"], 2048),
            ActiveKeyLifetime = ParseDuration(configuration["Identity:Tokens:ActiveKeyLifetime"], TimeSpan.FromDays(30)),
            KeyOverlapLifetime = ParseDuration(configuration["Identity:Tokens:KeyOverlapLifetime"], TimeSpan.FromDays(14)),
            AutomaticRotation = ParseBool(configuration["Identity:Tokens:AutomaticRotation"], true)
        };
        Validate(options);
        var records = LoadOrCreate(options, DateTimeOffset.UtcNow);
        var active = records.Single(x => x.RetireAt is null);
        KeyId = active.KeyId;
        Key = CreateKey(active);
        PublicKeys = records
            .Select(CreatePublicKey)
            .OrderBy(x => x.KeyId, StringComparer.Ordinal)
            .ToArray();
    }

    public string Issuer { get; }
    public string Audience { get; }
    public string KeyId { get; }
    public RsaSecurityKey Key { get; }
    public IReadOnlyCollection<RsaSecurityKey> PublicKeys { get; }
    public RsaSecurityKey PublicKey => PublicKeys.Single(x => x.KeyId == KeyId);

    public void Dispose()
    {
        foreach (var rsa in rsaKeys)
            rsa.Dispose();
        rsaKeys.Clear();
    }

    private RsaSecurityKey CreateKey(PersistedSigningKey record)
    {
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(record.PrivateKey), out _);
        rsaKeys.Add(rsa);
        return new RsaSecurityKey(rsa) { KeyId = record.KeyId };
    }

    private RsaSecurityKey CreatePublicKey(PersistedSigningKey record)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(record.PrivateKey), out _);
        return new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = record.KeyId };
    }

    private static List<PersistedSigningKey> LoadOrCreate(JwtSigningKeyOptions options, DateTimeOffset now)
    {
        var path = Path.GetFullPath(options.StoragePath);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        List<PersistedSigningKey> records;
        if (File.Exists(path))
        {
            try
            {
                records = JsonSerializer.Deserialize<List<PersistedSigningKey>>(File.ReadAllText(path)) ?? [];
            }
            catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"JWT signing-key store could not be read: {path}", exception);
            }
        }
        else
        {
            records = [];
        }

        records = records
            .Where(x => x.RetireAt is null || x.RetireAt > now)
            .GroupBy(x => x.KeyId, StringComparer.Ordinal)
            .Select(x => x.OrderByDescending(key => key.CreatedAt).First())
            .ToList();

        var active = records
            .Where(x => x.RetireAt is null)
            .OrderByDescending(x => x.CreatedAt)
            .FirstOrDefault();

        if (active is null)
        {
            active = CreatePersistedKey(options.KeyId, options.KeySize, now);
            records.Add(active);
        }
        else if (options.AutomaticRotation && now - active.CreatedAt >= options.ActiveKeyLifetime)
        {
            active.RetireAt = now.Add(options.KeyOverlapLifetime);
            var rotatedId = $"{options.KeyId}-{now:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
            records.Add(CreatePersistedKey(rotatedId, options.KeySize, now));
        }

        Persist(path, records);
        return records;
    }

    private static PersistedSigningKey CreatePersistedKey(string keyId, int keySize, DateTimeOffset createdAt)
    {
        using var rsa = RSA.Create(keySize);
        return new PersistedSigningKey(
            keyId,
            createdAt,
            null,
            Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()));
    }

    private static void Persist(string path, IReadOnlyCollection<PersistedSigningKey> records)
    {
        var temporaryPath = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            var json = JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(temporaryPath, json);
            File.Move(temporaryPath, path, overwrite: true);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static void Validate(JwtSigningKeyOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.StoragePath)) throw new InvalidOperationException("JWT signing-key storage path is required.");
        if (string.IsNullOrWhiteSpace(options.KeyId)) throw new InvalidOperationException("JWT signing-key ID is required.");
        if (options.KeySize < 2048) throw new InvalidOperationException("JWT signing keys must be at least 2048 bits.");
        if (options.ActiveKeyLifetime <= TimeSpan.Zero) throw new InvalidOperationException("JWT active-key lifetime must be positive.");
        if (options.KeyOverlapLifetime <= TimeSpan.Zero) throw new InvalidOperationException("JWT key-overlap lifetime must be positive.");
    }

    private static int ParsePositiveInt(string? value, int fallback)
        => int.TryParse(value, out var result) && result > 0 ? result : fallback;

    private static bool ParseBool(string? value, bool fallback)
        => bool.TryParse(value, out var result) ? result : fallback;

    private static TimeSpan ParseDuration(string? value, TimeSpan fallback)
        => TimeSpan.TryParse(value, out var result) && result > TimeSpan.Zero ? result : fallback;

    private sealed class PersistedSigningKey(string keyId, DateTimeOffset createdAt, DateTimeOffset? retireAt, string privateKey)
    {
        public string KeyId { get; } = keyId;
        public DateTimeOffset CreatedAt { get; } = createdAt;
        public DateTimeOffset? RetireAt { get; set; } = retireAt;
        public string PrivateKey { get; } = privateKey;
    }
}
