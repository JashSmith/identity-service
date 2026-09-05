using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Identity.Application;
using Identity.Domain;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;

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

public sealed class JwtSigningKeyProvider
{
    public JwtSigningKeyProvider(IConfiguration configuration)
    {
        Issuer = configuration["Identity:Tokens:Issuer"] ?? "https://localhost:7001"; Audience = configuration["Identity:Tokens:Audience"] ?? "identity-api"; KeyId = configuration["Identity:Tokens:KeyId"] ?? "development-key-1";
        using var rsa = RSA.Create(2048); Key = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = KeyId };
    }
    public string Issuer { get; } public string Audience { get; } public string KeyId { get; } public RsaSecurityKey Key { get; }
    public RsaSecurityKey PublicKey => new(Key.Rsa!.ExportParameters(false)) { KeyId = KeyId };
}
