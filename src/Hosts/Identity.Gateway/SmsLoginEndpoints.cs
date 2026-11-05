using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Sms;
using Identity.Contracts;
using Identity.Gateway.Errors;
using Identity.Gateway.Tenancy;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Identity.Gateway;

/// <summary>Secret shared with Keycloak's Avash SMS authenticators (<c>Identity:SmsLogin:HookSecret</c>).</summary>
public sealed class SmsLoginHookOptions
{
    /// <summary>At least 32 characters; Keycloak gets the same value as <c>AVASH_SMS_HOOK_SECRET</c>.</summary>
    public string HookSecret { get; set; } = "";
}

/// <summary>What Keycloak asks the gateway to deliver (one SMS code).</summary>
public sealed record SmsLoginHookRequest(string Realm, string? ClientId, string PhoneNumber, string Code, int LifetimeSeconds, string Purpose);

/// <summary>
/// SMS sign-in: the tenant's settings, and the hook Keycloak's authenticators call to deliver a code through the
/// tenant's SMS provider. The hook is anonymous but signed: HMAC-SHA256 over <c>"&lt;unix seconds&gt;.&lt;body&gt;"</c>
/// with the shared secret, at most five minutes old. The tenant comes from the signed realm, not from a header.
/// </summary>
public static class SmsLoginEndpoints
{
    public const string TimestampHeader = "X-Avash-Timestamp";
    public const string SignatureHeader = "X-Avash-Signature";
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>At most this many codes per number in <see cref="NumberWindow"/>, whatever Keycloak asks for.</summary>
    public const int MaxCodesPerNumber = 5;
    public static readonly TimeSpan NumberWindow = TimeSpan.FromMinutes(10);

    public static IEndpointRouteBuilder MapSmsLogin(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/settings/sms/login").WithTags("Settings");
        g.MapGet("", async (SmsLoginService login, CancellationToken ct) => (await login.GetAsync(ct)).ToHttpResult(s => Results.Ok(s)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("GetSmsLoginSettings")
            .Produces<SmsLoginSettingsDto>(200);
        g.MapPut("", async (SmsLoginSettingsDto body, SmsLoginService login, CancellationToken ct) =>
                (await login.SaveAsync(body, ct)).ToHttpResult(s => Results.Ok(s)))
            .WithValidation<SmsLoginSettingsDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("SetSmsLoginSettings")
            .Produces<SmsLoginSettingsDto>(200).ProducesProblem(400).ProducesProblem(503);

        app.MapPost("/api/identity/internal/sms-login/send", SendAsync)
            .AllowAnonymous().ExcludeFromDescription()
            .WithName("SmsLoginHook");
        return app;
    }

    private static async Task<IResult> SendAsync(HttpContext http, TenantRegistry tenants, IOptions<SmsLoginHookOptions> options,
        IMemoryCache cache, ILoggerFactory loggers, CancellationToken ct)
    {
        var logger = loggers.CreateLogger("Identity.Gateway.SmsLogin");
        using var reader = new StreamReader(http.Request.Body, Encoding.UTF8);
        var body = await reader.ReadToEndAsync(ct);

        var refused = Verify(options.Value.HookSecret, http.Request.Headers[TimestampHeader], http.Request.Headers[SignatureHeader], body,
            DateTimeOffset.UtcNow);
        if (refused is not null)
        {
            logger.LogWarning("Refused an SMS sign-in hook call: {Reason}", refused);
            return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Invalid signature");
        }

        SmsLoginHookRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<SmsLoginHookRequest>(body, JsonSerializerOptions.Web);
        }
        catch (JsonException)
        {
            return Error.Validation("request.malformed", "The request body is not valid JSON.").ToProblem();
        }
        if (request is null || string.IsNullOrWhiteSpace(request.Code) || request.Code.Length > 10 || !request.Code.All(char.IsAsciiDigit))
            return Error.Validation("request.invalid", "realm, phoneNumber and a numeric code are required.").ToProblem();

        var tenant = tenants.All.FirstOrDefault(t => string.Equals(t.Realm, request.Realm, StringComparison.Ordinal));
        if (tenant is null) return Error.NotFound("tenant.unknown", "No tenant uses this realm.").ToProblem();

        var phone = PhoneNumbers.NormalizeIranMobile(request.PhoneNumber);
        if (phone is null) return Error.Validation("sms.invalid_number", "The number is not an Iranian mobile number.").ToProblem();
        var counter = $"sms-login:{tenant.Id}:{phone}";
        var sent = cache.GetOrCreate(counter, e => { e.AbsoluteExpirationRelativeToNow = NumberWindow; return new int[1]; })!;
        if (Interlocked.Increment(ref sent[0]) > MaxCodesPerNumber)
        {
            logger.LogWarning("SMS sign-in codes for {Number} in tenant {Tenant} exceed {Max} per {Window}", PhoneNumbers.Mask(phone),
                tenant.Id, MaxCodesPerNumber, NumberWindow);
            return Error.Validation("sms_login.rate_limited", "Too many codes for this number; try again later.").ToProblem();
        }

        // The rest of the request runs as the signed realm's tenant (settings, provider, Keycloak calls).
        http.SetTenant(tenant);
        using (KeycloakTenant.Use(tenants.KeycloakOptions(tenant)))
        {
            var login = http.RequestServices.GetRequiredService<SmsLoginService>();
            var result = await login.SendCodeAsync(phone, request.Code, Math.Clamp(request.LifetimeSeconds, 60, 600),
                request.Purpose == "second-factor" ? "second-factor" : "login", ct);
            if (!result.IsSuccess)
            {
                logger.LogWarning("SMS sign-in code for {Number} in tenant {Tenant} was not sent: {Code}", PhoneNumbers.Mask(phone), tenant.Id,
                    result.Error!.Code);
                return result.Error.ToProblem();
            }
            return Results.Ok(new { accepted = true, provider = result.Value.Provider });
        }
    }

    /// <summary>Null when the signature is valid and fresh, otherwise why not (for the log; never sent back).</summary>
    public static string? Verify(string secret, string? timestamp, string? signature, string body, DateTimeOffset now)
    {
        if (secret.Length < 32) return "Identity:SmsLogin:HookSecret is not configured (32+ characters)";
        if (!long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)) return "missing timestamp";
        if ((now - DateTimeOffset.FromUnixTimeSeconds(seconds)).Duration() > MaxClockSkew) return "stale timestamp";
        if (string.IsNullOrEmpty(signature)) return "missing signature";
        var expected = Sign(secret, timestamp!, body);
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(signature.Trim().ToLowerInvariant()))
            ? null
            : "wrong signature";
    }

    /// <summary>Hex HMAC-SHA256 of <c>"&lt;timestamp&gt;.&lt;body&gt;"</c> (same as the Keycloak extension).</summary>
    public static string Sign(string secret, string timestamp, string body) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(timestamp + "." + body)));
}
