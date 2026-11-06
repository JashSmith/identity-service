using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Avash.Identity.Authentication.AspNetCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Authentication.Tests;

/// <summary>Web SSO for consumer applications: permissions from the access token and back-channel logout.</summary>
public sealed class WebSsoTests
{
    private const string Issuer = "https://kc.test/realms/avash";
    private const string ClientId = "crm";
    private static readonly RsaSecurityKey Key = new(RSA.Create(2048)) { KeyId = "k1" };

    private static string Token(Dictionary<string, object> claims, SecurityKey? key = null, string audience = ClientId) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = audience,
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(2),
            Claims = claims,
            SigningCredentials = new SigningCredentials(key ?? Key, SecurityAlgorithms.RsaSha256),
        });

    private static Dictionary<string, object> LogoutClaims(string? sid = "session-1") => new()
    {
        ["sub"] = "user-1",
        ["sid"] = sid ?? "",
        ["jti"] = Guid.NewGuid().ToString(),
        ["events"] = new Dictionary<string, object> { [AvashWebSsoDefaults.BackchannelLogoutEvent] = new Dictionary<string, object>() },
    };

    private static Task<string?> Validate(string token) =>
        WebSsoExtensions.ValidateLogoutTokenAsync(token, Issuer, ClientId, [Key]);

    [Fact]
    public async Task A_valid_logout_token_yields_its_session_id()
    {
        Assert.Equal("session-1", await Validate(Token(LogoutClaims())));
    }

    [Fact]
    public async Task Logout_tokens_for_another_client_or_signed_by_another_key_are_refused()
    {
        Assert.Null(await Validate(Token(LogoutClaims(), audience: "hr")));
        Assert.Null(await Validate(Token(LogoutClaims(), key: new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k1" })));
        Assert.Null(await Validate("not-a-jwt"));
        Assert.Null(await Validate(""));
    }

    [Fact]
    public async Task An_id_token_is_not_accepted_as_a_logout_token()
    {
        var withNonce = LogoutClaims();
        withNonce["nonce"] = "n-1";
        var withoutEvent = LogoutClaims();
        withoutEvent.Remove("events");

        Assert.Null(await Validate(Token(withNonce)));
        Assert.Null(await Validate(Token(withoutEvent)));
    }

    [Fact]
    public async Task A_logout_token_without_a_session_id_is_refused()
    {
        var claims = LogoutClaims();
        claims.Remove("sid");

        Assert.Null(await Validate(Token(claims)));
    }

    [Fact]
    public async Task Revoked_sessions_are_remembered_for_the_cookie_lifetime()
    {
        var revocations = new AvashSsoSessionRevocations(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            Options.Create(new AvashWebSsoOptions { CookieLifetime = TimeSpan.FromHours(1) }));

        await revocations.RevokeAsync("session-1", CancellationToken.None);

        Assert.True(await revocations.IsRevokedAsync("session-1", CancellationToken.None));
        Assert.False(await revocations.IsRevokedAsync("session-2", CancellationToken.None));
        Assert.False(await revocations.IsRevokedAsync(null, CancellationToken.None));
    }

    [Fact]
    public void Permissions_and_session_id_come_from_the_access_token()
    {
        var accessToken = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(Issuer, ClientId,
        [
            new Claim("permissions", "crm:Orders:Order:View"),
            new Claim("permissions", "crm:Orders:Order:Edit"),
            new Claim("permissions", "crm:Orders:Order:View"),
            new Claim("sid", "session-9"),
        ]));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("permissions", "crm:Orders:Order:Edit")], "oidc"));

        WebSsoExtensions.AddPermissions(principal, accessToken);

        Assert.Equal(["crm:Orders:Order:Edit", "crm:Orders:Order:View"],
            principal.FindAll("permissions").Select(c => c.Value).OrderBy(v => v, StringComparer.Ordinal));
        Assert.Equal("session-9", principal.FindFirst("sid")?.Value);
    }

    [Fact]
    public void A_missing_or_unreadable_access_token_adds_nothing()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity("oidc"));

        WebSsoExtensions.AddPermissions(principal, null);
        WebSsoExtensions.AddPermissions(principal, "garbage");

        Assert.Empty(principal.Claims);
    }
}
