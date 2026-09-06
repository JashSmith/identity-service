using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Identity.Providers.Abstractions;

namespace Identity.Providers.OpenIdConnect;

public sealed class OpenIdConnectOptions
{
    public required string Authority { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public string Name { get; init; } = "oidc";
    public string[] Scopes { get; init; } = ["openid", "profile", "email"];
    public bool RequireHttpsMetadata { get; init; } = true;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
    public string? ExpectedIssuer { get; init; }
}

public sealed class OpenIdConnectIdentityProvider(
    HttpClient httpClient,
    OpenIdConnectOptions options) : IExternalIdentityProvider
{
    private readonly SemaphoreSlim metadataLock = new(1, 1);
    private DiscoveryDocument? metadata;

    public string Name => options.Name;

    public async Task<ExternalIdentity?> AuthenticateAsync(
        ExternalAuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.AuthorizationCode) ||
            string.IsNullOrWhiteSpace(request.RedirectUri) ||
            string.IsNullOrWhiteSpace(request.CodeVerifier))
            return null;

        var discovery = await GetDiscoveryAsync(cancellationToken);
        if (discovery is null || string.IsNullOrWhiteSpace(discovery.TokenEndpoint))
            return null;

        using var content = new FormUrlEncodedContent(BuildTokenRequest(request));
        using var tokenResponse = await httpClient.PostAsync(discovery.TokenEndpoint, content, cancellationToken);
        if (!tokenResponse.IsSuccessStatusCode)
            return null;

        var token = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken);
        if (token is null || string.IsNullOrWhiteSpace(token.AccessToken) || string.IsNullOrWhiteSpace(discovery.UserInfoEndpoint))
            return null;

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        using var userInfoResponse = await httpClient.SendAsync(userInfoRequest, cancellationToken);
        if (!userInfoResponse.IsSuccessStatusCode)
            return null;

        using var document = JsonDocument.Parse(await userInfoResponse.Content.ReadAsStreamAsync(cancellationToken));
        var root = document.RootElement;
        var subject = GetString(root, "sub");
        if (string.IsNullOrWhiteSpace(subject))
            return null;

        var claims = root.EnumerateObject()
            .Where(x => x.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
            .Select(x => $"{x.Name}={x.Value}")
            .ToArray();
        return new ExternalIdentity(
            Name,
            subject,
            GetString(root, "preferred_username") ?? GetString(root, "email"),
            GetString(root, "name") ?? GetString(root, "given_name"),
            claims);
    }

    private Dictionary<string, string> BuildTokenRequest(ExternalAuthenticationRequest request)
    {
        var values = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = request.AuthorizationCode,
            ["redirect_uri"] = request.RedirectUri,
            ["client_id"] = options.ClientId,
            ["code_verifier"] = request.CodeVerifier,
            ["scope"] = string.Join(' ', options.Scopes.Where(x => !string.IsNullOrWhiteSpace(x)))
        };
        if (!string.IsNullOrWhiteSpace(options.ClientSecret))
            values["client_secret"] = options.ClientSecret;
        return values;
    }

    private async Task<DiscoveryDocument?> GetDiscoveryAsync(CancellationToken cancellationToken)
    {
        if (metadata is not null)
            return metadata;

        await metadataLock.WaitAsync(cancellationToken);
        try
        {
            if (metadata is not null)
                return metadata;

            var authority = options.Authority.TrimEnd('/');
            if (!Uri.TryCreate(authority, UriKind.Absolute, out var authorityUri) ||
                (options.RequireHttpsMetadata && authorityUri.Scheme != Uri.UriSchemeHttps))
                return null;

            var discoveryUri = $"{authority}/.well-known/openid-configuration";
            var candidate = await httpClient.GetFromJsonAsync<DiscoveryDocument>(discoveryUri, cancellationToken);
            if (candidate is null ||
                (!string.IsNullOrWhiteSpace(options.ExpectedIssuer) && !string.Equals(candidate.Issuer, options.ExpectedIssuer, StringComparison.Ordinal)) ||
                !IsAllowedEndpoint(candidate.TokenEndpoint, options.RequireHttpsMetadata) ||
                !IsAllowedEndpoint(candidate.UserInfoEndpoint, options.RequireHttpsMetadata))
                return null;

            metadata = candidate;
            return metadata;
        }
        finally
        {
            metadataLock.Release();
        }
    }

    private static bool IsAllowedEndpoint(string? value, bool requireHttps)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
           (!requireHttps || uri.Scheme == Uri.UriSchemeHttps);

    private static string? GetString(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private sealed record DiscoveryDocument(
        [property: JsonPropertyName("issuer")] string? Issuer,
        [property: JsonPropertyName("token_endpoint")] string? TokenEndpoint,
        [property: JsonPropertyName("userinfo_endpoint")] string? UserInfoEndpoint);

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);
}
