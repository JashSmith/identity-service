using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Thin client for the Keycloak Admin REST API of one realm. It attaches the service-account token and
/// turns every failure (no token, Keycloak unreachable, error status, unreadable body) into an
/// <see cref="Error"/>, so adapters never mistake a failure for an empty result.
/// </summary>
public sealed class KeycloakAdminApi(
    HttpClient http,
    KeycloakOptions options,
    KeycloakAdminTokenProvider tokens,
    ILogger logger)
{
    /// <summary>Page size used when reading collections; Keycloak truncates silently without paging.</summary>
    public const int PageSize = 100;

    private string RealmBase => $"{options.BaseUrl.TrimEnd('/')}/admin/realms/{Uri.EscapeDataString(options.Realm)}";

    /// <summary>
    /// Sends a request to <paramref name="path"/> (relative to the realm, e.g. "groups/{id}") and returns
    /// the JSON body, or null when Keycloak answered without one. <paramref name="resource"/> prefixes error codes.
    /// </summary>
    public async Task<Result<JsonElement?>> SendAsync(
        HttpMethod method, string path, object? body, string resource, CancellationToken ct)
    {
        var token = await tokens.GetTokenResultAsync(ct);
        if (!token.IsSuccess) return token.Error!;

        using var request = new HttpRequestMessage(method, $"{RealmBase}/{path}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        if (body is not null) request.Content = JsonContent.Create(body);

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "Keycloak unreachable for {Method} {Path}", method, path);
            return KeycloakErrors.Unreachable;
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                return await KeycloakErrors.FromResponseAsync(response, resource, logger, ct);

            var text = await response.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(text)) return (JsonElement?)null;
            try
            {
                using var document = JsonDocument.Parse(text);
                return (JsonElement?)document.RootElement.Clone();
            }
            catch (JsonException ex)
            {
                logger.LogError(ex, "Keycloak returned invalid JSON for {Method} {Path}", method, path);
                return InvalidResponse;
            }
        }
    }

    /// <summary>GETs a JSON document; an empty body is treated as an invalid response.</summary>
    public async Task<Result<JsonElement>> GetAsync(string path, string resource, CancellationToken ct)
    {
        var result = await SendAsync(HttpMethod.Get, path, null, resource, ct);
        if (!result.IsSuccess) return result.Error!;
        return result.Value is { } json ? json : InvalidResponse;
    }

    /// <summary>
    /// GETs every page of a collection endpoint (<paramref name="path"/> may already have a query string)
    /// and returns all items.
    /// </summary>
    public async Task<Result<IReadOnlyList<JsonElement>>> GetAllAsync(string path, string resource, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        var separator = path.Contains('?') ? '&' : '?';
        for (var first = 0; ; first += PageSize)
        {
            var page = await GetAsync($"{path}{separator}first={first}&max={PageSize}", resource, ct);
            if (!page.IsSuccess) return page.Error!;
            if (page.Value.ValueKind != JsonValueKind.Array) return InvalidResponse;

            var count = 0;
            foreach (var item in page.Value.EnumerateArray())
            {
                items.Add(item);
                count++;
            }
            if (count < PageSize) return items;
        }
    }

    public async Task<Result> SendWithoutResultAsync(
        HttpMethod method, string path, object? body, string resource, CancellationToken ct)
    {
        var result = await SendAsync(method, path, body, resource, ct);
        return result.IsSuccess ? Result.Success() : result.Error!;
    }

    public static string? GetString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static readonly Error InvalidResponse =
        Error.Upstream("keycloak.invalid_response", "Keycloak returned a response the gateway could not read.");
}
