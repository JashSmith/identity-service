using System.Globalization;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Audit;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Keycloak's event store of the tenant realm: <c>GET events</c>, <c>GET admin-events</c> and <c>GET events/config</c>
/// (role view-events). Settings are written with a partial realm update (eventsEnabled, eventsExpiration,
/// adminEventsEnabled, adminEventsDetailsEnabled; role manage-realm), because <c>PUT events/config</c> needs
/// manage-events, which the gateway's service account does not have.
/// </summary>
public sealed class KeycloakAuditAdapter(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakAuditAdapter>? logger = null) : IAuditEventReader
{
    private const string Resource = "audit";
    private const int SecondsPerDay = 86_400;

    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    public async Task<Result<IReadOnlyList<LoginEventDto>>> ListLoginEventsAsync(LoginEventQuery query, CancellationToken ct)
    {
        var parameters = new List<string>();
        Dates(parameters, query.From, query.To);
        foreach (var type in query.Types ?? []) parameters.Add("type=" + Uri.EscapeDataString(type));
        if (!string.IsNullOrEmpty(query.ClientId)) parameters.Add("client=" + Uri.EscapeDataString(query.ClientId));
        if (!string.IsNullOrEmpty(query.UserId)) parameters.Add("user=" + Uri.EscapeDataString(query.UserId));
        var page = await PageAsync("events", parameters, query.First, query.Max, ct);
        if (!page.IsSuccess) return page.Error!;
        return page.Value.Select(LoginEvent).ToArray();
    }

    public async Task<Result<IReadOnlyList<AdminEventDto>>> ListAdminEventsAsync(AdminEventQuery query, CancellationToken ct)
    {
        var parameters = new List<string>();
        Dates(parameters, query.From, query.To);
        foreach (var type in query.ResourceTypes ?? []) parameters.Add("resourceTypes=" + Uri.EscapeDataString(type));
        foreach (var op in query.Operations ?? []) parameters.Add("operationTypes=" + Uri.EscapeDataString(op));
        var page = await PageAsync("admin-events", parameters, query.First, query.Max, ct);
        if (!page.IsSuccess) return page.Error!;
        return page.Value.Select(AdminEvent).ToArray();
    }

    public async Task<Result<EventSettingsDto>> GetSettingsAsync(CancellationToken ct)
    {
        var config = await _api.GetAsync("events/config", Resource, ct);
        if (!config.IsSuccess) return config.Error!;
        var c = config.Value;
        var expiration = c.TryGetProperty("eventsExpiration", out var e) && e.ValueKind == JsonValueKind.Number ? e.GetInt64() : 0;
        return new EventSettingsDto(Bool(c, "eventsEnabled"), Bool(c, "adminEventsEnabled"), Bool(c, "adminEventsDetailsEnabled"),
            expiration > 0 ? (int)Math.Max(1, expiration / SecondsPerDay) : 0);
    }

    public Task<Result> SetSettingsAsync(EventSettingsDto s, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Put, "", new
        {
            eventsEnabled = s.LoginEventsEnabled,
            eventsExpiration = (long)s.RetentionDays * SecondsPerDay,
            adminEventsEnabled = s.AdminEventsEnabled,
            adminEventsDetailsEnabled = s.AdminEventDetails,
        }, Resource, ct);

    /// <summary>Reads up to <paramref name="max"/> events from <paramref name="first"/>, in Keycloak-sized pages.</summary>
    private async Task<Result<IReadOnlyList<JsonElement>>> PageAsync(string path, List<string> parameters, int first, int max,
        CancellationToken ct)
    {
        var items = new List<JsonElement>();
        while (items.Count < max)
        {
            var size = Math.Min(KeycloakAdminApi.PageSize, max - items.Count);
            var query = string.Join('&', parameters.Append($"first={first + items.Count}").Append($"max={size}"));
            var page = await _api.GetAsync($"{path}?{query}", Resource, ct);
            if (!page.IsSuccess) return page.Error!;
            if (page.Value.ValueKind != JsonValueKind.Array)
                return Error.Upstream("keycloak.invalid_response", "Keycloak returned a response the gateway could not read.");
            var count = 0;
            foreach (var item in page.Value.EnumerateArray())
            {
                items.Add(item);
                count++;
            }
            if (count < size) break;
        }
        return items;
    }

    private static void Dates(List<string> parameters, DateOnly? from, DateOnly? to)
    {
        if (from is { } f) parameters.Add("dateFrom=" + f.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        if (to is { } t) parameters.Add("dateTo=" + t.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
    }

    internal static LoginEventDto LoginEvent(JsonElement e)
    {
        var type = KeycloakAdminApi.GetString(e, "type") ?? "UNKNOWN";
        var error = KeycloakAdminApi.GetString(e, "error");
        string? username = null;
        if (e.TryGetProperty("details", out var details)) username = KeycloakAdminApi.GetString(details, "username");
        return new LoginEventDto(Time(e), type, error is not null || type.EndsWith("_ERROR", StringComparison.Ordinal), error,
            KeycloakAdminApi.GetString(e, "clientId"), KeycloakAdminApi.GetString(e, "userId"), username,
            KeycloakAdminApi.GetString(e, "ipAddress"));
    }

    internal static AdminEventDto AdminEvent(JsonElement e)
    {
        string? actor = null, actorClient = null, ip = null;
        if (e.TryGetProperty("authDetails", out var auth))
        {
            actor = KeycloakAdminApi.GetString(auth, "userId");
            actorClient = KeycloakAdminApi.GetString(auth, "clientId");
            ip = KeycloakAdminApi.GetString(auth, "ipAddress");
        }
        return new AdminEventDto(Time(e), KeycloakAdminApi.GetString(e, "operationType") ?? "UNKNOWN",
            KeycloakAdminApi.GetString(e, "resourceType") ?? "UNKNOWN", KeycloakAdminApi.GetString(e, "resourcePath"),
            actor, actorClient, ip, KeycloakAdminApi.GetString(e, "error"));
    }

    private static DateTimeOffset Time(JsonElement e) =>
        e.TryGetProperty("time", out var t) && t.ValueKind == JsonValueKind.Number
            ? DateTimeOffset.FromUnixTimeMilliseconds(t.GetInt64())
            : DateTimeOffset.MinValue;

    private static bool Bool(JsonElement e, string property) =>
        e.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.True;
}
