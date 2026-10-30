using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using Identity.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Avash.Identity.Authorization;

/// <summary>Options of <see cref="GatewayAccessScheduleProvider"/>; section <c>Identity:AccessSchedule</c>.</summary>
public sealed class AccessScheduleClientOptions
{
    public const string SectionName = "Identity:AccessSchedule";

    /// <summary>Base URL of the Identity Gateway, e.g. <c>http://localhost:5080</c>.</summary>
    public string? GatewayBaseUrl { get; set; }

    public string Path { get; set; } = "/api/identity/access-schedule";

    /// <summary>How long a user's schedules are reused; schedule changes reach the service after at most this long.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(1);

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);
}

/// <summary>The current user's resolved weekly schedules, or null when they could not be read.</summary>
public interface IAccessScheduleProvider
{
    Task<AccessScheduleSnapshot?> GetAsync(ClaimsPrincipal user, CancellationToken ct);
}

/// <summary>
/// Reads <c>/api/identity/access-schedule</c> from the gateway with the caller's bearer token and caches it per
/// user (<c>sub</c>). Failures are logged and reported as null; callers deny access in that case.
/// </summary>
public sealed class GatewayAccessScheduleProvider(
    IHttpContextAccessor httpAccessor,
    IHttpClientFactory httpFactory,
    IOptions<AccessScheduleClientOptions> options,
    TimeProvider clock,
    ILogger<GatewayAccessScheduleProvider> logger) : IAccessScheduleProvider
{
    public const string HttpClientName = "IdentityAccessSchedule";

    private readonly ConcurrentDictionary<string, (DateTimeOffset Expires, AccessScheduleSnapshot Snapshot)> _cache = new(StringComparer.Ordinal);

    public async Task<AccessScheduleSnapshot?> GetAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var userId = user.FindFirst("sub")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return null;
        var now = clock.GetUtcNow();
        if (_cache.TryGetValue(userId, out var cached) && cached.Expires > now) return cached.Snapshot;

        var o = options.Value;
        var authorization = httpAccessor.HttpContext?.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(o.GatewayBaseUrl) || !AuthenticationHeaderValue.TryParse(authorization, out var header) ||
            !string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("Access schedules cannot be read: no gateway URL or no bearer token on the request");
            return null;
        }

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(o.Timeout);
            using var request = new HttpRequestMessage(HttpMethod.Get, o.GatewayBaseUrl.TrimEnd('/') + o.Path);
            request.Headers.Authorization = header;
            using var response = await httpFactory.CreateClient(HttpClientName).SendAsync(request, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Access schedules for {UserId}: gateway answered {Status}", userId, (int)response.StatusCode);
                return null;
            }
            var snapshot = await response.Content.ReadFromJsonAsync<AccessScheduleSnapshot>(timeout.Token);
            if (snapshot is not null) _cache[userId] = (now + o.CacheDuration, snapshot);
            return snapshot;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or System.Text.Json.JsonException)
        {
            logger.LogWarning(ex, "Access schedules for {UserId} could not be read from the gateway", userId);
            return null;
        }
    }
}
