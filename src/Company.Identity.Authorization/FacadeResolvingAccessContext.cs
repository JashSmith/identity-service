using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Identity.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Company.Identity.Authorization;

/// <summary>
/// Facade-resolving decorator: reads <c>iam_access</c> from the inbound <see cref="ClaimsPrincipal"/> first
/// and, when absent, lazily <c>GET</c>s authoritative assignments from the Identity Facade's
/// <c>/api/identity/access-context</c> (and updates the effective permission set from the same response).
/// Call <see cref="EnsureLoadedAsync"/> once per request before scope-dependent checks when the caller
/// may hold an oversized/claim-stripped token; no-op when assignments came from the claim.
/// Registered by <c>AddCompanyAccessContext</c> when <see cref="AccessContextOptions.FacadeBaseUrl"/> is set.
/// </summary>
public sealed class FacadeResolvingAccessContext : ICurrentAccessContext
{
    private readonly ClaimsPrincipal _principal;
    private readonly IHttpContextAccessor _httpAccessor;
    private readonly IHttpClientFactory _httpFactory;
    private readonly AccessContextOptions _options;

    private ClaimsPrincipalAccessContext _inner;
    private bool _resolved;
    private readonly object _gate = new();

    public FacadeResolvingAccessContext(
        ClaimsPrincipal principal,
        IHttpContextAccessor httpAccessor,
        IHttpClientFactory httpFactory,
        IOptions<AccessContextOptions> options)
    {
        _principal = principal;
        _httpAccessor = httpAccessor;
        _httpFactory = httpFactory;
        _options = options.Value;
        _inner = new ClaimsPrincipalAccessContext(principal);
    }

    public IReadOnlyCollection<ScopedRoleAssignment> GetAssignments() => _inner.GetAssignments();
    public bool HasPermission(string permission) => _inner.HasPermission(permission);
    public bool HasPermission(string permission, string scopeKey, string scopeValue) => _inner.HasPermission(permission, scopeKey, scopeValue);
    public IReadOnlyCollection<string> GetScopeValues(string scopeKey) => _inner.GetScopeValues(scopeKey);
    public bool HasScope(string scopeKey, string scopeValue) => _inner.HasScope(scopeKey, scopeValue);

    public async Task EnsureLoadedAsync(CancellationToken ct = default)
    {
        // No facade configured, already resolved, or inline claim was present — nothing to do.
        if (_resolved) return;
        if (string.IsNullOrWhiteSpace(_options.FacadeBaseUrl)) return;
        if (_inner.HasInlineAssignments) { _resolved = true; return; }

        // Best-effort single-flight: if two callers await concurrently the same scoped instance
        // could race; _gate serializes the first resolution.
        // Keep it simple: early-exit second waiter will also no-op; acceptable to re-enter once.
        var authorization = _httpAccessor.HttpContext?.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization)) return;

        // Forward only Bearer; opaque values are not forwarded.
        if (!AuthenticationHeaderValue.TryParse(authorization, out var header) ||
            !string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(header.Parameter))
            return;

        var baseUrl = _options.FacadeBaseUrl!.TrimEnd('/');
        var url = baseUrl + _options.AccessContextPath;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_options.Timeout);
            var client = _httpFactory.CreateClient("IdentityAccessContext");
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", header.Parameter);
            using var resp = await client.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return;
            var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var dto = JsonSerializer.Deserialize<AccessContextResponse>(json,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            if (dto is null) return;

            var assignments = (dto.Assignments ?? Array.Empty<ScopedRoleAssignment>())
                .Where(a => !string.IsNullOrWhiteSpace(a.Role)).ToArray();
            var permissions = (dto.Permissions ?? Array.Empty<string>())
                .Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.Ordinal).ToArray();

            // On success, replace inner so subsequent reads see facade-authoritative data.
            // Keep the principal's permission set as the base and overlay facade permissions
            // (facade is authoritative for the user's effective permission set).
            lock (_gate)
            {
                if (_resolved) return;
                var effectivePerms = permissions.Length > 0 ? permissions : _inner.Permissions.ToArray();
                _inner = new ClaimsPrincipalAccessContext(effectivePerms, assignments);
                _resolved = true;
            }
        }
        catch (OperationCanceledException) { }
        catch { /* best-effort: leave claims-derived view intact */ }
    }
}
