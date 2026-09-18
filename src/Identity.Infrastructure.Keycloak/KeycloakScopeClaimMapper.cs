using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Provisions the <c>authz-scopes</c> client scope that exposes <c>authz.scope.*</c>
/// user/group attributes as token claims. One <c>oidc-usermodel-attribute-mapper</c>
/// per scope key → claim <c>scope.&lt;key&gt;</c> (flat, multivalued) plus a
/// JSON <c>scopes</c> claim for convenience. Stacked built-in mappers are sufficient;
/// no custom SPI is required for the nested JSON — consumers can reconstruct
/// <c>scopes:{region:[…]}</c> from the flat claims, or read the single
/// <c>iam_access</c> JSON claim during the migration window.
/// Freshness: already-issued access tokens do NOT mutate; short-lived AT (300s for
/// identity-facade) + refresh-token rotation propagates changes on next refresh.
/// Best-effort, never blocks startup.
/// </summary>
public sealed class KeycloakScopeClaimMapper(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakScopeClaimMapper> logger)
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private const string ScopeName = "authz-scopes";
    private const string ScopeAttrPrefix = "authz.scope.";

    public async Task EnsureAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) { logger.LogDebug("Skipping authz-scopes mapper — token unavailable"); return; }
        try
        {
            var scopeId = await EnsureClientScopeAsync(token, ct);
            if (string.IsNullOrEmpty(scopeId)) return;
            await EnsureDefaultScopeAsync(scopeId, token, ct);
            // Ensure mappers for registry-defined scopes plus well-known defaults (so startup works before registry exists)
            var keys = await ResolveScopeKeysAsync(token, ct);
            foreach (var k in keys) await EnsureAttributeMapperAsync(scopeId, k, token, ct);
            // Realm-level defaults are not applied retroactively, and a realm imported with
            // IGNORE_EXISTING keeps its old clients — so attach the scope to every client here.
            // Without it the authz.scope.* mappers never run and tokens carry no scope claims.
            await EnsureScopeAssignedToClientsAsync(scopeId, token, ct);
        }
        catch (Exception ex) { logger.LogDebug(ex, "Failed to provision authz-scopes mappers"); }
    }

    /// <summary>Idempotently assigns the scope as a default client scope on every realm client.</summary>
    private async Task EnsureScopeAssignedToClientsAsync(string scopeId, string token, CancellationToken ct)
    {
        var listReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients?first=0&max=200");
        listReq.Headers.Add("Authorization", $"Bearer {token}");
        var listRes = await http.SendAsync(listReq, ct);
        if (!listRes.IsSuccessStatusCode) return;
        var doc = JsonDocument.Parse(await listRes.Content.ReadAsStringAsync(ct));
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return;
        int assigned = 0;
        foreach (var c in doc.RootElement.EnumerateArray())
        {
            var clientUuid = c.TryGetProperty("id", out var id) ? id.GetString() : null;
            if (string.IsNullOrEmpty(clientUuid)) continue;

            var assignedReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(clientUuid)}/default-client-scopes");
            assignedReq.Headers.Add("Authorization", $"Bearer {token}");
            var assignedRes = await http.SendAsync(assignedReq, ct);
            if (assignedRes.IsSuccessStatusCode)
            {
                var adoc = JsonDocument.Parse(await assignedRes.Content.ReadAsStringAsync(ct));
                if (adoc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    var already = adoc.RootElement.EnumerateArray()
                        .Any(s => s.TryGetProperty("id", out var sid) && sid.GetString() == scopeId);
                    if (already) continue;
                }
            }

            var addReq = new HttpRequestMessage(HttpMethod.Put,
                $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(clientUuid)}/default-client-scopes/{Uri.EscapeDataString(scopeId)}");
            addReq.Headers.Add("Authorization", $"Bearer {token}");
            var addRes = await http.SendAsync(addReq, ct);
            if (addRes.IsSuccessStatusCode) assigned++;
            else logger.LogDebug("Could not assign {Scope} to client {Client}: {Status}", ScopeName, clientUuid, addRes.StatusCode);
        }
        if (assigned > 0) logger.LogInformation("Assigned client scope {Scope} to {Count} client(s)", ScopeName, assigned);
    }

    private async Task<string> EnsureClientScopeAsync(string token, CancellationToken ct)
    {
        var listReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/client-scopes");
        listReq.Headers.Add("Authorization", $"Bearer {token}");
        var listRes = await http.SendAsync(listReq, ct);
        if (listRes.IsSuccessStatusCode)
        {
            var doc = JsonDocument.Parse(await listRes.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var el in doc.RootElement.EnumerateArray())
                    if (el.TryGetProperty("name", out var n) && n.GetString() == ScopeName && el.TryGetProperty("id", out var id))
                        return id.GetString() ?? "";
        }
        var body = new { name = ScopeName, description = "Exposes authz.scope.* attributes as scopes claims", protocol = "openid-connect", attributes = new Dictionary<string,string>{ ["include.in.token.scope"]="false", ["display.on.consent.screen"]="false" } };
        var createReq = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/client-scopes") { Content = JsonContent.Create(body) };
        createReq.Headers.Add("Authorization", $"Bearer {token}");
        var createRes = await http.SendAsync(createReq, ct);
        if (createRes.Headers.Location is not null) return createRes.Headers.Location.ToString().Split('/').LastOrDefault()?.Trim() ?? "";
        if (createRes.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            var retry = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/client-scopes");
            retry.Headers.Add("Authorization", $"Bearer {token}");
            var r2 = await http.SendAsync(retry, ct);
            if (r2.IsSuccessStatusCode)
            {
                var d2 = JsonDocument.Parse(await r2.Content.ReadAsStringAsync(ct));
                if (d2.RootElement.ValueKind == JsonValueKind.Array)
                    foreach (var el in d2.RootElement.EnumerateArray())
                        if (el.TryGetProperty("name", out var n2) && n2.GetString() == ScopeName && el.TryGetProperty("id", out var id2))
                            return id2.GetString() ?? "";
            }
        }
        logger.LogDebug("Failed to create client scope {Scope}: {Status}", ScopeName, createRes.StatusCode);
        return "";
    }

    private async Task EnsureDefaultScopeAsync(string scopeId, string token, CancellationToken ct)
    {
        var realmReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}");
        realmReq.Headers.Add("Authorization", $"Bearer {token}");
        var realmRes = await http.SendAsync(realmReq, ct);
        if (!realmRes.IsSuccessStatusCode) return;
        var realmDoc = JsonDocument.Parse(await realmRes.Content.ReadAsStringAsync(ct));
        if (realmDoc.RootElement.TryGetProperty("defaultDefaultClientScopes", out var scopes) && scopes.ValueKind == JsonValueKind.Array)
            foreach (var s in scopes.EnumerateArray()) if (s.GetString() == ScopeName) return;
        var addReq = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/default-default-client-scopes/{Uri.EscapeDataString(scopeId)}");
        addReq.Headers.Add("Authorization", $"Bearer {token}");
        var addRes = await http.SendAsync(addReq, ct);
        if (addRes.IsSuccessStatusCode) logger.LogInformation("Added {Scope} to realm default scopes", ScopeName);
    }

    private async Task<IReadOnlyCollection<string>> ResolveScopeKeysAsync(string token, CancellationToken ct)
    {
        var defaults = new[] { "region","branch","department","organization","warehouse","customer","project","test-key" };
        try
        {
            // Read iam-scope-registry group attributes for scope.<key>
            var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search=iam-scope-registry");
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return defaults;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return defaults;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.TryGetProperty("name", out var n) && n.GetString() == "iam-scope-registry")
                {
                    var id = el.TryGetProperty("id", out var gid) ? gid.GetString() : null;
                    JsonElement target = el;
                    if (!string.IsNullOrEmpty(id))
                    {
                        var gReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(id)}");
                        gReq.Headers.Add("Authorization", $"Bearer {token}");
                        var gRes = await http.SendAsync(gReq, ct);
                        if (gRes.IsSuccessStatusCode) target = JsonDocument.Parse(await gRes.Content.ReadAsStringAsync(ct)).RootElement;
                    }
                    if (!target.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object) return defaults;
                    var keys = new List<string>();
                    foreach (var p in attrs.EnumerateObject()) if (p.Name.StartsWith("scope.", StringComparison.Ordinal)) keys.Add(p.Name.Substring("scope.".Length));
                    return keys.Count > 0 ? keys : defaults;
                }
            }
        } catch { }
        return defaults;
    }

    private async Task EnsureAttributeMapperAsync(string scopeId, string scopeKey, string token, CancellationToken ct)
    {
        var mapperName = $"authz-scope-{scopeKey}";
        var listReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/client-scopes/{Uri.EscapeDataString(scopeId)}/protocol-mappers/models");
        listReq.Headers.Add("Authorization", $"Bearer {token}");
        var listRes = await http.SendAsync(listReq, ct);
        if (listRes.IsSuccessStatusCode)
        {
            var doc = JsonDocument.Parse(await listRes.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var el in doc.RootElement.EnumerateArray())
                    if (el.TryGetProperty("name", out var n) && n.GetString() == mapperName) return;
        }
        var body = new
        {
            name = mapperName,
            protocol = "openid-connect",
            protocolMapper = "oidc-usermodel-attribute-mapper",
            config = new Dictionary<string,string>
            {
                ["user.attribute"] = ScopeAttrPrefix + scopeKey,
                ["claim.name"] = $"authz.scope.{scopeKey}",
                ["jsonType.label"] = "String",
                ["multivalued"] = "true",
                ["aggregate.attrs"] = "true",
                ["userinfo.token.claim"] = "true",
                ["access.token.claim"] = "true",
                ["id.token.claim"] = "false",
            }
        };
        var createReq = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/client-scopes/{Uri.EscapeDataString(scopeId)}/protocol-mappers/models") { Content = JsonContent.Create(body) };
        createReq.Headers.Add("Authorization", $"Bearer {token}");
        var createRes = await http.SendAsync(createReq, ct);
        if (!createRes.IsSuccessStatusCode) logger.LogDebug("Failed to create mapper {Mapper}: {Status} {Body}", mapperName, createRes.StatusCode, await createRes.Content.ReadAsStringAsync(ct));
        else logger.LogInformation("Provisioned authz scope mapper {Mapper}", mapperName);
    }
}
