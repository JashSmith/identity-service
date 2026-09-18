using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Hardens the Keycloak Declarative User Profile so the scoped-access attributes are usable
/// and admin-only.
/// <para>
/// Keycloak's default unmanaged-attribute policy silently DISCARDS any user attribute that is
/// not declared in the profile — which is why scope writes returned 204 but never persisted.
/// Wildcards are not supported either: an attribute literally named <c>authz.scope.*</c> does
/// not match <c>authz.scope.region</c>. So this declares one concrete attribute per registry
/// scope key (<c>authz.scope.&lt;key&gt;</c>, multivalued) plus the legacy <c>iam.scoped_access</c>,
/// each with <c>view/edit = admin</c> so users cannot self-grant scopes through the Account API.
/// </para>
/// Must be re-run whenever a scope is added to the registry. Best-effort; never blocks startup.
/// </summary>
public sealed class KeycloakUserProfileHardening(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakUserProfileHardening> logger) : IUserProfileRequirements
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private const string ScopeAttrPrefix = "authz.scope.";
    private const string LegacyAttributeName = "iam.scoped_access";
    private static readonly TimeSpan RequirementsCacheTtl = TimeSpan.FromMinutes(5);
    private DateTimeOffset _requirementsCachedAt = DateTimeOffset.MinValue;
    private IReadOnlyCollection<string> _requiredAttributes = Array.Empty<string>();

    /// <summary>
    /// Profile attributes Keycloak marks required for the <c>user</c> role (e.g. email,
    /// firstName). Creating a user without them succeeds but locks them out of login.
    /// </summary>
    public async Task<IReadOnlyCollection<string>> GetRequiredAttributesAsync(CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow - _requirementsCachedAt < RequirementsCacheTtl) return _requiredAttributes;
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<string>(); // fail-open: do not block user creation
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/profile");
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var root = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct)).RootElement;
            _requiredAttributes = ExtractRequiredAttributes(root);
            _requirementsCachedAt = DateTimeOffset.UtcNow;
            return _requiredAttributes;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not read required profile attributes");
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// An attribute is required for created users when its <c>required.roles</c> list includes
    /// <c>user</c> (Keycloak's declarative-profile convention), or when required with no roles.
    /// </summary>
    internal static IReadOnlyCollection<string> ExtractRequiredAttributes(JsonElement root)
    {
        var result = new List<string>();
        if (!root.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Array) return result;
        foreach (var a in attrs.EnumerateArray())
        {
            if (!a.TryGetProperty("name", out var n) || n.GetString() is not { } name) continue;
            if (!a.TryGetProperty("required", out var req) || req.ValueKind != JsonValueKind.Object) continue;
            if (req.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
            {
                var roleNames = roles.EnumerateArray().Select(r => r.GetString() ?? "").ToArray();
                if (roleNames.Length > 0 && !roleNames.Contains("user", StringComparer.Ordinal)) continue;
            }
            result.Add(name);
        }
        return result;
    }

    public async Task EnsureAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) { logger.LogDebug("Skipping User Profile hardening — token unavailable"); return; }
        try
        {
            var getReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/profile");
            getReq.Headers.Add("Authorization", $"Bearer {token}");
            var getRes = await http.SendAsync(getReq, ct);
            if (!getRes.IsSuccessStatusCode) { logger.LogDebug("User Profile GET failed: {Status}", getRes.StatusCode); return; }
            var root = JsonDocument.Parse(await getRes.Content.ReadAsStringAsync(ct)).RootElement;

            var scopeKeys = await ResolveScopeKeysAsync(token, ct);
            var patched = PatchProfile(root, scopeKeys);
            if (patched is null) return; // already hardened — avoid churn

            var putReq = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/users/profile")
            { Content = JsonContent.Create(JsonDocument.Parse(patched).RootElement) };
            putReq.Headers.Add("Authorization", $"Bearer {token}");
            var putRes = await http.SendAsync(putReq, ct);
            if (!putRes.IsSuccessStatusCode)
                logger.LogWarning("User Profile PUT failed: {Status} {Body}", putRes.StatusCode, await putRes.Content.ReadAsStringAsync(ct));
            else
                logger.LogInformation("Hardened User Profile: {Count} authz.scope.* attributes admin-only", scopeKeys.Count);
        }
        catch (Exception ex) { logger.LogWarning(ex, "User Profile hardening failed"); }
    }

    /// <summary>Scope keys from the iam-scope-registry group, falling back to the well-known defaults.</summary>
    private async Task<IReadOnlyCollection<string>> ResolveScopeKeysAsync(string token, CancellationToken ct)
    {
        var defaults = new[] { "region", "branch", "department", "organization", "warehouse", "customer", "project", "test-key" };
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search=iam-scope-registry");
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return defaults;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return defaults;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.TryGetProperty("name", out var n) && n.GetString() != "iam-scope-registry") continue;
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
                foreach (var p in attrs.EnumerateObject())
                    if (p.Name.StartsWith("scope.", StringComparison.Ordinal)) keys.Add(p.Name.Substring("scope.".Length));
                return keys.Count > 0 ? keys : defaults;
            }
        }
        catch (Exception ex) { logger.LogDebug(ex, "Could not resolve scope keys for profile hardening"); }
        return defaults;
    }

    /// <summary>Returns the patched profile JSON, or null when every required attribute already exists.</summary>
    public static string? PatchProfile(JsonElement root, IReadOnlyCollection<string> scopeKeys)
    {
        var required = scopeKeys.Select(k => ScopeAttrPrefix + k).Append(LegacyAttributeName).ToArray();

        var existing = new HashSet<string>(StringComparer.Ordinal);
        if (root.TryGetProperty("attributes", out var attrs) && attrs.ValueKind == JsonValueKind.Array)
            foreach (var a in attrs.EnumerateArray())
                if (a.TryGetProperty("name", out var n) && n.GetString() is { } name) existing.Add(name);

        // Drop the literal wildcard attribute left by earlier versions — it matches nothing.
        var stale = existing.Contains(ScopeAttrPrefix + "*");
        if (!stale && required.All(existing.Contains)) return null;

        using var ms = new MemoryStream();
        using var w = new Utf8JsonWriter(ms);
        w.WriteStartObject();
        bool wroteAttrs = false;
        foreach (var prop in root.EnumerateObject())
        {
            if (prop.NameEquals("attributes") && prop.Value.ValueKind == JsonValueKind.Array)
            {
                wroteAttrs = true;
                w.WritePropertyName("attributes");
                w.WriteStartArray();
                foreach (var a in prop.Value.EnumerateArray())
                {
                    var nm = a.TryGetProperty("name", out var n2) ? n2.GetString() : null;
                    if (nm == ScopeAttrPrefix + "*") continue; // remove non-functional wildcard
                    a.WriteTo(w);
                }
                foreach (var attrName in required.Where(r => !existing.Contains(r)))
                    WriteAdminOnlyAttribute(w, attrName, multivalued: attrName.StartsWith(ScopeAttrPrefix, StringComparison.Ordinal));
                w.WriteEndArray();
            }
            else prop.WriteTo(w);
        }
        if (!wroteAttrs)
        {
            w.WritePropertyName("attributes");
            w.WriteStartArray();
            foreach (var attrName in required)
                WriteAdminOnlyAttribute(w, attrName, multivalued: attrName.StartsWith(ScopeAttrPrefix, StringComparison.Ordinal));
            w.WriteEndArray();
        }
        w.WriteEndObject();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void WriteAdminOnlyAttribute(Utf8JsonWriter w, string name, bool multivalued)
    {
        w.WriteStartObject();
        w.WriteString("name", name);
        w.WriteString("displayName", name);
        w.WriteBoolean("multivalued", multivalued);
        w.WritePropertyName("permissions");
        w.WriteStartObject();
        w.WritePropertyName("view"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
        w.WritePropertyName("edit"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
        w.WriteEndObject();
        w.WritePropertyName("validations"); w.WriteStartObject(); w.WriteEndObject();
        w.WritePropertyName("annotations"); w.WriteStartObject(); w.WriteEndObject();
        w.WriteEndObject();
    }
}
