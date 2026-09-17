using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Hardens the Keycloak Declarative User Profile so that <c>authz.scope.*</c>
/// (and the legacy <c>iam.scoped_access</c>) are admin-only writable.
/// Users cannot self-grant scopes via Account API / User Profile endpoints.
/// Complements server-side validation — defense in depth.
/// Best-effort; never blocks startup.
/// </summary>
public sealed class KeycloakUserProfileHardening(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakUserProfileHardening> logger)
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

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
            var json = await getRes.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Build patched profile: ensure attributes for authz.scope.* wildcard and legacy iam.scoped_access are admin-only edit.
            // Keycloak UP uses per-attribute permissions: {"view":["admin","user"],"edit":["admin"]}
            // We inject/override two unmanaged attribute configs mixing with existing.
            var patched = PatchProfile(root);
            if (patched is null) return; // already hardened

            var putReq = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/users/profile")
            { Content = JsonContent.Create(JsonDocument.Parse(patched).RootElement) };
            putReq.Headers.Add("Authorization", $"Bearer {token}");
            var putRes = await http.SendAsync(putReq, ct);
            if (!putRes.IsSuccessStatusCode)
                logger.LogDebug("User Profile PUT failed: {Status} {Body}", putRes.StatusCode, await putRes.Content.ReadAsStringAsync(ct));
            else
                logger.LogInformation("Hardened User Profile: authz.scope.* admin-only");
        }
        catch (Exception ex) { logger.LogDebug(ex, "User Profile hardening failed"); }
    }

    private static string? PatchProfile(JsonElement root)
    {
        // Check if already has attributes for our keys with edit: admin-only
        var hasHardening = false;
        if (root.TryGetProperty("attributes", out var attrs) && attrs.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in attrs.EnumerateArray())
            {
                var name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
                if (name is "authz.scope.*" or "iam.scoped_access")
                {
                    if (a.TryGetProperty("permissions", out var perms) &&
                        perms.TryGetProperty("edit", out var edit) && edit.ValueKind == JsonValueKind.Array)
                    {
                        var editors = edit.EnumerateArray().Select(e => e.GetString()).ToHashSet(StringComparer.Ordinal);
                        if (editors.SetEquals(new[] { "admin" })) hasHardening = true;
                    }
                }
            }
            if (hasHardening) return null; // already present — avoid churn
        }

        // Build new profile JSON by cloning and injecting attributes if missing
        using var ms = new System.IO.MemoryStream();
        using var w = new Utf8JsonWriter(ms);
        w.WriteStartObject();
        bool wroteAttrs = false;
        foreach (var prop in root.EnumerateObject())
        {
            if (prop.NameEquals("attributes") && prop.Value.ValueKind == JsonValueKind.Array)
            {
                w.WritePropertyName("attributes");
                w.WriteStartArray();
                foreach (var a in prop.Value.EnumerateArray()) a.WriteTo(w);
                // Ensure authz.scope.* wildcard
                if (!ContainsAttr(prop.Value, "authz.scope.*"))
                {
                    w.WriteStartObject();
                    w.WriteString("name", "authz.scope.*");
                    w.WriteString("displayName", "${authz.scope.*}");
                    w.WritePropertyName("permissions"); w.WriteStartObject();
                    w.WritePropertyName("view"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
                    w.WritePropertyName("edit"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
                    w.WriteEndObject();
                    w.WritePropertyName("validations"); w.WriteStartObject(); w.WriteEndObject();
                    w.WritePropertyName("annotations"); w.WriteStartObject(); w.WriteEndObject();
                    w.WriteEndObject();
                }
                if (!ContainsAttr(prop.Value, "iam.scoped_access"))
                {
                    w.WriteStartObject();
                    w.WriteString("name", "iam.scoped_access");
                    w.WriteString("displayName", "${iam.scoped_access}");
                    w.WritePropertyName("permissions"); w.WriteStartObject();
                    w.WritePropertyName("view"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
                    w.WritePropertyName("edit"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
                    w.WriteEndObject();
                    w.WritePropertyName("validations"); w.WriteStartObject(); w.WriteEndObject();
                    w.WritePropertyName("annotations"); w.WriteStartObject(); w.WriteEndObject();
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                wroteAttrs = true;
            }
            else prop.WriteTo(w);
        }
        if (!wroteAttrs)
        {
            w.WritePropertyName("attributes");
            w.WriteStartArray();
            w.WriteStartObject();
            w.WriteString("name", "authz.scope.*");
            w.WritePropertyName("permissions"); w.WriteStartObject();
            w.WritePropertyName("view"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
            w.WritePropertyName("edit"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
            w.WriteEndObject();
            w.WritePropertyName("validations"); w.WriteStartObject(); w.WriteEndObject();
            w.WritePropertyName("annotations"); w.WriteStartObject(); w.WriteEndObject();
            w.WriteEndObject();
            w.WriteStartObject();
            w.WriteString("name", "iam.scoped_access");
            w.WritePropertyName("permissions"); w.WriteStartObject();
            w.WritePropertyName("view"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
            w.WritePropertyName("edit"); w.WriteStartArray(); w.WriteStringValue("admin"); w.WriteEndArray();
            w.WriteEndObject();
            w.WritePropertyName("validations"); w.WriteStartObject(); w.WriteEndObject();
            w.WritePropertyName("annotations"); w.WriteStartObject(); w.WriteEndObject();
            w.WriteEndObject();
            w.WriteEndArray();
        }
        w.WriteEndObject();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }

    private static bool ContainsAttr(JsonElement arr, string name)
    {
        foreach (var a in arr.EnumerateArray())
            if (a.TryGetProperty("name", out var n) && n.GetString() == name) return true;
        return false;
    }
}
