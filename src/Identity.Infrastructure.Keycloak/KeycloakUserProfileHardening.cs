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
/// Must be re-run whenever a scope is added to the registry; failures are returned, not hidden.
/// </summary>
public sealed class KeycloakUserProfileHardening(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakUserProfileHardening> logger) : IUserProfileRequirements
{
    private const string Resource = "user_profile";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);
    private const string ScopeAttrPrefix = "authz.scope.";
    private const string LegacyAttributeName = "iam.scoped_access";
    private static readonly TimeSpan RequirementsCacheTtl = TimeSpan.FromMinutes(5);
    private DateTimeOffset _requirementsCachedAt = DateTimeOffset.MinValue;
    private IReadOnlyCollection<string> _requiredAttributes = Array.Empty<string>();

    /// <summary>
    /// Profile attributes Keycloak marks required for the <c>user</c> role (e.g. email,
    /// firstName). Creating a user without them succeeds but locks them out of login.
    /// </summary>
    public async Task<Result<IReadOnlyCollection<string>>> GetRequiredAttributesAsync(CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow - _requirementsCachedAt < RequirementsCacheTtl) return Result<IReadOnlyCollection<string>>.Success(_requiredAttributes);
        var profile = await _api.GetAsync("users/profile", Resource, ct);
        if (!profile.IsSuccess) return profile.Error!;
        _requiredAttributes = ExtractRequiredAttributes(profile.Value);
        _requirementsCachedAt = DateTimeOffset.UtcNow;
        return Result<IReadOnlyCollection<string>>.Success(_requiredAttributes);
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

    /// <summary>
    /// Declares <c>authz.scope.&lt;key&gt;</c> for every given registry key (plus the legacy document
    /// attribute) as admin-only. Without the declaration Keycloak silently drops the attribute on write.
    /// </summary>
    public async Task<Result> EnsureAsync(IReadOnlyCollection<string> scopeKeys, CancellationToken ct)
    {
        var profile = await _api.GetAsync("users/profile", Resource, ct);
        if (!profile.IsSuccess) return profile.Error!;

        var patched = PatchProfile(profile.Value, scopeKeys);
        if (patched is null) return Result.Success(); // already hardened — avoid churn

        using var document = JsonDocument.Parse(patched);
        var written = await _api.SendWithoutResultAsync(HttpMethod.Put, "users/profile", document.RootElement.Clone(), Resource, ct);
        if (written.IsSuccess)
            logger.LogInformation("Declared {Count} admin-only authz.scope.* attributes in the user profile", scopeKeys.Count);
        return written;
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
