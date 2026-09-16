using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Idempotently provisions the <c>iam_access</c> protocol mapper that exposes the
/// <c>iam.scoped_access</c> user attribute as a compact JWT claim. Best-effort — failure
/// never blocks startup; the facade fallback (<c>GET /users/{id}/scoped-access</c>) remains.
/// Uses the Keycloak Admin REST API against the realm's clientScopes.
/// </summary>
public sealed class KeycloakIamAccessClaimMapper(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakIamAccessClaimMapper> logger)
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private const string ScopeName = "iam-access";
    private const string MapperName = "iam-access-mapper";
    private const string AttributeName = "iam.scoped_access";
    private const string ClaimName = "iam_access";

    public async Task EnsureAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token))
        {
            logger.LogDebug("Skipping iam_access mapper provisioning — admin token unavailable");
            return;
        }

        try
        {
            var scopeId = await EnsureClientScopeAsync(token, ct);
            if (string.IsNullOrEmpty(scopeId)) return;
            await EnsureMapperAsync(scopeId, token, ct);
            await EnsureDefaultScopeAsync(scopeId, token, ct);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to provision iam_access mapper — facade fallback will be used");
        }
    }

    private async Task<string> EnsureClientScopeAsync(string token, CancellationToken ct)
    {
        // Check if scope already exists
        var listReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/client-scopes");
        listReq.Headers.Add("Authorization", $"Bearer {token}");
        var listRes = await http.SendAsync(listReq, ct);
        if (listRes.IsSuccessStatusCode)
        {
            var doc = JsonDocument.Parse(await listRes.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var el in doc.RootElement.EnumerateArray())
                    if (el.TryGetProperty("name", out var n) && n.GetString() == ScopeName &&
                        el.TryGetProperty("id", out var id))
                        return id.GetString() ?? "";
        }

        // Create
        var body = new
        {
            name = ScopeName,
            description = "Exposes iam.scoped_access as iam_access claim",
            protocol = "openid-connect",
            attributes = new Dictionary<string, string>
            {
                ["include.in.token.scope"] = "false",
                ["display.on.consent.screen"] = "false",
                ["gui.order"] = "",
            }
        };
        var createReq = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/client-scopes")
        {
            Content = JsonContent.Create(body)
        };
        createReq.Headers.Add("Authorization", $"Bearer {token}");
        var createRes = await http.SendAsync(createReq, ct);
        if (createRes.Headers.Location is not null)
        {
            var loc = createRes.Headers.Location.ToString();
            return loc.Split('/').LastOrDefault()?.Trim() ?? "";
        }
        if (createRes.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            // Race — fetch again
            var retryReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/client-scopes");
            retryReq.Headers.Add("Authorization", $"Bearer {token}");
            var retryRes = await http.SendAsync(retryReq, ct);
            if (retryRes.IsSuccessStatusCode)
            {
                var doc2 = JsonDocument.Parse(await retryRes.Content.ReadAsStringAsync(ct));
                if (doc2.RootElement.ValueKind == JsonValueKind.Array)
                    foreach (var el in doc2.RootElement.EnumerateArray())
                        if (el.TryGetProperty("name", out var n2) && n2.GetString() == ScopeName &&
                            el.TryGetProperty("id", out var id2))
                            return id2.GetString() ?? "";
            }
        }
        logger.LogDebug("Failed to create client scope {ScopeName}: {Status}", ScopeName, createRes.StatusCode);
        return "";
    }

    private async Task EnsureMapperAsync(string scopeId, string token, CancellationToken ct)
    {
        var listReq = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/client-scopes/{Uri.EscapeDataString(scopeId)}/protocol-mappers/models");
        listReq.Headers.Add("Authorization", $"Bearer {token}");
        var listRes = await http.SendAsync(listReq, ct);
        if (listRes.IsSuccessStatusCode)
        {
            var doc = JsonDocument.Parse(await listRes.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var el in doc.RootElement.EnumerateArray())
                    if (el.TryGetProperty("name", out var n) && n.GetString() == MapperName)
                        return; // already exists
        }

        var mapperBody = new
        {
            name = MapperName,
            protocol = "openid-connect",
            protocolMapper = "oidc-usermodel-attribute-mapper",
            config = new Dictionary<string, string>
            {
                ["user.attribute"] = AttributeName,
                ["claim.name"] = ClaimName,
                ["jsonType.label"] = "String",
                ["multivalued"] = "false",
                ["aggregate.attrs"] = "false",
                ["userinfo.token.claim"] = "true",
                ["access.token.claim"] = "true",
                ["id.token.claim"] = "false",
                ["access.tokenResponse.claim"] = "false",
            }
        };
        var createReq = new HttpRequestMessage(HttpMethod.Post,
            $"{AdminBase}/{_o.Realm}/client-scopes/{Uri.EscapeDataString(scopeId)}/protocol-mappers/models")
        {
            Content = JsonContent.Create(mapperBody)
        };
        createReq.Headers.Add("Authorization", $"Bearer {token}");
        var createRes = await http.SendAsync(createReq, ct);
        if (!createRes.IsSuccessStatusCode)
            logger.LogDebug("Failed to create mapper {MapperName}: {Status} {Body}", MapperName, createRes.StatusCode, await createRes.Content.ReadAsStringAsync(ct));
        else
            logger.LogInformation("Provisioned iam_access mapper in client scope {ScopeName}", ScopeName);
    }

    private async Task EnsureDefaultScopeAsync(string scopeId, string token, CancellationToken ct)
    {
        // Add to realm default scopes so it applies without explicit scope param
        var realmReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}");
        realmReq.Headers.Add("Authorization", $"Bearer {token}");
        var realmRes = await http.SendAsync(realmReq, ct);
        if (!realmRes.IsSuccessStatusCode) return;
        var realmDoc = JsonDocument.Parse(await realmRes.Content.ReadAsStringAsync(ct));
        var hasDefault = false;
        if (realmDoc.RootElement.TryGetProperty("defaultDefaultClientScopes", out var scopes) && scopes.ValueKind == JsonValueKind.Array)
            foreach (var s in scopes.EnumerateArray())
                if (s.GetString() == ScopeName) { hasDefault = true; break; }
        if (hasDefault) return;

        // PUT default-default-client-scopes/{scopeId}
        var addReq = new HttpRequestMessage(HttpMethod.Put,
            $"{AdminBase}/{_o.Realm}/default-default-client-scopes/{Uri.EscapeDataString(scopeId)}");
        addReq.Headers.Add("Authorization", $"Bearer {token}");
        var addRes = await http.SendAsync(addReq, ct);
        if (!addRes.IsSuccessStatusCode)
            logger.LogDebug("Failed to add {ScopeName} to default scopes: {Status}", ScopeName, addRes.StatusCode);
        else
            logger.LogInformation("Added {ScopeName} to realm default scopes", ScopeName);
    }
}
