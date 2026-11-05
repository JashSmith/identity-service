using System.Text.Json;
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Applications and their permissions, stored entirely in Keycloak:
/// <list type="bullet">
/// <item>an application is a client with attribute <c>iam.application=true</c> (display name, description and
/// kind in client attributes, per-application login theme in <c>login_theme</c>);</item>
/// <item>a permission is a client role named <c>Module:Resource:Action</c> on that client, with attributes
/// <c>iam.display_name</c>, <c>iam.source</c> (manifest|manual) and <c>iam.deprecated</c>;</item>
/// <item>tokens carry permissions as <c>{clientId}:{Module}:{Resource}:{Action}</c> through one prefixed client-role
/// mapper per application in the shared <c>iam-permissions</c> client scope.</item>
/// </list>
/// </summary>
public sealed class KeycloakApplicationCatalog(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    IKeycloakClientRoleProvisioner superAdmins,
    ILogger<KeycloakApplicationCatalog> logger) : IApplicationCatalog, IPermissionCatalog
{
    public const string ApplicationAttribute = "iam.application";
    private const string DisplayNameAttribute = "iam.display_name";
    private const string DescriptionAttribute = "iam.description";
    private const string KindAttribute = "iam.kind";
    private const string ManifestHashAttribute = "iam.manifest_hash";
    private const string LoginThemeAttribute = "login_theme";
    private const string SourceAttribute = "iam.source";
    private const string DeprecatedAttribute = "iam.deprecated";
    private const string PermissionScope = "iam-permissions";
    private const string GatewayAudienceMapper = "gateway-audience";

    /// <summary>Clients the gateway itself depends on; they cannot be deleted through the catalog.</summary>
    private static readonly string[] ReservedApplications = ["identity-gateway", "identity-gateway-admin", "identity-admin-console"];

    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);

    private sealed record Client(string Uuid, JsonElement Representation)
    {
        public string ClientId => KeycloakAdminApi.GetString(Representation, "clientId") ?? "";
    }

    private static Error AppNotFound(string clientId) => Error.NotFound("application.not_found", $"Application '{clientId}' was not found.");

    private static Error PermissionNotFound(string application, string local) =>
        Error.NotFound("permission.not_found", $"Permission '{application}:{local}' was not found.");

    // ---------------- applications ----------------

    public async Task<Result<IReadOnlyCollection<ApplicationDto>>> ListAsync(CancellationToken ct)
    {
        var clients = await ApplicationClientsAsync(ct);
        return clients.IsSuccess ? clients.Value.Select(c => ToApplication(c.Representation)).ToArray() : clients.Error!;
    }

    public async Task<Result<ApplicationDto>> GetAsync(string clientId, CancellationToken ct)
    {
        var client = await FindApplicationAsync(clientId, ct);
        return client.IsSuccess ? ToApplication(client.Value.Representation) : client.Error!;
    }

    public async Task<Result<ApplicationSecretResponse>> CreateAsync(CreateApplicationRequest request, CancellationToken ct)
    {
        var existing = await FindClientAsync(request.ClientId, ct);
        if (!existing.IsSuccess) return existing.Error!;
        if (existing.Value is not null)
            return Error.Conflict("application.already_exists", $"A client named '{request.ClientId}' already exists.");

        var signIn = request.Kind is "web" or "hybrid";
        var body = new Dictionary<string, object?>
        {
            ["clientId"] = request.ClientId,
            ["name"] = request.DisplayName,
            ["description"] = request.Description,
            ["enabled"] = true,
            ["protocol"] = "openid-connect",
            ["publicClient"] = false,
            ["clientAuthenticatorType"] = "client-secret",
            // Every application authenticates as itself to register its permission manifest.
            ["serviceAccountsEnabled"] = true,
            ["standardFlowEnabled"] = signIn,
            ["directAccessGrantsEnabled"] = false,
            ["implicitFlowEnabled"] = false,
            ["redirectUris"] = request.RedirectUris ?? [],
            ["webOrigins"] = signIn ? new[] { "+" } : Array.Empty<string>(),
            ["attributes"] = new Dictionary<string, string?>
            {
                [ApplicationAttribute] = "true",
                [DisplayNameAttribute] = request.DisplayName,
                [DescriptionAttribute] = request.Description ?? "",
                [KindAttribute] = request.Kind,
                [LoginThemeAttribute] = request.LoginTheme ?? "",
            },
        };
        var created = await _api.CreateAsync("clients", body, "application", ct, includeKeycloakMessage: true);
        if (!created.IsSuccess) return created.Error!;

        var claims = await EnsurePermissionClaimsAsync(ct);
        if (!claims.IsSuccess)
        {
            // An application whose permissions never reach tokens is useless: remove it again.
            var removed = await _api.SendWithoutResultAsync(HttpMethod.Delete, $"clients/{Uri.EscapeDataString(created.Value)}", null, "application", ct);
            if (!removed.IsSuccess) logger.LogError("Application {ClientId} could not be provisioned or removed again", request.ClientId);
            return claims.Error!;
        }
        return await SecretAsync(request.ClientId, regenerate: false, ct);
    }

    public async Task<Result<ApplicationDto>> UpdateAsync(string clientId, UpdateApplicationRequest request, CancellationToken ct)
    {
        var client = await FindApplicationAsync(clientId, ct);
        if (!client.IsSuccess) return client.Error!;

        var representation = JsonSerializer.Deserialize<Dictionary<string, object?>>(client.Value.Representation.GetRawText())!;
        // Client attributes are plain strings (unlike role attributes).
        var attributes = Attributes(client.Value.Representation)
            .ToDictionary(kv => kv.Key, kv => (object?)(kv.Value.Length > 0 ? kv.Value[0] : ""));
        if (request.DisplayName is not null)
        {
            representation["name"] = request.DisplayName;
            attributes[DisplayNameAttribute] = request.DisplayName;
        }
        if (request.Description is not null)
        {
            representation["description"] = request.Description;
            attributes[DescriptionAttribute] = request.Description;
        }
        if (request.Enabled.HasValue) representation["enabled"] = request.Enabled.Value;
        if (request.RedirectUris is not null) representation["redirectUris"] = request.RedirectUris;
        if (request.LoginTheme is not null) attributes[LoginThemeAttribute] = request.LoginTheme;
        representation["attributes"] = attributes;

        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"clients/{Uri.EscapeDataString(client.Value.Uuid)}",
            representation, "application", ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? await GetAsync(clientId, ct) : updated.Error!;
    }

    public async Task<Result> DeleteAsync(string clientId, CancellationToken ct)
    {
        if (ReservedApplications.Contains(clientId, StringComparer.Ordinal))
            return Error.Validation("application.reserved", $"Application '{clientId}' is required by the gateway and cannot be deleted.");
        var client = await FindApplicationAsync(clientId, ct);
        if (!client.IsSuccess) return client.Error!;

        var deleted = await _api.SendWithoutResultAsync(HttpMethod.Delete, $"clients/{Uri.EscapeDataString(client.Value.Uuid)}", null, "application", ct);
        if (!deleted.IsSuccess) return deleted;
        return await EnsurePermissionClaimsAsync(ct);
    }

    public Task<Result<ApplicationSecretResponse>> RotateSecretAsync(string clientId, CancellationToken ct) =>
        SecretAsync(clientId, regenerate: true, ct);

    private async Task<Result<ApplicationSecretResponse>> SecretAsync(string clientId, bool regenerate, CancellationToken ct)
    {
        var client = await FindApplicationAsync(clientId, ct);
        if (!client.IsSuccess) return client.Error!;
        var path = $"clients/{Uri.EscapeDataString(client.Value.Uuid)}/client-secret";
        var secret = regenerate
            ? await _api.SendAsync(HttpMethod.Post, path, null, "application", ct)
            : await GetNullableAsync(path, ct);
        if (!secret.IsSuccess) return secret.Error!;
        var value = secret.Value is { } json ? KeycloakAdminApi.GetString(json, "value") : null;
        if (string.IsNullOrEmpty(value)) return Error.Upstream("keycloak.invalid_response", "Keycloak returned no client secret.");
        return new ApplicationSecretResponse(ToApplication(client.Value.Representation), value);
    }

    private async Task<Result<JsonElement?>> GetNullableAsync(string path, CancellationToken ct) =>
        await _api.SendAsync(HttpMethod.Get, path, null, "application", ct);

    /// <summary>
    /// One client scope (<c>iam-permissions</c>, a realm default and assigned to every client) with one
    /// client-role mapper per application; each mapper prefixes that application's roles with its client id,
    /// so the <c>permissions</c> claim contains <c>{clientId}:{Module}:{Resource}:{Action}</c> and nothing else.
    /// </summary>
    public async Task<Result> EnsurePermissionClaimsAsync(CancellationToken ct)
    {
        var applications = await ApplicationClientsAsync(ct);
        if (!applications.IsSuccess) return applications.Error!;
        var scopeId = await EnsureClientScopeAsync(ct);
        if (!scopeId.IsSuccess) return scopeId.Error!;

        var mappersPath = $"client-scopes/{Uri.EscapeDataString(scopeId.Value)}/protocol-mappers/models";
        var mappers = await _api.GetAsync(mappersPath, "client_scope", ct);
        if (!mappers.IsSuccess) return mappers.Error!;
        var wanted = applications.Value.Select(a => a.ClientId).ToHashSet(StringComparer.Ordinal);
        var existing = mappers.Value.EnumerateArray()
            .Select(m => (Id: KeycloakAdminApi.GetString(m, "id"), Name: KeycloakAdminApi.GetString(m, "name")))
            .Where(m => m.Id is not null && m.Name is not null && m.Name.StartsWith("perm-", StringComparison.Ordinal))
            .ToArray();

        foreach (var clientId in wanted.Where(c => existing.All(m => m.Name != MapperName(c))))
        {
            var created = await _api.SendWithoutResultAsync(HttpMethod.Post, mappersPath, PermissionMapper(clientId), "client_scope", ct);
            if (!created.IsSuccess) return created;
        }
        // Every application's tokens must be accepted by the gateway (e.g. to register its manifest).
        if (!mappers.Value.EnumerateArray().Any(m => KeycloakAdminApi.GetString(m, "name") == GatewayAudienceMapper))
        {
            var created = await _api.SendWithoutResultAsync(HttpMethod.Post, mappersPath, new
            {
                name = GatewayAudienceMapper,
                protocol = "openid-connect",
                protocolMapper = "oidc-audience-mapper",
                config = new Dictionary<string, string>
                {
                    ["included.client.audience"] = "identity-gateway",
                    ["access.token.claim"] = "true",
                    ["id.token.claim"] = "false",
                },
            }, "client_scope", ct);
            if (!created.IsSuccess) return created;
        }
        foreach (var stale in existing.Where(m => !wanted.Contains(m.Name!["perm-".Length..])))
        {
            var removed = await _api.SendWithoutResultAsync(HttpMethod.Delete, $"{mappersPath}/{Uri.EscapeDataString(stale.Id!)}", null, "client_scope", ct);
            if (!removed.IsSuccess) return removed;
        }

        var realmDefaults = await _api.GetAsync("default-default-client-scopes", "client_scope", ct);
        if (!realmDefaults.IsSuccess) return realmDefaults.Error!;
        if (!realmDefaults.Value.EnumerateArray().Any(s => KeycloakAdminApi.GetString(s, "id") == scopeId.Value))
        {
            var added = await _api.SendWithoutResultAsync(HttpMethod.Put, $"default-default-client-scopes/{Uri.EscapeDataString(scopeId.Value)}", null, "client_scope", ct);
            if (!added.IsSuccess) return added;
        }

        var clients = await _api.GetAllAsync("clients", "client_scope", ct);
        if (!clients.IsSuccess) return clients.Error!;
        foreach (var uuid in clients.Value.Select(c => KeycloakAdminApi.GetString(c, "id")).OfType<string>())
        {
            var path = $"clients/{Uri.EscapeDataString(uuid)}/default-client-scopes";
            var assigned = await _api.GetAsync(path, "client_scope", ct);
            if (!assigned.IsSuccess) return assigned.Error!;
            if (assigned.Value.EnumerateArray().Any(s => KeycloakAdminApi.GetString(s, "id") == scopeId.Value)) continue;
            var added = await _api.SendWithoutResultAsync(HttpMethod.Put, $"{path}/{Uri.EscapeDataString(scopeId.Value)}", null, "client_scope", ct);
            if (!added.IsSuccess) return added;
        }
        return Result.Success();
    }

    private async Task<Result<string>> EnsureClientScopeAsync(CancellationToken ct)
    {
        var scopes = await _api.GetAsync("client-scopes", "client_scope", ct);
        if (!scopes.IsSuccess) return scopes.Error!;
        var id = scopes.Value.EnumerateArray().Where(s => KeycloakAdminApi.GetString(s, "name") == PermissionScope)
            .Select(s => KeycloakAdminApi.GetString(s, "id")).FirstOrDefault();
        if (id is not null) return id;

        var created = await _api.CreateAsync("client-scopes", new
        {
            name = PermissionScope,
            description = "Emits application permissions as {clientId}:{Module}:{Resource}:{Action} in the permissions claim",
            protocol = "openid-connect",
            attributes = new Dictionary<string, string> { ["include.in.token.scope"] = "false", ["display.on.consent.screen"] = "false" },
        }, "client_scope", ct);
        return created;
    }

    private static string MapperName(string clientId) => $"perm-{clientId}";

    private static object PermissionMapper(string clientId) => new
    {
        name = MapperName(clientId),
        protocol = "openid-connect",
        protocolMapper = "oidc-usermodel-client-role-mapper",
        config = new Dictionary<string, string>
        {
            ["usermodel.clientRoleMapping.clientId"] = clientId,
            ["usermodel.clientRoleMapping.rolePrefix"] = $"{clientId}:",
            ["claim.name"] = "permissions",
            ["jsonType.label"] = "String",
            ["multivalued"] = "true",
            ["access.token.claim"] = "true",
            ["userinfo.token.claim"] = "true",
            ["id.token.claim"] = "false",
        },
    };

    // ---------------- permissions ----------------

    public async Task<Result<IReadOnlyCollection<CatalogPermissionDto>>> ListAsync(string? application, bool includeDeprecated, CancellationToken ct)
    {
        IReadOnlyCollection<Client> clients;
        if (string.IsNullOrWhiteSpace(application))
        {
            var all = await ApplicationClientsAsync(ct);
            if (!all.IsSuccess) return all.Error!;
            clients = all.Value;
        }
        else
        {
            var one = await FindApplicationAsync(application, ct);
            if (!one.IsSuccess) return one.Error!;
            clients = [one.Value];
        }

        var permissions = new List<CatalogPermissionDto>();
        foreach (var client in clients)
        {
            var roles = await RolesAsync(client, ct);
            if (!roles.IsSuccess) return roles.Error!;
            permissions.AddRange(roles.Value.Where(p => includeDeprecated || !p.Deprecated));
        }
        return permissions.OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();
    }

    public async Task<Result<PermissionTreeDto>> GetTreeAsync(bool includeDeprecated, CancellationToken ct)
    {
        var applications = await ApplicationClientsAsync(ct);
        if (!applications.IsSuccess) return applications.Error!;

        var tree = new List<PermissionTreeApplication>();
        foreach (var client in applications.Value)
        {
            var roles = await RolesAsync(client, ct);
            if (!roles.IsSuccess) return roles.Error!;
            var modules = roles.Value.Where(p => includeDeprecated || !p.Deprecated)
                .GroupBy(p => p.Module).OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(m => new PermissionTreeModule(m.Key, m.GroupBy(p => p.Resource).OrderBy(g => g.Key, StringComparer.Ordinal)
                    .Select(r => new PermissionTreeResource(r.Key, r.OrderBy(p => p.Action, StringComparer.Ordinal).ToArray()))
                    .ToArray()))
                .ToArray();
            tree.Add(new PermissionTreeApplication(client.ClientId, ToApplication(client.Representation).DisplayName, modules));
        }
        return new PermissionTreeDto(tree);
    }

    public async Task<Result<CatalogPermissionDto>> CreateAsync(string application, CreateCatalogPermissionRequest request, CancellationToken ct)
    {
        if (!PermissionName.TryParseLocal(application, request.Name, out var name))
            return Error.Validation("permission.invalid", "Permission names are Module:Resource:Action.");
        var client = await FindApplicationAsync(application, ct);
        if (!client.IsSuccess) return client.Error!;

        var existing = await FindRoleAsync(client.Value, name.Local, ct);
        if (!existing.IsSuccess) return existing.Error!;
        if (existing.Value is not null)
            return Error.Conflict("permission.already_exists", $"Permission '{name.Full}' already exists.");

        var created = await CreateRoleAsync(client.Value, name.Local, request.DisplayName, request.Description, "manual", ct);
        if (!created.IsSuccess) return created.Error!;
        var granted = await superAdmins.ReconcileAdminAsync(ct);
        if (!granted.IsSuccess) return granted.Error!;
        return await GetPermissionAsync(client.Value, name.Local, ct);
    }

    public async Task<Result<CatalogPermissionDto>> UpdateAsync(string application, string localName, UpdateCatalogPermissionRequest request, CancellationToken ct)
    {
        var client = await FindApplicationAsync(application, ct);
        if (!client.IsSuccess) return client.Error!;
        var role = await FindRoleAsync(client.Value, localName, ct);
        if (!role.IsSuccess) return role.Error!;
        if (role.Value is null) return PermissionNotFound(application, localName);

        var attributes = Attributes(role.Value.Value);
        if (request.DisplayName is not null) attributes[DisplayNameAttribute] = [request.DisplayName];
        if (request.Deprecated.HasValue) attributes[DeprecatedAttribute] = [request.Deprecated.Value ? "true" : "false"];
        var updated = await PutRoleAsync(client.Value, localName, request.Description ?? KeycloakAdminApi.GetString(role.Value.Value, "description"), attributes, ct);
        return updated.IsSuccess ? await GetPermissionAsync(client.Value, localName, ct) : updated.Error!;
    }

    public async Task<Result> DeleteAsync(string application, string localName, CancellationToken ct)
    {
        var client = await FindApplicationAsync(application, ct);
        if (!client.IsSuccess) return client.Error!;
        var role = await FindRoleAsync(client.Value, localName, ct);
        if (!role.IsSuccess) return role.Error!;
        if (role.Value is null) return PermissionNotFound(application, localName);
        return await _api.SendWithoutResultAsync(HttpMethod.Delete,
            $"clients/{Uri.EscapeDataString(client.Value.Uuid)}/roles/{Uri.EscapeDataString(localName)}", null, "permission", ct);
    }

    public async Task<Result<ManifestRegistrationResponse>> RegisterManifestAsync(string application, PermissionManifestRequest manifest, CancellationToken ct)
    {
        // The authenticated caller decides the namespace: a service can only register its own permissions.
        if (!string.Equals(application, manifest.ServiceId, StringComparison.Ordinal))
            return Error.Forbidden("permission.foreign_namespace",
                $"'{application}' cannot register permissions for '{manifest.ServiceId}'.");

        var client = await FindClientAsync(application, ct);
        if (!client.IsSuccess) return client.Error!;
        if (client.Value is null || !IsApplication(client.Value.Representation))
            return Error.Forbidden("application.not_registered",
                $"'{application}' is not a registered application; create it in the gateway first.");

        var invalid = manifest.Permissions.Where(p => !PermissionName.IsValidLocal(p.Name)).Select(p => p.Name).ToArray();
        if (invalid.Length > 0)
            return Error.Validation("permission.invalid", $"Invalid permission names (expected Module:Resource:Action): {string.Join(", ", invalid)}.");

        var current = await RolesAsync(client.Value, ct);
        if (!current.IsSuccess) return current.Error!;
        var byLocal = current.Value.ToDictionary(p => $"{p.Module}:{p.Resource}:{p.Action}", StringComparer.Ordinal);

        foreach (var permission in manifest.Permissions)
        {
            if (!byLocal.TryGetValue(permission.Name, out var existing))
            {
                var created = await CreateRoleAsync(client.Value, permission.Name, null, permission.Description, "manifest", ct);
                if (!created.IsSuccess) return created.Error!;
                continue;
            }
            if (!existing.Deprecated && existing.Description == permission.Description) continue;
            var refreshed = await PutRoleAsync(client.Value, permission.Name, permission.Description,
                RoleAttributes(existing.DisplayName, existing.Source, deprecated: false), ct);
            if (!refreshed.IsSuccess) return refreshed.Error!;
        }

        var declared = manifest.Permissions.Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        var deprecated = new List<string>();
        foreach (var gone in current.Value.Where(p => p.Source == "manifest" && !p.Deprecated &&
                                                       !declared.Contains($"{p.Module}:{p.Resource}:{p.Action}")))
        {
            var local = $"{gone.Module}:{gone.Resource}:{gone.Action}";
            var marked = await PutRoleAsync(client.Value, local, gone.Description, RoleAttributes(gone.DisplayName, gone.Source, deprecated: true), ct);
            if (!marked.IsSuccess) return marked.Error!;
            deprecated.Add(gone.Name);
        }

        var granted = await superAdmins.ReconcileAdminAsync(ct);
        if (!granted.IsSuccess) return granted.Error!;
        logger.LogInformation("Registered {Count} permission(s) for {Application}; {Deprecated} deprecated",
            manifest.Permissions.Count, application, deprecated.Count);
        return new ManifestRegistrationResponse(application, manifest.ManifestVersion, manifest.ManifestHash, true, deprecated);
    }

    // ---------------- helpers ----------------

    private async Task<Result<IReadOnlyCollection<Client>>> ApplicationClientsAsync(CancellationToken ct)
    {
        var clients = await _api.GetAllAsync("clients", "application", ct);
        if (!clients.IsSuccess) return clients.Error!;
        return clients.Value.Where(IsApplication)
            .Select(c => new Client(KeycloakAdminApi.GetString(c, "id")!, c))
            .OrderBy(c => c.ClientId, StringComparer.Ordinal)
            .ToArray();
    }

    private async Task<Result<Client?>> FindClientAsync(string clientId, CancellationToken ct)
    {
        var found = await _api.GetAsync($"clients?clientId={Uri.EscapeDataString(clientId)}", "application", ct);
        if (!found.IsSuccess) return found.Error!;
        return found.Value.EnumerateArray()
            .Where(c => KeycloakAdminApi.GetString(c, "clientId") == clientId)
            .Select(c => new Client(KeycloakAdminApi.GetString(c, "id")!, c))
            .FirstOrDefault();
    }

    private async Task<Result<Client>> FindApplicationAsync(string clientId, CancellationToken ct)
    {
        var client = await FindClientAsync(clientId, ct);
        if (!client.IsSuccess) return client.Error!;
        return client.Value is not null && IsApplication(client.Value.Representation) ? client.Value : AppNotFound(clientId);
    }

    private async Task<Result<IReadOnlyCollection<CatalogPermissionDto>>> RolesAsync(Client client, CancellationToken ct)
    {
        var roles = await _api.GetAllAsync($"clients/{Uri.EscapeDataString(client.Uuid)}/roles?briefRepresentation=false", "permission", ct);
        if (!roles.IsSuccess) return roles.Error!;
        return roles.Value.Select(r => ToPermission(client.ClientId, r)).OfType<CatalogPermissionDto>().ToArray();
    }

    private async Task<Result<JsonElement?>> FindRoleAsync(Client client, string local, CancellationToken ct)
    {
        var role = await _api.GetAsync($"clients/{Uri.EscapeDataString(client.Uuid)}/roles/{Uri.EscapeDataString(local)}", "permission", ct);
        if (role.IsSuccess) return role.Value;
        return role.Error!.Kind == ErrorKind.NotFound ? Result<JsonElement?>.Success(null) : role.Error;
    }

    private async Task<Result<CatalogPermissionDto>> GetPermissionAsync(Client client, string local, CancellationToken ct)
    {
        var role = await FindRoleAsync(client, local, ct);
        if (!role.IsSuccess) return role.Error!;
        return role.Value is { } json && ToPermission(client.ClientId, json) is { } permission
            ? permission
            : PermissionNotFound(client.ClientId, local);
    }

    private Task<Result> CreateRoleAsync(Client client, string local, string? displayName, string? description, string source, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Post, $"clients/{Uri.EscapeDataString(client.Uuid)}/roles", new
        {
            name = local,
            description = description ?? "",
            attributes = RoleAttributes(displayName, source, deprecated: false),
        }, "permission", ct);

    private Task<Result> PutRoleAsync(Client client, string local, string? description, Dictionary<string, string[]> attributes, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Put,
            $"clients/{Uri.EscapeDataString(client.Uuid)}/roles/{Uri.EscapeDataString(local)}",
            new { name = local, description = description ?? "", attributes }, "permission", ct);

    private static Dictionary<string, string[]> RoleAttributes(string? displayName, string source, bool deprecated)
    {
        var attributes = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            [SourceAttribute] = [source],
            [DeprecatedAttribute] = [deprecated ? "true" : "false"],
        };
        if (!string.IsNullOrWhiteSpace(displayName)) attributes[DisplayNameAttribute] = [displayName];
        return attributes;
    }

    private static CatalogPermissionDto? ToPermission(string clientId, JsonElement role)
    {
        if (!PermissionName.TryParseLocal(clientId, KeycloakAdminApi.GetString(role, "name"), out var name)) return null;
        var attributes = Attributes(role);
        return new CatalogPermissionDto(name.Full, clientId, name.Module, name.Resource, name.Action,
            First(attributes, DisplayNameAttribute),
            KeycloakAdminApi.GetString(role, "description") is { Length: > 0 } d ? d : null,
            First(attributes, SourceAttribute) ?? "manual",
            First(attributes, DeprecatedAttribute) == "true");
    }

    private static bool IsApplication(JsonElement client) =>
        client.TryGetProperty("attributes", out var attrs) && attrs.ValueKind == JsonValueKind.Object &&
        attrs.TryGetProperty(ApplicationAttribute, out var flag) && flag.ValueKind == JsonValueKind.String && flag.GetString() == "true";

    private static ApplicationDto ToApplication(JsonElement client)
    {
        var clientId = KeycloakAdminApi.GetString(client, "clientId") ?? "";
        var attrs = client.TryGetProperty("attributes", out var a) && a.ValueKind == JsonValueKind.Object ? a : default;
        string? Attr(string name) => attrs.ValueKind == JsonValueKind.Object && attrs.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() is { Length: > 0 } s ? s : null
            : null;
        var redirects = client.TryGetProperty("redirectUris", out var r) && r.ValueKind == JsonValueKind.Array
            ? r.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToArray()
            : [];
        return new ApplicationDto(clientId, Attr(DisplayNameAttribute) ?? KeycloakAdminApi.GetString(client, "name") ?? clientId,
            Attr(DescriptionAttribute), Attr(KindAttribute) ?? "service",
            !client.TryGetProperty("enabled", out var e) || e.ValueKind != JsonValueKind.False, redirects, Attr(LoginThemeAttribute));
    }

    /// <summary>Role attributes are string arrays; client attributes are plain strings.</summary>
    private static Dictionary<string, string[]> Attributes(JsonElement element)
    {
        var result = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (!element.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object) return result;
        foreach (var p in attrs.EnumerateObject())
            result[p.Name] = p.Value.ValueKind switch
            {
                JsonValueKind.Array => p.Value.EnumerateArray().Select(v => v.GetString() ?? "").ToArray(),
                JsonValueKind.String => [p.Value.GetString() ?? ""],
                _ => [],
            };
        return result;
    }

    private static string? First(Dictionary<string, string[]> attributes, string name) =>
        attributes.TryGetValue(name, out var values) && values.Length > 0 && values[0].Length > 0 ? values[0] : null;
}
