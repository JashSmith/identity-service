using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Identity.TenantProvisioning;

/// <summary>What a new tenant needs: its realm name, display name and first administrator.</summary>
public sealed record TenantRequest(string Realm, string DisplayName, string AdminUsername);

/// <summary>Generated secrets of a new tenant; shown once, then kept in the operator's secret store.</summary>
public sealed record TenantSecrets(string GatewayAdminClientSecret, string GatewayClientSecret, string AdminTemporaryPassword)
{
    public static TenantSecrets Generate() => new(Random(40), Random(40), Random(16) + "-Aa1");

    private static string Random(int length)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        return string.Create(length, alphabet, (span, chars) =>
        {
            for (var i = 0; i < span.Length; i++) span[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
        });
    }
}

/// <summary>
/// Builds the realm representation of a new tenant from the embedded template: the gateway's service account
/// and login clients, the <c>super-admins</c> and <c>iam-scope-registry</c> groups, the claim scopes and one
/// administrator in <c>super-admins</c> who must change the temporary password at the first login.
/// The gateway's bootstrap adds the rest (claim mappers, gateway permissions, console client) once the tenant is configured.
/// </summary>
public static partial class RealmTemplate
{
    public const string GatewayAdminClient = "identity-gateway-admin";
    public const string GatewayClient = "identity-gateway";

    [GeneratedRegex("^[a-z][a-z0-9-]{1,49}$")]
    private static partial Regex RealmName();

    public static string? Validate(TenantRequest request)
    {
        if (!RealmName().IsMatch(request.Realm))
            return "The realm name is 2-50 lower-case letters, digits or '-', starting with a letter.";
        if (request.Realm is "master")
            return "The master realm cannot be a tenant.";
        if (string.IsNullOrWhiteSpace(request.DisplayName) || request.DisplayName.Length > 100)
            return "The display name is required (at most 100 characters).";
        if (string.IsNullOrWhiteSpace(request.AdminUsername))
            return "The administrator user name is required.";
        return null;
    }

    public static JsonObject Load()
    {
        using var stream = typeof(RealmTemplate).Assembly.GetManifestResourceStream("tenant-realm-template.json")
                           ?? throw new InvalidOperationException("The realm template is not embedded.");
        return JsonNode.Parse(stream)!.AsObject();
    }

    /// <summary>Fills the template; values are set as JSON values, so names with quotes or Persian text stay intact.</summary>
    public static JsonObject Render(JsonObject template, TenantRequest request, TenantSecrets secrets)
    {
        var realm = template.DeepClone().AsObject();
        realm["realm"] = request.Realm;
        realm["displayName"] = request.DisplayName;
        realm["enabled"] = true;

        foreach (var client in realm["clients"]!.AsArray().Select(c => c!.AsObject()))
        {
            client["secret"] = client["clientId"]!.GetValue<string>() switch
            {
                GatewayAdminClient => secrets.GatewayAdminClientSecret,
                GatewayClient => secrets.GatewayClientSecret,
                _ => throw new InvalidOperationException($"The template has an unexpected client '{client["clientId"]}'."),
            };
        }

        var users = realm["users"]!.AsArray();
        var admin = users.Select(u => u!.AsObject()).Single(u => u["serviceAccountClientId"] is null);
        admin["username"] = request.AdminUsername;
        admin["credentials"] = new JsonArray(new JsonObject
        {
            ["type"] = "password",
            ["value"] = secrets.AdminTemporaryPassword,
            ["temporary"] = true,
        });
        // A realm created through the Admin API does not turn "temporary" into a required action by itself.
        admin["requiredActions"] = new JsonArray("UPDATE_PASSWORD");
        return realm;
    }

    /// <summary>Settings for the gateway and the console (environment-variable form; N is the next free index).</summary>
    public static string Configuration(TenantRequest request, TenantSecrets secrets) => $"""
        # Tenant '{request.Realm}' - keep this file in a secret store and delete the local copy.
        # Replace N with the next free index in Identity:Tenants (gateway) and Console:Tenants (console).

        # Identity.Gateway
        Identity__Tenants__N__Id={request.Realm}
        Identity__Tenants__N__DisplayName={request.DisplayName}
        Identity__Tenants__N__Realm={request.Realm}
        Identity__Tenants__N__AdminClientSecret={secrets.GatewayAdminClientSecret}
        Identity__Tenants__N__ClientSecret={secrets.GatewayClientSecret}

        # Identity.Admin (the gateway creates the console's client in the realm at its next start)
        Console__Tenants__N__Id={request.Realm}
        Console__Tenants__N__DisplayName={request.DisplayName}
        Console__Tenants__N__Realm={request.Realm}

        # First administrator (member of super-admins); the password must be changed at the first sign-in.
        ADMIN_USERNAME={request.AdminUsername}
        ADMIN_TEMPORARY_PASSWORD={secrets.AdminTemporaryPassword}

        """;
}
