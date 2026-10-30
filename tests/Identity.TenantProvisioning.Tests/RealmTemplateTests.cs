using System.Text.Json.Nodes;
using Identity.TenantProvisioning;

namespace Identity.TenantProvisioning.Tests;

/// <summary>The new-tenant realm carries generated secrets, a temporary administrator password and no leftovers.</summary>
public sealed class RealmTemplateTests
{
    private static readonly TenantRequest Request = new("branch-north", "شعبه \"شمال\"", "boss");
    private static readonly TenantSecrets Secrets = new("admin-secret", "gateway-secret", "Temp-Pass-1");

    [Fact]
    public void Realm_gets_the_tenant_name_and_generated_secrets()
    {
        var realm = RealmTemplate.Render(RealmTemplate.Load(), Request, Secrets);

        Assert.Equal("branch-north", realm["realm"]!.GetValue<string>());
        Assert.Equal("شعبه \"شمال\"", realm["displayName"]!.GetValue<string>());
        var clients = realm["clients"]!.AsArray().ToDictionary(c => c!["clientId"]!.GetValue<string>(), c => c!["secret"]!.GetValue<string>());
        Assert.Equal("admin-secret", clients[RealmTemplate.GatewayAdminClient]);
        Assert.Equal("gateway-secret", clients[RealmTemplate.GatewayClient]);
    }

    [Fact]
    public void Administrator_is_a_super_admin_with_a_temporary_password()
    {
        var realm = RealmTemplate.Render(RealmTemplate.Load(), Request, Secrets);

        var admin = realm["users"]!.AsArray().Single(u => u!["serviceAccountClientId"] is null)!;
        Assert.Equal("boss", admin["username"]!.GetValue<string>());
        Assert.Contains("super-admins", admin["groups"]!.AsArray().Select(g => g!.GetValue<string>()));
        var credential = admin["credentials"]!.AsArray().Single()!;
        Assert.Equal("Temp-Pass-1", credential["value"]!.GetValue<string>());
        Assert.True(credential["temporary"]!.GetValue<bool>());
        Assert.Equal(["UPDATE_PASSWORD"], admin["requiredActions"]!.AsArray().Select(a => a!.GetValue<string>()));
    }

    [Fact]
    public void Template_carries_no_secret_and_no_development_password()
    {
        var text = RealmTemplate.Load().ToJsonString();

        Assert.DoesNotContain("\"value\"", text);
        Assert.All(RealmTemplate.Load()["clients"]!.AsArray(), c => Assert.Equal("", c!["secret"]!.GetValue<string>()));
    }

    [Fact]
    public void Template_matches_the_demo_tenant_realm()
    {
        // Guards drift: the template and the realm imported for the demo tenant must define the same building blocks.
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "IdentityService.slnx"))) root = Path.GetDirectoryName(root)!;
        var demo = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "src/Identity.AppHost/Keycloak/Realms/realm-acme.json")))!;
        var template = RealmTemplate.Load();

        foreach (var (collection, key) in new[] { ("clients", "clientId"), ("groups", "name"), ("clientScopes", "name"), ("users", "username") })
            Assert.Equal(Names(demo, collection, key), Names(template, collection, key));
    }

    private static string[] Names(JsonNode realm, string collection, string key) =>
        realm[collection]!.AsArray().Select(n => n![key]!.GetValue<string>()).Order().ToArray();

    [Theory]
    [InlineData("North", false)]
    [InlineData("master", false)]
    [InlineData("a", false)]
    [InlineData("branch-north", true)]
    public void Realm_names_are_validated(string realm, bool valid) =>
        Assert.Equal(valid, RealmTemplate.Validate(new TenantRequest(realm, "x", "admin")) is null);

    [Fact]
    public void Generated_secrets_are_unique_and_long()
    {
        var a = TenantSecrets.Generate();
        var b = TenantSecrets.Generate();

        Assert.NotEqual(a.GatewayAdminClientSecret, b.GatewayAdminClientSecret);
        Assert.True(a.GatewayClientSecret.Length >= 40);
        Assert.NotEqual(a.GatewayAdminClientSecret, a.GatewayClientSecret);
    }
}
