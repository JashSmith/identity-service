using Identity.Gateway.Tenancy;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Configuration;

namespace Identity.Gateway.Tests;

/// <summary>Tenants map to Keycloak realms; the ambient realm drives every Admin API call.</summary>
public sealed class TenancyTests
{
    private static TenantRegistry Registry(params (string Key, string Value)[] extra)
    {
        var values = new Dictionary<string, string?>
        {
            ["Identity:Authority"] = "http://kc:8080/realms/avash",
            ["Identity:KeycloakAdmin:BaseUrl"] = "http://kc-internal:8080",
            ["Identity:KeycloakAdmin:Realm"] = "avash",
            ["Identity:KeycloakAdmin:AdminClientSecret"] = "a",
            ["Identity:Keycloak:ClientSecret"] = "c",
        };
        foreach (var (key, value) in extra) values[key] = value;
        return new TenantRegistry(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
    }

    [Fact]
    public void Default_tenant_comes_from_the_single_realm_settings()
    {
        var registry = Registry();

        Assert.Equal("avash", registry.Default.Id);
        Assert.Equal("http://kc:8080/realms/avash", registry.Issuer(registry.Default));
        Assert.Equal("http://kc-internal:8080", registry.KeycloakOptions(registry.Default).BaseUrl);
    }

    [Fact]
    public void Further_tenants_get_their_own_realm_issuer_and_optional_cluster()
    {
        var registry = Registry(
            ("Identity:Tenants:0:Id", "branch-north"), ("Identity:Tenants:0:Realm", "branch-north"),
            ("Identity:Tenants:1:Id", "big"), ("Identity:Tenants:1:Realm", "big"), ("Identity:Tenants:1:BaseUrl", "https://kc-big"));

        Assert.True(registry.TryGet("BRANCH-NORTH", out var branch));
        Assert.Equal("http://kc:8080/realms/branch-north", registry.Issuer(branch));
        Assert.True(registry.TryGet("big", out var big));
        Assert.Equal("https://kc-big/realms/big", registry.Issuer(big));
        Assert.Equal("https://kc-big", registry.KeycloakOptions(big).BaseUrl);
        Assert.False(registry.TryGet("ghost", out _));
    }

    [Fact]
    public void Duplicate_or_incomplete_tenants_fail_at_startup()
    {
        Assert.Throws<InvalidOperationException>(() => Registry(("Identity:Tenants:0:Id", "avash"), ("Identity:Tenants:0:Realm", "x")));
        Assert.Throws<InvalidOperationException>(() => Registry(("Identity:Tenants:0:Id", "branch-north")));
    }

    [Fact]
    public async Task The_ambient_tenant_flows_through_async_calls_and_is_restored()
    {
        var fallback = new KeycloakOptions { Realm = "avash" };
        string? inner = null;

        using (KeycloakTenant.Use(new KeycloakOptions { Realm = "branch-north" }))
        {
            await Task.Run(async () => { await Task.Yield(); inner = KeycloakTenant.Resolve(fallback).Realm; });
        }

        Assert.Equal("branch-north", inner);
        Assert.Equal("avash", KeycloakTenant.Resolve(fallback).Realm);
    }
}
