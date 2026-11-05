using System.Security.Claims;
using Avash.Identity.Authentication.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Identity.Authentication.Tests;

/// <summary>Server-side sessions: the cookie holds only a key, the encrypted ticket stays in the cache.</summary>
public sealed class TicketStoreTests
{
    private readonly MemoryDistributedCache _cache = new(Options.Create(new MemoryDistributedCacheOptions()));

    private static AuthenticationTicket Ticket(int permissions = 3)
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim("sub", "user-1"));
        for (var i = 0; i < permissions; i++) identity.AddClaim(new Claim("permission", $"crm:Sales:Invoice:Action{i}"));
        return new AuthenticationTicket(new ClaimsPrincipal(identity), new AuthenticationProperties(), "Cookies");
    }

    [Fact]
    public async Task A_stored_ticket_comes_back_with_its_claims_and_the_key_is_short()
    {
        var store = new DistributedCacheTicketStore(_cache, new EphemeralDataProtectionProvider());

        var key = await store.StoreAsync(Ticket(permissions: 200));
        var ticket = await store.RetrieveAsync(key);

        Assert.Equal(32, key.Length); // whatever the number of permissions, the cookie carries only this key
        Assert.Equal(200, ticket!.Principal.FindAll("permission").Count());
        Assert.Equal("user-1", ticket.Principal.FindFirst("sub")!.Value);
    }

    [Fact]
    public async Task The_cache_holds_the_ticket_encrypted()
    {
        var store = new DistributedCacheTicketStore(_cache, new EphemeralDataProtectionProvider());

        var key = await store.StoreAsync(Ticket());
        var raw = System.Text.Encoding.UTF8.GetString((await _cache.GetAsync("avash-ticket:" + key))!);

        Assert.DoesNotContain("crm:Sales:Invoice", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_removed_or_unknown_session_is_gone()
    {
        var store = new DistributedCacheTicketStore(_cache, new EphemeralDataProtectionProvider());
        var key = await store.StoreAsync(Ticket());

        await store.RemoveAsync(key);

        Assert.Null(await store.RetrieveAsync(key));
        Assert.Null(await store.RetrieveAsync("unknown"));
    }

    [Fact]
    public async Task A_ticket_written_with_other_data_protection_keys_is_dropped_instead_of_failing()
    {
        var key = await new DistributedCacheTicketStore(_cache, new EphemeralDataProtectionProvider()).StoreAsync(Ticket());
        var otherMachine = new DistributedCacheTicketStore(_cache, new EphemeralDataProtectionProvider());

        Assert.Null(await otherMachine.RetrieveAsync(key));
        Assert.Null(await _cache.GetAsync("avash-ticket:" + key));
    }

    [Fact]
    public async Task The_cache_entry_expires_with_the_ticket()
    {
        var store = new DistributedCacheTicketStore(_cache, new EphemeralDataProtectionProvider());
        var ticket = Ticket();
        ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMilliseconds(-1);

        var key = await store.StoreAsync(ticket);

        Assert.Null(await _cache.GetAsync("avash-ticket:" + key));
    }
}
