using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Identity.E2E.Tests;

/// <summary>
/// Helpers for SMS sign-in on the real stack: the development SMS provider records codes in the outbox instead of
/// sending them, so a test reads the code there like a user reads their phone. Tests that turn SMS sign-in on must
/// turn it off again (<see cref="RestoreAsync"/>): the mode applies to the whole tenant, including the admin.
/// </summary>
public static partial class SmsSignIn
{
    /// <summary>A unique, valid Iranian mobile number per run and purpose.</summary>
    public static string Phone(string run, int purpose) =>
        "0912" + (Math.Abs(HashCode.Combine(run, purpose)) % 10_000_000).ToString("D7", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>+98912***4567, the way the outbox shows a number.</summary>
    public static string Masked(string phone) => "+98" + phone[1..4] + "***" + phone[^4..];

    public static async Task SetModeAsync(IdentityStack stack, string admin, string mode)
    {
        using (var sms = await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", admin,
                   new { enabled = true, provider = "development", settings = new Dictionary<string, object>() }))
            Assert.Equal(HttpStatusCode.OK, sms.StatusCode);
        using var saved = await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms/login", admin, new { mode });
        Assert.True(saved.IsSuccessStatusCode, $"{(int)saved.StatusCode} {await saved.Content.ReadAsStringAsync()}");
    }

    /// <summary>SMS sign-in off and SMS sending off: the state the other tests expect.</summary>
    public static async Task RestoreAsync(IdentityStack stack, string admin)
    {
        using (await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms/login", admin, new { mode = "off" })) { }
        using (await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", admin,
                   new { enabled = false, provider = "development", settings = new Dictionary<string, object>() })) { }
    }

    /// <summary>A user with a password, a mobile number (or none), a console reader role and no schedule limits.</summary>
    public static async Task<(string Id, string Username, string Password)> CreateUserAsync(IdentityStack stack, string admin, string username,
        string? phone, string? role = null)
    {
        var password = $"Sms#{username}-pass";
        using var user = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin, new
        {
            username, email = $"{username}@sms.local", firstName = "SMS", lastName = "User", enabled = true,
            credentials = new { password, temporary = false },
            assignments = role is null ? null : new[] { new { role, scopes = new Dictionary<string, string[]> { ["region"] = ["tehran"] } } },
            phoneNumber = phone,
        });
        Assert.True(user.StatusCode == HttpStatusCode.Created, $"{(int)user.StatusCode} {await user.Content.ReadAsStringAsync()}");
        var id = (await user.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        // Keycloak's own login page follows the realm's weekly schedule; this account may sign in at any time.
        using (await stack.CallAsync(HttpMethod.Put, $"/api/identity/schedules/users/{id}", admin, new { unrestricted = true })) { }
        return (id, username, password);
    }

    /// <summary>The newest code the development provider recorded for <paramref name="phone"/>, after <paramref name="after"/>.</summary>
    public static async Task<string> CodeAsync(IdentityStack stack, string admin, string phone, DateTimeOffset after)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            using var outbox = await stack.CallAsync(HttpMethod.Get, "/api/identity/settings/sms/outbox?max=50", admin);
            var message = (await outbox.Content.ReadFromJsonAsync<JsonElement>()).EnumerateArray()
                .Where(m => m.GetProperty("phoneNumber").GetString() == Masked(phone) && m.GetProperty("time").GetDateTimeOffset() >= after)
                .OrderByDescending(m => m.GetProperty("time").GetDateTimeOffset())
                .Select(m => m.GetProperty("text").GetString())
                .FirstOrDefault();
            if (message is not null) return CodePattern().Match(message).Value;
            await Task.Delay(250);
        }
        throw new Xunit.Sdk.XunitException($"No SMS code for {Masked(phone)} in the development outbox.");
    }

    /// <summary>How many messages the outbox holds for <paramref name="phone"/>.</summary>
    public static async Task<int> CountAsync(IdentityStack stack, string admin, string phone)
    {
        using var outbox = await stack.CallAsync(HttpMethod.Get, "/api/identity/settings/sms/outbox?max=50", admin);
        return (await outbox.Content.ReadFromJsonAsync<JsonElement>()).EnumerateArray().Count(m => m.GetProperty("phoneNumber").GetString() == Masked(phone));
    }

    [GeneratedRegex("[0-9]{4,8}")]
    private static partial Regex CodePattern();
}
