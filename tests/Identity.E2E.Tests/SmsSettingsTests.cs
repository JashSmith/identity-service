using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Identity.E2E.Tests;

/// <summary>SMS settings on the real stack: stored in the tenant realm, secrets masked, test message, outbox, isolation.</summary>
[Collection(StackCollection.Name)]
public sealed class SmsSettingsTests(IdentityStack stack)
{
    private static async Task<JsonElement> Json(HttpResponseMessage response) => await response.Content.ReadFromJsonAsync<JsonElement>();

    /// <summary>A test message; another test (the console's) may have sent one moments ago, so the cooldown is waited out once.</summary>
    private async Task<HttpResponseMessage> SendTestAsync(string token, string phone)
    {
        var sent = await stack.CallAsync(HttpMethod.Post, "/api/identity/settings/sms/test", token, new { phoneNumber = phone });
        if (sent.StatusCode != HttpStatusCode.BadRequest || !(await sent.Content.ReadAsStringAsync()).Contains("sms.test_rate_limited")) return sent;
        sent.Dispose();
        await Task.Delay(TimeSpan.FromSeconds(21));
        return await stack.CallAsync(HttpMethod.Post, "/api/identity/settings/sms/test", token, new { phoneNumber = phone });
    }

    [E2EFact]
    public async Task Sms_is_configured_for_the_tenant_tested_through_the_development_provider_and_secrets_stay_hidden()
    {
        var avash = await stack.LoginAsync("admin", "admin");

        using (var providers = await stack.CallAsync(HttpMethod.Get, "/api/identity/settings/sms/providers", avash))
        {
            var ids = (await Json(providers)).EnumerateArray().Select(p => p.GetProperty("id").GetString()).ToArray();
            Assert.Contains("kavenegar", ids);
            Assert.Contains("development", ids);
        }

        // Kavenegar credentials are stored but never returned; the development provider is the active one.
        using (var saved = await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", avash, new
               {
                   enabled = true,
                   provider = "development",
                   settings = new Dictionary<string, Dictionary<string, string>>
                   {
                       ["kavenegar"] = new() { ["apiKey"] = "e2e-secret-key", ["sender"] = "10004346" },
                   },
               }))
        {
            Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
            var body = await saved.Content.ReadAsStringAsync();
            Assert.DoesNotContain("e2e-secret-key", body);
            Assert.Contains("**********", body);
        }
        using (var read = await stack.CallAsync(HttpMethod.Get, "/api/identity/settings/sms", avash))
        {
            var settings = await Json(read);
            Assert.True(settings.GetProperty("enabled").GetBoolean());
            Assert.Equal("10004346", settings.GetProperty("settings").GetProperty("kavenegar").GetProperty("sender").GetString());
            Assert.Equal("**********", settings.GetProperty("settings").GetProperty("kavenegar").GetProperty("apiKey").GetString());
        }

        // A test message goes to the development outbox of the tenant.
        using (var sent = await SendTestAsync(avash, "۰۹۱۲۱۲۳۴۵۶۷"))
        {
            Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
            var result = await Json(sent);
            Assert.Equal("development", result.GetProperty("provider").GetString());
            Assert.False(result.GetProperty("delivered").GetBoolean());
            Assert.Equal("+98912***4567", result.GetProperty("phoneNumber").GetString());
        }
        using (var again = await stack.CallAsync(HttpMethod.Post, "/api/identity/settings/sms/test", avash, new { phoneNumber = "09121234567" }))
            Assert.Equal("sms.test_rate_limited", (await Json(again)).GetProperty("code").GetString());
        using (var outbox = await stack.CallAsync(HttpMethod.Get, "/api/identity/settings/sms/outbox", avash))
            Assert.Contains((await Json(outbox)).EnumerateArray(), m => m.GetProperty("phoneNumber").GetString() == "+98912***4567");
        // Validation: an unknown provider fails.
        using (var unknown = await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", avash,
                   new { enabled = false, provider = "nope", settings = new Dictionary<string, object>() }))
            Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);

        // Leave SMS off so other runs start from a known state.
        using (await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", avash,
                   new { enabled = false, provider = "development", settings = new Dictionary<string, object>() })) { }
    }
}
