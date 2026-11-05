using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Identity.E2E.Tests;

/// <summary>
/// SMS sign-in through the gateway's login API on the real stack: Keycloak's Avash authenticators make and check the
/// codes, the gateway delivers them through the tenant's SMS provider (development provider: the outbox).
/// </summary>
[Collection(StackCollection.Name)]
public sealed class SmsLoginTests(IdentityStack stack)
{
    private static readonly string Run = Guid.NewGuid().ToString("N")[..8];

    private async Task<HttpResponseMessage> LoginAsync(params (string Key, string Value)[] form) =>
        await stack.Gateway.PostAsync("/api/identity/auth/login", new FormUrlEncodedContent(form.ToDictionary(f => f.Key, f => f.Value)));

    private static async Task<JsonElement> Json(HttpResponseMessage response) => await response.Content.ReadFromJsonAsync<JsonElement>();

    [E2EFact]
    public async Task A_user_signs_in_with_a_mobile_number_and_an_sms_code_without_a_password()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var phone = SmsSignIn.Phone(Run, 1);
        var (_, username, _) = await SmsSignIn.CreateUserAsync(stack, admin, $"sms-pl-{Run}", phone);
        await SmsSignIn.SetModeAsync(stack, admin, "passwordless");
        try
        {
            var before = DateTimeOffset.UtcNow.AddSeconds(-5);
            using (var sent = await LoginAsync(("phone_number", phone)))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, sent.StatusCode);
                var body = await Json(sent);
                Assert.Equal("sms_code_sent", body.GetProperty("error").GetString());
                Assert.Equal(120, body.GetProperty("expires_in").GetInt32());
            }
            var code = await SmsSignIn.CodeAsync(stack, admin, phone, before);
            Assert.Equal(6, code.Length);

            // Asking again right away does not send another SMS.
            using (var again = await LoginAsync(("phone_number", phone)))
                Assert.Equal("sms_code_sent", (await Json(again)).GetProperty("error").GetString());
            Assert.Equal(1, await SmsSignIn.CountAsync(stack, admin, phone));

            using (var wrong = await LoginAsync(("phone_number", phone), ("sms_code", code == "000000" ? "111111" : "000000")))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
                Assert.Equal("wrong", (await Json(wrong)).GetProperty("sms_error").GetString());
            }

            // Any common spelling of the number works, the code with Persian digits too.
            var persianCode = string.Concat(code.Select(c => (char)('۰' + (c - '0'))));
            using var signedIn = await LoginAsync(("phone_number", "+98" + phone[1..]), ("sms_code", persianCode));
            Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
            var token = (await Json(signedIn)).GetProperty("access_token").GetString()!;
            Assert.Contains(username, IdentityStack.Claims(token, "preferred_username"));

            // The code is used up.
            using (var reused = await LoginAsync(("phone_number", phone), ("sms_code", code)))
                Assert.Equal(HttpStatusCode.Unauthorized, reused.StatusCode);
        }
        finally
        {
            await SmsSignIn.RestoreAsync(stack, admin);
        }
    }

    [E2EFact]
    public async Task An_unknown_number_gets_the_same_answer_and_no_sms()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var unknown = SmsSignIn.Phone(Run, 2);
        await SmsSignIn.SetModeAsync(stack, admin, "passwordless");
        try
        {
            using var sent = await LoginAsync(("phone_number", unknown));

            Assert.Equal(HttpStatusCode.Unauthorized, sent.StatusCode);
            Assert.Equal("sms_code_sent", (await Json(sent)).GetProperty("error").GetString());
            await Task.Delay(500);
            Assert.Equal(0, await SmsSignIn.CountAsync(stack, admin, unknown));
            using var guessed = await LoginAsync(("phone_number", unknown), ("sms_code", "123456"));
            Assert.Equal(HttpStatusCode.Unauthorized, guessed.StatusCode);
        }
        finally
        {
            await SmsSignIn.RestoreAsync(stack, admin);
        }
    }

    [E2EFact]
    public async Task As_a_second_factor_the_password_alone_is_not_enough()
    {
        // The admin token is taken before the switch: in this mode the admin (without a number) could not sign in.
        var admin = await stack.LoginAsync("admin", "admin");
        var phone = SmsSignIn.Phone(Run, 3);
        var (_, username, password) = await SmsSignIn.CreateUserAsync(stack, admin, $"sms-2f-{Run}", phone);
        var (_, noPhone, noPhonePassword) = await SmsSignIn.CreateUserAsync(stack, admin, $"sms-np-{Run}", null);
        await SmsSignIn.SetModeAsync(stack, admin, "second-factor");
        try
        {
            var before = DateTimeOffset.UtcNow.AddSeconds(-5);
            using (var required = await stack.LoginResponseAsync(username, password))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, required.StatusCode);
                Assert.Equal("sms_code_required", (await Json(required)).GetProperty("error").GetString());
            }
            var code = await SmsSignIn.CodeAsync(stack, admin, phone, before);

            using (var wrongPassword = await LoginAsync(("grant_type", "password"), ("username", username), ("password", "wrong"), ("sms_code", code)))
                Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
            using (var signedIn = await LoginAsync(("grant_type", "password"), ("username", username), ("password", password), ("sms_code", code)))
                Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);

            using var withoutPhone = await stack.LoginResponseAsync(noPhone, noPhonePassword);
            Assert.Equal(HttpStatusCode.Unauthorized, withoutPhone.StatusCode);
            Assert.Equal("no_phone_number", (await Json(withoutPhone)).GetProperty("sms_error").GetString());
        }
        finally
        {
            await SmsSignIn.RestoreAsync(stack, admin);
        }

        // Off again: the password is enough.
        using var plain = await stack.LoginResponseAsync(username, password);
        Assert.Equal(HttpStatusCode.OK, plain.StatusCode);
    }

    [E2EFact]
    public async Task A_mobile_number_belongs_to_one_user_and_sms_sign_in_needs_sms_sending()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var phone = SmsSignIn.Phone(Run, 4);
        var (id, _, _) = await SmsSignIn.CreateUserAsync(stack, admin, $"sms-u1-{Run}", phone);

        using (var duplicate = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin,
                   new { username = $"sms-u2-{Run}", email = $"sms-u2-{Run}@sms.local", firstName = "SMS", lastName = "Duplicate", enabled = true,
                         phoneNumber = "+98" + phone[1..] }))
        {
            Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
            Assert.Equal("user.phone_number_taken", (await Json(duplicate)).GetProperty("code").GetString());
        }
        using (var generic = await stack.CallAsync(HttpMethod.Put, $"/api/identity/users/{id}", admin,
                   new { attributes = new Dictionary<string, string[]> { ["phone_number"] = ["+989120000000"] } }))
            Assert.Equal(HttpStatusCode.BadRequest, generic.StatusCode);
        using (var read = await stack.CallAsync(HttpMethod.Get, $"/api/identity/users/{id}", admin))
            Assert.Equal("+98" + phone[1..], (await Json(read)).GetProperty("phoneNumber").GetString());

        using (await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", admin,
                   new { enabled = false, provider = "development", settings = new Dictionary<string, object>() })) { }
        using var refused = await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms/login", admin, new { mode = "passwordless" });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal("sms_login.sms_disabled", (await Json(refused)).GetProperty("code").GetString());
    }
}
