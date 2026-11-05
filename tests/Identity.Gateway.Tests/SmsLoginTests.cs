using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Identity.Application;
using Identity.Application.Schedules;
using Identity.Application.Sms;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Identity.Infrastructure.Sms;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>
/// SMS sign-in: the signed hook Keycloak calls, the settings and their storage, and the flow setup against an
/// in-memory Keycloak that keeps flows, sub-flows and executions like the real Admin API.
/// </summary>
public sealed class SmsLoginTests
{
    // ---- Signed hook -------------------------------------------------------------------------------------------

    private const string Secret = "0123456789abcdef0123456789abcdef";

    [Fact]
    public void The_signature_matches_the_vector_shared_with_the_keycloak_extension() =>
        // Same vector as keycloak/extensions SmsLoginTest.the_gateway_signature_matches_the_shared_test_vector.
        Assert.Equal("a764da6b09824f54bf53c4399cad9254858dc943c31807e4ac139eb38ebc5c24",
            SmsLoginEndpoints.Sign(Secret, "1700000000", "{\"realm\":\"company\"}"));

    [Fact]
    public void Only_fresh_requests_signed_with_the_secret_are_accepted()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var body = "{\"realm\":\"company\"}";
        var signature = SmsLoginEndpoints.Sign(Secret, "1700000000", body);

        Assert.Null(SmsLoginEndpoints.Verify(Secret, "1700000000", signature, body, now));
        Assert.Null(SmsLoginEndpoints.Verify(Secret, "1700000000", signature.ToUpperInvariant(), body, now.AddMinutes(4)));
        Assert.Equal("stale timestamp", SmsLoginEndpoints.Verify(Secret, "1700000000", signature, body, now.AddMinutes(6)));
        Assert.Equal("wrong signature", SmsLoginEndpoints.Verify(Secret, "1700000000", signature, body + " ", now));
        Assert.Equal("wrong signature", SmsLoginEndpoints.Verify(Secret.Replace('0', '1'), "1700000000", signature, body, now));
        Assert.Equal("missing signature", SmsLoginEndpoints.Verify(Secret, "1700000000", "", body, now));
        Assert.Equal("missing timestamp", SmsLoginEndpoints.Verify(Secret, "soon", signature, body, now));
        Assert.Contains("not configured", SmsLoginEndpoints.Verify("short", "1700000000", signature, body, now));
    }

    // ---- Settings and sending ----------------------------------------------------------------------------------

    private sealed class LoginStore : ISmsLoginSettingsStore
    {
        public SmsLoginSettingsDto Value { get; set; } = new(SmsLoginModes.Off);
        public List<string> Log { get; init; } = [];
        public Task<Result<SmsLoginSettingsDto>> GetAsync(CancellationToken ct) => Task.FromResult(Result<SmsLoginSettingsDto>.Success(Value));
        public Task<Result> SaveAsync(SmsLoginSettingsDto settings, CancellationToken ct)
        {
            Log.Add("save:" + settings.Mode);
            Value = settings;
            return Task.FromResult(Result.Success());
        }
    }

    private sealed class Flows(bool ready, List<string> log) : ISmsLoginFlows
    {
        public Task<Result<bool>> ReadyAsync(CancellationToken ct) => Task.FromResult(Result<bool>.Success(ready));
        public Task<Result> ApplyAsync(string mode, CancellationToken ct)
        {
            log.Add("flows:" + mode);
            return Task.FromResult(Result.Success());
        }
    }

    private sealed class SmsStore : ISmsSettingsStore
    {
        public StoredSmsSettings Value { get; set; } = StoredSmsSettings.Empty;
        public Task<Result<StoredSmsSettings>> GetAsync(CancellationToken ct) => Task.FromResult(Result<StoredSmsSettings>.Success(Value));
        public Task<Result> SaveAsync(StoredSmsSettings settings, CancellationToken ct) { Value = settings; return Task.FromResult(Result.Success()); }
    }

    private sealed class Tenant : ITenantContext
    {
        public string TenantId => "company";
    }

    private static (SmsLoginService Login, LoginStore Store, SmsStore Sms, DevelopmentSmsProvider Outbox, List<string> Log) Login(
        bool smsEnabled = true, bool ready = true)
    {
        var log = new List<string>();
        var store = new LoginStore { Log = log };
        var sms = new SmsStore { Value = new StoredSmsSettings(smsEnabled, "development", new Dictionary<string, IReadOnlyDictionary<string, string>>()) };
        var dev = new DevelopmentSmsProvider(TimeProvider.System, NullLogger<DevelopmentSmsProvider>.Instance);
        var service = new SmsService([dev], sms, new Tenant(), dev, store);
        return (new SmsLoginService(store, new Flows(ready, log), sms, service), store, sms, dev, log);
    }

    [Fact]
    public async Task Sms_sign_in_needs_sms_sending_and_the_keycloak_extension()
    {
        var withoutSms = Login(smsEnabled: false);
        var refused = await withoutSms.Login.SaveAsync(new SmsLoginSettingsDto(SmsLoginModes.Passwordless), CancellationToken.None);
        Assert.Equal("sms_login.sms_disabled", refused.Error!.Code);

        var withoutExtension = Login(ready: false);
        refused = await withoutExtension.Login.SaveAsync(new SmsLoginSettingsDto(SmsLoginModes.SecondFactor), CancellationToken.None);
        Assert.Equal("sms_login.extension_missing", refused.Error!.Code);
        Assert.Empty(withoutExtension.Log);

        // Turning it off always works, even without SMS or the extension.
        Assert.True((await withoutExtension.Login.SaveAsync(new SmsLoginSettingsDto(SmsLoginModes.Off), CancellationToken.None)).IsSuccess);
    }

    [Fact]
    public async Task Settings_are_stored_before_the_flows_change()
    {
        var (login, store, _, _, log) = Login();

        var saved = await login.SaveAsync(new SmsLoginSettingsDto(SmsLoginModes.Passwordless, CodeLength: 5), CancellationToken.None);

        Assert.True(saved.IsSuccess);
        Assert.Equal(["save:passwordless", "flows:passwordless"], log);
        Assert.Equal(5, store.Value.CodeLength);
    }

    [Fact]
    public async Task Sms_sending_cannot_be_disabled_while_users_sign_in_with_it()
    {
        var (_, store, sms, _, _) = Login();
        store.Value = new SmsLoginSettingsDto(SmsLoginModes.SecondFactor);
        var service = new SmsService([new DevelopmentSmsProvider(TimeProvider.System, NullLogger<DevelopmentSmsProvider>.Instance)], sms, new Tenant(),
            loginSettings: store);

        var refused = await service.SaveSettingsAsync(new SmsSettingsDto(false, "development", new Dictionary<string, IReadOnlyDictionary<string, string>>()),
            CancellationToken.None);

        Assert.Equal("sms.login_enabled", refused.Error!.Code);
        Assert.True(sms.Value.Enabled);
    }

    [Fact]
    public async Task A_code_is_delivered_only_while_sms_sign_in_is_on()
    {
        var (login, store, _, outbox, _) = Login();

        var off = await login.SendCodeAsync("09121234567", "482913", 120, "login", CancellationToken.None);
        Assert.Equal("sms_login.disabled", off.Error!.Code);

        store.Value = new SmsLoginSettingsDto(SmsLoginModes.Passwordless);
        var sent = await login.SendCodeAsync("09121234567", "482913", 120, "login", CancellationToken.None);

        Assert.True(sent.IsSuccess);
        var message = Assert.Single(outbox.Recent("company", 5));
        Assert.Contains("482913", message.Text);
        Assert.Contains("۲ دقیقه", message.Text);
    }

    [Fact]
    public void The_second_factor_text_warns_the_user()
    {
        Assert.StartsWith("کد تأیید ورود: 123456", SmsLoginService.Text("123456", 300, "second-factor"));
        Assert.Contains("رمز عبور خود را عوض کنید", SmsLoginService.Text("123456", 300, "second-factor"));
        Assert.StartsWith("کد ورود: 123456", SmsLoginService.Text("123456", 90, "login"));
    }

    [Theory]
    [InlineData("passwordless", 6, 120, 60, 5, true)]
    [InlineData("second-factor", 4, 600, 300, 10, true)]
    [InlineData("sms", 6, 120, 60, 5, false)]
    [InlineData("off", 3, 120, 60, 5, false)]
    [InlineData("off", 6, 30, 60, 5, false)]
    [InlineData("off", 6, 120, 10, 5, false)]
    [InlineData("off", 6, 120, 60, 0, false)]
    public void Settings_are_validated(string mode, int length, int lifetime, int resend, int attempts, bool valid) =>
        Assert.Equal(valid, new SmsLoginSettingsDtoValidator().Validate(new SmsLoginSettingsDto(mode, length, lifetime, resend, attempts)).IsValid);

    // ---- Storage ------------------------------------------------------------------------------------------------

    [Fact]
    public void Settings_round_trip_through_realm_attributes_and_bad_values_fall_back()
    {
        var settings = new SmsLoginSettingsDto(SmsLoginModes.SecondFactor, 7, 300, 90, 3);
        var attributes = KeycloakSmsLoginSettingsStore.ToAttributes(settings).ToDictionary();

        Assert.Equal(settings, KeycloakSmsLoginSettingsStore.Parse(attributes));
        attributes["iam.smslogin.mode"] = "everything";
        attributes["iam.smslogin.code_length"] = "50";
        var parsed = KeycloakSmsLoginSettingsStore.Parse(attributes);
        Assert.Equal(SmsLoginModes.Off, parsed.Mode);
        Assert.Equal(6, parsed.CodeLength);
    }

    [Fact]
    public void Sms_login_attributes_are_not_read_as_sms_provider_settings() =>
        Assert.Empty(KeycloakSmsSettingsStore.Parse(new Dictionary<string, string>
        {
            ["iam.smslogin.mode"] = "passwordless",
            ["iam.smslogin.code_length"] = "6",
        }).Settings);

    // ---- Flow setup ---------------------------------------------------------------------------------------------

    /// <summary>The parts of Keycloak's Admin API the flow setup uses, with the same depth-first execution listing.</summary>
    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public sealed class Execution
        {
            public string Id { get; } = Guid.NewGuid().ToString();
            public string? Provider { get; init; }
            public string? Subflow { get; init; }
            public string Requirement { get; set; } = "DISABLED";
            public string? Config { get; set; }
        }

        public Dictionary<string, List<Execution>> Flows { get; } = new(StringComparer.Ordinal);
        public HashSet<string> TopLevel { get; } = new(StringComparer.Ordinal);
        public string BrowserFlow { get; set; } = KeycloakSmsLoginFlowSetup.BrowserFlow;
        public string DirectGrantFlow { get; set; } = "direct grant";
        public bool ExtensionInstalled { get; set; } = true;
        public int Writes { get; private set; }

        public FakeKeycloak()
        {
            Flows[KeycloakSmsLoginFlowSetup.BrowserFlow] =
            [
                new() { Provider = "auth-cookie", Requirement = "ALTERNATIVE" },
                new() { Subflow = KeycloakSmsLoginFlowSetup.BrowserForms, Requirement = "ALTERNATIVE" },
            ];
            Flows[KeycloakSmsLoginFlowSetup.BrowserForms] =
            [
                new() { Provider = "auth-username-password-form", Requirement = "REQUIRED" },
                new() { Provider = KeycloakScheduleAuthenticatorSetup.ProviderId, Requirement = "REQUIRED" },
            ];
            Flows["direct grant"] = [new() { Provider = "direct-grant-validate-username", Requirement = "REQUIRED" }];
            TopLevel.UnionWith([KeycloakSmsLoginFlowSetup.BrowserFlow, "direct grant", "browser"]);
        }

        public IEnumerable<Execution> In(string flow) => Flows[flow];
        public Execution Step(string flow, string provider) => Flows[flow].Single(e => e.Provider == provider);
        public Execution Sub(string flow, string subflow) => Flows[flow].Single(e => e.Subflow == subflow);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            var body = request.Content?.Headers.ContentType?.MediaType == "application/json"
                ? JsonNode.Parse(await request.Content.ReadAsStringAsync(ct))
                : null;
            if (request.Method != HttpMethod.Get && !path.EndsWith("/token", StringComparison.Ordinal)) Writes++;
            const string realm = "/admin/realms/company";
            if (path.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });
            if (path == realm + "/authentication/authenticator-providers")
                return Json((ExtensionInstalled ? new[] { KeycloakSmsLoginFlowSetup.LoginProvider, KeycloakSmsLoginFlowSetup.OtpProvider,
                    KeycloakSmsLoginFlowSetup.DirectLoginProvider, KeycloakSmsLoginFlowSetup.DirectOtpProvider } : [])
                    .Append(KeycloakScheduleAuthenticatorSetup.ProviderId).Select(id => new { id }));
            if (path == realm && request.Method == HttpMethod.Get) return Json(new { realm = "company", browserFlow = BrowserFlow, directGrantFlow = DirectGrantFlow });
            if (path == realm && request.Method == HttpMethod.Put)
            {
                if (body!["directGrantFlow"] is { } direct) DirectGrantFlow = direct.GetValue<string>();
                return NoContent();
            }
            if (path == realm + "/authentication/flows" && request.Method == HttpMethod.Get)
                return Json(TopLevel.Select(alias => new { alias }));
            if (path == realm + "/authentication/flows" && request.Method == HttpMethod.Post)
            {
                var alias = body!["alias"]!.GetValue<string>();
                Assert.Equal("basic-flow", body["providerId"]!.GetValue<string>());
                TopLevel.Add(alias);
                Flows[alias] = [];
                return Created();
            }
            if (path.StartsWith(realm + "/authentication/executions/", StringComparison.Ordinal) && path.EndsWith("/config", StringComparison.Ordinal))
            {
                var id = path.Split('/')[^2];
                Flows.Values.SelectMany(f => f).Single(e => e.Id == id).Config = body!["alias"]!.GetValue<string>();
                return Created();
            }
            const string flows = realm + "/authentication/flows/";
            if (path.StartsWith(flows, StringComparison.Ordinal))
            {
                var rest = path[flows.Length..];
                var alias = rest[..rest.IndexOf("/executions", StringComparison.Ordinal)];
                if (rest.EndsWith("/executions/execution", StringComparison.Ordinal))
                {
                    Flows[alias].Add(new Execution { Provider = body!["provider"]!.GetValue<string>() });
                    return Created();
                }
                if (rest.EndsWith("/executions/flow", StringComparison.Ordinal))
                {
                    var sub = body!["alias"]!.GetValue<string>();
                    Assert.Equal("basic-flow", body["type"]!.GetValue<string>());
                    Flows[alias].Add(new Execution { Subflow = sub });
                    Flows[sub] = [];
                    return Created();
                }
                if (request.Method == HttpMethod.Get) return Json(List(alias, 0));
                if (request.Method == HttpMethod.Put)
                {
                    var id = body!["id"]!.GetValue<string>();
                    Assert.True(TopLevel.Contains(alias), "requirements are changed through the top-level flow");
                    Flows.Values.SelectMany(f => f).Single(e => e.Id == id).Requirement = body["requirement"]!.GetValue<string>();
                    return NoContent();
                }
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private IEnumerable<object> List(string flow, int level)
        {
            var index = 0;
            foreach (var e in Flows[flow])
            {
                yield return new
                {
                    id = e.Id, level, index = index++, requirement = e.Requirement, providerId = e.Provider,
                    displayName = e.Subflow ?? e.Provider, authenticationFlow = e.Subflow is not null, authenticationConfig = e.Config,
                };
                if (e.Subflow is not null)
                    foreach (var child in List(e.Subflow, level + 1)) yield return child;
            }
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };

        private static HttpResponseMessage NoContent() => new(HttpStatusCode.NoContent);

        private static HttpResponseMessage Created() => new(HttpStatusCode.Created)
        {
            Headers = { Location = new Uri("http://kc.test/admin/realms/company/x/" + Guid.NewGuid()) }
        };
    }

    private static KeycloakSmsLoginFlowSetup Setup(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakSmsLoginFlowSetup(new HttpClient(kc), options, new KeycloakAdminTokenProvider(new HttpClient(kc), options),
            new AccessScheduleOptions());
    }

    private const string Browser = KeycloakSmsLoginFlowSetup.BrowserFlow;
    private const string Direct = KeycloakSmsLoginFlowSetup.DirectFlow;

    [Fact]
    public async Task Passwordless_adds_an_sms_branch_to_the_login_page_and_the_token_endpoint()
    {
        var kc = new FakeKeycloak();

        Assert.True((await Setup(kc).ApplyAsync(SmsLoginModes.Passwordless, CancellationToken.None)).IsSuccess);

        Assert.Equal("ALTERNATIVE", kc.Sub(Browser, KeycloakSmsLoginFlowSetup.BrowserSms).Requirement);
        Assert.Equal([KeycloakSmsLoginFlowSetup.LoginProvider, KeycloakScheduleAuthenticatorSetup.ProviderId],
            kc.In(KeycloakSmsLoginFlowSetup.BrowserSms).Select(e => e.Provider));
        Assert.All(kc.In(KeycloakSmsLoginFlowSetup.BrowserSms), e => Assert.Equal("REQUIRED", e.Requirement));
        Assert.NotNull(kc.Step(KeycloakSmsLoginFlowSetup.BrowserSms, KeycloakScheduleAuthenticatorSetup.ProviderId).Config);
        Assert.Equal("DISABLED", kc.Step(KeycloakSmsLoginFlowSetup.BrowserForms, KeycloakSmsLoginFlowSetup.OtpProvider).Requirement);

        Assert.Equal(Direct, kc.DirectGrantFlow);
        Assert.Equal("ALTERNATIVE", kc.Step(Direct, KeycloakSmsLoginFlowSetup.DirectLoginProvider).Requirement);
        Assert.Equal("ALTERNATIVE", kc.Sub(Direct, KeycloakSmsLoginFlowSetup.DirectPassword).Requirement);
        Assert.Equal(["direct-grant-validate-username", "direct-grant-validate-password", null, KeycloakSmsLoginFlowSetup.DirectOtpProvider],
            kc.In(KeycloakSmsLoginFlowSetup.DirectPassword).Select(e => e.Provider));
        Assert.Equal("CONDITIONAL", kc.Sub(KeycloakSmsLoginFlowSetup.DirectPassword, KeycloakSmsLoginFlowSetup.DirectConditionalOtp).Requirement);
        Assert.Equal("DISABLED", kc.Step(KeycloakSmsLoginFlowSetup.DirectPassword, KeycloakSmsLoginFlowSetup.DirectOtpProvider).Requirement);
    }

    [Fact]
    public async Task Switching_modes_only_changes_requirements_and_never_duplicates_steps()
    {
        var kc = new FakeKeycloak();
        var setup = Setup(kc);
        await setup.ApplyAsync(SmsLoginModes.Passwordless, CancellationToken.None);
        var counts = kc.Flows.ToDictionary(f => f.Key, f => f.Value.Count);

        Assert.True((await setup.ApplyAsync(SmsLoginModes.SecondFactor, CancellationToken.None)).IsSuccess);
        await setup.ApplyAsync(SmsLoginModes.SecondFactor, CancellationToken.None);

        Assert.Equal(counts, kc.Flows.ToDictionary(f => f.Key, f => f.Value.Count));
        Assert.Equal("REQUIRED", kc.Step(KeycloakSmsLoginFlowSetup.BrowserForms, KeycloakSmsLoginFlowSetup.OtpProvider).Requirement);
        Assert.Equal("DISABLED", kc.Sub(Browser, KeycloakSmsLoginFlowSetup.BrowserSms).Requirement);
        Assert.Equal("DISABLED", kc.Step(Direct, KeycloakSmsLoginFlowSetup.DirectLoginProvider).Requirement);
        Assert.Equal("REQUIRED", kc.Step(KeycloakSmsLoginFlowSetup.DirectPassword, KeycloakSmsLoginFlowSetup.DirectOtpProvider).Requirement);
    }

    [Fact]
    public async Task Off_disables_the_sms_steps_and_gives_the_realm_back_keycloaks_direct_grant_flow()
    {
        var kc = new FakeKeycloak();
        var setup = Setup(kc);
        await setup.ApplyAsync(SmsLoginModes.SecondFactor, CancellationToken.None);

        Assert.True((await setup.ApplyAsync(SmsLoginModes.Off, CancellationToken.None)).IsSuccess);

        Assert.Equal("direct grant", kc.DirectGrantFlow);
        Assert.Equal("DISABLED", kc.Step(KeycloakSmsLoginFlowSetup.BrowserForms, KeycloakSmsLoginFlowSetup.OtpProvider).Requirement);
        Assert.Equal("DISABLED", kc.Sub(Browser, KeycloakSmsLoginFlowSetup.BrowserSms).Requirement);
    }

    [Fact]
    public async Task Off_on_a_realm_that_never_had_sms_sign_in_writes_nothing()
    {
        var kc = new FakeKeycloak();

        Assert.True((await Setup(kc).ApplyAsync(SmsLoginModes.Off, CancellationToken.None)).IsSuccess);

        Assert.Equal(0, kc.Writes);
    }

    [Fact]
    public async Task Without_the_extension_sms_sign_in_is_refused_and_off_is_a_no_op()
    {
        var kc = new FakeKeycloak { ExtensionInstalled = false };
        var setup = Setup(kc);

        Assert.False((await setup.ReadyAsync(CancellationToken.None)).Value);
        Assert.Equal("sms_login.extension_missing", (await setup.ApplyAsync(SmsLoginModes.Passwordless, CancellationToken.None)).Error!.Code);
        Assert.True((await setup.ApplyAsync(SmsLoginModes.Off, CancellationToken.None)).IsSuccess);
        Assert.Equal(0, kc.Writes);
    }

    [Fact]
    public async Task Flows_chosen_by_the_realm_administrators_are_left_alone()
    {
        var kc = new FakeKeycloak { BrowserFlow = "corporate-mfa", DirectGrantFlow = "corporate-direct" };

        Assert.True((await Setup(kc).ApplyAsync(SmsLoginModes.Passwordless, CancellationToken.None)).IsSuccess);

        Assert.Equal(0, kc.Writes);
        Assert.Equal("corporate-direct", kc.DirectGrantFlow);
    }
}
