using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Sms;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Identity.Infrastructure.Sms;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>SMS: provider abstraction, settings with secrets, Kavenegar, realm storage and phone numbers.</summary>
public sealed class SmsTests
{
    private sealed class MemoryStore : ISmsSettingsStore
    {
        public StoredSmsSettings Value { get; set; } = StoredSmsSettings.Empty;
        public Task<Result<StoredSmsSettings>> GetAsync(CancellationToken ct) => Task.FromResult(Result<StoredSmsSettings>.Success(Value));
        public Task<Result> SaveAsync(StoredSmsSettings settings, CancellationToken ct) { Value = settings; return Task.FromResult(Result.Success()); }
    }

    private sealed class Tenant(string id) : ITenantContext
    {
        public string TenantId { get; set; } = id;
    }

    private sealed class FakeProvider(bool accept = true) : ISmsProvider
    {
        public List<(SmsMessage Message, IReadOnlyDictionary<string, string> Settings)> Sent { get; } = [];
        public string Id => "fake";
        public string DisplayName => "Fake";
        public string Description => "";
        public bool SendsMessages => true;
        public IReadOnlyList<SmsFieldDto> Fields { get; } =
            [new("token", "Token", "secret", true), new("sender", "Sender", "phone", false), new("endpoint", "Endpoint", "url", false)];
        public Task<SmsSendResult> SendAsync(SmsMessage message, IReadOnlyDictionary<string, string> settings, CancellationToken ct)
        {
            Sent.Add((message, settings));
            return Task.FromResult(accept ? new SmsSendResult(true, "m-1") : SmsSendResult.Failed("418 account credit is not enough"));
        }
    }

    private static readonly DevelopmentSmsProvider Development = new(TimeProvider.System, NullLogger<DevelopmentSmsProvider>.Instance);

    private static (SmsService Service, MemoryStore Store, FakeProvider Fake, Tenant Tenant) Create(bool accept = true)
    {
        var store = new MemoryStore();
        var fake = new FakeProvider(accept);
        var tenant = new Tenant("avash");
        var dev = new DevelopmentSmsProvider(TimeProvider.System, NullLogger<DevelopmentSmsProvider>.Instance);
        return (new SmsService([fake, dev], store, tenant, dev), store, fake, tenant);
    }

    private static Dictionary<string, IReadOnlyDictionary<string, string>> Settings(string provider, params (string Key, string Value)[] fields) =>
        new() { [provider] = fields.ToDictionary(f => f.Key, f => f.Value) };

    [Fact]
    public void Real_providers_are_listed_before_the_development_provider()
    {
        var providers = Create().Service.ListProviders();

        Assert.Equal(["fake", "development"], providers.Select(p => p.Id));
        Assert.False(providers[1].SendsMessages);
    }

    [Fact]
    public async Task Secrets_are_masked_when_read_and_kept_when_the_mask_is_sent_back()
    {
        var (sms, store, _, _) = Create();
        await sms.SaveSettingsAsync(new SmsSettingsDto(true, "fake", Settings("fake", ("token", "s3cret"), ("sender", "1000"))), CancellationToken.None);

        var read = await sms.GetSettingsAsync(CancellationToken.None);
        await sms.SaveSettingsAsync(new SmsSettingsDto(true, "fake", Settings("fake", ("token", SmsService.Mask), ("sender", "2000"))), CancellationToken.None);

        Assert.Equal(SmsService.Mask, read.Value.Settings["fake"]["token"]);
        Assert.Equal("1000", read.Value.Settings["fake"]["sender"]);
        Assert.Equal("s3cret", store.Value.Settings["fake"]["token"]);
        Assert.Equal("2000", store.Value.Settings["fake"]["sender"]);
    }

    [Fact]
    public async Task Switching_providers_keeps_each_providers_settings()
    {
        var (sms, store, _, _) = Create();
        await sms.SaveSettingsAsync(new SmsSettingsDto(true, "fake", Settings("fake", ("token", "s3cret"))), CancellationToken.None);

        await sms.SaveSettingsAsync(new SmsSettingsDto(true, "development", new Dictionary<string, IReadOnlyDictionary<string, string>>()), CancellationToken.None);

        Assert.Equal("development", store.Value.Provider);
        Assert.Equal("s3cret", store.Value.Settings["fake"]["token"]);
    }

    [Fact]
    public async Task Enabling_requires_a_provider_and_its_required_fields()
    {
        var (sms, store, _, _) = Create();

        var noProvider = await sms.SaveSettingsAsync(new SmsSettingsDto(true, null, Settings("fake")), CancellationToken.None);
        var missingToken = await sms.SaveSettingsAsync(new SmsSettingsDto(true, "fake", Settings("fake", ("sender", "1000"))), CancellationToken.None);
        var disabledIsFine = await sms.SaveSettingsAsync(new SmsSettingsDto(false, "fake", Settings("fake", ("sender", "1000"))), CancellationToken.None);

        Assert.Equal("sms.provider_required", noProvider.Error!.Code);
        Assert.Contains("Settings.fake.token", missingToken.Error!.Fields!.Keys);
        Assert.True(disabledIsFine.IsSuccess);
        Assert.False(store.Value.Enabled);
    }

    [Theory]
    [InlineData("sender", "10-00", "Settings.fake.sender")]
    [InlineData("endpoint", "ftp://x", "Settings.fake.endpoint")]
    [InlineData("token", "bad\nvalue", "Settings.fake.token")]
    public async Task Field_values_follow_their_kind(string key, string value, string error)
    {
        var (sms, _, _, _) = Create();

        var result = await sms.SaveSettingsAsync(new SmsSettingsDto(false, "fake", Settings("fake", (key, value))), CancellationToken.None);

        Assert.Contains(error, result.Error!.Fields!.Keys);
    }

    [Fact]
    public async Task Unknown_providers_are_refused()
    {
        var (sms, _, _, _) = Create();

        var selected = await sms.SaveSettingsAsync(new SmsSettingsDto(false, "nope", Settings("fake")), CancellationToken.None);
        var configured = await sms.SaveSettingsAsync(new SmsSettingsDto(false, null, Settings("nope", ("a", "b"))), CancellationToken.None);

        Assert.Equal("sms.unknown_provider", selected.Error!.Code);
        Assert.Equal("sms.unknown_provider", configured.Error!.Code);
    }

    [Fact]
    public async Task Sending_needs_sms_to_be_enabled_and_a_mobile_number()
    {
        var (sms, store, fake, _) = Create();

        var disabled = await sms.SendTestAsync("09121234567", CancellationToken.None);
        store.Value = new StoredSmsSettings(true, "fake", Settings("fake", ("token", "t")));
        var badNumber = await sms.SendTestAsync("021-88776655", CancellationToken.None);

        Assert.Equal("sms.disabled", disabled.Error!.Code);
        Assert.Equal("sms.invalid_number", badNumber.Error!.Code);
        Assert.Empty(fake.Sent);
    }

    [Fact]
    public async Task Sending_uses_the_selected_provider_with_its_settings_and_a_normalised_number()
    {
        var (sms, store, fake, _) = Create();
        store.Value = new StoredSmsSettings(true, "fake", Settings("fake", ("token", "t")));

        var result = await sms.SendTestAsync("۰۹۱۲ ۱۲۳ ۴۵۶۷", CancellationToken.None);

        var (message, settings) = Assert.Single(fake.Sent);
        Assert.Equal(("+989121234567", "avash"), (message.To, message.Tenant));
        Assert.Equal(SmsService.TestText, message.Text);
        Assert.Equal("t", settings["token"]);
        Assert.Equal(("fake", true, "m-1", "+98912***4567"), (result.Value.Provider, result.Value.Delivered, result.Value.MessageId, result.Value.PhoneNumber));
    }

    [Fact]
    public async Task A_provider_refusal_is_an_upstream_error_with_its_reason()
    {
        var (sms, store, _, _) = Create(accept: false);
        store.Value = new StoredSmsSettings(true, "fake", Settings("fake", ("token", "t")));

        var result = await sms.SendTestAsync("09121234567", CancellationToken.None);

        Assert.Equal((ErrorKind.Upstream, "sms.send_failed"), (result.Error!.Kind, result.Error.Code));
        Assert.Contains("418", result.Error.Message);
    }

    [Fact]
    public async Task The_development_outbox_is_separate_per_tenant()
    {
        var (sms, store, _, tenant) = Create();
        store.Value = new StoredSmsSettings(true, "development", new Dictionary<string, IReadOnlyDictionary<string, string>>());

        await sms.SendTestAsync("09121234567", CancellationToken.None);
        tenant.TenantId = "branch-north";
        var other = sms.Outbox();
        tenant.TenantId = "avash";
        var avash = sms.Outbox();

        Assert.Empty(other);
        var item = Assert.Single(avash);
        Assert.Equal("+98912***4567", item.PhoneNumber);
        Assert.Equal(SmsService.TestText, item.Text);
    }

    [Theory]
    [InlineData("09121234567", "+989121234567")]
    [InlineData("+98 912 123 4567", "+989121234567")]
    [InlineData("00989121234567", "+989121234567")]
    [InlineData("989121234567", "+989121234567")]
    [InlineData("9121234567", "+989121234567")]
    [InlineData("۰۹۱۲۱۲۳۴۵۶۷", "+989121234567")]
    [InlineData("٠٩١٢١٢٣٤٥٦٧", "+989121234567")]
    [InlineData("02188776655", null)]
    [InlineData("0912123456", null)]
    [InlineData("0912abc4567", null)]
    [InlineData("", null)]
    public void Iranian_mobile_numbers_are_normalised(string input, string? expected) =>
        Assert.Equal(expected, PhoneNumbers.NormalizeIranMobile(input));

    // ---------- Kavenegar ----------

    private sealed class FakeKavenegar(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }
        public string? Form { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Request = request;
            Form = await request.Content!.ReadAsStringAsync(ct);
            return new HttpResponseMessage(status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler);
    }

    private static readonly IReadOnlyDictionary<string, string> KavenegarSettings =
        new Dictionary<string, string> { ["apiKey"] = "KEY-123", ["sender"] = "10004346" };

    private static KavenegarSmsProvider Kavenegar(HttpMessageHandler handler) =>
        new(new Factory(handler), NullLogger<KavenegarSmsProvider>.Instance);

    [Fact]
    public async Task Kavenegar_posts_to_its_send_endpoint_with_the_national_number()
    {
        var kc = new FakeKavenegar(HttpStatusCode.OK,
            """{"return":{"status":200,"message":"تایید شد"},"entries":[{"messageid":8792343,"status":1}]}""");

        var result = await Kavenegar(kc).SendAsync(new SmsMessage("+989121234567", "سلام", "avash"), KavenegarSettings, CancellationToken.None);

        Assert.True(result.Accepted);
        Assert.Equal("8792343", result.MessageId);
        Assert.Equal("https://api.kavenegar.com/v1/KEY-123/sms/send.json", kc.Request!.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, kc.Request.Method);
        Assert.Contains("receptor=09121234567", kc.Form);
        Assert.Contains("sender=10004346", kc.Form);
        Assert.True(kc.Request.Options.TryGetValue(SmsHttp.SuppressTelemetry, out var suppressed) && suppressed);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, 403, "API key is not valid")]
    [InlineData(HttpStatusCode.PaymentRequired, 418, "account credit is not enough")]
    [InlineData(HttpStatusCode.BadRequest, 411, "receptor is not valid")]
    public async Task Kavenegar_errors_explain_the_status_without_the_api_key(HttpStatusCode http, int status, string reason)
    {
        var kc = new FakeKavenegar(http, $$"""{"return":{"status":{{status}},"message":"خطا"},"entries":null}""");

        var result = await Kavenegar(kc).SendAsync(new SmsMessage("+989121234567", "x", "avash"), KavenegarSettings, CancellationToken.None);

        Assert.False(result.Accepted);
        Assert.Contains(reason, result.Error);
        Assert.DoesNotContain("KEY-123", result.Error);
    }

    private sealed class Unreachable : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            throw new HttpRequestException($"No connection to {request.RequestUri}", null, HttpStatusCode.BadGateway);
    }

    [Fact]
    public async Task Kavenegar_network_failures_never_carry_the_url()
    {
        var result = await Kavenegar(new Unreachable()).SendAsync(new SmsMessage("+989121234567", "x", "avash"), KavenegarSettings, CancellationToken.None);

        Assert.Equal("Kavenegar is unreachable.", result.Error);
    }

    [Fact]
    public async Task Kavenegar_without_an_api_key_does_not_call_out()
    {
        var kc = new FakeKavenegar(HttpStatusCode.OK, "{}");

        var result = await Kavenegar(kc).SendAsync(new SmsMessage("+989121234567", "x", "avash"), new Dictionary<string, string>(), CancellationToken.None);

        Assert.False(result.Accepted);
        Assert.Null(kc.Request);
    }

    [Fact]
    public void The_telemetry_suppression_key_matches_the_one_service_defaults_filters_on() =>
        Assert.Equal(Microsoft.Extensions.Hosting.Extensions.SuppressTelemetry.Key, SmsHttp.SuppressTelemetry.Key);

    // ---------- Keycloak realm attributes ----------

    private sealed class FakeRealm : HttpMessageHandler
    {
        public Dictionary<string, string> Attributes { get; } = new()
        {
            ["cibaExpiresIn"] = "120",
            ["oauth2DeviceCodeLifespan"] = "600",
            ["iam.sms.oldprovider.key"] = "stale",
        };

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/token", StringComparison.Ordinal))
                return Json(new { access_token = "t", expires_in = 300 });
            if (request.Method == HttpMethod.Put)
            {
                // Like Keycloak 26.4: the attribute map is replaced, not merged.
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                Attributes.Clear();
                foreach (var p in body.RootElement.GetProperty("attributes").EnumerateObject()) Attributes[p.Name] = p.Value.GetString()!;
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            return Json(new { realm = "avash", attributes = Attributes });
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json"),
        };
    }

    [Fact]
    public async Task Saving_keeps_the_realms_other_attributes_and_replaces_only_the_sms_ones()
    {
        var realm = new FakeRealm();
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "avash", AdminClientSecret = "s" });
        var store = new KeycloakSmsSettingsStore(new HttpClient(realm), options, new KeycloakAdminTokenProvider(new HttpClient(realm), options));

        var saved = await store.SaveAsync(new StoredSmsSettings(true, "kavenegar", Settings("kavenegar", ("apiKey", "K"), ("sender", "1000"))), CancellationToken.None);
        var read = await store.GetAsync(CancellationToken.None);

        Assert.True(saved.IsSuccess);
        Assert.Equal("120", realm.Attributes["cibaExpiresIn"]);
        Assert.Equal("600", realm.Attributes["oauth2DeviceCodeLifespan"]);
        Assert.False(realm.Attributes.ContainsKey("iam.sms.oldprovider.key"));
        Assert.Equal("true", realm.Attributes["iam.sms.enabled"]);
        Assert.Equal("K", realm.Attributes["iam.sms.kavenegar.apiKey"]);
        Assert.Equal((true, "kavenegar", "1000"), (read.Value.Enabled, read.Value.Provider, read.Value.Settings["kavenegar"]["sender"]));
    }

    [Fact]
    public void Attribute_mapping_ignores_malformed_keys()
    {
        var parsed = KeycloakSmsSettingsStore.Parse(new Dictionary<string, string>
        {
            ["iam.sms.enabled"] = "false",
            ["iam.sms.kavenegar"] = "no field",
            ["iam.sms..x"] = "no provider",
            ["iam.sms.kavenegar.apiKey"] = "",
            ["other"] = "x",
        });

        Assert.False(parsed.Enabled);
        Assert.Null(parsed.Provider);
        Assert.Empty(parsed.Settings);
    }
}
