using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Audit;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>Keycloak events as the gateway reads them, and the dashboard summary built from them.</summary>
public sealed class AuditTests
{
    private sealed class FakeKeycloak(Func<HttpRequestMessage, HttpResponseMessage?>? respond = null) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Url, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var url = request.RequestUri!.PathAndQuery;
            Requests.Add((request.Method, url, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));
            if (url.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });
            return respond?.Invoke(request) ?? (request.Method == HttpMethod.Put
                ? new HttpResponseMessage(HttpStatusCode.NoContent)
                : Json(Array.Empty<object>()));
        }
    }

    private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json"),
    };

    private static KeycloakAuditAdapter Adapter(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "avash", AdminClientSecret = "s" });
        return new KeycloakAuditAdapter(new HttpClient(kc), options, new KeycloakAdminTokenProvider(new HttpClient(kc), options));
    }

    [Fact]
    public async Task Login_events_are_queried_with_keycloaks_parameters_and_mapped()
    {
        var kc = new FakeKeycloak(r => r.RequestUri!.AbsolutePath.EndsWith("/events", StringComparison.Ordinal)
            ? Json(new object[]
            {
                new { time = 1_793_868_000_000L, type = "LOGIN", clientId = "crm", userId = "u-1", ipAddress = "10.0.0.5",
                      details = new { username = "sara" } },
                new { time = 1_793_868_060_000L, type = "LOGIN_ERROR", clientId = "crm", error = "invalid_user_credentials" },
            })
            : null);

        var events = await Adapter(kc).ListLoginEventsAsync(
            new LoginEventQuery(new DateOnly(2026, 11, 1), new DateOnly(2026, 11, 5), ["LOGIN", "LOGIN_ERROR"], "crm", null, 0, 20),
            CancellationToken.None);

        var url = Assert.Single(kc.Requests, r => r.Url.Contains("/events?", StringComparison.Ordinal)).Url;
        Assert.StartsWith("/admin/realms/avash/events?", url);
        Assert.Contains("dateFrom=2026-11-01", url);
        Assert.Contains("dateTo=2026-11-05", url);
        Assert.Contains("type=LOGIN&type=LOGIN_ERROR", url);
        Assert.Contains("client=crm", url);
        Assert.Contains("first=0&max=20", url);
        Assert.Equal(2, events.Value.Count);
        var ok = events.Value[0];
        Assert.Equal(("LOGIN", false, "sara", "u-1", "10.0.0.5"), (ok.Type, ok.IsError, ok.Username, ok.UserId, ok.IpAddress));
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1_793_868_000_000L), ok.Time);
        Assert.True(events.Value[1].IsError);
        Assert.Equal("invalid_user_credentials", events.Value[1].Error);
    }

    [Fact]
    public async Task Large_reads_are_split_into_keycloak_pages_and_stop_at_the_last_page()
    {
        var served = 0;
        var kc = new FakeKeycloak(r =>
        {
            if (!r.RequestUri!.AbsolutePath.EndsWith("/admin-events", StringComparison.Ordinal)) return null;
            var batch = served == 0 ? 100 : 30; // second page is short: no third request
            served += batch;
            return Json(Enumerable.Range(0, batch).Select(_ => new { time = 1L, operationType = "UPDATE", resourceType = "USER" }));
        });

        var events = await Adapter(kc).ListAdminEventsAsync(new AdminEventQuery(Max: 500), CancellationToken.None);

        Assert.Equal(130, events.Value.Count);
        var pages = kc.Requests.Where(r => r.Url.Contains("/admin-events?", StringComparison.Ordinal)).Select(r => r.Url).ToArray();
        Assert.Equal(2, pages.Length);
        Assert.Contains("first=0&max=100", pages[0]);
        Assert.Contains("first=100&max=100", pages[1]);
    }

    [Fact]
    public async Task Admin_events_carry_the_actor_and_filters()
    {
        var kc = new FakeKeycloak(r => r.RequestUri!.AbsolutePath.EndsWith("/admin-events", StringComparison.Ordinal)
            ? Json(new[]
            {
                new
                {
                    time = 1_793_868_000_000L, operationType = "DELETE", resourceType = "GROUP", resourcePath = "groups/g-1",
                    authDetails = new { userId = "admin-1", clientId = "identity-gateway-admin", ipAddress = "127.0.0.1" },
                },
            })
            : null);

        var events = await Adapter(kc).ListAdminEventsAsync(
            new AdminEventQuery(ResourceTypes: ["GROUP"], Operations: ["DELETE"]), CancellationToken.None);

        var url = kc.Requests.Single(r => r.Url.Contains("/admin-events?", StringComparison.Ordinal)).Url;
        Assert.Contains("resourceTypes=GROUP", url);
        Assert.Contains("operationTypes=DELETE", url);
        var e = Assert.Single(events.Value);
        Assert.Equal(("DELETE", "GROUP", "groups/g-1", "admin-1", "identity-gateway-admin"),
            (e.Operation, e.ResourceType, e.ResourcePath, e.ActorUserId, e.ActorClientId));
    }

    [Fact]
    public async Task Settings_are_read_from_events_config_and_written_with_a_partial_realm_update()
    {
        var kc = new FakeKeycloak(r => r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath.EndsWith("/events/config", StringComparison.Ordinal)
            ? Json(new { eventsEnabled = true, eventsExpiration = 2_592_000, adminEventsEnabled = false, adminEventsDetailsEnabled = false })
            : null);
        var adapter = Adapter(kc);

        var read = await adapter.GetSettingsAsync(CancellationToken.None);
        var written = await adapter.SetSettingsAsync(new EventSettingsDto(true, true, false, 14), CancellationToken.None);

        Assert.Equal(new EventSettingsDto(true, false, false, 30), read.Value);
        Assert.True(written.IsSuccess);
        var put = Assert.Single(kc.Requests, r => r.Method == HttpMethod.Put);
        Assert.Equal("/admin/realms/avash", put.Url);
        using var body = JsonDocument.Parse(put.Body!);
        Assert.True(body.RootElement.GetProperty("eventsEnabled").GetBoolean());
        Assert.True(body.RootElement.GetProperty("adminEventsEnabled").GetBoolean());
        Assert.Equal(14 * 86_400, body.RootElement.GetProperty("eventsExpiration").GetInt64());
        Assert.DoesNotContain(kc.Requests, r => r.Method == HttpMethod.Put && r.Url.Contains("events/config", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Keycloak_refusal_surfaces_as_an_error_not_an_empty_list()
    {
        var kc = new FakeKeycloak(r => r.RequestUri!.AbsolutePath.EndsWith("/events", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.Forbidden)
            : null);

        var events = await Adapter(kc).ListLoginEventsAsync(new LoginEventQuery(), CancellationToken.None);

        Assert.False(events.IsSuccess);
        // The gateway's own credentials were refused: an upstream problem, not the caller's.
        Assert.Equal(ErrorKind.Upstream, events.Error!.Kind);
    }

    private static LoginEventDto Login(string day, string client, bool error = false) =>
        new(DateTimeOffset.Parse(day + "T10:00:00Z"), error ? "LOGIN_ERROR" : "LOGIN", error, error ? "invalid_user_credentials" : null,
            client, "u", "user", null);

    [Fact]
    public void Summary_counts_every_day_including_days_without_logins()
    {
        var from = new DateOnly(2026, 11, 3);
        var summary = AuditService.Summarize(from, new DateOnly(2026, 11, 5), new EventSettingsDto(true, true, false, 30),
            [Login("2026-11-03", "crm"), Login("2026-11-03", "crm", error: true), Login("2026-11-05", "hr"), Login("2026-11-05", "crm")],
            [new AdminEventDto(DateTimeOffset.Parse("2026-11-04T09:00:00Z"), "UPDATE", "USER", "users/u", null, null, null, null)]);

        Assert.Equal([(2026_11_03, 1, 1), (2026_11_04, 0, 0), (2026_11_05, 2, 0)],
            summary.Days.Select(d => (d.Date.Year * 10000 + d.Date.Month * 100 + d.Date.Day, d.Succeeded, d.Failed)));
        Assert.Equal((3, 1, 1), (summary.Logins, summary.FailedLogins, summary.AdminChanges));
        Assert.Equal([("crm", 2), ("hr", 1)], summary.TopApplications.Select(a => (a.ClientId, a.Logins)));
        Assert.False(summary.Truncated);
    }

    [Fact]
    public void Summary_is_marked_truncated_when_the_read_limit_is_reached()
    {
        var many = Enumerable.Range(0, AuditService.SummaryEventLimit).Select(_ => Login("2026-11-05", "crm")).ToArray();

        var summary = AuditService.Summarize(new DateOnly(2026, 11, 5), new DateOnly(2026, 11, 5),
            new EventSettingsDto(true, false, false, 30), many, []);

        Assert.True(summary.Truncated);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class StubReader(EventSettingsDto settings) : IAuditEventReader
    {
        public List<LoginEventQuery> LoginQueries { get; } = [];
        public int AdminReads { get; private set; }

        public Task<Result<IReadOnlyList<LoginEventDto>>> ListLoginEventsAsync(LoginEventQuery query, CancellationToken ct)
        {
            LoginQueries.Add(query);
            return Task.FromResult(Result<IReadOnlyList<LoginEventDto>>.Success([]));
        }

        public Task<Result<IReadOnlyList<AdminEventDto>>> ListAdminEventsAsync(AdminEventQuery query, CancellationToken ct)
        {
            AdminReads++;
            return Task.FromResult(Result<IReadOnlyList<AdminEventDto>>.Success([]));
        }

        public Task<Result<EventSettingsDto>> GetSettingsAsync(CancellationToken ct) => Task.FromResult(Result<EventSettingsDto>.Success(settings));
        public Task<Result> SetSettingsAsync(EventSettingsDto s, CancellationToken ct) => Task.FromResult(Result.Success());
    }

    [Fact]
    public async Task Summary_reads_only_enabled_event_kinds_over_the_requested_days()
    {
        var reader = new StubReader(new EventSettingsDto(true, false, false, 30));
        var clock = new FixedClock(DateTimeOffset.Parse("2026-11-05T20:00:00Z"));

        var summary = await new AuditService(reader, clock).SummaryAsync(7, CancellationToken.None);

        var query = Assert.Single(reader.LoginQueries);
        Assert.Equal((new DateOnly(2026, 10, 30), new DateOnly(2026, 11, 5)), (query.From!.Value, query.To!.Value));
        Assert.Equal(AuditService.LoginTypes, query.Types);
        Assert.Equal(0, reader.AdminReads);
        Assert.Equal(7, summary.Value.Days.Count);
        Assert.False(summary.Value.AdminEventsEnabled);
    }

    [Fact]
    public async Task Summary_days_are_clamped_to_a_month()
    {
        var reader = new StubReader(new EventSettingsDto(true, true, false, 30));

        var summary = await new AuditService(reader, new FixedClock(DateTimeOffset.Parse("2026-11-05T00:00:00Z")))
            .SummaryAsync(365, CancellationToken.None);

        Assert.Equal(30, summary.Value.Days.Count);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(365, true)]
    [InlineData(366, false)]
    public void Retention_is_one_day_to_one_year(int days, bool valid) =>
        Assert.Equal(valid, new EventSettingsValidator().Validate(new EventSettingsDto(true, true, false, days)).IsValid);

    [Fact]
    public void Queries_reject_reversed_dates_oversized_pages_and_unknown_operations()
    {
        Assert.False(new LoginEventQueryValidator().Validate(new LoginEventQuery(new DateOnly(2026, 11, 5), new DateOnly(2026, 11, 1))).IsValid);
        Assert.False(new LoginEventQueryValidator().Validate(new LoginEventQuery(Max: 500)).IsValid);
        Assert.False(new LoginEventQueryValidator().Validate(new LoginEventQuery(Types: ["login; drop"])).IsValid);
        Assert.False(new AdminEventQueryValidator().Validate(new AdminEventQuery(Operations: ["PATCH"])).IsValid);
        Assert.True(new AdminEventQueryValidator().Validate(new AdminEventQuery(Operations: ["CREATE"], ResourceTypes: ["CLIENT_ROLE"])).IsValid);
    }
}
