using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Identity.Admin.Auth;
using Identity.Admin.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Radzen;

namespace Identity.Admin.Tests;

/// <summary>
/// A gateway stand-in for console page tests: answers by "METHOD path" (query string included), records the
/// requests, and can hold a response back to show the loading state.
/// </summary>
public sealed class FakeGateway : HttpMessageHandler
{
    private readonly Dictionary<string, Func<HttpRequestMessage, Task<HttpResponseMessage>>> _routes = new(StringComparer.Ordinal);

    public List<(string Route, string? Body)> Requests { get; } = [];

    public FakeGateway Json(string route, object body, HttpStatusCode status = HttpStatusCode.OK)
    {
        _routes[route] = _ => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                System.Text.Encoding.UTF8, "application/json"),
        });
        return this;
    }

    public FakeGateway Problem(string route, HttpStatusCode status, string code = "keycloak.unreachable") =>
        Json(route, new { title = "Problem", status = (int)status, detail = "From the fake gateway.", code }, status);

    /// <summary>The response waits until the returned source completes (loading state).</summary>
    public TaskCompletionSource Hold(string route, object body)
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Json(route, body);
        var answer = _routes[route];
        _routes[route] = async request =>
        {
            await gate.Task;
            return await answer(request);
        };
        return gate;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var route = $"{request.Method} {request.RequestUri!.PathAndQuery.TrimStart('/')}";
        Requests.Add((route, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));
        return _routes.TryGetValue(route, out var answer)
            ? await answer(request)
            : new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                Content = new StringContent($$"""{"title":"Not found","status":404,"code":"test.no_route","detail":"{{route}}"}""",
                    System.Text.Encoding.UTF8, "application/json"),
            };
    }
}

/// <summary>A bUnit context with a signed-in administrator, a console session and the gateway replaced by <see cref="FakeGateway"/>.</summary>
public abstract class ConsoleTestContext : BunitContext
{
    protected FakeGateway Gateway { get; } = new();

    protected void SignIn(params string[] permissions)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        Services.AddRadzenComponents();
        var sessions = new ConsoleSessionStore();
        sessions.Set("s-1", new ConsoleSession("avash", "token", null, null, DateTimeOffset.UtcNow.AddHours(1)));
        Services.AddSingleton(sessions);
        Services.AddSingleton(Options.Create(new ConsoleOptions
        {
            KeycloakBaseUrl = "https://kc.test",
            GatewayBaseUrl = "http://gateway.test",
            Tenants = [new ConsoleTenant { Id = "avash", DisplayName = "آوش", Realm = "avash" }],
        }));
        Services.AddSingleton<IHttpClientFactory>(new SingleClientFactory());
        Services.AddScoped(sp => new GatewayApi(new HttpClient(Gateway) { BaseAddress = new Uri("http://gateway.test/") },
            sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider>(),
            sessions, sp.GetRequiredService<IOptions<ConsoleOptions>>()));

        var auth = AddAuthorization();
        auth.SetAuthorized("admin");
        auth.SetClaims([new Claim(ConsoleClaims.SessionId, "s-1"), new Claim(ConsoleClaims.Tenant, "avash"),
            .. permissions.Select(p => new Claim(ConsoleClaims.Permission, p))]);
    }

    private sealed class SingleClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    protected static readonly string[] AllRead =
    [
        Permissions.UsersRead, Permissions.RolesRead, Permissions.ApplicationsRead, Permissions.PermissionsRead, Permissions.AuditRead,
    ];
}
