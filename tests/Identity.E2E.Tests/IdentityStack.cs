using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;

namespace Identity.E2E.Tests;

/// <summary>
/// Runs only with IDENTITY_E2E=1: the tests start the real stack (PostgreSQL, Keycloak, Redis, gateway, sample,
/// console) through the Aspire AppHost, so they need Docker and the stack's ports (Keycloak 18080) to be free.
/// </summary>
public sealed class E2EFactAttribute : FactAttribute
{
    public E2EFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("IDENTITY_E2E") != "1")
            Skip = "End-to-end test: set IDENTITY_E2E=1 (needs Docker and a stopped local stack).";
    }
}

/// <summary>The running stack, started once for all end-to-end tests.</summary>
public sealed class IdentityStack : IAsyncLifetime
{
    private static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(6);
    private DistributedApplication? _app;

    public HttpClient Gateway { get; private set; } = default!;
    public HttpClient Sample { get; private set; } = default!;
    public HttpClient Console { get; private set; } = default!;

    public async Task InitializeAsync()
    {
        if (Environment.GetEnvironmentVariable("IDENTITY_E2E") != "1") return;

        using var timeout = new CancellationTokenSource(StartTimeout);
        var builder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.Identity_AppHost>(timeout.Token);
        _app = await builder.BuildAsync(timeout.Token);
        await _app.StartAsync(timeout.Token);

        await _app.ResourceNotifications.WaitForResourceHealthyAsync("identity-gateway", timeout.Token);
        await _app.ResourceNotifications.WaitForResourceHealthyAsync("order-service", timeout.Token);
        await _app.ResourceNotifications.WaitForResourceHealthyAsync("identity-admin", timeout.Token);
        Gateway = _app.CreateHttpClient("identity-gateway", "http");
        Sample = _app.CreateHttpClient("order-service", "http");
        Console = _app.CreateHttpClient("identity-admin", "http");

        // Liveness is not readiness: wait until the Keycloak bootstrap (claim mappers, super-admins, ...) completed.
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            using var health = await Gateway.GetAsync("/health", timeout.Token);
            if (health.IsSuccessStatusCode) break;
            await Task.Delay(TimeSpan.FromSeconds(2), timeout.Token);
        }
    }

    public async Task DisposeAsync()
    {
        if (_app is not null) await _app.DisposeAsync();
    }

    public async Task<string> LoginAsync(string username, string password, string? tenant = null)
    {
        using var response = await LoginResponseAsync(username, password, tenant);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_token").GetString()!;
    }

    public Task<HttpResponseMessage> LoginResponseAsync(string username, string password, string? tenant = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/identity/auth/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = username,
                ["password"] = password,
            }),
        };
        if (tenant is not null) request.Headers.Add("X-Tenant-Id", tenant);
        return Gateway.SendAsync(request);
    }

    public async Task<HttpResponseMessage> CallAsync(HttpMethod method, string path, string token, object? body = null, string? tenant = null,
        HttpClient? client = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (tenant is not null) request.Headers.Add("X-Tenant-Id", tenant);
        if (body is not null) request.Content = JsonContent.Create(body);
        return await (client ?? Gateway).SendAsync(request);
    }

    public static IReadOnlyCollection<string> Claims(string accessToken, string type)
    {
        var payload = accessToken.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        using var json = JsonDocument.Parse(Convert.FromBase64String(payload));
        // Keycloak nests dotted claim names: authz.scope.region arrives as {"authz":{"scope":{"region":[...]}}}.
        var value = json.RootElement;
        foreach (var part in type.Split('.'))
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(part, out value)) return [];
        return value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Select(v => v.ToString()).ToArray()
            : [value.ToString()];
    }
}

[CollectionDefinition(Name)]
public sealed class StackCollection : ICollectionFixture<IdentityStack>
{
    public const string Name = "identity-stack";
}
