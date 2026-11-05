using Avash.Identity.Authentication.AspNetCore;
using Avash.Identity.Authorization.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Identity.E2E.Tests;

/// <summary>
/// A minimal consumer service hosted inside the test process: it is wired exactly as the integration guide tells
/// a real service to be (authority = the gateway, permission policies from <c>Avash.Identity.*</c>), so the
/// end-to-end tests prove that consumers enforce what the gateway issues.
/// </summary>
public sealed class ConsumerHost : IAsyncDisposable
{
    public const string ViewPermission = "Orders:Order:View";
    public const string CreatePermission = "Orders:Order:Create";

    private readonly WebApplication _app;

    private ConsumerHost(WebApplication app, HttpClient client)
    {
        _app = app;
        Client = client;
    }

    public HttpClient Client { get; }

    public static async Task<ConsumerHost> StartAsync(Uri gateway, string applicationId)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddAvashAuthentication(o =>
        {
            o.Authority = gateway.ToString().TrimEnd('/');
            o.RequireHttpsMetadata = false;
            o.AcceptIssuerFromDiscovery = true;
        });
        builder.Services.AddAvashAuthorization(o => o.ApplicationId = applicationId);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/api/orders", () => Results.Ok(Array.Empty<object>())).RequireAuthorization(ViewPermission);
        app.MapPost("/api/orders", () => Results.Ok()).RequireAuthorization(CreatePermission);
        await app.StartAsync();

        // After start, Urls holds the address Kestrel actually bound (port 0 = any free port).
        var address = app.Urls.First();
        return new ConsumerHost(app, new HttpClient { BaseAddress = new Uri(address) });
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
    }
}
