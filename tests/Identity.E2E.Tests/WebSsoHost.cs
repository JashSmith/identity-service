using System.Net;
using System.Net.Sockets;
using Avash.Identity.Authentication.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Identity.E2E.Tests;

/// <summary>
/// A minimal server-rendered web application inside the test process, wired as the integration guide shows
/// (AddAvashWebSso + MapAvashSso). Two of them prove single sign-on across applications.
/// </summary>
public sealed class WebSsoHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    private WebSsoHost(WebApplication app, Uri baseAddress)
    {
        _app = app;
        BaseAddress = baseAddress;
    }

    public Uri BaseAddress { get; }

    /// <summary>A free loopback port, known before the Keycloak client (with its redirect URI) is created.</summary>
    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <param name="listenOnAllInterfaces">Needed when Keycloak (a container) must call the app, e.g. back-channel logout.</param>
    public static async Task<WebSsoHost> StartAsync(int port, Uri gateway, string clientId, string clientSecret, bool listenOnAllInterfaces = false)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.WebHost.UseUrls(listenOnAllInterfaces ? $"http://0.0.0.0:{port}" : $"http://127.0.0.1:{port}");
        builder.Services.AddAvashWebSso(o =>
        {
            o.Authority = gateway.ToString().TrimEnd('/');
            o.ClientId = clientId;
            o.ClientSecret = clientSecret;
            o.RequireHttpsMetadata = false;
            // Both test applications share the host name 127.0.0.1, so their cookies need different names.
            o.CookieName = $".Avash.Sso.{clientId}";
        });
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapAvashSso();
        app.MapGet("/me", (HttpContext http) => Results.Ok(new
        {
            name = http.User.Identity?.Name,
            permissions = http.User.FindAll("permissions").Select(c => c.Value).ToArray(),
        })).RequireAuthorization();
        await app.StartAsync();
        return new WebSsoHost(app, new Uri($"http://127.0.0.1:{port}"));
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

/// <summary>A cookie-keeping HTTP client that follows redirects itself and records every page it saw.</summary>
public sealed class Browser : IDisposable
{
    private readonly HttpClient _http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        CookieContainer = new CookieContainer(),
        UseCookies = true,
        ServerCertificateCustomValidationCallback = (request, _, _, _) => request.RequestUri?.IsLoopback == true,
    });

    public List<Uri> Visited { get; } = [];

    /// <summary>Sends the request and follows redirects; returns the final response and its URL.</summary>
    public async Task<(HttpResponseMessage Response, Uri Url)> NavigateAsync(HttpRequestMessage request)
    {
        for (var hops = 0; hops < 15; hops++)
        {
            Visited.Add(request.RequestUri!);
            var response = await _http.SendAsync(request);
            if ((int)response.StatusCode is < 300 or >= 400 || response.Headers.Location is null)
                return (response, request.RequestUri!);
            var next = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(request.RequestUri!, response.Headers.Location);
            response.Dispose();
            request = new HttpRequestMessage(HttpMethod.Get, next);
        }
        throw new InvalidOperationException("Too many redirects.");
    }

    public Task<(HttpResponseMessage Response, Uri Url)> GetAsync(Uri url) => NavigateAsync(new HttpRequestMessage(HttpMethod.Get, url));

    public Task<(HttpResponseMessage Response, Uri Url)> PostFormAsync(Uri url, Dictionary<string, string> form) =>
        NavigateAsync(new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form) });

    /// <summary>The action of Keycloak's username/password form, or null when the page is not a login form.</summary>
    public static Uri? LoginFormAction(string html, Uri page)
    {
        var match = System.Text.RegularExpressions.Regex.Match(html, "<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"");
        if (!match.Success) match = System.Text.RegularExpressions.Regex.Match(html, "<form[^>]*action=\"([^\"]+)\"[^>]*id=\"kc-form-login\"");
        return match.Success ? new Uri(page, WebUtility.HtmlDecode(match.Groups[1].Value)) : null;
    }

    public void Dispose() => _http.Dispose();
}
