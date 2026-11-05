using Microsoft.Playwright;

namespace Identity.E2E.Tests.Ui;

/// <summary>
/// One real browser (the installed Google Chrome, driven by Playwright) for the UI tests. Every page records HTTP
/// responses >= 400 and browser console errors, so a test fails on a 431, a 500 or a script error anywhere in the flow,
/// not only on what it asserts explicitly. On failure, a screenshot is saved to TestResults/ui.
/// </summary>
public sealed class BrowserSession : IAsyncLifetime
{
    private IPlaywright? _playwright;

    public IBrowser Browser { get; private set; } = default!;

    public const string Console = "http://localhost:5090";
    public const string Keycloak = "https://localhost:18080";

    public async Task InitializeAsync()
    {
        if (Environment.GetEnvironmentVariable("IDENTITY_E2E") != "1") return;
        _playwright = await Playwright.CreateAsync();
        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            // The installed Chrome: no browser download needed (PLAYWRIGHT_CHANNEL=msedge also works).
            Channel = Environment.GetEnvironmentVariable("PLAYWRIGHT_CHANNEL") ?? "chrome",
            Headless = Environment.GetEnvironmentVariable("PLAYWRIGHT_HEADED") != "1",
        });
    }

    public async Task DisposeAsync()
    {
        if (_playwright is null) return;
        await Browser.CloseAsync();
        _playwright.Dispose();
    }

    /// <summary>A fresh browser profile (cookies, storage) watched for errors.</summary>
    public async Task<UiContext> NewContextAsync(int width = 1440, int height = 900)
    {
        var context = await Browser.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true, // Keycloak's local development certificate
            Locale = "fa-IR",
            ViewportSize = new ViewportSize { Width = width, Height = height },
        });
        return await UiContext.CreateAsync(context);
    }
}

public sealed class UiContext : IAsyncDisposable
{
    private readonly List<string> _problems = [];

    /// <summary>Windows socket exhaustion as Chrome reports it (WSAENOBUFS, EADDRINUSE).</summary>
    private static readonly string[] EnvironmentErrors = ["ERR_NO_BUFFER_SPACE", "ERR_ADDRESS_IN_USE"];

    private UiContext(IBrowserContext context, IPage page)
    {
        Context = context;
        Page = page;
    }

    public IBrowserContext Context { get; }
    public IPage Page { get; }

    /// <summary>Largest Cookie header sent to Keycloak (431 regression guard).</summary>
    public int LargestKeycloakCookieHeader { get; private set; }

    public IReadOnlyList<string> Problems => _problems;

    public static async Task<UiContext> CreateAsync(IBrowserContext context)
    {
        var page = await context.NewPageAsync();
        page.SetDefaultTimeout(30_000);
        var ui = new UiContext(context, page);
        context.Response += (_, response) =>
        {
            var url = response.Url;
            if (response.Status < 400 || url.EndsWith("/favicon.ico", StringComparison.Ordinal)) return;
            lock (ui._problems) ui._problems.Add($"HTTP {response.Status} {response.Request.Method} {url}");
        };
        context.Request += (_, request) =>
        {
            if (!request.Url.StartsWith(BrowserSession.Keycloak, StringComparison.Ordinal)) return;
            _ = Task.Run(async () =>
            {
                try
                {
                    var headers = await request.AllHeadersAsync();
                    var size = headers.TryGetValue("cookie", out var cookie) ? cookie.Length : 0;
                    lock (ui._problems) ui.LargestKeycloakCookieHeader = Math.Max(ui.LargestKeycloakCookieHeader, size);
                }
                catch (PlaywrightException) { /* the page navigated on; the header size is not needed */ }
            });
        };
        page.Console += (_, message) =>
        {
            // The browser's automatic /favicon.ico probe is not part of the application.
            if (message.Type != "error" || message.Location.Contains("/favicon.ico", StringComparison.Ordinal)) return;
            lock (ui._problems) ui._problems.Add($"console error: {message.Text} ({message.Location})");
        };
        page.PageError += (_, error) => { lock (ui._problems) ui._problems.Add($"page error: {error}"); };
        return ui;
    }

    /// <summary>Signs in through the console's tenant list and Keycloak's (Persian) login page.</summary>
    public async Task SignInAsync(string username = "admin", string password = "admin", string tenant = "company")
    {
        try
        {
            await Page.GotoAsync($"{BrowserSession.Console}/login");
            await Page.Locator($"a.av-login__tenant[href*='/auth/login/{tenant}']").ClickAsync();
            await Page.WaitForURLAsync(u => u.StartsWith(BrowserSession.Keycloak, StringComparison.Ordinal));
            await Page.Locator("#username").FillAsync(username);
            await Page.Locator("#password").FillAsync(password);
            await Page.Locator("#kc-login").ClickAsync();
            await Page.WaitForURLAsync(u => u.StartsWith(BrowserSession.Console, StringComparison.Ordinal) && !u.Contains("/login"));
            await Page.Locator("nav.av-nav").WaitForAsync();
        }
        catch (TimeoutException)
        {
            // Where did the sign-in stop (Keycloak error page, console message)? The screenshot and URL tell.
            await ScreenshotAsync($"sign-in-{username}-{DateTime.UtcNow:HHmmss}");
            lock (_problems) _problems.Add($"sign-in stopped at {Page.Url}");
            throw;
        }
    }

    public async Task SignOutAsync()
    {
        await Page.Locator("button[aria-label='خروج از حساب']").ClickAsync();
        await Page.WaitForURLAsync(u => u.Contains("/login"));
    }

    /// <summary>Fails with every recorded HTTP/script problem (except the allowed ones) and a screenshot.</summary>
    public async Task AssertNoProblemsAsync(string name, params string[] allowed)
    {
        string[] problems;
        lock (_problems) problems = _problems.Where(p => !allowed.Any(a => p.Contains(a, StringComparison.Ordinal))).ToArray();
        if (problems.Length == 0) return;
        await ScreenshotAsync(name);
        var environment = problems.Any(p => EnvironmentErrors.Any(e => p.Contains(e, StringComparison.Ordinal)))
            ? $"\nThe machine ran out of sockets ({string.Join(", ", EnvironmentErrors)}): this is the environment, not the " +
              "application. Look in `netstat -ano` for a process holding thousands of connections (e.g. Docker Desktop) and restart it."
            : "";
        Assert.Fail($"{name}: {problems.Length} problem(s):\n" + string.Join("\n", problems.Distinct()) + environment);
    }

    public async Task ScreenshotAsync(string name)
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "TestResults", "ui");
        Directory.CreateDirectory(directory);
        await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(directory, name + ".png"), FullPage = true });
    }

    /// <summary>True when the page is wider than the viewport (horizontal scrolling).</summary>
    public Task<bool> OverflowsAsync() => Page.EvaluateAsync<bool>("document.documentElement.scrollWidth > window.innerWidth + 1");

    public async ValueTask DisposeAsync() => await Context.CloseAsync();
}
