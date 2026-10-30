using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Admin.Auth;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;

namespace Identity.Admin.Services;

/// <summary>A gateway error (RFC 9457 problem details) with its stable code and field errors.</summary>
public sealed class ApiException(int status, string code, string message, IReadOnlyDictionary<string, string[]> fields)
    : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public IReadOnlyDictionary<string, string[]> Fields { get; } = fields;

    /// <summary>A Persian summary for the notification title; the gateway's own message is shown below it.</summary>
    public string PersianTitle => Code switch
    {
        "access.outside_schedule" => "خارج از بازه زمانی مجاز",
        _ when Code.StartsWith("delegation.", StringComparison.Ordinal) => "خارج از محدوده دسترسی شما",
        _ when Code.StartsWith("tenant.", StringComparison.Ordinal) => "سازمان نامعتبر است",
        "session.expired" => "نشست شما به پایان رسیده است؛ دوباره وارد شوید",
        _ when Status == 400 => "اطلاعات ورودی نامعتبر است",
        _ when Status == 401 => "نشست شما به پایان رسیده است؛ دوباره وارد شوید",
        _ when Status == 403 => "به این بخش دسترسی ندارید",
        _ when Status == 404 => "مورد درخواستی یافت نشد",
        _ when Status == 409 => "این مورد قبلاً وجود دارد یا در حال استفاده است",
        _ when Status >= 500 => "سرویس هویت در حال حاضر در دسترس نیست",
        _ => "خطا در انجام عملیات",
    };

    public string Details => Fields.Count == 0 ? Message : $"{Message} {string.Join(" ", Fields.SelectMany(f => f.Value))}";
}

/// <summary>
/// Calls the Identity Gateway with the signed-in administrator's access token and tenant. Tokens are refreshed
/// shortly before they expire; when that is no longer possible the call fails with session.expired.
/// </summary>
public sealed class GatewayApi(
    HttpClient http,
    IHttpClientFactory httpFactory,
    AuthenticationStateProvider authentication,
    ConsoleSessionStore sessions,
    IOptions<ConsoleOptions> options)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Task<T> GetAsync<T>(string path) => SendAsync<T>(HttpMethod.Get, path, null);

    public async Task<T> SendAsync<T>(HttpMethod method, string path, object? body)
    {
        using var response = await SendCoreAsync(method, path, body);
        return (await response.Content.ReadFromJsonAsync<T>(Json))!;
    }

    public async Task SendAsync(HttpMethod method, string path, object? body = null)
    {
        using var response = await SendCoreAsync(method, path, body);
    }

    private async Task<HttpResponseMessage> SendCoreAsync(HttpMethod method, string path, object? body)
    {
        var (session, sessionId) = await CurrentSessionAsync();
        session = await FreshAsync(session, sessionId);

        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.AccessToken);
        request.Headers.Add("X-Tenant-Id", session.TenantId);
        if (body is not null) request.Content = JsonContent.Create(body, options: Json);

        var response = await http.SendAsync(request);
        if (response.IsSuccessStatusCode) return response;
        using (response) throw await ToExceptionAsync(response);
    }

    private async Task<(ConsoleSession Session, string Id)> CurrentSessionAsync()
    {
        var state = await authentication.GetAuthenticationStateAsync();
        var id = state.User.FindFirst(ConsoleClaims.SessionId)?.Value;
        var session = sessions.Get(id);
        return session is null || id is null ? throw Expired() : (session, id);
    }

    /// <summary>Refreshes the access token at Keycloak when it expires within 30 seconds.</summary>
    private async Task<ConsoleSession> FreshAsync(ConsoleSession session, string sessionId)
    {
        if (session.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30)) return session;
        if (session.RefreshToken is null) throw Expired();

        var o = options.Value;
        var tenant = o.Tenants.FirstOrDefault(t => t.Id == session.TenantId) ?? throw Expired();
        using var client = httpFactory.CreateClient("keycloak");
        using var response = await client.PostAsync($"{o.KeycloakBaseUrl.TrimEnd('/')}/realms/{tenant.Realm}/protocol/openid-connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = session.RefreshToken,
                ["client_id"] = o.ClientId,
                ["client_secret"] = o.ClientSecret,
            }));
        if (!response.IsSuccessStatusCode)
        {
            sessions.Remove(sessionId);
            throw Expired();
        }
        var tokens = await response.Content.ReadFromJsonAsync<JsonElement>();
        var refreshed = session with
        {
            AccessToken = tokens.GetProperty("access_token").GetString()!,
            RefreshToken = tokens.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : session.RefreshToken,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokens.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 60),
        };
        sessions.Set(sessionId, refreshed);
        return refreshed;
    }

    private static ApiException Expired() =>
        new(401, "session.expired", "The console session has expired.", new Dictionary<string, string[]>());

    private static async Task<ApiException> ToExceptionAsync(HttpResponseMessage response)
    {
        var status = (int)response.StatusCode;
        try
        {
            var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
            var code = problem.TryGetProperty("code", out var c) ? c.GetString() ?? "" : "";
            var detail = problem.TryGetProperty("detail", out var d) ? d.GetString() : null;
            var title = problem.TryGetProperty("title", out var t) ? t.GetString() : null;
            var fields = problem.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object
                ? errors.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.EnumerateArray().Select(v => v.GetString() ?? "").ToArray())
                : new Dictionary<string, string[]>();
            return new ApiException(status, code, detail ?? title ?? response.ReasonPhrase ?? "", fields);
        }
        catch (JsonException)
        {
            return new ApiException(status, "", response.ReasonPhrase ?? $"HTTP {status}", new Dictionary<string, string[]>());
        }
    }
}
