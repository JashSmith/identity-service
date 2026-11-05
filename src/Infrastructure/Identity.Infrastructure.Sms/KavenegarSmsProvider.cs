using System.Net;
using System.Text.Json;
using Identity.Application.Sms;
using Identity.Contracts;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Sms;

/// <summary>
/// Kavenegar (kavenegar.com), a common Iranian SMS gateway: <c>POST https://api.kavenegar.com/v1/{API-KEY}/sms/send.json</c>
/// with form fields receptor, message and sender. The API key is part of the URL, so this client has no request
/// logging and its requests are kept out of telemetry (<see cref="SmsHttp.SuppressTelemetry"/>); errors never contain it.
/// Also the reference for adding another provider: implement <see cref="ISmsProvider"/> and register it.
/// </summary>
public sealed class KavenegarSmsProvider(IHttpClientFactory httpFactory, ILogger<KavenegarSmsProvider> logger) : ISmsProvider
{
    public const string HttpClientName = "sms-kavenegar";
    public const string DefaultBaseUrl = "https://api.kavenegar.com";

    public string Id => "kavenegar";
    public string DisplayName => "کاوه‌نگار";
    public string Description => "ارسال پیامک از طریق سرویس کاوه‌نگار (kavenegar.com) با کلید API حساب کاربری.";
    public bool SendsMessages => true;

    public IReadOnlyList<SmsFieldDto> Fields { get; } =
    [
        new("apiKey", "کلید API", "secret", true, null, "از پنل کاوه‌نگار، بخش تنظیمات حساب ← کلید API"),
        new("sender", "شماره فرستنده", "phone", false, "10004346", "خالی یعنی شماره پیش‌فرض حساب"),
        new("baseUrl", "نشانی سرویس", "url", false, DefaultBaseUrl, "فقط اگر از نشانی دیگری (مثلاً پروکسی داخلی) استفاده می‌کنید"),
    ];

    public async Task<SmsSendResult> SendAsync(SmsMessage message, IReadOnlyDictionary<string, string> settings, CancellationToken ct)
    {
        if (!settings.TryGetValue("apiKey", out var apiKey) || string.IsNullOrWhiteSpace(apiKey))
            return SmsSendResult.Failed("API key is not configured.");
        var baseUrl = settings.TryGetValue("baseUrl", out var b) && b.Length > 0 ? b.TrimEnd('/') : DefaultBaseUrl;
        var form = new Dictionary<string, string>
        {
            // Kavenegar expects the national form 09xxxxxxxxx.
            ["receptor"] = "0" + message.To[3..],
            ["message"] = message.Text,
        };
        if (settings.TryGetValue("sender", out var sender) && sender.Length > 0) form["sender"] = sender;

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/v1/{Uri.EscapeDataString(apiKey)}/sms/send.json")
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.Options.Set(SmsHttp.SuppressTelemetry, true);

        HttpResponseMessage response;
        try
        {
            response = await httpFactory.CreateClient(HttpClientName).SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            // The exception message may contain the URL; only its kind is logged.
            logger.LogWarning("Kavenegar unreachable ({Error})", ex.HttpRequestError);
            return SmsSendResult.Failed("Kavenegar is unreachable.");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning("Kavenegar timed out");
            return SmsSendResult.Failed("Kavenegar did not answer in time.");
        }

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            var (status, text, messageId) = Parse(body);
            if (response.IsSuccessStatusCode && status == 200)
            {
                logger.LogInformation("SMS accepted by Kavenegar for {Receptor} (message {MessageId})", PhoneNumbers.Mask(message.To), messageId);
                return new SmsSendResult(true, messageId);
            }
            var code = status ?? (int)response.StatusCode;
            logger.LogWarning("Kavenegar refused the SMS: {Status}", code);
            return SmsSendResult.Failed($"{code} {Explain(code, response.StatusCode)}{(text is null ? "" : $" ({text})")}");
        }
    }

    /// <summary>{"return":{"status":200,"message":"..."},"entries":[{"messageid":123,...}]}</summary>
    private static (int? Status, string? Message, string? MessageId) Parse(string body)
    {
        try
        {
            using var json = JsonDocument.Parse(body);
            var root = json.RootElement;
            int? status = null;
            string? message = null;
            if (root.TryGetProperty("return", out var ret))
            {
                if (ret.TryGetProperty("status", out var s) && s.TryGetInt32(out var value)) status = value;
                if (ret.TryGetProperty("message", out var m)) message = m.GetString();
            }
            string? id = null;
            if (root.TryGetProperty("entries", out var entries) && entries.ValueKind == JsonValueKind.Array && entries.GetArrayLength() > 0 &&
                entries[0].TryGetProperty("messageid", out var mid))
                id = mid.ValueKind == JsonValueKind.Number ? mid.GetRawText() : mid.GetString();
            return (status, message, id);
        }
        catch (JsonException)
        {
            return (null, null, null);
        }
    }

    /// <summary>Kavenegar's documented status codes; others fall back to the HTTP status.</summary>
    private static string Explain(int code, HttpStatusCode http) => code switch
    {
        400 => "invalid parameters",
        401 => "account is not active",
        403 => "API key is not valid",
        411 => "receptor is not valid",
        412 => "sender line is not valid",
        418 => "account credit is not enough",
        422 => "message contains invalid characters",
        501 => "test accounts can only send to the account owner's number",
        _ => http.ToString(),
    };
}

public static class SmsHttp
{
    /// <summary>Set on requests whose URL carries a secret; Identity.ServiceDefaults keeps them out of traces.</summary>
    public static readonly HttpRequestOptionsKey<bool> SuppressTelemetry = new("Avash.SuppressTelemetry");
}
