using System.Collections.Concurrent;
using Identity.Application.Sms;
using Identity.Contracts;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Sms;

/// <summary>
/// Records messages instead of sending them (development, tests, demos). The console shows the latest messages of the
/// administrator's own tenant; nothing leaves the gateway and the store lives in memory only.
/// </summary>
public sealed class DevelopmentSmsProvider(TimeProvider clock, ILogger<DevelopmentSmsProvider> logger) : ISmsProvider, ISmsOutbox
{
    private const int Capacity = 50;
    private readonly ConcurrentDictionary<string, ConcurrentQueue<SmsOutboxItemDto>> _outbox = new(StringComparer.Ordinal);

    public string Id => "development";
    public string DisplayName => "حالت آزمایشی (بدون ارسال)";
    public string Description => "پیامک ارسال نمی‌شود؛ متن آن در همین کنسول نمایش داده می‌شود. فقط برای توسعه و آزمایش.";
    public bool SendsMessages => false;
    public IReadOnlyList<SmsFieldDto> Fields { get; } = [];

    public Task<SmsSendResult> SendAsync(SmsMessage message, IReadOnlyDictionary<string, string> settings, CancellationToken ct)
    {
        var queue = _outbox.GetOrAdd(message.Tenant, _ => new ConcurrentQueue<SmsOutboxItemDto>());
        queue.Enqueue(new SmsOutboxItemDto(clock.GetUtcNow(), PhoneNumbers.Mask(message.To), message.Text));
        while (queue.Count > Capacity && queue.TryDequeue(out _)) { }
        logger.LogInformation("Development SMS recorded for tenant {Tenant} to {Receptor}", message.Tenant, PhoneNumbers.Mask(message.To));
        return Task.FromResult(new SmsSendResult(true, $"dev-{Guid.NewGuid():N}"[..16]));
    }

    public IReadOnlyList<SmsOutboxItemDto> Recent(string tenant, int max) =>
        _outbox.TryGetValue(tenant, out var queue) ? queue.Reverse().Take(max).ToArray() : [];
}
