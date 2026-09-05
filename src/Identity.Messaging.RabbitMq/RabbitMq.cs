using System.Text;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Identity.Messaging;
using Identity.Messaging.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Identity.Messaging.RabbitMq;

public sealed class RabbitMqOptions
{
    public const string SectionName = "Identity:Messaging:RabbitMq";
    public bool Enabled { get; init; }
    public bool ConsumeEnabled { get; init; }
    public string ConnectionString { get; init; } = "amqp://guest:guest@localhost:5672/";
    public string Exchange { get; init; } = "identity.permission-manifests";
    public string Queue { get; init; } = "identity.permission-manifests.identity-service";
    public string RoutingKey { get; init; } = "permission.manifest";
    public string DeadLetterExchange { get; init; } = "identity.permission-manifests.dlx";
    public string RetryExchange { get; init; } = "identity.permission-manifests.retry";
    public int RetryCount { get; init; } = 3;
    public int RetryDelayMilliseconds { get; init; } = 1000;
}

public static class RabbitMqServiceCollectionExtensions
{
    public static IServiceCollection AddIdentityRabbitMq(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RabbitMqOptions>()
            .Bind(configuration.GetSection(RabbitMqOptions.SectionName))
            .Validate(x => !x.Enabled || Uri.TryCreate(x.ConnectionString, UriKind.Absolute, out _), "RabbitMQ connection string must be a valid URI when enabled.")
            .Validate(x => x.RetryCount is >= 0 and <= 20, "RetryCount must be between 0 and 20.")
            .Validate(x => x.RetryDelayMilliseconds is >= 100 and <= 300_000, "RetryDelayMilliseconds must be between 100 and 300000.")
            .ValidateOnStart();
        services.AddSingleton<IIntegrationEventPublisher, RabbitMqIntegrationEventPublisher>();
        if (configuration.GetValue<bool>($"{RabbitMqOptions.SectionName}:ConsumeEnabled"))
            services.AddHostedService<RabbitMqPermissionManifestConsumer>();
        return services;
    }
}

public sealed class RabbitMqIntegrationEventPublisher(
    IOptions<RabbitMqOptions> options,
    ILogger<RabbitMqIntegrationEventPublisher> logger) : IIntegrationEventPublisher
{
    private readonly RabbitMqOptions _options = options.Value;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public async Task PublishAsync<T>(T message, CancellationToken cancellationToken) where T : class
    {
        if (!_options.Enabled)
            return;

        var envelope = message switch
        {
            PermissionManifestEvent value => value,
            ServicePermissionManifestPublished value => ToEnvelope(value.Manifest, PermissionManifestEventTypes.Published),
            ServicePermissionManifestUpdated value => ToEnvelope(value.Manifest, PermissionManifestEventTypes.Updated),
            _ => throw new NotSupportedException($"Unsupported RabbitMQ message type: {typeof(T).FullName}.")
        };

        var factory = new ConnectionFactory
        {
            Uri = new Uri(_options.ConnectionString),
            ClientProvidedName = "identity-service-publisher"
        };
        await using var connection = await factory.CreateConnectionAsync(cancellationToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);
        await RabbitMqTopology.DeclareAsync(channel, _options, cancellationToken);

        var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope, _json));
        var properties = new BasicProperties
        {
            ContentType = "application/json",
            DeliveryMode = DeliveryModes.Persistent,
            MessageId = envelope.EventId.ToString("N"),
            CorrelationId = envelope.CorrelationId.ToString("N"),
            Type = envelope.EventType
        };
        await channel.BasicPublishAsync(_options.Exchange, _options.RoutingKey, true, properties, body, cancellationToken);
        logger.LogInformation("Published permission manifest event {EventId} for service {ServiceName}.", envelope.EventId, envelope.ServiceName);
    }

    private static PermissionManifestEvent ToEnvelope(PermissionManifestMessage message, string eventType) => new(
        Guid.NewGuid(), eventType, 1, message.ServiceId, message.ServiceName, message.Version,
        message.Environment, message.ManifestVersion, message.CorrelationId, message.PublishedAt, message.Permissions);
}

internal static class RabbitMqTopology
{
    public static async Task DeclareAsync(IChannel channel, RabbitMqOptions options, CancellationToken cancellationToken)
    {
        await channel.ExchangeDeclareAsync(options.Exchange, ExchangeType.Topic, durable: true, autoDelete: false, cancellationToken: cancellationToken);
        await channel.ExchangeDeclareAsync(options.DeadLetterExchange, ExchangeType.Direct, durable: true, autoDelete: false, cancellationToken: cancellationToken);
        await channel.ExchangeDeclareAsync(options.RetryExchange, ExchangeType.Direct, durable: true, autoDelete: false, cancellationToken: cancellationToken);
        await channel.QueueDeclareAsync(options.Queue, durable: true, exclusive: false, autoDelete: false,
            arguments: new Dictionary<string, object?>
            {
                ["x-dead-letter-exchange"] = options.DeadLetterExchange,
                ["x-dead-letter-routing-key"] = options.Queue
            }, cancellationToken: cancellationToken);
        await channel.QueueBindAsync(options.Queue, options.Exchange, options.RoutingKey, cancellationToken: cancellationToken);
        await channel.QueueDeclareAsync($"{options.Queue}.retry", durable: true, exclusive: false, autoDelete: false,
            arguments: new Dictionary<string, object?>
            {
                ["x-message-ttl"] = options.RetryDelayMilliseconds,
                ["x-dead-letter-exchange"] = options.Exchange,
                ["x-dead-letter-routing-key"] = options.RoutingKey
            }, cancellationToken: cancellationToken);
        await channel.QueueBindAsync($"{options.Queue}.retry", options.RetryExchange, options.Queue, cancellationToken: cancellationToken);
        await channel.QueueDeclareAsync($"{options.Queue}.dead", durable: true, exclusive: false, autoDelete: false, cancellationToken: cancellationToken);
        await channel.QueueBindAsync($"{options.Queue}.dead", options.DeadLetterExchange, options.Queue, cancellationToken: cancellationToken);
    }
}

public sealed class RabbitMqPermissionManifestConsumer(
    IOptions<RabbitMqOptions> options,
    IServiceScopeFactory scopeFactory,
    ILogger<RabbitMqPermissionManifestConsumer> logger) : BackgroundService
{
    private const string RetryHeader = "x-identity-retry-count";
    private readonly RabbitMqOptions _options = options.Value;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ConsumeConnectionAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "RabbitMQ consumer unavailable; retrying without stopping the service.");
                try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            }
        }
    }

    private async Task ConsumeConnectionAsync(CancellationToken cancellationToken)
    {
        var factory = new ConnectionFactory
        {
            Uri = new Uri(_options.ConnectionString),
            ClientProvidedName = "identity-service-consumer"
        };
        await using var connection = await factory.CreateConnectionAsync(cancellationToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);
        await RabbitMqTopology.DeclareAsync(channel, _options, cancellationToken);
        await channel.BasicQosAsync(0, 1, false, cancellationToken);

        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.ReceivedAsync += async (_, delivery) => await HandleAsync(channel, delivery, cancellationToken);
        await channel.BasicConsumeAsync(_options.Queue, autoAck: false, consumer, cancellationToken);
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private async Task HandleAsync(IChannel channel, BasicDeliverEventArgs delivery, CancellationToken cancellationToken)
    {
        try
        {
            var message = JsonSerializer.Deserialize<PermissionManifestEvent>(delivery.Body.Span, _json);
            if (message is null || message.SchemaVersion != 1 || string.IsNullOrWhiteSpace(message.ServiceId) || string.IsNullOrWhiteSpace(message.ServiceName))
                throw new InvalidDataException("Invalid permission-manifest event.");

            await using var scope = scopeFactory.CreateAsyncScope();
            var synchronizer = scope.ServiceProvider.GetRequiredService<PermissionManifestSynchronizer>();
            await synchronizer.SynchronizeAsync(PermissionManifestEventMapper.ToApplicationManifest(message), cancellationToken);
            await channel.BasicAckAsync(delivery.DeliveryTag, multiple: false, cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
        {
            logger.LogWarning(exception, "Rejecting malformed permission-manifest message {DeliveryTag}.", delivery.DeliveryTag);
            await channel.BasicRejectAsync(delivery.DeliveryTag, requeue: false, cancellationToken);
        }
        catch (Exception exception)
        {
            var retryCount = GetRetryCount(delivery.BasicProperties);
            if (retryCount >= _options.RetryCount)
            {
                logger.LogError(exception, "Permission-manifest processing failed after {RetryCount} retries for {DeliveryTag}; moving to dead letter queue.", retryCount, delivery.DeliveryTag);
                await channel.BasicRejectAsync(delivery.DeliveryTag, requeue: false, cancellationToken);
                return;
            }

            logger.LogWarning(exception, "Permission-manifest processing failed for {DeliveryTag}; scheduling retry {RetryCount}.", delivery.DeliveryTag, retryCount + 1);
            var properties = new BasicProperties
            {
                ContentType = delivery.BasicProperties.ContentType,
                DeliveryMode = DeliveryModes.Persistent,
                MessageId = delivery.BasicProperties.MessageId,
                CorrelationId = delivery.BasicProperties.CorrelationId,
                Type = delivery.BasicProperties.Type,
                Headers = new Dictionary<string, object?> { [RetryHeader] = retryCount + 1 }
            };
            await channel.BasicPublishAsync(_options.RetryExchange, _options.Queue, true, properties, delivery.Body, cancellationToken);
            await channel.BasicAckAsync(delivery.DeliveryTag, multiple: false, cancellationToken);
        }
    }

    private static int GetRetryCount(IReadOnlyBasicProperties properties)
    {
        if (properties.Headers is null || !properties.Headers.TryGetValue(RetryHeader, out var value))
            return 0;
        return value switch
        {
            byte[] bytes when int.TryParse(Encoding.UTF8.GetString(bytes), out var parsed) => parsed,
            int parsed => parsed,
            long parsed => (int)parsed,
            _ => 0
        };
    }
}
