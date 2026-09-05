using Company.Identity.PermissionDiscovery;
using Identity.Application;
using Identity.Contracts;
using Identity.Messaging;
using Identity.Messaging.Contracts;
using Microsoft.Extensions.Options;
using System.Reflection;

namespace Identity.Api;

public sealed class PermissionManifestOptions
{
    public const string SectionName = "Identity:PermissionManifest";
    public string ServiceId { get; init; } = "identity-service";
    public string ServiceName { get; init; } = "Identity Service";
    public string Version { get; init; } = "1.0.0";
    public string ManifestVersion { get; init; } = "1";
}

public sealed class PermissionManifestHostedService(
    IIntegrationEventPublisher publisher,
    ISystemClock clock,
    IHostEnvironment environment,
    IOptions<PermissionManifestOptions> options,
    ILogger<PermissionManifestHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var configuration = options.Value;
        var manifest = new PermissionManifestMessage(
            configuration.ServiceId,
            configuration.ServiceName,
            configuration.Version,
            environment.EnvironmentName,
            PermissionDiscovery.Discover(Assembly.GetExecutingAssembly())
                .Select(x => new PermissionMessage(x.Name, x.Description, x.Module))
                .ToArray(),
            configuration.ManifestVersion,
            Guid.NewGuid(),
            clock.UtcNow);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await publisher.PublishAsync(
                    new ServicePermissionManifestPublished(manifest),
                    stoppingToken);
                logger.LogInformation(
                    "Published permission manifest {ManifestVersion} for {ServiceName}.",
                    manifest.ManifestVersion,
                    manifest.ServiceName);
                return;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogWarning(
                    exception,
                    "Permission manifest publication is unavailable; the service remains available and will retry.");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
            }
        }
    }
}
