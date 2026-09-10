using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Company.Identity.PermissionRegistration;

/// <summary>
/// Background service that discovers <c>[RequirePermission]</c> attributes from an assembly,
/// builds a manifest and registers it with the Identity Facade using exponential backoff.
/// Catches all exceptions — registration failure never blocks application startup.
/// </summary>
internal sealed class PermissionRegistrationHostedService(
    IPermissionRegistrationClient client,
    IOptions<PermissionRegistrationOptions> options,
    ILogger<PermissionRegistrationHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var opts = options.Value;
        var assembly = opts.RegistrationAssembly ?? Assembly.GetEntryAssembly();
        if (assembly is null)
        {
            logger.LogDebug("No assembly available for permission registration — skipping");
            return;
        }

        var manifest = PermissionManifest.Create(opts, assembly);

        for (var attempt = 0; attempt <= opts.MaximumRetries; attempt++)
        {
            if (stoppingToken.IsCancellationRequested) return;
            try
            {
                var response = await client.RegisterAsync(manifest, stoppingToken);
                if (response is { Accepted: true })
                {
                    logger.LogInformation(
                        "Permission manifest registered for {ServiceId} v{Version} " +
                        "({PermissionCount} permissions, attempt {Attempt})",
                        manifest.ServiceId, manifest.ServiceVersion, manifest.Permissions.Count, attempt + 1);
                    return;
                }

                logger.LogWarning("Permission registration not accepted for {ServiceId} (attempt {Attempt})",
                    manifest.ServiceId, attempt + 1);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Permission registration failed for {ServiceId} (attempt {Attempt})",
                    manifest.ServiceId, attempt + 1);
            }

            if (attempt < opts.MaximumRetries)
            {
                var delay = opts.InitialRetryDelay * Math.Pow(2, Math.Min(attempt, 5));
                try
                {
                    await Task.Delay(delay, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        logger.LogWarning(
            "Permission registration incomplete for {ServiceId} after {MaxRetries} attempts — " +
            "the application continues without registered permissions",
            manifest.ServiceId, opts.MaximumRetries);
    }
}

/// <summary>
/// Registers the permission discovery + registration pipeline: scans for
/// <c>[RequirePermission]</c> attributes at startup and pushes the manifest to the
/// Identity Facade in the background. Failure never prevents app start.
/// </summary>
public static class PermissionRegistrationExtensions
{
    /// <summary>
    /// Registers the permission registration background service. Scans the entry assembly
    /// (or <paramref name="assembly"/> when provided) for <c>[RequirePermission]</c> attributes.
    /// </summary>
    public static IServiceCollection AddPermissionRegistration(
        this IServiceCollection services,
        Action<PermissionRegistrationOptions> configure)
        => services.AddPermissionRegistration(null, configure);

    /// <inheritdoc cref="AddPermissionRegistration(IServiceCollection,Action{PermissionRegistrationOptions})"/>
    /// <param name="assembly">Explicit assembly to scan; defaults to the entry assembly.</param>
    public static IServiceCollection AddPermissionRegistration(
        this IServiceCollection services,
        Assembly? assembly,
        Action<PermissionRegistrationOptions> configure)
    {
        services.Configure<PermissionRegistrationOptions>(o =>
        {
            configure(o);
            if (assembly is not null) o.RegistrationAssembly = assembly;
        });

        services.AddHttpClient<IPermissionRegistrationClient, PermissionRegistrationClient>();
        services.AddHostedService<PermissionRegistrationHostedService>();
        return services;
    }
}
