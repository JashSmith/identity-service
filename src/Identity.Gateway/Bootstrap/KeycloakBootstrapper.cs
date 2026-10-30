using Identity.Application;
using Identity.Gateway.Tenancy;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Identity.Gateway.Bootstrap;

/// <summary>
/// One step of preparing Keycloak for the gateway (scope registry, claim mappers, gateway permissions,
/// the super-admins group). Steps must be idempotent: they run on every start and are retried.
/// </summary>
public sealed record BootstrapStep(string Name, Func<IServiceProvider, CancellationToken, Task<Result>> Run);

/// <summary>
/// Runs the bootstrap steps in order for every tenant realm after startup and retries a failed step with exponential backoff
/// until it succeeds, logging every failure. Until all steps have succeeded the health check reports
/// Unhealthy, so dependants (and orchestrators) wait for a gateway that is actually usable instead of
/// one that silently started without its super-admins group or token mappers.
/// </summary>
public sealed class KeycloakBootstrapper(
    IServiceScopeFactory scopes,
    IEnumerable<BootstrapStep> steps,
    TenantRegistry tenants,
    TimeProvider time,
    ILogger<KeycloakBootstrapper> logger) : BackgroundService, IHealthCheck
{
    private static readonly TimeSpan FirstRetryDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(60);

    private volatile bool _completed;
    private volatile string _status = "not started";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        foreach (var tenant in tenants.All)
        {
            using var realm = KeycloakTenant.Use(tenants.KeycloakOptions(tenant));
            foreach (var step in steps)
            {
                var delay = FirstRetryDelay;
                while (true)
                {
                    _status = $"{tenant.Id}: running {step.Name}";
                    var result = await RunAsync(step, stoppingToken);
                    if (result.IsSuccess)
                    {
                        logger.LogInformation("Keycloak bootstrap step {Step} completed for tenant {Tenant}", step.Name, tenant.Id);
                        break;
                    }

                    _status = $"{tenant.Id}: {step.Name} failed: {result.Error!.Code}";
                    logger.LogWarning("Keycloak bootstrap step {Step} failed for tenant {Tenant} ({Code}: {Message}); retrying in {Delay}",
                        step.Name, tenant.Id, result.Error.Code, result.Error.Message, delay);
                    await Task.Delay(delay, time, stoppingToken);
                    delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, MaxRetryDelay.Ticks));
                }
            }
        }

        _completed = true;
        _status = "completed";
        logger.LogInformation("Keycloak bootstrap completed");
    }

    private async Task<Result> RunAsync(BootstrapStep step, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        try
        {
            return await step.Run(scope.ServiceProvider, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Keycloak bootstrap step {Step} threw", step.Name);
            return Error.Unexpected("bootstrap.step_failed", $"Bootstrap step '{step.Name}' threw {ex.GetType().Name}.");
        }
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(_completed
            ? HealthCheckResult.Healthy("Keycloak bootstrap completed.")
            : HealthCheckResult.Unhealthy($"Keycloak bootstrap pending ({_status})."));
}
