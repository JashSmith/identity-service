using Identity.Gateway.Bootstrap;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Identity.Gateway.Tests;

/// <summary>
/// Readiness during the Keycloak bootstrap: waiting for Keycloak is Degraded (not an error in the logs),
/// a failing step is Unhealthy, completion is Healthy.
/// </summary>
public sealed class BootstrapHealthTests
{
    [Theory]
    [InlineData(false, "not started", HealthStatus.Degraded)]
    [InlineData(false, "company: running realm-check", HealthStatus.Degraded)]
    [InlineData(false, "company: super-admins failed: keycloak_unavailable", HealthStatus.Unhealthy)]
    [InlineData(true, "completed", HealthStatus.Healthy)]
    public void Bootstrap_state_maps_to_a_health_status(bool completed, string status, HealthStatus expected) =>
        Assert.Equal(expected, KeycloakBootstrapper.Health(completed, status).Status);
}
