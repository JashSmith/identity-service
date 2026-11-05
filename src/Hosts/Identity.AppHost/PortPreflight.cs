using System.Net.NetworkInformation;

/// <summary>
/// The stack uses fixed ports (Keycloak's issuer and the console's redirect URIs depend on them). When another
/// Identity stack already holds them (a second <c>dotnet run</c>, or the E2E tests, which start their own stack on
/// the same ports and the same persistent PostgreSQL container), Aspire's orchestrator only fails after a two-minute
/// timeout with no hint. This check fails at once and says which port is taken and what to do.
/// </summary>
internal static class PortPreflight
{
    public static void EnsureFree(params (int Port, string Resource)[] ports)
    {
        var listening = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(e => e.Port).ToHashSet();
        var busy = ports.Where(p => listening.Contains(p.Port)).ToArray();
        if (busy.Length == 0) return;

        var list = string.Join(", ", busy.Select(p => $"{p.Port} ({p.Resource})"));
        var message =
            $"Port(s) {list} already in use. Another Identity stack is probably running: a second AppHost or the E2E tests " +
            "(IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests), which use the same ports. Stop it first (Ctrl+C in its window, " +
            "or: Get-Process Identity.Gateway,Identity.Admin,Identity.AppHost | Stop-Process), then remove its leftover " +
            "keycloak-*/redis-* containers. To see who holds a port: netstat -ano | findstr :" + busy[0].Port;
        Console.Error.WriteLine(message);
        // An exception rather than Environment.Exit: the E2E tests run this entry point inside the test process.
        throw new InvalidOperationException(message);
    }
}
