using Identity.Contracts.Diagnostics;

namespace Identity.Application;

/// <summary>
/// Service abstraction for checking database connectivity and diagnostics across supported engines (PostgreSQL, MSSQL, Oracle).
/// </summary>
public interface IDatabaseDiagnosticsService
{
    /// <summary>
    /// Checks connectivity to the currently configured database engine and returns diagnostics.
    /// </summary>
    /// <param name="cancellationToken">A token to observe for cancellation requests.</param>
    /// <returns>A task returning the current database status and diagnostics.</returns>
    Task<DatabaseStatusDto> CheckStatusAsync(CancellationToken cancellationToken = default);
}
