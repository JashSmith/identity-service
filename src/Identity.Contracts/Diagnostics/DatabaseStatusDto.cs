namespace Identity.Contracts.Diagnostics;

/// <summary>
/// Data transfer object describing the configured database engine status and diagnostics.
/// </summary>
public sealed class DatabaseStatusDto
{
    /// <summary>
    /// Gets or sets the active database provider name (e.g. "postgres", "mssql", "oracle").
    /// </summary>
    public string Provider { get; set; } = "postgres";

    /// <summary>
    /// Gets or sets a value indicating whether the active database is reachable and healthy.
    /// </summary>
    public bool IsHealthy { get; set; }

    /// <summary>
    /// Gets or sets the health status description (e.g. "Online", "Degraded", "Unreachable").
    /// </summary>
    public string Status { get; set; } = "Unknown";

    /// <summary>
    /// Gets or sets the database host name or IP address if parsed from connection string.
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    /// Gets or sets the database port number if parsed from connection string.
    /// </summary>
    public int? Port { get; set; }

    /// <summary>
    /// Gets or sets the target database name or service identifier.
    /// </summary>
    public string? DatabaseName { get; set; }

    /// <summary>
    /// Gets or sets the measured round-trip probe latency in milliseconds.
    /// </summary>
    public double LatencyMs { get; set; }

    /// <summary>
    /// Gets or sets diagnostic details or error message if connection probe failed.
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// Gets or sets the list of database engines supported by the Identity Service.
    /// </summary>
    public string[] SupportedProviders { get; set; } = ["postgres", "mssql", "oracle"];
}
