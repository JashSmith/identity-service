using System.Diagnostics;
using System.Net.Sockets;
using Identity.Application;
using Identity.Contracts.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Database;

/// <summary>
/// Probes and reports connectivity diagnostics for configured database engines (PostgreSQL, SQL Server, Oracle).
/// </summary>
public sealed class DatabaseDiagnosticsService : IDatabaseDiagnosticsService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<DatabaseDiagnosticsService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DatabaseDiagnosticsService"/> class.
    /// </summary>
    /// <param name="configuration">Application configuration containing database connection settings.</param>
    /// <param name="logger">The logger instance.</param>
    public DatabaseDiagnosticsService(IConfiguration configuration, ILogger<DatabaseDiagnosticsService> logger)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<DatabaseStatusDto> CheckStatusAsync(CancellationToken cancellationToken = default)
    {
        var rawProvider = _configuration["Database:Provider"]
                          ?? Environment.GetEnvironmentVariable("DB_PROVIDER")
                          ?? "postgres";

        var provider = NormalizeProvider(rawProvider);
        var connectionString = _configuration[$"Database:ConnectionStrings:{provider}"]
                               ?? _configuration.GetConnectionString(provider)
                               ?? string.Empty;

        var (host, port, dbName) = ParseEndpoint(provider, connectionString);

        var dto = new DatabaseStatusDto
        {
            Provider = provider,
            Host = host,
            Port = port,
            DatabaseName = dbName,
            SupportedProviders = ["postgres", "mssql", "oracle"]
        };

        if (string.IsNullOrWhiteSpace(host) || port <= 0)
        {
            dto.IsHealthy = false;
            dto.Status = "Misconfigured";
            dto.Details = $"Unable to parse host and port for provider '{provider}'.";
            return dto;
        }

        var sw = Stopwatch.StartNew();
        try
        {
            using var tcpClient = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));

            await tcpClient.ConnectAsync(host, port, cts.Token);
            sw.Stop();

            dto.IsHealthy = true;
            dto.Status = "Online";
            dto.LatencyMs = Math.Round(sw.Elapsed.TotalMilliseconds, 2);
            dto.Details = $"Successfully reached {provider} at {host}:{port}";
        }
        catch (Exception ex)
        {
            sw.Stop();
            dto.IsHealthy = false;
            dto.Status = "Unreachable";
            dto.LatencyMs = Math.Round(sw.Elapsed.TotalMilliseconds, 2);
            dto.Details = ex.Message;
            _logger.LogWarning("Database health check probe for provider {Provider} ({Host}:{Port}) failed: {Message}",
                provider, host, port, ex.Message);
        }

        return dto;
    }

    private static string NormalizeProvider(string provider)
    {
        var p = provider.Trim().ToLowerInvariant();
        return p switch
        {
            "mssql" or "sqlserver" or "mssql-db" => "mssql",
            "oracle" or "oracle-db" => "oracle",
            _ => "postgres"
        };
    }

    private static (string host, int port, string databaseName) ParseEndpoint(string provider, string connectionString)
    {
        var host = "localhost";
        var port = provider switch
        {
            "mssql" => 1433,
            "oracle" => 1521,
            _ => 5432
        };
        var dbName = "keycloak";

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return (host, port, dbName);
        }

        var parts = connectionString.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var kv = part.Split('=', 2);
            if (kv.Length != 2) continue;
            var key = kv[0].Trim().ToLowerInvariant();
            var val = kv[1].Trim();

            switch (key)
            {
                case "host" or "server" or "data source":
                    ParseHostAndPort(val, ref host, ref port);
                    break;
                case "port":
                    if (int.TryParse(val, out var p)) port = p;
                    break;
                case "database" or "initial catalog":
                    dbName = val;
                    break;
            }
        }

        return (host, port, dbName);
    }

    private static void ParseHostAndPort(string source, ref string host, ref int port)
    {
        // Format: host,port (MSSQL style)
        if (source.Contains(','))
        {
            var sub = source.Split(',', 2);
            host = sub[0].Trim();
            if (int.TryParse(sub[1].Trim(), out var p)) port = p;
            return;
        }

        // Format: host:port/service (Oracle or standard style)
        if (source.Contains(':'))
        {
            var sub = source.Split(':', 2);
            host = sub[0].Trim();
            var remainder = sub[1];
            if (remainder.Contains('/'))
            {
                var slash = remainder.Split('/', 2);
                if (int.TryParse(slash[0].Trim(), out var p)) port = p;
            }
            else if (int.TryParse(remainder.Trim(), out var p))
            {
                port = p;
            }
            return;
        }

        host = source.Trim();
    }
}
