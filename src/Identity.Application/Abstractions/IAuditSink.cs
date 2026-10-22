using Identity.Domain;

namespace Identity.Application;

/// <summary>
/// Sink interface for recording auditable events (user creation, role modifications, logins, revokes).
/// </summary>
public interface IAuditSink
{
    /// <summary>
    /// Records a non-secret audit event asynchronously.
    /// </summary>
    /// <param name="auditEvent">The audit event to record.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken);
}
