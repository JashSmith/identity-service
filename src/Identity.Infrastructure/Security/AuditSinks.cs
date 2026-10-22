using Identity.Application;
using Identity.Domain;

namespace Identity.Infrastructure;

/// <summary>
/// Default sink that redacts detail values before delegating. Registration, provisioning,
/// linking and permission changes are recorded here; passwords, raw tokens, private keys and
/// secrets are never accepted.
/// </summary>
public sealed class RedactingAuditSink(IAuditSink inner) : IAuditSink
{
    /// <summary>
    /// Records a redacted audit event to the inner sink.
    /// </summary>
    /// <param name="auditEvent">The original audit event.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        var safe = new AuditEvent(
            SecretRedaction.Redact(auditEvent.Actor),
            auditEvent.Action,
            SecretRedaction.Redact(auditEvent.Target),
            auditEvent.OccurredAt,
            SecretRedaction.Redact(auditEvent.Details));
        return inner.RecordAsync(safe, cancellationToken);
    }
}

/// <summary>
/// No-op implementation of <see cref="IAuditSink"/> used when no external audit storage is provisioned.
/// </summary>
public sealed class NoopAuditSink : IAuditSink
{
    /// <summary>
    /// No-op record method.
    /// </summary>
    /// <param name="auditEvent">The audit event.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
