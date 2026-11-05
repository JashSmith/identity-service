namespace Identity.Domain.Entities;

/// <summary>
/// Represents an active user session within Keycloak, used to identify online status.
/// </summary>
public sealed class UserSession
{
    /// <summary>
    /// Gets or sets the unique session identifier assigned by Keycloak.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the username associated with this session.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user ID associated with this session.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the IP address from which the session was established.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the session was created.
    /// </summary>
    public DateTimeOffset StartTime { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the session was last active.
    /// </summary>
    public DateTimeOffset LastAccessTime { get; set; }

    /// <summary>
    /// Gets or sets the dictionary of clients associated with this session.
    /// </summary>
    public IReadOnlyDictionary<string, string> Clients { get; set; } = new Dictionary<string, string>();
}
