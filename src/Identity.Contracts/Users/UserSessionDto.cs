namespace Identity.Contracts;

/// <summary>
/// Data transfer object describing an active user session in Keycloak.
/// </summary>
/// <param name="Id">The unique session identifier.</param>
/// <param name="Username">The username associated with this session.</param>
/// <param name="UserId">The Keycloak user identifier.</param>
/// <param name="IpAddress">The client IP address associated with the session.</param>
/// <param name="Start">The UTC timestamp when the session began.</param>
/// <param name="LastAccess">The UTC timestamp when the session was last refreshed/accessed.</param>
/// <param name="Clients">The dictionary of client IDs and names attached to the session.</param>
public sealed record UserSessionDto(
    string Id,
    string Username,
    string UserId,
    string? IpAddress,
    DateTimeOffset Start,
    DateTimeOffset LastAccess,
    IReadOnlyDictionary<string, string> Clients);
