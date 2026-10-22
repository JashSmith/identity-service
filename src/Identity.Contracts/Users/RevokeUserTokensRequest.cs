namespace Identity.Contracts;

/// <summary>
/// Request payload to revoke tokens and sessions for a user.
/// </summary>
/// <param name="Reason">Optional administrative reason for revoking the tokens.</param>
public sealed record RevokeUserTokensRequest(string? Reason = null);

/// <summary>
/// Response payload indicating the result of a token and session revocation.
/// </summary>
/// <param name="UserId">The identifier of the user whose tokens/sessions were revoked.</param>
/// <param name="Success">Indicates whether Keycloak sessions were successfully terminated and cache invalidated.</param>
/// <param name="Message">Descriptive message of the operation.</param>
/// <param name="RevokedAt">The UTC timestamp when revocation occurred.</param>
public sealed record RevokeUserTokensResponse(
    string UserId,
    bool Success,
    string Message,
    DateTimeOffset RevokedAt);
