namespace Identity.Contracts;

public sealed record LoginRequest(string Username, string Password);

public sealed record RefreshRequest(string RefreshToken);

public sealed record ExternalIdentityLinkRequest(
    string Provider,
    string AuthorizationCode,
    string RedirectUri,
    string CodeVerifier);

public sealed record ExternalLoginRequest(
    string Provider,
    string AuthorizationCode,
    string RedirectUri,
    string CodeVerifier);

public sealed record TokenResponse(string AccessToken, string RefreshToken, DateTimeOffset ExpiresAt, Guid SessionId);

public sealed record UserResponse(
    Guid UserId,
    string Username,
    string DisplayName,
    IReadOnlyCollection<string> Roles,
    IReadOnlyCollection<string> Permissions,
    Guid? SessionId);

public sealed record ProblemResponse(string Code, string Message, string CorrelationId);

public sealed record PermissionManifestMessage(
    string ServiceId,
    string ServiceName,
    string Version,
    string Environment,
    IReadOnlyCollection<PermissionMessage> Permissions,
    string ManifestVersion,
    Guid CorrelationId,
    DateTimeOffset PublishedAt);

public sealed record PermissionMessage(string Name, string Description, string Module);