namespace Identity.Contracts;

public sealed record AccessTokenResponse(
    string AccessToken,
    string? RefreshToken,
    int ExpiresIn,
    string TokenType = "Bearer");

public sealed record UserDto(
    string Id,
    string Username,
    string? DisplayName,
    bool Enabled,
    IReadOnlyDictionary<string, string[]> Attributes);

public sealed record RoleDto(string Id, string Name, string? Description, string? ClientId, bool Composite);

public sealed record PermissionDto(
    string Name,
    string Description,
    string ServiceId,
    string ServiceVersion,
    bool Deprecated,
    string? KeycloakRoleId = null);

public sealed record PagedResponse<T>(IReadOnlyCollection<T> Items, int Page, int PageSize, int? Total = null);

public sealed record PermissionManifestRequest(
    string ServiceId,
    string ServiceVersion,
    string ManifestVersion,
    IReadOnlyCollection<PermissionDefinitionDto> Permissions,
    string ManifestHash,
    string? IdempotencyKey = null);

public sealed record PermissionDefinitionDto(string Name, string Description);

public sealed record ManifestRegistrationResponse(
    string ServiceId,
    string ManifestVersion,
    string ManifestHash,
    bool Accepted,
    IReadOnlyCollection<string> DeprecatedPermissions);

public sealed record ExternalIdentityValidationResult(
    string Provider,
    string Subject,
    IReadOnlyDictionary<string, string> AllowlistedAttributes,
    IReadOnlyCollection<string> ExternalRoles,
    DateTimeOffset ValidatedAt);

public sealed record OrganizationTokenRequest(string ExternalToken);

public sealed record ProblemResponse(string Code, string Message, string CorrelationId);