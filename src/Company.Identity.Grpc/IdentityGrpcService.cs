namespace Company.Identity.Grpc;

// Transport contracts intentionally expose normalized facade DTOs only. Interactive
// login, refresh, logout, and session management remain Keycloak-owned.
public sealed class IdentityGrpcService : IdentityService.IdentityServiceBase
{
}
