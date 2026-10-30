namespace Identity.Infrastructure.Keycloak;

public sealed class KeycloakOptions
{
    public string BaseUrl { get; set; } = "http://localhost:8080";
    public string Realm { get; set; } = "company";

    /// <summary>Confidential client in <see cref="Realm"/> whose service account calls the Admin REST API.</summary>
    public string AdminClientId { get; set; } = "identity-gateway-admin";

    public string AdminClientSecret { get; set; } = "";
}