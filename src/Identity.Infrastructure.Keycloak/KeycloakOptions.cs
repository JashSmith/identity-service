namespace Identity.Infrastructure.Keycloak;

public sealed class KeycloakOptions
{
    public string BaseUrl { get; set; } = "http://localhost:8080";
    public string Realm { get; set; } = "company";
    public string AdminClientId { get; set; } = "admin-cli";
    public string AdminClientSecret { get; set; } = "";
    public string AdminUsername { get; set; } = "";
    public string AdminPassword { get; set; } = "";
}