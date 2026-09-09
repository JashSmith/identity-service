namespace Company.Identity.Authentication;

public sealed class IdentityAuthenticationOptions
{
    public string Authority { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string[] Audiences { get; set; } = [];
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(1);
    public bool RequireHttpsMetadata { get; set; } = true;
    public string[] ValidAlgorithms { get; set; } = ["RS256"];
    public bool ValidateTokenType { get; set; } = true;
}