using Microsoft.IdentityModel.Tokens;

namespace Company.Identity.Authentication;

public sealed class IdentityAuthenticationOptions
{
    public required string Authority { get; init; }
    public string[] Audiences { get; init; } = [];
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(1);
    public bool RequireHttpsMetadata { get; init; } = true;
    public SecurityKey? SigningKey { get; init; }
    public IReadOnlyCollection<SecurityKey> SigningKeys { get; init; } = [];
}
