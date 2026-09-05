using Company.Identity.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Company.Identity.Authentication.AspNetCore;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCompanyAuthentication(this IServiceCollection services, IdentityAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(jwt =>
        {
            jwt.Authority = options.Authority;
            jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;
            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = options.Audiences.Length > 0,
                ValidAudiences = options.Audiences,
                ValidateLifetime = true,
                ClockSkew = options.ClockSkew,
                IssuerSigningKey = options.SigningKey,
                IssuerSigningKeys = options.SigningKeys.Count > 0 ? options.SigningKeys : null,
                ValidateIssuerSigningKey = options.SigningKey is not null || options.SigningKeys.Count > 0,
                ValidIssuer = options.SigningKey is not null || options.SigningKeys.Count > 0 ? options.Authority : null
            };
        });
        return services;
    }
}
