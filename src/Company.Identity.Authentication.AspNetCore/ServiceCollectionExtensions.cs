using Company.Identity.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Company.Identity.Authentication.AspNetCore;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCompanyAuthentication(this IServiceCollection services, Action<IdentityAuthenticationOptions> configure)
    {
        var options = new IdentityAuthenticationOptions();
        configure(options);
        if (string.IsNullOrWhiteSpace(options.Authority)) throw new InvalidOperationException("Identity authority is required.");
        var audiences = options.Audiences.Length > 0 ? options.Audiences : string.IsNullOrWhiteSpace(options.Audience) ? [] : [options.Audience];
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(jwt =>
        {
            jwt.Authority = options.Authority.TrimEnd('/');
            jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;
            jwt.RefreshOnIssuerKeyNotFound = true;
            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true, ValidIssuer = options.Authority.TrimEnd('/'),
                ValidateAudience = audiences.Length > 0, ValidAudiences = audiences,
                ValidateLifetime = true, ValidateIssuerSigningKey = true,
                ClockSkew = options.ClockSkew, ValidAlgorithms = options.ValidAlgorithms
            };
            jwt.Events = new JwtBearerEvents
            {
                OnTokenValidated = context =>
                {
                    if (!options.ValidateTokenType || context.SecurityToken is not System.IdentityModel.Tokens.Jwt.JwtSecurityToken token) return Task.CompletedTask;
                    if (token.Header.TryGetValue("typ", out var value) && value is string type &&
                        !string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(type, "at+jwt", StringComparison.OrdinalIgnoreCase)) context.Fail("Unexpected token type.");
                    return Task.CompletedTask;
                }
            };
        });
        return services;
    }
}
