using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Company.Identity.Abstractions;

namespace Company.Identity.PermissionRegistration;

public sealed class PermissionRegistrationOptions
{
    public required Uri IdentityServer { get; set; }
    public required string ServiceName { get; set; }
    public string ServiceId { get; set; } = string.Empty;
    public string ServiceVersion { get; set; } = "0.0.0";
    public string ManifestVersion { get; set; } = "1";
    public TimeSpan InitialRetryDelay { get; set; } = TimeSpan.FromSeconds(2);
    public int MaximumRetries { get; set; } = 8;

    // Service client credentials, sent through the facade's login proxy — no Keycloak config needed.
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }

    // Assembly to scan for [RequirePermission] attributes. Defaults to the entry assembly.
    internal Assembly? RegistrationAssembly { get; set; }
}

public sealed record PermissionManifest(
    string ServiceId,
    string ServiceVersion,
    string ManifestVersion,
    IReadOnlyCollection<PermissionDescriptor> Permissions,
    string ManifestHash)
{
    public static PermissionManifest Create(PermissionRegistrationOptions options, Assembly assembly)
    {
        var permissions = assembly.GetTypes().SelectMany(type => type
                .GetCustomAttributes<RequirePermissionAttribute>(true)
                .Select(attribute => new PermissionDescriptor(attribute.Name,
                    $"Permission for {type.FullName ?? type.Name}", type.Namespace ?? string.Empty))
                .Concat(type
                    .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance |
                                BindingFlags.Static)
                    .SelectMany(method => method.GetCustomAttributes<RequirePermissionAttribute>(true)
                        .Select(attribute => new PermissionDescriptor(attribute.Name,
                            $"Permission for {method.DeclaringType?.FullName ?? type.Name}.{method.Name}",
                            type.Namespace ?? string.Empty)))))
            .Where(x => !string.IsNullOrWhiteSpace(x.Name)).DistinctBy(x => x.Name, StringComparer.Ordinal)
            .OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
        var serviceId = string.IsNullOrWhiteSpace(options.ServiceId) ? options.ServiceName : options.ServiceId;
        var canonical = JsonSerializer.Serialize(new
        {
            serviceId, serviceVersion = options.ServiceVersion, manifestVersion = options.ManifestVersion, permissions
        });
        var hash = "sha256:" +
                   Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        return new(serviceId, options.ServiceVersion, options.ManifestVersion, permissions, hash);
    }
}