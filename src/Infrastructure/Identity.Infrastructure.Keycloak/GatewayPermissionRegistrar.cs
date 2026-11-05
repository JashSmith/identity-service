using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Avash.Identity.Abstractions;
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Contracts;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Registers the gateway's own permission manifest (from <see cref="IPermissionDefinitionSource"/> types and
/// <c>[RequirePermission]</c> attributes in the host assembly) through the same catalog path external
/// services use, so the gateway's management permissions exist in Keycloak on every start.
/// </summary>
public sealed class GatewayPermissionRegistrar(IPermissionCatalog catalog)
{
    public const string ServiceId = "identity-gateway";

    public async Task<Result> RegisterAsync(Assembly assembly, CancellationToken ct)
    {
        var fromSources = assembly.GetTypes()
            .Where(t => typeof(IPermissionDefinitionSource).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface)
            .SelectMany(t => ((IPermissionDefinitionSource)Activator.CreateInstance(t)!).GetPermissions())
            .Select(p => new PermissionDefinitionDto(p.Name, p.Description));
        var fromAttributes = assembly.GetTypes()
            .SelectMany(t => t.GetCustomAttributes<RequirePermissionAttribute>(inherit: true)
                .Concat(t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
                    .SelectMany(m => m.GetCustomAttributes<RequirePermissionAttribute>(inherit: true))))
            .Select(a => new PermissionDefinitionDto(a.Name, $"Permission {a.Name}"));

        var permissions = fromSources.Concat(fromAttributes)
            .DistinctBy(p => p.Name, StringComparer.Ordinal)
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToArray();
        if (permissions.Length == 0) return Result.Success();

        var version = assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        var canonical = JsonSerializer.Serialize(new { serviceId = ServiceId, permissions });
        var hash = "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        var registered = await catalog.RegisterManifestAsync(ServiceId,
            new PermissionManifestRequest(ServiceId, version, "1", permissions, hash), ct);
        return registered.IsSuccess ? Result.Success() : registered.Error!;
    }
}
