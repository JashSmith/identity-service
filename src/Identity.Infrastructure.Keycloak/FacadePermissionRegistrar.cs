using System.Reflection;
using Company.Identity.Abstractions;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Scans the host assembly for [RequirePermission] and registers the manifest via
/// IPermissionRegistry — the same code path used by external services, so mirroring
/// and idempotency semantics are preserved. The facade calls this at startup so
/// management permissions such as identity.users.manage exist without a DB migration.
/// </summary>
public sealed class FacadePermissionRegistrar(
    IPermissionRegistry registry,
    ILogger<FacadePermissionRegistrar> logger)
{
    public const string ServiceId = "identity-facade";

    public static string ServiceVersion
    {
        get
        {
            var asm = System.Reflection.Assembly.GetEntryAssembly() ?? typeof(FacadePermissionRegistrar).Assembly;
            return asm.GetName().Version?.ToString(3) ?? "1.0.0";
        }
    }

    public async Task<string?> RegisterAsync(Assembly assembly, CancellationToken ct)
    {
        try
        {
            var sourcePerms = new List<PermissionDefinitionDto>();
            foreach (var type in assembly.GetTypes())
            {
                if (!typeof(Company.Identity.Abstractions.IPermissionDefinitionSource).IsAssignableFrom(type) || type.IsAbstract || type.IsInterface) continue;
                try
                {
                    var inst = (Company.Identity.Abstractions.IPermissionDefinitionSource)Activator.CreateInstance(type)!;
                    foreach (var d in inst.GetPermissions())
                        sourcePerms.Add(new PermissionDefinitionDto(d.Name, d.Description));
                }
                catch { }
            }

            var perms = assembly.GetTypes().SelectMany(t => t
                    .GetCustomAttributes<RequirePermissionAttribute>(inherit: true)
                    .Select(a => new PermissionDefinitionDto(a.Name, $"Permission for {t.FullName ?? t.Name}"))
                    .Concat(t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
                        .SelectMany(m => m.GetCustomAttributes<RequirePermissionAttribute>(inherit: true)
                            .Select(a => new PermissionDefinitionDto(a.Name, $"Permission for {(m.DeclaringType?.FullName ?? t.Name)}.{m.Name}")))))
                .Where(p => !string.IsNullOrWhiteSpace(p.Name))
                .Concat(sourcePerms)
                .DistinctBy(p => p.Name, StringComparer.Ordinal)
                .OrderBy(p => p.Name, StringComparer.Ordinal)
                .ToArray();

            if (perms.Length == 0) return null;

            var canonical = System.Text.Json.JsonSerializer.Serialize(new
            {
                serviceId = ServiceId,
                serviceVersion = ServiceVersion,
                manifestVersion = "1",
                permissions = perms,
            });
            var hash = "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            var manifest = new PermissionManifestRequest(ServiceId, ServiceVersion, "1", perms, hash);
            var res = await registry.RegisterAsync(manifest, ServiceId, ct);
            if (res.Accepted)
                logger.LogInformation("Seeded {Count} facade permissions under {ServiceId}", perms.Length, ServiceId);
            else
                logger.LogWarning("Facade permission seed not accepted for {ServiceId}", ServiceId);
            return hash;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to seed facade permissions — startup continues");
            return null;
        }
    }
}
