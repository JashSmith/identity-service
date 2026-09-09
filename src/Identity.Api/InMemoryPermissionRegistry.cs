using System.Collections.Concurrent;
using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

/// <summary>
/// In-memory permission catalog that satisfies <see cref="IPermissionRegistry"/> without
/// requiring the facade metadata DB to be available at startup. Missing permissions are
/// soft-deprecated, never deleted — matching the contract expected of an EF-backed store.
/// Backed by a concurrent dictionary so it works in single-node and test hosts.
/// </summary>
public sealed class InMemoryPermissionRegistry : IPermissionRegistry
{
    private readonly ConcurrentDictionary<string, PermissionDto> _perms = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (string Version, string Hash)> _manifests = new(StringComparer.Ordinal);

    public Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest, string authenticatedServiceId, CancellationToken ct)
    {
        var incoming = manifest.Permissions.Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        var already = _perms.Values.Where(p => p.ServiceId == manifest.ServiceId).ToList();
        var deprecated = already.Where(p => !incoming.Contains(p.Name)).Select(p => p.Name).ToList();
        foreach (var name in deprecated)
            if (_perms.TryGetValue(name, out var cur))
                _perms[name] = cur with { Deprecated = true };
        foreach (var d in manifest.Permissions)
        {
            _perms.AddOrUpdate(d.Name,
                _ => new PermissionDto(d.Name, d.Description, manifest.ServiceId, manifest.ManifestVersion, false),
                (_, cur) => cur with { Description = d.Description, ServiceVersion = manifest.ManifestVersion, Deprecated = false });
        }
        _manifests[manifest.ServiceId] = (manifest.ManifestVersion, manifest.ManifestHash);
        return Task.FromResult(new ManifestRegistrationResponse(manifest.ServiceId, manifest.ManifestVersion, manifest.ManifestHash, true, deprecated));
    }

    public Task<IReadOnlyCollection<PermissionDto>> GetPermissionsAsync(string? serviceId, bool includeDeprecated, CancellationToken ct)
    {
        IEnumerable<PermissionDto> q = _perms.Values;
        if (!string.IsNullOrWhiteSpace(serviceId)) q = q.Where(p => p.ServiceId == serviceId);
        if (!includeDeprecated) q = q.Where(p => !p.Deprecated);
        return Task.FromResult<IReadOnlyCollection<PermissionDto>>(q.ToList());
    }
}
