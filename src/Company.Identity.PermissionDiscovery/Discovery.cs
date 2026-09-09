using System.Reflection;
using Company.Identity.Abstractions;

namespace Company.Identity.PermissionDiscovery;

public static class PermissionDiscovery
{
    public static IReadOnlyCollection<PermissionDescriptor> Discover(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        return assembly.GetTypes().SelectMany(type => type.GetCustomAttributes<RequirePermissionAttribute>(true)
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
    }
}