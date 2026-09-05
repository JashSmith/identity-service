using System.Reflection;
using Company.Identity.Abstractions;

namespace Company.Identity.PermissionDiscovery;

public static class PermissionDiscovery
{
    public static IReadOnlyCollection<PermissionDescriptor> Discover(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        var descriptors = new List<PermissionDescriptor>();
        foreach (var type in GetLoadableTypes(assembly))
        {
            var typePermissions = type
                .GetCustomAttributes<RequirePermissionAttribute>(inherit: true)
                .Select(attribute => new PermissionDescriptor(
                    attribute.Name,
                    $"Permission for {type.FullName ?? type.Name}",
                    type.Namespace ?? string.Empty));
            descriptors.AddRange(typePermissions);

            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            {
                var methodPermissions = method
                    .GetCustomAttributes<RequirePermissionAttribute>(inherit: true)
                    .Select(attribute => new PermissionDescriptor(
                        attribute.Name,
                        $"Permission for {method.DeclaringType?.FullName ?? type.Name}.{method.Name}",
                        type.Namespace ?? string.Empty));
                descriptors.AddRange(methodPermissions);
            }
        }

        return descriptors
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .DistinctBy(x => x.Name, StringComparer.Ordinal)
            .OrderBy(x => x.Name, StringComparer.Ordinal)
            .ToArray();
    }

    private static IEnumerable<Type> GetLoadableTypes(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException exception)
        {
            return exception.Types.Where(x => x is not null)!;
        }
    }
}
