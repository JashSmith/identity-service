using System.Reflection;
using Company.Identity.Abstractions;
namespace Company.Identity.PermissionDiscovery;

public static class PermissionDiscovery
{
    public static IReadOnlyCollection<PermissionDescriptor> Discover(Assembly assembly) =>
        assembly.GetTypes().SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            .SelectMany(m => m.GetCustomAttributes<RequirePermissionAttribute>(true).Select(a => new PermissionDescriptor(a.Name, $"Permission for {m.DeclaringType?.FullName}.{m.Name}")))
            .DistinctBy(x => x.Name, StringComparer.Ordinal).ToArray();
}
