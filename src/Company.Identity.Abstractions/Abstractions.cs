namespace Company.Identity.Abstractions;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true, Inherited = true)]
public sealed class RequirePermissionAttribute(string name) : Attribute
{
    public string Name { get; } = string.IsNullOrWhiteSpace(name)
        ? throw new ArgumentException("Permission is required.", nameof(name))
        : name;
}

public sealed record PermissionDescriptor(string Name, string Description, string Module = "");

public interface IPermissionDefinitionSource
{
    IReadOnlyCollection<PermissionDescriptor> GetPermissions();
}