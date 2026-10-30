namespace Identity.Contracts;

/// <summary>
/// A permission of the catalog. <see cref="Name"/> is the full name carried in tokens:
/// <c>{application}:{module}:{resource}:{action}</c>, e.g. <c>order-service:Sales:Invoice:Read</c>.
/// </summary>
/// <param name="Source">"manifest" when registered by the owning service, "manual" when created by an admin.</param>
public sealed record CatalogPermissionDto(
    string Name,
    string Application,
    string Module,
    string Resource,
    string Action,
    string? DisplayName,
    string? Description,
    string Source,
    bool Deprecated);

/// <summary>The catalog as a tree: application → module → resource → actions (for "select all" at every level).</summary>
public sealed record PermissionTreeDto(IReadOnlyCollection<PermissionTreeApplication> Applications);

public sealed record PermissionTreeApplication(string Application, string DisplayName, IReadOnlyCollection<PermissionTreeModule> Modules);

public sealed record PermissionTreeModule(string Module, IReadOnlyCollection<PermissionTreeResource> Resources);

public sealed record PermissionTreeResource(string Resource, IReadOnlyCollection<CatalogPermissionDto> Actions);

/// <summary>Creates a permission manually; <see cref="Name"/> is the local name <c>Module:Resource:Action</c>.</summary>
public sealed record CreateCatalogPermissionRequest(string Name, string? DisplayName, string? Description);

/// <summary>Changes the given fields; null keeps the current value.</summary>
public sealed record UpdateCatalogPermissionRequest(string? DisplayName, string? Description, bool? Deprecated);
