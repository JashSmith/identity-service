using Identity.Contracts;

namespace Identity.Admin.Services;

/// <summary>Roles, scopes and scope value catalogs used by the assignment editors.</summary>
public sealed record AccessLookups(
    IReadOnlyCollection<BusinessRoleDto> Roles,
    IReadOnlyCollection<ScopeDefinitionView> Scopes,
    IReadOnlyDictionary<string, IReadOnlyCollection<ScopeValueDto>> Values)
{
    public static readonly AccessLookups Empty = new([], [], new Dictionary<string, IReadOnlyCollection<ScopeValueDto>>());

    public static async Task<AccessLookups> LoadAsync(GatewayApi api)
    {
        var roles = await api.GetAsync<List<BusinessRoleDto>>("api/identity/business-roles");
        var scopes = await api.GetAsync<List<ScopeDefinitionView>>("api/identity/scopes");
        var values = new Dictionary<string, IReadOnlyCollection<ScopeValueDto>>(StringComparer.Ordinal);
        foreach (var scope in scopes.Where(s => s.IsActive))
            values[scope.Key] = await api.GetAsync<List<ScopeValueDto>>($"api/identity/scopes/{Uri.EscapeDataString(scope.Key)}/values");
        return new AccessLookups(roles, scopes, values);
    }
}
