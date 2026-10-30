using Identity.Contracts;

namespace Identity.Application.Scope;

public sealed class ScopeAssignmentValidator(IScopeDefinitionLookup lookup, IScopeValueValidatorRegistry validators)
{
    /// <summary>
    /// Field errors keyed like "assignments[0].scopes.region"; empty when valid. Fails when the registry or
    /// role store cannot be read, so unchecked scopes are never accepted.
    /// </summary>
    public async Task<Result<Dictionary<string, string[]>>> ValidateAsync(IEnumerable<ScopedRoleAssignmentDto> assignments, IBusinessRoleStore roles, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        int idx = 0;
        foreach (var a in assignments)
        {
            if (!await roles.ExistsAsync(a.Role, ct)) Add(errors, $"assignments[{idx}].role", $"Role '{a.Role}' does not exist.");
            foreach (var kv in a.Scopes)
            {
                var scopeKey = kv.Key;
                var exists = await lookup.ExistsActiveAsync(scopeKey, ct);
                if (!exists.IsSuccess) return exists.Error!;
                if (!exists.Value)
                {
                    Add(errors, $"assignments[{idx}].scopes.{scopeKey}", $"Scope '{scopeKey}' is not defined or is inactive.");
                    continue;
                }
                var allowed = await lookup.IsScopeAllowedForRoleAsync(a.Role, scopeKey, ct);
                if (!allowed.IsSuccess) return allowed.Error!;
                if (!allowed.Value)
                    Add(errors, $"assignments[{idx}].scopes.{scopeKey}", $"Scope '{scopeKey}' is not allowed for role '{a.Role}'.");
                var validator = validators.GetValidator(scopeKey);
                var values = kv.Value ?? Array.Empty<string>();
                foreach (var v in values)
                    if (!validator.IsValid(v, out var err))
                        Add(errors, $"assignments[{idx}].scopes.{scopeKey}", err ?? "Invalid scope value.");
                if (values.Count == 0)
                    Add(errors, $"assignments[{idx}].scopes.{scopeKey}", "Scope must have at least one value.");
            }
            idx++;
        }
        return errors;
    }
    private static void Add(Dictionary<string,string[]> d, string key, string msg)
    {
        if (d.TryGetValue(key, out var arr)) d[key] = arr.Append(msg).ToArray();
        else d[key] = new[] { msg };
    }
}
