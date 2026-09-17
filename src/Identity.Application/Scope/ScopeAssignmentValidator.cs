using Identity.Contracts;

namespace Identity.Application.Scope;

public sealed class ScopeAssignmentValidator(IScopeDefinitionLookup lookup, IScopeValueValidatorRegistry validators)
{
    public async Task<Dictionary<string, string[]>> ValidateAsync(IEnumerable<ScopedRoleAssignmentDto> assignments, IBusinessRoleStore roles, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        int idx = 0;
        foreach (var a in assignments)
        {
            var roleExists = await roles.GetAsync(a.Role, ct);
            if (roleExists is null) Add(errors, $"assignments[{idx}].role", $"Role '{a.Role}' does not exist.");
            foreach (var kv in a.Scopes)
            {
                var scopeKey = kv.Key;
                if (!await lookup.ExistsActiveAsync(scopeKey, ct))
                {
                    Add(errors, $"assignments[{idx}].scopes.{scopeKey}", $"Scope '{scopeKey}' is not defined or is inactive.");
                    continue;
                }
                if (!await lookup.IsScopeAllowedForRoleAsync(a.Role, scopeKey, ct))
                    Add(errors, $"assignments[{idx}].scopes.{scopeKey}", $"Scope '{scopeKey}' is not allowed for role '{a.Role}'.");
                var validator = validators.GetValidator(scopeKey);
                foreach (var v in kv.Value)
                    if (!validator.IsValid(v, out var err))
                        Add(errors, $"assignments[{idx}].scopes.{scopeKey}", err ?? "Invalid scope value.");
                if (kv.Value.Count == 0)
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
