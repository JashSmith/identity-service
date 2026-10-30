using Identity.Contracts;

namespace Identity.Application.Scope;

/// <summary>
/// Validates scoped role assignments against the role's scope policy and the scope registry:
/// <list type="bullet">
/// <item>the role exists and allows each scope key; every key it requires has concrete values (no "*");</item>
/// <item>each key is an active registry scope and each value passes its value validator;</item>
/// <item>when a scope has a value catalog, values come from it ("*" stays possible for keys that are not required);</item>
/// <item>child values belong to the parent values of the same assignment (e.g. city "tehran-2" needs province "tehran").</item>
/// </list>
/// </summary>
public sealed class ScopeAssignmentValidator(IScopeDefinitionLookup lookup, IScopeValueValidatorRegistry validators)
{
    public const string Wildcard = "*";

    /// <summary>
    /// Field errors keyed like "assignments[0].scopes.region"; empty when valid. Fails when the registry or
    /// role store cannot be read, so unchecked scopes are never accepted.
    /// </summary>
    public async Task<Result<Dictionary<string, string[]>>> ValidateAsync(
        IEnumerable<ScopedRoleAssignmentDto> assignments, IBusinessRoleStore roles, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        var index = 0;
        foreach (var a in assignments)
        {
            var prefix = $"assignments[{index++}]";
            var scopes = a.Scopes ?? new Dictionary<string, IReadOnlyCollection<string>>();

            var role = await roles.GetAsync(a.Role, ct);
            if (!role.IsSuccess)
            {
                if (role.Error!.Kind != ErrorKind.NotFound) return role.Error;
                Add(errors, $"{prefix}.role", $"Role '{a.Role}' does not exist.");
                continue;
            }

            foreach (var required in role.Value.RequiredScopes ?? [])
            {
                var values = scopes.TryGetValue(required, out var v) ? v ?? [] : [];
                if (values.Count == 0)
                    Add(errors, $"{prefix}.scopes.{required}", $"Role '{a.Role}' requires a value for '{required}'.");
                else if (values.Contains(Wildcard))
                    Add(errors, $"{prefix}.scopes.{required}", $"Role '{a.Role}' requires concrete '{required}' values; '*' is not allowed.");
            }

            foreach (var (scopeKey, rawValues) in scopes)
            {
                var field = $"{prefix}.scopes.{scopeKey}";
                var values = rawValues ?? [];

                var rules = await lookup.GetRulesAsync(scopeKey, ct);
                if (!rules.IsSuccess)
                {
                    if (rules.Error!.Kind != ErrorKind.NotFound) return rules.Error;
                    Add(errors, field, $"Scope '{scopeKey}' is not defined or is inactive.");
                    continue;
                }

                var allowed = await lookup.IsScopeAllowedForRoleAsync(a.Role, scopeKey, ct);
                if (!allowed.IsSuccess) return allowed.Error!;
                if (!allowed.Value) Add(errors, field, $"Scope '{scopeKey}' is not allowed for role '{a.Role}'.");

                if (values.Count == 0) Add(errors, field, "Scope must have at least one value.");
                var validator = validators.GetValidator(scopeKey);
                foreach (var value in values)
                    if (!validator.IsValid(value, out var error))
                        Add(errors, field, error ?? "Invalid scope value.");

                CheckCatalog(errors, field, rules.Value, values, scopes);
            }
        }
        return errors;
    }

    private static void CheckCatalog(Dictionary<string, string[]> errors, string field, ScopeRules rules,
        IReadOnlyCollection<string> values, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes)
    {
        if (rules.Values.Count == 0) return;
        var catalog = rules.Values.ToDictionary(v => v.Value, StringComparer.Ordinal);

        foreach (var value in values.Where(v => v != Wildcard))
        {
            if (!catalog.TryGetValue(value, out var entry))
            {
                Add(errors, field, $"'{value}' is not a value of scope '{rules.Key}'.");
                continue;
            }
            if (rules.Parent is null || entry.Parent is null) continue;
            if (!scopes.TryGetValue(rules.Parent, out var parentValues) || parentValues is null || parentValues.Count == 0) continue;
            if (!parentValues.Contains(Wildcard) && !parentValues.Contains(entry.Parent))
                Add(errors, field, $"'{value}' belongs to {rules.Parent} '{entry.Parent}', which is not assigned.");
        }
    }

    private static void Add(Dictionary<string, string[]> d, string key, string msg) =>
        d[key] = d.TryGetValue(key, out var arr) ? [.. arr, msg] : [msg];
}
