using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;

namespace Identity.Gateway.Tests;

/// <summary>Role scope policies (required keys) and the registry's value catalog and hierarchy are enforced on assignment.</summary>
public sealed class ScopeAssignmentValidatorTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private sealed class Registry : IScopeDefinitionLookup
    {
        private readonly Dictionary<string, ScopeRules> _rules = new(StringComparer.Ordinal)
        {
            ["province"] = new("province", null, [new("tehran", "تهران"), new("fars", "فارس")]),
            ["city"] = new("city", "province", [new("tehran-city", "تهران", "tehran"), new("shiraz", "شیراز", "fars")]),
            ["district"] = new("district", "city", []),
        };

        public Task<Result<bool>> ExistsActiveAsync(string key, CancellationToken ct) =>
            Task.FromResult(Result<bool>.Success(_rules.ContainsKey(key)));

        public Task<Result<bool>> IsScopeAllowedForRoleAsync(string role, string scopeKey, CancellationToken ct) =>
            Task.FromResult(Result<bool>.Success(true));

        public Task<Result<ScopeRules>> GetRulesAsync(string key, CancellationToken ct) =>
            Task.FromResult(_rules.TryGetValue(key, out var r) ? Result<ScopeRules>.Success(r) : Error.NotFound("scope.not_found", key));
    }

    private sealed class Roles : IBusinessRoleStore
    {
        public Task<Result<BusinessRoleDto>> GetAsync(string name, CancellationToken ct) =>
            Task.FromResult(name == "TehranManager"
                ? Result<BusinessRoleDto>.Success(new BusinessRoleDto(name, null, true, [], ["province", "city"], ["province", "city", "district"]))
                : Error.NotFound("role.not_found", name));
        public Task<Result<IReadOnlyCollection<BusinessRoleDto>>> ListAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<BusinessRoleDto>> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, RoleScopePolicy? scopePolicy, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<BusinessRoleDto>> UpdateAsync(string name, string? description, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string name, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<IReadOnlyCollection<string>>> GetEffectivePermissionsAsync(string name, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> RemovePermissionAsync(string name, string permission, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> SetPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> SetScopePolicyAsync(string name, RoleScopePolicy policy, CancellationToken ct) => throw new NotSupportedException();
    }

    private static async Task<Dictionary<string, string[]>> Validate(Dictionary<string, IReadOnlyCollection<string>> scopes)
    {
        var validator = new ScopeAssignmentValidator(new Registry(), new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var result = await validator.ValidateAsync([new ScopedRoleAssignmentDto("TehranManager", scopes)], new Roles(), Ct);
        Assert.True(result.IsSuccess);
        return result.Value;
    }

    [Fact]
    public async Task Required_keys_with_catalog_values_are_valid_and_optional_keys_may_be_wildcard()
    {
        var errors = await Validate(new() { ["province"] = ["tehran"], ["city"] = ["tehran-city"], ["district"] = ["*"] });

        Assert.Empty(errors);
    }

    [Fact]
    public async Task Missing_or_wildcard_required_keys_are_rejected()
    {
        var errors = await Validate(new() { ["province"] = ["*"] });

        Assert.Contains("assignments[0].scopes.province", errors.Keys);
        Assert.Contains("assignments[0].scopes.city", errors.Keys);
    }

    [Fact]
    public async Task Values_outside_the_catalog_are_rejected()
    {
        var errors = await Validate(new() { ["province"] = ["isfahan"], ["city"] = ["tehran-city"] });

        Assert.Contains(errors["assignments[0].scopes.province"], e => e.Contains("isfahan", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_child_value_must_belong_to_an_assigned_parent_value()
    {
        var errors = await Validate(new() { ["province"] = ["tehran"], ["city"] = ["shiraz"] });

        Assert.Contains(errors["assignments[0].scopes.city"], e => e.Contains("fars", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unknown_scope_keys_are_rejected()
    {
        var errors = await Validate(new() { ["province"] = ["tehran"], ["city"] = ["tehran-city"], ["branch"] = ["b1"] });

        Assert.Contains("assignments[0].scopes.branch", errors.Keys);
    }
}
