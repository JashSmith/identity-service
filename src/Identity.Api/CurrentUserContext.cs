using System.Security.Claims;
using Identity.Application;

namespace Identity.Api;

public sealed class HttpCurrentUserContext(IHttpContextAccessor accessor, TimeProvider timeProvider) : ICurrentUserContext
{
    private ClaimsPrincipal Principal => accessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());
    public string? UserId => Principal.FindFirstValue("sub");
    public string? Username => Principal.FindFirstValue("preferred_username") ?? Principal.Identity?.Name;
    public IReadOnlyCollection<string> Roles => Principal.FindAll(ClaimTypes.Role).Concat(Principal.FindAll("role")).Select(x => x.Value).Distinct(StringComparer.Ordinal).ToArray();
    public IReadOnlyCollection<string> Permissions => Principal.FindAll("permission").Concat(Principal.FindAll("permissions")).Select(x => x.Value).Distinct(StringComparer.Ordinal).ToArray();
    public IReadOnlyDictionary<string, string?> Claims => Principal.Claims.GroupBy(x => x.Type).ToDictionary(x => x.Key, x => x.FirstOrDefault()?.Value, StringComparer.Ordinal);
    public string? SessionId => Principal.FindFirstValue("sid");
    public DateTimeOffset RequestDateTime => timeProvider.GetUtcNow();
}
