using System.Text.RegularExpressions;

namespace Identity.Application.Permissions;

/// <summary>
/// The permission naming scheme: <c>{application}:{module}:{resource}:{action}</c>. Services declare the
/// local part (<c>Module:Resource:Action</c>); the application (Keycloak client id) is added in tokens.
/// </summary>
public sealed partial record PermissionName(string Application, string Module, string Resource, string Action)
{
    public string Local => $"{Module}:{Resource}:{Action}";

    public string Full => $"{Application}:{Local}";

    public override string ToString() => Full;

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_-]{0,63}$")]
    private static partial Regex SegmentPattern();

    [GeneratedRegex("^[a-z][a-z0-9-]{1,62}$")]
    private static partial Regex ApplicationPattern();

    public static bool IsValidApplicationId(string? clientId) => clientId is not null && ApplicationPattern().IsMatch(clientId);

    public static bool IsValidLocal(string? local) => TryParseLocal("application", local, out _);

    public static bool TryParseLocal(string application, string? local, out PermissionName name)
    {
        name = null!;
        var parts = local?.Split(':') ?? [];
        if (parts.Length != 3 || !parts.All(p => SegmentPattern().IsMatch(p))) return false;
        name = new PermissionName(application, parts[0], parts[1], parts[2]);
        return true;
    }

    public static bool TryParseFull(string? full, out PermissionName name)
    {
        name = null!;
        var separator = full?.IndexOf(':') ?? -1;
        if (separator <= 0) return false;
        var application = full![..separator];
        return IsValidApplicationId(application) && TryParseLocal(application, full[(separator + 1)..], out name);
    }
}
