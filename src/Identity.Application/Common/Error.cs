namespace Identity.Application;

/// <summary>Category of a failure. The API layer maps each kind to one HTTP status.</summary>
public enum ErrorKind
{
    /// <summary>The request is invalid (400).</summary>
    Validation,

    /// <summary>The target does not exist (404).</summary>
    NotFound,

    /// <summary>The request conflicts with existing state (409).</summary>
    Conflict,

    /// <summary>The caller may not perform the operation (403).</summary>
    Forbidden,

    /// <summary>A dependency such as Keycloak is down or unreachable (503).</summary>
    Unavailable,

    /// <summary>A dependency answered in a way the gateway cannot use, e.g. it lacks rights (502).</summary>
    Upstream,

    /// <summary>A bug or an unexpected state (500).</summary>
    Unexpected
}

/// <summary>
/// A failure with a stable, machine-readable <see cref="Code"/> (for example <c>role.not_found</c>)
/// and a message safe to show to API callers. Field-level validation problems go in <see cref="Fields"/>.
/// </summary>
public sealed record Error(
    string Code,
    string Message,
    ErrorKind Kind,
    IReadOnlyDictionary<string, string[]>? Fields = null)
{
    public static Error Validation(string code, string message, IReadOnlyDictionary<string, string[]>? fields = null) =>
        new(code, message, ErrorKind.Validation, fields);

    public static Error NotFound(string code, string message) => new(code, message, ErrorKind.NotFound);

    public static Error Conflict(string code, string message) => new(code, message, ErrorKind.Conflict);

    public static Error Forbidden(string code, string message) => new(code, message, ErrorKind.Forbidden);

    public static Error Unavailable(string code, string message) => new(code, message, ErrorKind.Unavailable);

    public static Error Upstream(string code, string message) => new(code, message, ErrorKind.Upstream);

    public static Error Unexpected(string code, string message) => new(code, message, ErrorKind.Unexpected);
}
