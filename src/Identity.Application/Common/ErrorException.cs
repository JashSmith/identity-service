namespace Identity.Application;

/// <summary>
/// Carries an <see cref="Application.Error"/> through code that does not return results yet. The API's
/// exception handler turns it into the matching problem response.
/// </summary>
public sealed class ErrorException(Error error) : Exception(error.Message)
{
    public Error Error { get; } = error;
}
