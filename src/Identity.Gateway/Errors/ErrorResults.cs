using Identity.Application;

namespace Identity.Gateway.Errors;

/// <summary>
/// Turns application errors into RFC 9457 problem responses. Every error response of the gateway
/// carries a stable <c>code</c> extension next to the standard fields (and <c>traceId</c>, added by
/// the problem details service).
/// </summary>
public static class ErrorResults
{
    public static int StatusCode(this ErrorKind kind) => kind switch
    {
        ErrorKind.Validation => StatusCodes.Status400BadRequest,
        ErrorKind.NotFound => StatusCodes.Status404NotFound,
        ErrorKind.Conflict => StatusCodes.Status409Conflict,
        ErrorKind.Forbidden => StatusCodes.Status403Forbidden,
        ErrorKind.Unavailable => StatusCodes.Status503ServiceUnavailable,
        ErrorKind.Upstream => StatusCodes.Status502BadGateway,
        _ => StatusCodes.Status500InternalServerError,
    };

    public static IResult ToProblem(this Error error)
    {
        ArgumentNullException.ThrowIfNull(error);
        var extensions = new Dictionary<string, object?> { ["code"] = error.Code };

        if (error.Kind == ErrorKind.Validation && error.Fields is { Count: > 0 })
        {
            return TypedResults.ValidationProblem(
                error.Fields, detail: error.Message, title: Title(error.Kind), extensions: extensions);
        }

        return TypedResults.Problem(
            detail: error.Message, statusCode: error.Kind.StatusCode(), title: Title(error.Kind), extensions: extensions);
    }

    public static IResult ToHttpResult(this Result result, Func<IResult> onSuccess) =>
        result.IsSuccess ? onSuccess() : result.Error!.ToProblem();

    public static IResult ToHttpResult<T>(this Result<T> result, Func<T, IResult> onSuccess) =>
        result.IsSuccess ? onSuccess(result.Value) : result.Error!.ToProblem();

    private static string Title(ErrorKind kind) => kind switch
    {
        ErrorKind.Validation => "The request is invalid.",
        ErrorKind.NotFound => "The resource was not found.",
        ErrorKind.Conflict => "The request conflicts with the current state.",
        ErrorKind.Forbidden => "The operation is not allowed.",
        ErrorKind.Unavailable => "A required service is unavailable.",
        ErrorKind.Upstream => "A required service returned an unusable response.",
        _ => "An unexpected error occurred.",
    };
}
