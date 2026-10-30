using FluentValidation;
using Identity.Application;

namespace Identity.Gateway.Errors;

/// <summary>
/// Validates the <typeparamref name="TRequest"/> argument of an endpoint with its registered
/// FluentValidation validator and answers 400 with field errors before the handler runs.
/// </summary>
public sealed class ValidationFilter<TRequest> : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var validator = context.HttpContext.RequestServices.GetService<IValidator<TRequest>>();
        var request = context.Arguments.OfType<TRequest>().FirstOrDefault();
        if (validator is null || request is null) return await next(context);

        var validation = await validator.ValidateAsync(request, context.HttpContext.RequestAborted);
        if (validation.IsValid) return await next(context);

        var fields = validation.Errors
            .GroupBy(e => e.PropertyName)
            .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).Distinct().ToArray());
        return Error.Validation("request.invalid", "One or more fields are invalid.", fields).ToProblem();
    }
}

public static class ValidationFilterExtensions
{
    /// <summary>Runs the registered validator for <typeparamref name="TRequest"/> before the handler.</summary>
    public static RouteHandlerBuilder WithValidation<TRequest>(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter<ValidationFilter<TRequest>>()
            .ProducesValidationProblem();
}
