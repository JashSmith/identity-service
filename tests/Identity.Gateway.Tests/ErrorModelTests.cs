using System.Net;
using System.Text.Json;
using FluentValidation;
using Identity.Application;
using Identity.Gateway.Errors;
using Identity.Infrastructure.Keycloak;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Identity.Gateway.Tests;

public sealed class ErrorModelTests
{
    private static ServiceProvider Services(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddProblemDetails();
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext Context(IServiceProvider services) => new()
    {
        RequestServices = services,
        Response = { Body = new MemoryStream() },
    };

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IResult result)
    {
        await using var services = Services();
        var http = Context(services);
        await result.ExecuteAsync(http);
        return (http.Response.StatusCode, await ReadBodyAsync(http));
    }

    private static async Task<JsonElement> ReadBodyAsync(HttpContext http)
    {
        http.Response.Body.Position = 0;
        return (await JsonDocument.ParseAsync(http.Response.Body)).RootElement.Clone();
    }

    private static GlobalExceptionHandler Handler(IServiceProvider services) =>
        new(services.GetRequiredService<IProblemDetailsService>(), NullLogger<GlobalExceptionHandler>.Instance);

    [Theory]
    [InlineData(ErrorKind.Validation, 400)]
    [InlineData(ErrorKind.NotFound, 404)]
    [InlineData(ErrorKind.Conflict, 409)]
    [InlineData(ErrorKind.Forbidden, 403)]
    [InlineData(ErrorKind.Unavailable, 503)]
    [InlineData(ErrorKind.Upstream, 502)]
    [InlineData(ErrorKind.Unexpected, 500)]
    public async Task Each_error_kind_becomes_a_problem_with_its_status_and_code(ErrorKind kind, int status)
    {
        var (actual, body) = await ExecuteAsync(new Error("thing.failed", "It failed.", kind).ToProblem());

        Assert.Equal(status, actual);
        Assert.Equal(status, body.GetProperty("status").GetInt32());
        Assert.Equal("thing.failed", body.GetProperty("code").GetString());
        Assert.Equal("It failed.", body.GetProperty("detail").GetString());
        Assert.True(body.TryGetProperty("traceId", out _));
    }

    [Fact]
    public async Task Validation_error_lists_field_errors()
    {
        var error = Error.Validation("request.invalid", "Bad input.",
            new Dictionary<string, string[]> { ["name"] = ["Name is required."] });

        var (status, body) = await ExecuteAsync(error.ToProblem());

        Assert.Equal(400, status);
        Assert.Equal("Name is required.", body.GetProperty("errors").GetProperty("name")[0].GetString());
        Assert.Equal("request.invalid", body.GetProperty("code").GetString());
    }

    [Fact]
    public void Result_carries_either_a_value_or_an_error()
    {
        Result<int> ok = 42;
        Result<int> failed = Error.NotFound("x.not_found", "missing");

        Assert.True(ok.IsSuccess);
        Assert.Equal(43, ok.Map(v => v + 1).Value);
        Assert.False(failed.IsSuccess);
        Assert.Equal("x.not_found", failed.Map(v => v + 1).Error!.Code);
        Assert.Throws<InvalidOperationException>(() => failed.Value);
    }

    [Fact]
    public async Task Unhandled_exception_returns_generic_500_without_details()
    {
        await using var services = Services();
        var http = Context(services);
        http.Request.Headers.Authorization = "Bearer secret-token";

        Assert.True(await Handler(services).TryHandleAsync(
            http, new InvalidOperationException("db password=hunter2"), CancellationToken.None));

        var raw = (await ReadBodyAsync(http)).GetRawText();
        Assert.Equal(500, http.Response.StatusCode);
        Assert.Contains("\"code\":\"unexpected\"", raw);
        Assert.DoesNotContain("hunter2", raw);
        Assert.DoesNotContain("secret-token", raw);
    }

    [Fact]
    public async Task Malformed_request_returns_400_without_echoing_headers()
    {
        await using var services = Services();
        var http = Context(services);
        http.Request.Headers.Authorization = "Bearer secret-token";

        await Handler(services).TryHandleAsync(
            http, new BadHttpRequestException("Failed to read parameter as JSON."), CancellationToken.None);

        var raw = (await ReadBodyAsync(http)).GetRawText();
        Assert.Equal(400, http.Response.StatusCode);
        Assert.Contains("request.malformed", raw);
        Assert.DoesNotContain("secret-token", raw);
    }

    public sealed record SampleRequest(string? Name);

    private sealed class SampleValidator : AbstractValidator<SampleRequest>
    {
        public SampleValidator() => RuleFor(r => r.Name).NotEmpty().WithMessage("Name is required.");
    }

    [Fact]
    public async Task Validation_filter_stops_invalid_requests_before_the_handler()
    {
        await using var services = Services(s => s.AddSingleton<IValidator<SampleRequest>, SampleValidator>());
        var http = Context(services);
        var handlerRan = false;
        var context = EndpointFilterInvocationContext.Create(http, new SampleRequest(""));

        var outcome = await new ValidationFilter<SampleRequest>().InvokeAsync(context, _ =>
        {
            handlerRan = true;
            return ValueTask.FromResult<object?>(Results.Ok());
        });

        Assert.False(handlerRan);
        await ((IResult)outcome!).ExecuteAsync(http);
        Assert.Equal(400, http.Response.StatusCode);
        var body = await ReadBodyAsync(http);
        Assert.Equal("Name is required.", body.GetProperty("errors").GetProperty("Name")[0].GetString());
    }

    [Fact]
    public async Task Validation_filter_lets_valid_requests_through()
    {
        await using var services = Services(s => s.AddSingleton<IValidator<SampleRequest>, SampleValidator>());
        var context = EndpointFilterInvocationContext.Create(Context(services), new SampleRequest("ok"));

        var outcome = await new ValidationFilter<SampleRequest>().InvokeAsync(context,
            _ => ValueTask.FromResult<object?>("handled"));

        Assert.Equal("handled", outcome);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, "role.not_found", ErrorKind.NotFound)]
    [InlineData(HttpStatusCode.Conflict, "role.conflict", ErrorKind.Conflict)]
    [InlineData(HttpStatusCode.BadRequest, "role.rejected", ErrorKind.Validation)]
    [InlineData(HttpStatusCode.Forbidden, "keycloak.access_denied", ErrorKind.Upstream)]
    [InlineData(HttpStatusCode.Unauthorized, "keycloak.access_denied", ErrorKind.Upstream)]
    [InlineData(HttpStatusCode.ServiceUnavailable, "keycloak.error", ErrorKind.Unavailable)]
    public async Task Keycloak_responses_map_to_errors_without_leaking_the_body(
        HttpStatusCode status, string code, ErrorKind kind)
    {
        using var response = new HttpResponseMessage(status)
        {
            Content = new StringContent("{\"errorMessage\":\"internal detail: table KEYCLOAK_ROLE\"}")
        };

        var error = await KeycloakErrors.FromResponseAsync(response, "role", NullLogger.Instance, CancellationToken.None);

        Assert.Equal(code, error.Code);
        Assert.Equal(kind, error.Kind);
        Assert.DoesNotContain("KEYCLOAK_ROLE", error.Message);
    }
}
