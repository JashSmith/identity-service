using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Identity.Api;
using Identity.Application;
using Identity.Contracts;

var builder = WebApplication.CreateBuilder(args);
var authority = builder.Configuration["Identity:Authority"] ?? throw new InvalidOperationException("Identity:Authority is required.");
var audience = builder.Configuration["Identity:Audience"] ?? string.Empty;
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
builder.Services.AddCompanyAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
});
builder.Services.AddCompanyAuthorization();
builder.Services.AddGrpc();
builder.Services.AddHealthChecks();
builder.Services.AddOpenApi();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapHealthChecks("/health/live");
app.MapGet("/api/identity/me", (ICurrentUserContext current) =>
    current.UserId is null ? Results.Unauthorized() : Results.Ok(new { current.UserId, current.Username, current.Roles, current.Permissions, current.SessionId }))
    .RequireAuthorization();
app.MapPost("/api/identity/external/organization-token", (OrganizationTokenRequest request) =>
    Results.StatusCode(StatusCodes.Status501NotImplemented));
app.Run();

public partial class Program;
