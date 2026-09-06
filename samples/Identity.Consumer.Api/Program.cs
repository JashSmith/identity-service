using Company.Identity.Authentication;
using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Company.Identity.PermissionDiscovery;

var builder = WebApplication.CreateBuilder(args);
var identity = builder.Configuration.GetSection("Identity");
var authority = identity["Authority"] ?? "https://localhost:7001";
var audience = identity["Audience"] ?? "identity-api";
var identityBaseUrl = new Uri(identity["BaseUrl"] ?? "https://localhost:7001");

builder.Services.AddCompanyAuthentication(new IdentityAuthenticationOptions
{
    Authority = authority,
    Audiences = [audience],
    RequireHttpsMetadata = !builder.Environment.IsDevelopment()
});
builder.Services.AddCompanyAuthorization();
builder.Services.AddIdentityApiClient(identityBaseUrl);
builder.Services.AddGrpcClient<Company.Identity.Grpc.IdentityService.IdentityServiceClient>(options =>
    options.Address = identityBaseUrl);
builder.Services.AddOpenApi();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapOpenApi();

app.MapGet("/api/sample/orders", () => Results.Ok(new[] { "order-1001", "order-1002" }))
    .RequireAuthorization("sample.orders.read");

app.MapGet("/api/sample/permissions", () => Results.Ok(Company.Identity.PermissionDiscovery.PermissionDiscovery
    .Discover(typeof(Program).Assembly)))
    .RequireAuthorization();

app.MapGet("/api/sample/identity-rest", async (IHttpClientFactory clients, CancellationToken cancellationToken) =>
{
    var response = await clients.CreateClient("IdentityApi")
        .GetAsync("/api/users/me", cancellationToken);
    return Results.Content(
        await response.Content.ReadAsStringAsync(cancellationToken),
        response.Content.Headers.ContentType?.MediaType,
        statusCode: (int)response.StatusCode);
}).RequireAuthorization();

app.MapGrpcService<SampleIdentityGrpcProxy>();
app.Run();

public partial class Program;

[Company.Identity.Abstractions.RequirePermission("sample.orders.read")]
public sealed class SampleOrderPermissionMarker;
