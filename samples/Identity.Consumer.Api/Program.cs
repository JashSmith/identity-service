using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Company.Identity.PermissionDiscovery;

var builder = WebApplication.CreateBuilder(args);
var identity = builder.Configuration.GetSection("Identity");
var authority = identity["Authority"] ?? "http://localhost:8080/realms/company";
var audience = identity["Audience"] ?? "order-service";

builder.Services.AddCompanyAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
});
builder.Services.AddCompanyAuthorization();
builder.Services.AddOpenApi();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapOpenApi();

app.MapGet("/api/sample/orders", () => Results.Ok(new[] { "order-1001", "order-1002" }))
    .RequireAuthorization("Orders.Read");
app.MapGet("/api/sample/permissions", () => Results.Ok(PermissionDiscovery.Discover(typeof(Program).Assembly)))
    .RequireAuthorization();
app.Run();

public partial class Program;

[Company.Identity.Abstractions.RequirePermission("Orders.Cancel")]
public sealed class SampleOrderPermissionMarker;
