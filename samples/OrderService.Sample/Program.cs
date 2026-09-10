using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Company.Identity.PermissionRegistration;
using Scalar.AspNetCore;
using SampleApp;

var builder = WebApplication.CreateBuilder(args);

var authority = builder.Configuration["Identity:Authority"] ?? "http://localhost:8080/realms/company";
var audience = builder.Configuration["Identity:Audience"] ?? string.Empty;

// Authority is the Identity Facade itself — the facade proxies OIDC discovery + JWKS and
// rewrites jwks_uri to itself, so this service never learns where Keycloak is.
// AcceptIssuerFromDiscovery validates the issuer claim from the proxied discovery document
// (the genuine Keycloak issuer) instead of the facade URL.
builder.Services.AddCompanyAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.AcceptIssuerFromDiscovery = true;
});
builder.Services.AddCompanyAuthorization();
builder.Services.AddSingleton<OrderService>();

// Discover [RequirePermission] attributes in this assembly and push the manifest to the
// Identity Facade in the background. Registration failure never blocks startup.
builder.Services.AddPermissionRegistration(o =>
{
    o.IdentityServer = new Uri(builder.Configuration["PermissionRegistration:IdentityServer"] ??
                               "http://localhost:5080");
    o.ServiceName = "order-service";
    o.ServiceVersion = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    o.ClientId = builder.Configuration["PermissionRegistration:ClientId"] ?? "order-service";
    o.ClientSecret = builder.Configuration["PermissionRegistration:ClientSecret"];
    o.InitialRetryDelay = TimeSpan.FromSeconds(2);
    o.MaximumRetries = 8;
});

// Scalar API reference + OpenAPI document — every guarded endpoint is listed with its
// required permission and accepts a Bearer token from the facade login proxy.
builder.Services.AddOpenApi("v1", o =>
{
    o.AddDocumentTransformer((document, _, _) =>
    {
        document.Info.Title = "Order Service (sample)";
        document.Info.Description =
            "Sample consumer of the Identity Facade. Every endpoint requires one of the ten " +
            "Orders.* permissions this service registered at startup via [RequirePermission]. " +
            "Get a token from POST /api/identity/auth/login on the Identity Facade and paste it " +
            "into the Bearer authentication dialog.";
        var components = document.Components ?? new Microsoft.OpenApi.OpenApiComponents();
        document.Components = components;
        components.SecuritySchemes ??= new Dictionary<string, Microsoft.OpenApi.IOpenApiSecurityScheme>();
        components.SecuritySchemes["Bearer"] = new Microsoft.OpenApi.OpenApiSecurityScheme
        {
            Type = Microsoft.OpenApi.SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Keycloak-issued JWT obtained through the Identity Facade"
        };
        document.Security =
        [
            new Microsoft.OpenApi.OpenApiSecurityRequirement
            {
                [new Microsoft.OpenApi.OpenApiSecuritySchemeReference("Bearer", document)] = []
            }
        ];
        return Task.CompletedTask;
    });
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapOpenApi();
if (app.Environment.IsDevelopment())
{
    app.MapScalarApiReference(options => options
        .WithTitle("Order Service (sample)")
        .WithOpenApiRoutePattern("/openapi/v1.json")
        .AddPreferredSecuritySchemes(["Bearer"]));
}

app.MapGet("/health/live", () => Results.Ok(new {status = "alive"}));

// One endpoint per permission — the policy name IS the permission name, resolved dynamically
// by PermissionPolicyProvider and enforced against the token's permission claims.
app.MapGet("/api/orders", (OrderService svc) => Results.Ok(svc.ListOrders()))
    .RequireAuthorization(OrderPermissions.ViewOrders).WithTags("Orders");

app.MapPost("/api/orders", (string customerUsername, decimal total, OrderService svc) =>
        Results.Ok(svc.CreateOrder(customerUsername, total)))
    .RequireAuthorization(OrderPermissions.CreateOrders).WithTags("Orders");

app.MapPut("/api/orders/{orderId}/total", (string orderId, decimal newTotal, OrderService svc) =>
        Results.Ok(svc.EditOrder(orderId, newTotal)))
    .RequireAuthorization(OrderPermissions.EditOrders).WithTags("Orders");

app.MapPost("/api/orders/{orderId}/cancel", (string orderId, OrderService svc) =>
        Results.Ok(svc.CancelOrder(orderId)))
    .RequireAuthorization(OrderPermissions.CancelOrders).WithTags("Orders");

app.MapGet("/api/orders/{orderId}/invoices", (string orderId, OrderService svc) =>
        Results.Ok(svc.ListInvoices(orderId)))
    .RequireAuthorization(OrderPermissions.ViewInvoices).WithTags("Invoices");

app.MapPost("/api/orders/{orderId}/invoices/issue", (string orderId, OrderService svc) =>
        Results.Ok(svc.IssueInvoice(orderId)))
    .RequireAuthorization(OrderPermissions.IssueInvoices).WithTags("Invoices");

app.MapGet("/api/orders/{orderId}/shipments", (string orderId, OrderService svc) =>
        Results.Ok(svc.ListShipments(orderId)))
    .RequireAuthorization(OrderPermissions.ViewShipments).WithTags("Shipments");

app.MapPost("/api/orders/{orderId}/shipments/schedule", (string orderId, DateTimeOffset shipsAt, OrderService svc) =>
        Results.Ok(svc.ScheduleShipment(orderId, shipsAt)))
    .RequireAuthorization(OrderPermissions.ScheduleShipments).WithTags("Shipments");

app.MapPost("/api/orders/{orderId}/refunds/approve", (string orderId, decimal amount, OrderService svc) =>
        Results.Ok(svc.ApproveRefund(orderId, amount)))
    .RequireAuthorization(OrderPermissions.ApproveRefunds).WithTags("Refunds");

app.MapPost("/api/reports/export",
        (string format, OrderService svc) => Results.Ok(new {file = svc.ExportReport(format)}))
    .RequireAuthorization(OrderPermissions.ExportReports).WithTags("Reports");

app.Run();

public partial class Program;