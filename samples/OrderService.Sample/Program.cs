using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Company.Identity.PermissionRegistration;
using SampleApp;

var builder = WebApplication.CreateBuilder(args);

var authority = builder.Configuration["Identity:Authority"] ?? "http://localhost:8080/realms/company";
var audience = builder.Configuration["Identity:Audience"] ?? string.Empty;

builder.Services.AddCompanyAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
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
    o.KeycloakBaseUrl = builder.Configuration["PermissionRegistration:KeycloakBaseUrl"] ?? "http://localhost:8080";
    o.KeycloakRealm = builder.Configuration["PermissionRegistration:KeycloakRealm"] ?? "company";
    o.KeycloakClientId = builder.Configuration["PermissionRegistration:KeycloakClientId"] ?? "order-service";
    o.KeycloakClientSecret = builder.Configuration["PermissionRegistration:KeycloakClientSecret"];
    o.InitialRetryDelay = TimeSpan.FromSeconds(2);
    o.MaximumRetries = 8;
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health/live", () => Results.Ok(new { status = "alive" }));

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
app.MapPost("/api/reports/export", (string format, OrderService svc) => Results.Ok(new { file = svc.ExportReport(format) }))
    .RequireAuthorization(OrderPermissions.ExportReports).WithTags("Reports");

app.Run();

public partial class Program;
