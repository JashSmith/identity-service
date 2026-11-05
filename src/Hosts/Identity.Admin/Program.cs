using Identity.Admin.Auth;
using Identity.Admin.Components;
using Identity.Admin.Services;
using Microsoft.Extensions.Options;
using Radzen;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddRadzenComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddConsoleAuthentication(builder.Configuration, builder.Environment.IsDevelopment());
builder.Services.AddAuthorization();

builder.Services.AddHttpClient("keycloak");
builder.Services.AddHttpClient<GatewayApi>((sp, client) =>
    client.BaseAddress = new Uri(sp.GetRequiredService<IOptions<ConsoleOptions>>().Value.GatewayBaseUrl.TrimEnd('/') + "/"));

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapDefaultEndpoints();
app.MapConsoleAuthentication();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
