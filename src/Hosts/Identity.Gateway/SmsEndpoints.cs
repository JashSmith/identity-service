using Identity.Application;
using Identity.Application.Sms;
using Identity.Contracts;
using Identity.Gateway.Errors;
using Microsoft.Extensions.Caching.Memory;

namespace Identity.Gateway;

/// <summary>SMS settings of the tenant: providers, settings (secrets masked), a test message and the development outbox.</summary>
public static class SmsEndpoints
{
    /// <summary>One test message per tenant in this window, so the test button cannot be used to flood a number.</summary>
    public static readonly TimeSpan TestCooldown = TimeSpan.FromSeconds(20);

    public static IEndpointRouteBuilder MapSms(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/settings/sms").WithTags("Settings");

        g.MapGet("/providers", (SmsService sms) => Results.Ok(sms.ListProviders()))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("ListSmsProviders")
            .Produces<IReadOnlyList<SmsProviderDto>>(200);

        g.MapGet("", async (SmsService sms, CancellationToken ct) => (await sms.GetSettingsAsync(ct)).ToHttpResult(s => Results.Ok(s)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("GetSmsSettings")
            .Produces<SmsSettingsDto>(200);

        g.MapPut("", async (SmsSettingsDto body, SmsService sms, CancellationToken ct) =>
                (await sms.SaveSettingsAsync(body, ct)).ToHttpResult(s => Results.Ok(s)))
            .WithValidation<SmsSettingsDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("SetSmsSettings")
            .Produces<SmsSettingsDto>(200).ProducesProblem(400);

        g.MapPost("/test", async (SmsTestRequest body, SmsService sms, ITenantContext tenant, IMemoryCache cache, CancellationToken ct) =>
            {
                var key = "sms-test:" + tenant.TenantId;
                if (cache.TryGetValue(key, out _))
                    return Error.Validation("sms.test_rate_limited",
                        $"Wait {TestCooldown.TotalSeconds:0} seconds between test messages.").ToProblem();
                cache.Set(key, true, TestCooldown);
                return (await sms.SendTestAsync(body.PhoneNumber, ct)).ToHttpResult(r => Results.Ok(r));
            })
            .WithValidation<SmsTestRequest>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("SendTestSms")
            .Produces<SmsTestResultDto>(200).ProducesProblem(400).ProducesProblem(502);

        g.MapGet("/outbox", (SmsService sms, int? max) => Results.Ok(sms.Outbox(max ?? 20)))
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("SmsDevelopmentOutbox")
            .Produces<IReadOnlyList<SmsOutboxItemDto>>(200);

        return app;
    }
}
