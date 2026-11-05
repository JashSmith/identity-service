using System.Text.Json;
using Identity.Application;
using Identity.Application.Schedules;
using Identity.Application.Sms;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Puts the Avash SMS authenticators (keycloak/extensions) into the tenant realm's sign-in flows and switches them by
/// SMS sign-in mode. The steps are added once and only their requirement changes afterwards:
/// <list type="bullet">
/// <item>Login page (<c>avash-browser</c>, created by <see cref="KeycloakScheduleAuthenticatorSetup"/>): an SMS code
/// after the password and schedule in the forms sub-flow (second factor), and a top-level alternative sub-flow
/// "<c>avash-browser sms</c>" with the passwordless SMS step and the schedule check, offered through Keycloak's
/// "try another way".</item>
/// <item>Token endpoint (gateway login API): <c>avash-direct-grant</c>, built from scratch because Keycloak's
/// "direct grant" flow cannot hold alternatives: a passwordless SMS alternative (phone_number) and the password
/// branch (username, password, conditional OTP, optional SMS second factor). The realm uses it only while SMS sign-in
/// is on; with SMS sign-in off the realm goes back to Keycloak's own "direct grant" flow.</item>
/// </list>
/// Realms whose administrators chose other flows are left alone (logged).
/// </summary>
public sealed class KeycloakSmsLoginFlowSetup(
    HttpClient http,
    IOptions<KeycloakOptions> keycloak,
    KeycloakAdminTokenProvider tokenProvider,
    AccessScheduleOptions schedules,
    ILogger<KeycloakSmsLoginFlowSetup>? logger = null) : ISmsLoginFlows
{
    public const string LoginProvider = "avash-sms-login";
    public const string OtpProvider = "avash-sms-otp";
    public const string DirectLoginProvider = "avash-sms-login-direct";
    public const string DirectOtpProvider = "avash-sms-otp-direct";
    private static readonly string[] Providers = [LoginProvider, OtpProvider, DirectLoginProvider, DirectOtpProvider];

    public const string BrowserFlow = KeycloakScheduleAuthenticatorSetup.FlowAlias;
    public const string BrowserForms = BrowserFlow + " forms";
    public const string BrowserSms = BrowserFlow + " sms";
    public const string DirectFlow = "avash-direct-grant";
    public const string DirectPassword = DirectFlow + " password";
    public const string DirectConditionalOtp = DirectFlow + " otp";
    private const string BuiltInDirectFlow = "direct grant";
    private const string ScheduleProvider = KeycloakScheduleAuthenticatorSetup.ProviderId;
    private const string Resource = "auth_flow";

    private readonly ILogger _logger = (ILogger?)logger ?? NullLogger.Instance;
    private readonly KeycloakAdminApi _api = new(http, keycloak.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    public async Task<Result<bool>> ReadyAsync(CancellationToken ct)
    {
        var installed = await InstalledProvidersAsync(ct);
        return installed.IsSuccess ? Providers.All(installed.Value.Contains) : installed.Error!;
    }

    public async Task<Result> ApplyAsync(string mode, CancellationToken ct)
    {
        var installed = await InstalledProvidersAsync(ct);
        if (!installed.IsSuccess) return installed.Error!;
        if (!Providers.All(installed.Value.Contains))
        {
            if (mode == SmsLoginModes.Off) return Result.Success();
            return Error.Unavailable("sms_login.extension_missing",
                "Keycloak does not have the Avash SMS authenticators; build keycloak/extensions and restart Keycloak.");
        }
        var withSchedule = installed.Value.Contains(ScheduleProvider);

        var realm = await _api.GetAsync("", Resource, ct);
        if (!realm.IsSuccess) return realm.Error!;

        var browser = KeycloakAdminApi.GetString(realm.Value, "browserFlow");
        if (browser == BrowserFlow)
        {
            var applied = await ApplyBrowserAsync(mode, withSchedule, ct);
            if (!applied.IsSuccess) return applied;
        }
        else if (mode != SmsLoginModes.Off)
            _logger.LogWarning("Realm uses the browser flow '{Flow}'; add the '{Provider}'/'{Otp}' authenticators to it manually",
                browser, LoginProvider, OtpProvider);

        var direct = KeycloakAdminApi.GetString(realm.Value, "directGrantFlow") ?? BuiltInDirectFlow;
        if (direct is not (BuiltInDirectFlow or DirectFlow))
        {
            if (mode != SmsLoginModes.Off)
                _logger.LogWarning("Realm uses the direct grant flow '{Flow}'; SMS sign-in through the login API is not available",
                    direct);
            return Result.Success();
        }
        if (mode == SmsLoginModes.Off)
            return direct == DirectFlow ? await BindDirectFlowAsync(BuiltInDirectFlow, ct) : Result.Success();

        var built = await ApplyDirectAsync(mode, ct);
        if (!built.IsSuccess) return built;
        return direct == DirectFlow ? Result.Success() : await BindDirectFlowAsync(DirectFlow, ct);
    }

    private async Task<Result<HashSet<string>>> InstalledProvidersAsync(CancellationToken ct)
    {
        var providers = await _api.GetAsync("authentication/authenticator-providers", Resource, ct);
        if (!providers.IsSuccess) return providers.Error!;
        return providers.Value.EnumerateArray().Select(p => KeycloakAdminApi.GetString(p, "id")).OfType<string>()
            .ToHashSet(StringComparer.Ordinal);
    }

    // ---- Login page -------------------------------------------------------------------------------------------

    private async Task<Result> ApplyBrowserAsync(string mode, bool withSchedule, CancellationToken ct)
    {
        var executions = await ExecutionsAsync(BrowserFlow, ct);
        if (!executions.IsSuccess) return executions.Error!;
        var list = executions.Value;

        if (mode != SmsLoginModes.Off)
        {
            var forms = FindFlow(list, BrowserForms, level: 0);
            if (forms is null)
                return Error.Unexpected("auth_flow.no_forms", $"Flow '{BrowserFlow}' has no '{BrowserForms}' sub-flow.");
            if (Children(list, forms.Value).All(e => Provider(e) != OtpProvider))
            {
                var added = await AddExecutionAsync(BrowserForms, OtpProvider, ct);
                if (!added.IsSuccess) return added;
            }
            if (FindFlow(list, BrowserSms, level: 0) is null)
            {
                var created = await AddSubflowAsync(BrowserFlow, BrowserSms, "Avash: passwordless sign-in with an SMS code", ct);
                if (!created.IsSuccess) return created;
                var login = await AddExecutionAsync(BrowserSms, LoginProvider, ct);
                if (!login.IsSuccess) return login;
                if (withSchedule)
                {
                    var schedule = await AddExecutionAsync(BrowserSms, ScheduleProvider, ct);
                    if (!schedule.IsSuccess) return schedule;
                }
                _logger.LogInformation("Added SMS sign-in to the '{Flow}' flow", BrowserFlow);
            }
            executions = await ExecutionsAsync(BrowserFlow, ct);
            if (!executions.IsSuccess) return executions.Error!;
            list = executions.Value;
        }

        var wanted = new List<(JsonElement Execution, string Requirement)>();
        if (FindFlow(list, BrowserForms, 0) is { } formsFlow &&
            Children(list, formsFlow).FirstOrDefault(e => Provider(e) == OtpProvider) is { ValueKind: JsonValueKind.Object } otp)
            wanted.Add((otp, mode == SmsLoginModes.SecondFactor ? "REQUIRED" : "DISABLED"));
        if (FindFlow(list, BrowserSms, 0) is { } smsFlow)
        {
            wanted.Add((smsFlow, mode == SmsLoginModes.Passwordless ? "ALTERNATIVE" : "DISABLED"));
            foreach (var child in Children(list, smsFlow)) wanted.Add((child, "REQUIRED"));
            var schedule = Children(list, smsFlow).FirstOrDefault(e => Provider(e) == ScheduleProvider);
            if (schedule.ValueKind == JsonValueKind.Object)
            {
                var configured = await EnsureScheduleConfigAsync(schedule, ct);
                if (!configured.IsSuccess) return configured;
            }
        }
        return await SetRequirementsAsync(BrowserFlow, wanted, ct);
    }

    /// <summary>The schedule check of the SMS branch reads the same time zone as the password branch.</summary>
    private async Task<Result> EnsureScheduleConfigAsync(JsonElement execution, CancellationToken ct)
    {
        if (KeycloakAdminApi.GetString(execution, "authenticationConfig") is not null) return Result.Success();
        var id = KeycloakAdminApi.GetString(execution, "id")!;
        return await _api.SendWithoutResultAsync(HttpMethod.Post, $"authentication/executions/{Uri.EscapeDataString(id)}/config",
            new { alias = "avash-access-schedule-sms", config = new Dictionary<string, string> { ["timeZone"] = schedules.TimeZone } },
            Resource, ct, includeKeycloakMessage: true);
    }

    // ---- Token endpoint ---------------------------------------------------------------------------------------

    private async Task<Result> ApplyDirectAsync(string mode, CancellationToken ct)
    {
        var flows = await _api.GetAsync("authentication/flows", Resource, ct);
        if (!flows.IsSuccess) return flows.Error!;
        if (flows.Value.EnumerateArray().All(f => KeycloakAdminApi.GetString(f, "alias") != DirectFlow))
        {
            var built = await BuildDirectFlowAsync(ct);
            if (!built.IsSuccess) return built;
        }

        var executions = await ExecutionsAsync(DirectFlow, ct);
        if (!executions.IsSuccess) return executions.Error!;
        var list = executions.Value;
        var wanted = new List<(JsonElement, string)>();
        foreach (var e in list)
        {
            var requirement = (Provider(e), KeycloakAdminApi.GetString(e, "displayName")) switch
            {
                (DirectLoginProvider, _) => mode == SmsLoginModes.Passwordless ? "ALTERNATIVE" : "DISABLED",
                (DirectOtpProvider, _) => mode == SmsLoginModes.SecondFactor ? "REQUIRED" : "DISABLED",
                (_, DirectPassword) => "ALTERNATIVE",
                (_, DirectConditionalOtp) => "CONDITIONAL",
                _ => "REQUIRED",
            };
            wanted.Add((e, requirement));
        }
        return await SetRequirementsAsync(DirectFlow, wanted, ct);
    }

    private async Task<Result> BuildDirectFlowAsync(CancellationToken ct)
    {
        var created = await _api.SendWithoutResultAsync(HttpMethod.Post, "authentication/flows", new
        {
            alias = DirectFlow,
            description = "Avash: token endpoint sign-in with a password or an SMS code (managed by the Identity Gateway)",
            providerId = "basic-flow",
            topLevel = true,
            builtIn = false,
        }, Resource, ct, includeKeycloakMessage: true);
        if (!created.IsSuccess) return created;

        var steps = new Func<Task<Result>>[]
        {
            () => AddExecutionAsync(DirectFlow, DirectLoginProvider, ct),
            () => AddSubflowAsync(DirectFlow, DirectPassword, "Username and password, then optional OTP or SMS code", ct),
            () => AddExecutionAsync(DirectPassword, "direct-grant-validate-username", ct),
            () => AddExecutionAsync(DirectPassword, "direct-grant-validate-password", ct),
            () => AddSubflowAsync(DirectPassword, DirectConditionalOtp, "OTP when the user has one configured", ct),
            () => AddExecutionAsync(DirectConditionalOtp, "conditional-user-configured", ct),
            () => AddExecutionAsync(DirectConditionalOtp, "direct-grant-validate-otp", ct),
            () => AddExecutionAsync(DirectPassword, DirectOtpProvider, ct),
        };
        foreach (var step in steps)
        {
            var done = await step();
            if (!done.IsSuccess) return done;
        }
        _logger.LogInformation("Created the '{Flow}' flow", DirectFlow);
        return Result.Success();
    }

    private Task<Result> BindDirectFlowAsync(string alias, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Put, "", new { directGrantFlow = alias }, Resource, ct, includeKeycloakMessage: true);

    // ---- Admin API helpers ------------------------------------------------------------------------------------

    private async Task<Result<List<JsonElement>>> ExecutionsAsync(string flow, CancellationToken ct)
    {
        var executions = await _api.GetAsync($"authentication/flows/{Uri.EscapeDataString(flow)}/executions", Resource, ct);
        return executions.IsSuccess ? executions.Value.EnumerateArray().Select(e => e.Clone()).ToList() : executions.Error!;
    }

    private Task<Result> AddExecutionAsync(string flow, string provider, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Post, $"authentication/flows/{Uri.EscapeDataString(flow)}/executions/execution",
            new { provider }, Resource, ct, includeKeycloakMessage: true);

    private Task<Result> AddSubflowAsync(string parent, string alias, string description, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Post, $"authentication/flows/{Uri.EscapeDataString(parent)}/executions/flow",
            new { alias, type = "basic-flow", provider = "registration-page-form", description }, Resource, ct, includeKeycloakMessage: true);

    /// <summary>Changes only the executions whose requirement differs (PUT on the top-level flow, as Keycloak expects).</summary>
    private async Task<Result> SetRequirementsAsync(string flow, IEnumerable<(JsonElement Execution, string Requirement)> wanted, CancellationToken ct)
    {
        foreach (var (execution, requirement) in wanted)
        {
            if (KeycloakAdminApi.GetString(execution, "requirement") == requirement) continue;
            var body = JsonSerializer.Deserialize<Dictionary<string, object?>>(execution.GetRawText())!;
            body["requirement"] = requirement;
            var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"authentication/flows/{Uri.EscapeDataString(flow)}/executions",
                body, Resource, ct, includeKeycloakMessage: true);
            if (!updated.IsSuccess) return updated;
        }
        return Result.Success();
    }

    private static string? Provider(JsonElement execution) => KeycloakAdminApi.GetString(execution, "providerId");

    private static int Level(JsonElement execution) => execution.GetProperty("level").GetInt32();

    private static bool IsFlow(JsonElement execution) =>
        execution.TryGetProperty("authenticationFlow", out var flow) && flow.ValueKind == JsonValueKind.True;

    /// <summary>The sub-flow execution named <paramref name="alias"/> at <paramref name="level"/>.</summary>
    internal static JsonElement? FindFlow(IReadOnlyList<JsonElement> executions, string alias, int level) =>
        executions.Where(e => IsFlow(e) && Level(e) == level && KeycloakAdminApi.GetString(e, "displayName") == alias)
            .Select(e => (JsonElement?)e).FirstOrDefault();

    /// <summary>Direct children of a sub-flow: Keycloak lists executions depth-first with their nesting level.</summary>
    internal static IReadOnlyList<JsonElement> Children(IReadOnlyList<JsonElement> executions, JsonElement parent)
    {
        var parentId = KeycloakAdminApi.GetString(parent, "id");
        var start = executions.ToList().FindIndex(e => KeycloakAdminApi.GetString(e, "id") == parentId);
        var level = Level(parent);
        var children = new List<JsonElement>();
        for (var i = start + 1; i < executions.Count && Level(executions[i]) > level; i++)
            if (Level(executions[i]) == level + 1) children.Add(executions[i]);
        return children;
    }
}
