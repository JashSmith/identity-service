using System.Text.Json;
using Identity.Application;
using Identity.Application.Schedules;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Puts the Avash access-schedule authenticator (keycloak/extensions) into the realm's browser flow, so weekly
/// schedules also apply on Keycloak's own login pages (SSO). Keycloak's built-in "browser" flow cannot be changed,
/// so it is copied to <see cref="FlowAlias"/>, the authenticator is added as REQUIRED after the username/password
/// form, and the copy becomes the realm's browser flow. A realm whose administrators chose another custom flow is
/// left alone (logged), and so is a Keycloak without the extension.
/// </summary>
public sealed class KeycloakScheduleAuthenticatorSetup(
    HttpClient http,
    IOptions<KeycloakOptions> keycloak,
    KeycloakAdminTokenProvider tokenProvider,
    AccessScheduleOptions schedules,
    ILogger<KeycloakScheduleAuthenticatorSetup>? logger = null)
{
    public const string ProviderId = "avash-access-schedule";
    public const string FlowAlias = "avash-browser";
    private const string BuiltInBrowserFlow = "browser";
    private const string Resource = "auth_flow";
    private const string ConfigAlias = "avash-access-schedule";

    private readonly ILogger _logger = (ILogger?)logger ?? NullLogger.Instance;
    private readonly KeycloakAdminApi _api = new(http, keycloak.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    public async Task<Result> EnsureAsync(CancellationToken ct)
    {
        var providers = await _api.GetAsync("authentication/authenticator-providers", Resource, ct);
        if (!providers.IsSuccess) return providers.Error!;
        if (providers.Value.EnumerateArray().All(p => KeycloakAdminApi.GetString(p, "id") != ProviderId))
        {
            _logger.LogWarning("Keycloak has no '{Provider}' authenticator (build keycloak/extensions); weekly schedules are not " +
                               "enforced on Keycloak's own login pages", ProviderId);
            return Result.Success();
        }

        var realm = await _api.GetAsync("", Resource, ct);
        if (!realm.IsSuccess) return realm.Error!;
        var browserFlow = KeycloakAdminApi.GetString(realm.Value, "browserFlow") ?? BuiltInBrowserFlow;
        if (browserFlow is not (BuiltInBrowserFlow or FlowAlias))
        {
            _logger.LogWarning("Realm uses its own browser flow '{Flow}'; add the '{Provider}' authenticator to it manually",
                browserFlow, ProviderId);
            return Result.Success();
        }

        var flow = await EnsureFlowAsync(ct);
        if (!flow.IsSuccess) return flow;
        var execution = await EnsureExecutionAsync(ct);
        if (!execution.IsSuccess) return execution.Error!;
        var config = await EnsureConfigAsync(execution.Value, ct);
        if (!config.IsSuccess) return config;

        return browserFlow == FlowAlias
            ? Result.Success()
            : await _api.SendWithoutResultAsync(HttpMethod.Put, "", new { browserFlow = FlowAlias }, Resource, ct, includeKeycloakMessage: true);
    }

    private async Task<Result> EnsureFlowAsync(CancellationToken ct)
    {
        var flows = await _api.GetAsync("authentication/flows", Resource, ct);
        if (!flows.IsSuccess) return flows.Error!;
        if (flows.Value.EnumerateArray().Any(f => KeycloakAdminApi.GetString(f, "alias") == FlowAlias)) return Result.Success();

        var copied = await _api.SendWithoutResultAsync(HttpMethod.Post, $"authentication/flows/{BuiltInBrowserFlow}/copy",
            new { newName = FlowAlias }, Resource, ct, includeKeycloakMessage: true);
        if (copied.IsSuccess) _logger.LogInformation("Copied the browser flow to '{Flow}'", FlowAlias);
        return copied;
    }

    /// <summary>The authenticator's execution in the flow (added to the forms sub-flow when missing), REQUIRED.</summary>
    private async Task<Result<JsonElement>> EnsureExecutionAsync(CancellationToken ct)
    {
        var path = $"authentication/flows/{Uri.EscapeDataString(FlowAlias)}/executions";
        var executions = await _api.GetAsync(path, Resource, ct);
        if (!executions.IsSuccess) return executions.Error!;

        var existing = Find(executions.Value);
        if (existing is null)
        {
            // The sub-flow that holds the username/password form ("<flow> forms" in a copied browser flow).
            var list = executions.Value.EnumerateArray().ToList();
            var form = list.FindIndex(e => KeycloakAdminApi.GetString(e, "providerId") == "auth-username-password-form");
            if (form < 0) return Error.Unexpected("auth_flow.no_password_form", $"Flow '{FlowAlias}' has no username/password form.");
            var level = list[form].GetProperty("level").GetInt32();
            var parent = list.Take(form).Last(e => e.TryGetProperty("authenticationFlow", out var sub) && sub.ValueKind == JsonValueKind.True &&
                                                    e.GetProperty("level").GetInt32() == level - 1);
            var subflow = KeycloakAdminApi.GetString(parent, "displayName")!;

            var added = await _api.SendWithoutResultAsync(HttpMethod.Post,
                $"authentication/flows/{Uri.EscapeDataString(subflow)}/executions/execution", new { provider = ProviderId },
                Resource, ct, includeKeycloakMessage: true);
            if (!added.IsSuccess) return added.Error!;
            executions = await _api.GetAsync(path, Resource, ct);
            if (!executions.IsSuccess) return executions.Error!;
            existing = Find(executions.Value);
            if (existing is null) return Error.Unexpected("auth_flow.execution_missing", "The schedule authenticator was not added to the flow.");
            _logger.LogInformation("Added the schedule authenticator to '{Subflow}'", subflow);
        }

        if (KeycloakAdminApi.GetString(existing.Value, "requirement") == "REQUIRED") return existing.Value;
        var body = JsonSerializer.Deserialize<Dictionary<string, object?>>(existing.Value.GetRawText())!;
        body["requirement"] = "REQUIRED";
        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, path, body, Resource, ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? existing.Value : updated.Error!;
    }

    private static JsonElement? Find(JsonElement executions) =>
        executions.EnumerateArray().Where(e => KeycloakAdminApi.GetString(e, "providerId") == ProviderId).Select(e => (JsonElement?)e).FirstOrDefault();

    /// <summary>The authenticator reads the schedules' time zone from its execution config.</summary>
    private async Task<Result> EnsureConfigAsync(JsonElement execution, CancellationToken ct)
    {
        var wanted = new Dictionary<string, string> { ["timeZone"] = schedules.TimeZone };
        if (KeycloakAdminApi.GetString(execution, "authenticationConfig") is not { } configId)
        {
            var executionId = KeycloakAdminApi.GetString(execution, "id")!;
            return await _api.SendWithoutResultAsync(HttpMethod.Post, $"authentication/executions/{Uri.EscapeDataString(executionId)}/config",
                new { alias = ConfigAlias, config = wanted }, Resource, ct, includeKeycloakMessage: true);
        }

        var configPath = $"authentication/config/{Uri.EscapeDataString(configId)}";
        var current = await _api.GetAsync(configPath, Resource, ct);
        if (!current.IsSuccess) return current.Error!;
        if (current.Value.TryGetProperty("config", out var c) && KeycloakAdminApi.GetString(c, "timeZone") == schedules.TimeZone)
            return Result.Success();
        return await _api.SendWithoutResultAsync(HttpMethod.Put, configPath,
            new { id = configId, alias = KeycloakAdminApi.GetString(current.Value, "alias") ?? ConfigAlias, config = wanted },
            Resource, ct, includeKeycloakMessage: true);
    }
}
