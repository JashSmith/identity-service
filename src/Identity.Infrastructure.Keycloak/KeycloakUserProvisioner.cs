using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>Creates, updates and deletes Keycloak users of the configured realm.</summary>
public sealed class KeycloakUserProvisioner(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakUserProvisioner>? logger = null) : IUserProvisioningService
{
    private const string Resource = "user";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider,
        (ILogger?)logger ?? NullLogger.Instance);

    private static Error UserNotFound(string id) => Error.NotFound("user.not_found", $"User '{id}' was not found.");

    public async Task<Result<UserDto>> GetAsync(string userId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId)) return UserNotFound(userId);
        var user = await _api.GetAsync($"users/{Uri.EscapeDataString(userId)}", Resource, ct);
        if (!user.IsSuccess) return Renamed(user.Error!, userId);
        return MapUser(user.Value);
    }

    public async Task<Result<UserDto>> CreateUserAsync(CreateUserRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Username);

        var body = new Dictionary<string, object?>
        {
            ["username"] = request.Username.Trim(),
            ["enabled"] = request.Enabled,
        };
        if (!string.IsNullOrWhiteSpace(request.Email)) body["email"] = request.Email.Trim();
        if (!string.IsNullOrWhiteSpace(request.FirstName)) body["firstName"] = request.FirstName.Trim();
        if (!string.IsNullOrWhiteSpace(request.LastName)) body["lastName"] = request.LastName.Trim();
        if (request.Credentials is not null)
        {
            body["credentials"] = new[]
            {
                new Dictionary<string, object?>
                {
                    ["type"] = "password",
                    ["value"] = request.Credentials.Password,
                    ["temporary"] = request.Credentials.Temporary,
                }
            };
        }

        // Keycloak's own message (duplicate username/email, password policy) is useful to the admin.
        var created = await _api.CreateAsync("users", body, Resource, ct, includeKeycloakMessage: true);
        if (!created.IsSuccess) return created.Error!;
        return await GetAsync(created.Value, ct);
    }

    public async Task<Result<UserDto>> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        // Defense in depth: authorization attributes are never written through a generic update.
        var protectedKeys = ProtectedUserAttributes.FindIn(request.Attributes);
        if (protectedKeys.Count > 0)
            return Error.Validation("user.protected_attributes",
                $"Attributes {string.Join(", ", protectedKeys)} cannot be set through a user update.");

        var current = await _api.GetAsync($"users/{Uri.EscapeDataString(userId)}", Resource, ct);
        if (!current.IsSuccess) return Renamed(current.Error!, userId);

        // PUT replaces the representation, so start from the current one and change only what was sent.
        var user = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(current.Value.GetRawText())!
            .ToDictionary(kv => kv.Key, kv => (object?)kv.Value, StringComparer.Ordinal);
        if (request.Email is not null) user["email"] = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email.Trim();
        if (request.FirstName is not null) user["firstName"] = string.IsNullOrWhiteSpace(request.FirstName) ? null : request.FirstName.Trim();
        if (request.LastName is not null) user["lastName"] = string.IsNullOrWhiteSpace(request.LastName) ? null : request.LastName.Trim();
        if (request.Enabled.HasValue) user["enabled"] = request.Enabled.Value;
        if (!string.IsNullOrWhiteSpace(request.Username)) user["username"] = request.Username.Trim();
        if (request.EmailVerified.HasValue) user["emailVerified"] = request.EmailVerified.Value;
        if (request.Attributes is not null)
        {
            var attributes = user.TryGetValue("attributes", out var existing) && existing is JsonElement { ValueKind: JsonValueKind.Object } json
                ? JsonSerializer.Deserialize<Dictionary<string, object?>>(json.GetRawText()) ?? new()
                : new Dictionary<string, object?>();
            foreach (var (key, values) in request.Attributes) attributes[key] = values;
            user["attributes"] = attributes;
        }

        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"users/{Uri.EscapeDataString(userId)}", user,
            Resource, ct, includeKeycloakMessage: true);
        if (!updated.IsSuccess) return Renamed(updated.Error!, userId);
        return await GetAsync(userId, ct);
    }

    public async Task<Result> DeleteUserAsync(string userId, CancellationToken ct)
    {
        var deleted = await _api.SendWithoutResultAsync(HttpMethod.Delete, $"users/{Uri.EscapeDataString(userId)}", null, Resource, ct);
        return deleted.IsSuccess ? deleted : Renamed(deleted.Error!, userId);
    }

    public async Task<Result> ResetPasswordAsync(string userId, string newPassword, bool temporary, CancellationToken ct)
    {
        var body = new Dictionary<string, object?> { ["type"] = "password", ["value"] = newPassword, ["temporary"] = temporary };
        var reset = await _api.SendWithoutResultAsync(HttpMethod.Put, $"users/{Uri.EscapeDataString(userId)}/reset-password",
            body, Resource, ct, includeKeycloakMessage: true);
        return reset.IsSuccess ? reset : Renamed(reset.Error!, userId);
    }

    /// <summary>Keycloak's generic 404 becomes a user.not_found that names the user.</summary>
    private static Error Renamed(Error error, string userId) =>
        error.Kind == ErrorKind.NotFound ? UserNotFound(userId) : error;

    private static UserDto MapUser(JsonElement e)
    {
        var id = KeycloakAdminApi.GetString(e, "id") ?? "";
        var username = KeycloakAdminApi.GetString(e, "username") ?? id;
        var enabled = e.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True;
        var firstName = KeycloakAdminApi.GetString(e, "firstName");
        var lastName = KeycloakAdminApi.GetString(e, "lastName");
        var displayName = string.Join(" ", new[] { firstName, lastName }.Where(s => !string.IsNullOrEmpty(s))).Trim();

        var attrs = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (e.TryGetProperty("attributes", out var at) && at.ValueKind == JsonValueKind.Object)
            foreach (var prop in at.EnumerateObject())
                attrs[prop.Name] = prop.Value.ValueKind == JsonValueKind.Array
                    ? prop.Value.EnumerateArray().Select(v => v.GetString() ?? "").ToArray()
                    : [prop.Value.GetString() ?? ""];
        if (KeycloakAdminApi.GetString(e, "email") is { } email) attrs["email"] = [email];
        if (e.TryGetProperty("emailVerified", out var ev) && ev.ValueKind is JsonValueKind.True or JsonValueKind.False)
            attrs["emailVerified"] = [ev.GetBoolean() ? "true" : "false"];
        if (firstName is not null) attrs["firstName"] = [firstName];
        if (lastName is not null) attrs["lastName"] = [lastName];
        return new UserDto(id, username, displayName.Length == 0 ? null : displayName, enabled, attrs);
    }
}
