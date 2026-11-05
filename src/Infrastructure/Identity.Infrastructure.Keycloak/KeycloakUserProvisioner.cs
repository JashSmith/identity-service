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
        if (!string.IsNullOrWhiteSpace(request.PhoneNumber))
        {
            var phone = await AvailablePhoneAsync(request.PhoneNumber, null, ct);
            if (!phone.IsSuccess) return phone.Error!;
            body["attributes"] = new Dictionary<string, string[]> { [ProtectedUserAttributes.PhoneNumber] = [phone.Value] };
        }
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
        if (request.Attributes is not null || request.PhoneNumber is not null)
        {
            var attributes = user.TryGetValue("attributes", out var existing) && existing is JsonElement { ValueKind: JsonValueKind.Object } json
                ? JsonSerializer.Deserialize<Dictionary<string, object?>>(json.GetRawText()) ?? new()
                : new Dictionary<string, object?>();
            foreach (var (key, values) in request.Attributes ?? new Dictionary<string, string[]>()) attributes[key] = values;
            if (request.PhoneNumber is { Length: 0 } || (request.PhoneNumber is not null && string.IsNullOrWhiteSpace(request.PhoneNumber)))
                attributes.Remove(ProtectedUserAttributes.PhoneNumber);
            else if (request.PhoneNumber is not null)
            {
                var phone = await AvailablePhoneAsync(request.PhoneNumber, userId, ct);
                if (!phone.IsSuccess) return phone.Error!;
                attributes[ProtectedUserAttributes.PhoneNumber] = new[] { phone.Value };
            }
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

    /// <summary>
    /// The normalised number (+989...) when no other user of the realm has it. Keycloak finds the user signing in with
    /// an SMS code by this number, so it must be unique. Errors: user.invalid_phone_number, user.phone_number_taken (409).
    /// </summary>
    private async Task<Result<string>> AvailablePhoneAsync(string typed, string? userId, CancellationToken ct)
    {
        var phone = Identity.Application.Sms.PhoneNumbers.NormalizeIranMobile(typed);
        if (phone is null)
            return Error.Validation("user.invalid_phone_number", "PhoneNumber is not an Iranian mobile number (e.g. 09121234567).");
        var found = await _api.GetAsync(
            $"users?q={Uri.EscapeDataString($"{ProtectedUserAttributes.PhoneNumber}:{phone}")}&briefRepresentation=false&max=5", Resource, ct);
        if (!found.IsSuccess) return found.Error!;
        var taken = found.Value.EnumerateArray().Any(u => KeycloakAdminApi.GetString(u, "id") != userId &&
            u.TryGetProperty("attributes", out var a) && a.TryGetProperty(ProtectedUserAttributes.PhoneNumber, out var values) &&
            values.EnumerateArray().Any(v => v.GetString() == phone));
        return taken
            ? Error.Conflict("user.phone_number_taken", "Another user already has this mobile number.")
            : Result<string>.Success(phone);
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
        var phone = attrs.TryGetValue(ProtectedUserAttributes.PhoneNumber, out var phones) ? phones.FirstOrDefault() : null;
        return new UserDto(id, username, displayName.Length == 0 ? null : displayName, enabled, attrs, PhoneNumber: phone);
    }
}
