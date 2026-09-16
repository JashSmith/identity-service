using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

public sealed class KeycloakUserProvisioner(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider) : IUserProvisioningService
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    public async Task<UserDto> CreateUserAsync(CreateUserRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Username);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");

        var body = new Dictionary<string, object?>
        {
            ["username"] = request.Username.Trim(),
            ["enabled"] = request.Enabled,
        };
        if (!string.IsNullOrWhiteSpace(request.Email)) body["email"] = request.Email!.Trim();
        if (!string.IsNullOrWhiteSpace(request.FirstName)) body["firstName"] = request.FirstName!.Trim();
        if (!string.IsNullOrWhiteSpace(request.LastName)) body["lastName"] = request.LastName!.Trim();
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

        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/users")
        {
            Content = JsonContent.Create(body)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to create user '{request.Username}': {(int)res.StatusCode} {err}");
        }

        // Keycloak returns 201 with Location header containing the new user id
        var location = res.Headers.Location?.ToString() ?? "";
        var userId = location.Split('/').LastOrDefault()?.Trim() ?? "";

        if (string.IsNullOrEmpty(userId))
        {
            // Fallback: search by username
            var searchReq = new HttpRequestMessage(HttpMethod.Get,
                $"{AdminBase}/{_o.Realm}/users?username={Uri.EscapeDataString(request.Username.Trim())}&exact=true");
            searchReq.Headers.Add("Authorization", $"Bearer {token}");
            var searchRes = await http.SendAsync(searchReq, ct);
            if (searchRes.IsSuccessStatusCode)
            {
                var doc = JsonDocument.Parse(await searchRes.Content.ReadAsStringAsync(ct));
                if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
                    userId = doc.RootElement[0].TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
            }
        }

        if (string.IsNullOrEmpty(userId))
            throw new InvalidOperationException($"User '{request.Username}' created but id could not be resolved.");

        // Fetch full user dto
        var getReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}");
        getReq.Headers.Add("Authorization", $"Bearer {token}");
        var getRes = await http.SendAsync(getReq, ct);
        if (!getRes.IsSuccessStatusCode)
            return new UserDto(userId, request.Username.Trim(), null, request.Enabled, new Dictionary<string, string[]>(StringComparer.Ordinal));
        var userDoc = JsonDocument.Parse(await getRes.Content.ReadAsStringAsync(ct));
        return MapUser(userDoc.RootElement);
    }

    public async Task<UserDto?> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(request);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");

        // GET then merge then PUT to preserve attributes/credentials
        var getReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}");
        getReq.Headers.Add("Authorization", $"Bearer {token}");
        var getRes = await http.SendAsync(getReq, ct);
        if (!getRes.IsSuccessStatusCode) return null;
        var userJson = JsonDocument.Parse(await getRes.Content.ReadAsStringAsync(ct)).RootElement.Clone();
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(userJson.GetRawText())!;
        var mutable = new Dictionary<string, object?>();
        foreach (var kv in dict)
        {
            if (kv.Key == "email" && request.Email is not null) continue;
            if (kv.Key == "firstName" && request.FirstName is not null) continue;
            if (kv.Key == "lastName" && request.LastName is not null) continue;
            if (kv.Key == "enabled" && request.Enabled.HasValue) continue;
            mutable[kv.Key] = kv.Value;
        }
        // Apply updates
        if (request.Email is not null) mutable["email"] = request.Email;
        if (request.FirstName is not null) mutable["firstName"] = request.FirstName;
        if (request.LastName is not null) mutable["lastName"] = request.LastName;
        if (request.Enabled.HasValue) mutable["enabled"] = request.Enabled.Value;

        // Re-serialize via JsonElement round-trip to keep other fields
        var updatedJson = JsonSerializer.Serialize(mutable);
        var putReq = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}")
        {
            Content = new StringContent(updatedJson, System.Text.Encoding.UTF8, "application/json")
        };
        putReq.Headers.Add("Authorization", $"Bearer {token}");
        var putRes = await http.SendAsync(putReq, ct);
        if (!putRes.IsSuccessStatusCode) return null;

        var verifyReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}");
        verifyReq.Headers.Add("Authorization", $"Bearer {token}");
        var verifyRes = await http.SendAsync(verifyReq, ct);
        if (!verifyRes.IsSuccessStatusCode) return null;
        var verifyDoc = JsonDocument.Parse(await verifyRes.Content.ReadAsStringAsync(ct));
        return MapUser(verifyDoc.RootElement);
    }

    public async Task<bool> DeleteUserAsync(string userId, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return false;
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            return res.IsSuccessStatusCode || res.StatusCode == System.Net.HttpStatusCode.NotFound;
        }
        catch { return false; }
    }

    private static UserDto MapUser(JsonElement e)
    {
        var id = e.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
        var username = e.TryGetProperty("username", out var p) ? p.GetString() ?? id : id;
        var enabled = e.TryGetProperty("enabled", out var en) && en.GetBoolean();
        string? displayName = null;
        string? fn = e.TryGetProperty("firstName", out var fnTmp) ? fnTmp.GetString() : null;
        string? ln = e.TryGetProperty("lastName", out var lnTmp) ? lnTmp.GetString() : null;
        if (!string.IsNullOrEmpty(fn) || !string.IsNullOrEmpty(ln))
            displayName = string.Join(" ", new[] { fn, ln }.Where(s => !string.IsNullOrEmpty(s))).Trim();
        if (string.IsNullOrEmpty(displayName)) displayName = null;
        var attrs = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (e.TryGetProperty("attributes", out var at) && at.ValueKind == JsonValueKind.Object)
            foreach (var prop in at.EnumerateObject())
                attrs[prop.Name] = prop.Value.ValueKind == JsonValueKind.Array
                    ? prop.Value.EnumerateArray().Select(v => v.GetString() ?? "").ToArray()
                    : [prop.Value.GetString() ?? ""];
        return new UserDto(id, username, displayName, enabled, attrs);
    }
}
