using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.TenantProvisioning;

// Creates the Keycloak realm of a new tenant. Run by an operator with master-realm credentials; the gateway
// itself never holds them. Usage:
//   identity-tenant-provisioning --keycloak https://kc.example --realm branch-north --display-name "شعبه شمال" --out branch-north.env
// Master credentials: --master-user (password from KEYCLOAK_MASTER_PASSWORD or a hidden prompt), or
// --master-client-id (secret from KEYCLOAK_MASTER_CLIENT_SECRET) for a master service account with create-realm.

var options = Arguments.Parse(args);
if (options is null)
{
    Console.Error.WriteLine(Arguments.Usage);
    return 2;
}

var request = new TenantRequest(options.Realm, options.DisplayName, options.AdminUsername);
if (RealmTemplate.Validate(request) is { } invalid)
{
    Console.Error.WriteLine(invalid);
    return 2;
}
if (File.Exists(options.OutputFile))
{
    Console.Error.WriteLine($"{options.OutputFile} already exists; choose another --out so no secret is overwritten.");
    return 2;
}

using var http = new HttpClient { BaseAddress = new Uri(options.KeycloakUrl.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(30) };

var token = await MasterTokenAsync(http, options);
if (token is null) return 1;
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

using (var existing = await http.GetAsync($"admin/realms/{Uri.EscapeDataString(request.Realm)}"))
{
    if (existing.IsSuccessStatusCode)
    {
        Console.Error.WriteLine($"Realm '{request.Realm}' already exists; nothing was changed.");
        return 1;
    }
    if (existing.StatusCode != HttpStatusCode.NotFound)
    {
        Console.Error.WriteLine($"Checking the realm failed with HTTP {(int)existing.StatusCode}.");
        return 1;
    }
}

var secrets = TenantSecrets.Generate();
var realm = RealmTemplate.Render(RealmTemplate.Load(), request, secrets);
using (var created = await http.PostAsJsonAsync("admin/realms", realm))
{
    if (!created.IsSuccessStatusCode)
    {
        // Keycloak's message explains template problems; it holds no secret.
        Console.Error.WriteLine($"Creating the realm failed with HTTP {(int)created.StatusCode}: {await created.Content.ReadAsStringAsync()}");
        return 1;
    }
}

await File.WriteAllTextAsync(options.OutputFile, RealmTemplate.Configuration(request, secrets));
Console.WriteLine($"Realm '{request.Realm}' created.");
Console.WriteLine($"Gateway and console settings, client secrets and the administrator's temporary password: {Path.GetFullPath(options.OutputFile)}");
Console.WriteLine("Add the settings to the gateway and console configuration and restart them; the gateway bootstrap prepares the realm.");
return 0;

static async Task<string?> MasterTokenAsync(HttpClient http, Arguments options)
{
    var form = new Dictionary<string, string>();
    if (options.MasterClientId is { } clientId)
    {
        var secret = Environment.GetEnvironmentVariable("KEYCLOAK_MASTER_CLIENT_SECRET");
        if (string.IsNullOrEmpty(secret))
        {
            Console.Error.WriteLine("Set KEYCLOAK_MASTER_CLIENT_SECRET for --master-client-id.");
            return null;
        }
        form["grant_type"] = "client_credentials";
        form["client_id"] = clientId;
        form["client_secret"] = secret;
    }
    else
    {
        var password = Environment.GetEnvironmentVariable("KEYCLOAK_MASTER_PASSWORD") ?? Arguments.ReadHidden($"Password of master user '{options.MasterUser}': ");
        form["grant_type"] = "password";
        form["client_id"] = "admin-cli";
        form["username"] = options.MasterUser;
        form["password"] = password;
    }

    using var response = await http.PostAsync("realms/master/protocol/openid-connect/token", new FormUrlEncodedContent(form));
    if (!response.IsSuccessStatusCode)
    {
        Console.Error.WriteLine($"Signing in to the master realm failed with HTTP {(int)response.StatusCode}.");
        return null;
    }
    var json = await response.Content.ReadFromJsonAsync<JsonElement>();
    return json.GetProperty("access_token").GetString();
}

internal sealed record Arguments(string KeycloakUrl, string Realm, string DisplayName, string AdminUsername,
    string MasterUser, string? MasterClientId, string OutputFile)
{
    public const string Usage = """
        Usage: identity-tenant-provisioning --keycloak <url> --realm <name> --display-name <text> [--admin <user>]
               [--master-user <user> | --master-client-id <client>] [--out <file>]
          --admin             first administrator of the tenant (default: admin)
          --master-user       master-realm administrator (default: admin); password from KEYCLOAK_MASTER_PASSWORD or a prompt
          --master-client-id  master-realm service account with create-realm; secret from KEYCLOAK_MASTER_CLIENT_SECRET
          --out               settings file to write (default: <realm>.tenant.env); never overwritten
        """;

    public static Arguments? Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length) return null;
            values[args[i][2..]] = args[++i];
        }
        if (!values.TryGetValue("keycloak", out var url) || !values.TryGetValue("realm", out var realm)) return null;
        return new Arguments(url, realm, values.GetValueOrDefault("display-name") ?? realm, values.GetValueOrDefault("admin") ?? "admin",
            values.GetValueOrDefault("master-user") ?? "admin", values.GetValueOrDefault("master-client-id"),
            values.GetValueOrDefault("out") ?? $"{realm}.tenant.env");
    }

    public static string ReadHidden(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
        var password = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace && password.Length > 0) password.Length--;
            else if (!char.IsControl(key.KeyChar)) password.Append(key.KeyChar);
        }
        Console.WriteLine();
        return password.ToString();
    }
}
