using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Domain;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Vault;

public sealed class VaultSigningKeyStore(
    HttpClient http,
    IOptions<VaultOptions> opts
) : ISigningKeyVaultWithPrivateRead
{
    private readonly VaultOptions _o = opts.Value;
    private string Path(string kid) => $"{_o.Mount}/data/{_o.Prefix}/{kid}";
    private string MetaPath(string kid) => $"{_o.Mount}/metadata/{_o.Prefix}/{kid}";

    private void AddAuth(HttpRequestMessage r)
    {
        if (!string.IsNullOrEmpty(_o.Token)) r.Headers.Add("X-Vault-Token", _o.Token);
    }

    public async Task<VaultKeyReference> StorePrivateKeyAsync(string kid, RsaKeySize size, string privatePem,
        string publicPem, string publicFingerprint, string realm, CancellationToken ct)
    {
        var path = Path(kid);
        var req = new HttpRequestMessage(HttpMethod.Post, $"{_o.Address}/v1/{path}")
        {
            Content = JsonContent.Create(new
            {
                data = new
                {
                    kid, realm, size = (int)size, private_pem = privatePem, public_pem = publicPem,
                    fingerprint = publicFingerprint
                }
            })
        };
        AddAuth(req);
        var res = await http.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        var ver = doc.RootElement.TryGetProperty("data", out var d) && d.TryGetProperty("metadata", out var m) &&
                  m.TryGetProperty("version", out var v)
            ? v.GetInt32()
            : 1;
        return new VaultKeyReference(path, ver);
    }

    public Task<bool> ExistsAsync(string kid, CancellationToken ct) =>
        ReadPublicAsync(kid, ct).ContinueWith(t => t.Result is not null, ct);

    public async Task<VaultStoredKey?> ReadPublicAsync(string kid, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{_o.Address}/v1/{Path(kid)}");
        AddAuth(req);
        var res = await http.SendAsync(req, ct);
        if (res.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        res.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        var d = doc.RootElement.GetProperty("data").GetProperty("data");
        var meta = doc.RootElement.GetProperty("data").GetProperty("metadata");
        return new VaultStoredKey(d.GetProperty("kid").GetString()!, meta.GetProperty("version").GetInt32(),
            d.GetProperty("public_pem").GetString()!, d.GetProperty("fingerprint").GetString()!,
            meta.GetProperty("created_time").GetDateTimeOffset());
    }

    public async Task<TransientPrivatePem> ReadPrivateAsync(string kid, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{_o.Address}/v1/{Path(kid)}");
        AddAuth(req);
        var res = await http.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var pem = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct)).RootElement.GetProperty("data")
            .GetProperty("data").GetProperty("private_pem").GetString()!;
        return new TransientPrivatePem(pem);
    }

    public async Task<bool> DestroyAsync(string kid, CancellationToken ct)
    {
        var del = new HttpRequestMessage(HttpMethod.Delete, $"{_o.Address}/v1/{MetaPath(kid)}");
        AddAuth(del);
        return (await http.SendAsync(del, ct)).IsSuccessStatusCode;
    }
}