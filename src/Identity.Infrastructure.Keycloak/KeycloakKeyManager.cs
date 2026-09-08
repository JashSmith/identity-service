using System.Net.Http.Json;using System.Text.Json;using Identity.Application;using Identity.Domain;using Microsoft.Extensions.Options;
namespace Identity.Infrastructure.Keycloak;
public sealed class KeycloakKeyManager(HttpClient http, IOptions<KeycloakOptions> opts) : IKeycloakKeyManager
{
    private readonly KeycloakOptions _o=opts.Value;
    private string AdminBase=>$"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private string JwksUrl(string realm)=>$"{_o.BaseUrl.TrimEnd('/')}/realms/{realm}/protocol/openid-connect/certs";
    private async Task<string> GetAdminTokenAsync(CancellationToken ct){
        var form=new FormUrlEncodedContent(new Dictionary<string,string>{["grant_type"]="client_credentials",["client_id"]=_o.AdminClientId,["client_secret"]=_o.AdminClientSecret});
        try{var res=await http.PostAsync($"{_o.BaseUrl.TrimEnd('/')}/realms/master/protocol/openid-connect/token",form,ct); if(!res.IsSuccessStatusCode) return ""; var doc=JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct)); return doc.RootElement.TryGetProperty("access_token",out var t)?t.GetString()!:"";}catch{return "";}
    }
    public async Task<IReadOnlyCollection<KeycloakComponentDto>> ListRsaComponentsAsync(string realm,CancellationToken ct){
        var token=await GetAdminTokenAsync(ct); var req=new HttpRequestMessage(HttpMethod.Get,$"{AdminBase}/{realm}/components?providerType=org.keycloak.keys.KeyProvider"); if(!string.IsNullOrEmpty(token)) req.Headers.Add("Authorization",$"Bearer {token}");
        try{var res=await http.SendAsync(req,ct); if(!res.IsSuccessStatusCode) return Array.Empty<KeycloakComponentDto>(); var list=await res.Content.ReadFromJsonAsync<List<JsonElement>>(cancellationToken:ct)??[]; return list.Where(e=>e.TryGetProperty("providerId",out var p)&&p.GetString()=="rsa").Select(e=>new KeycloakComponentDto(e.GetProperty("id").GetString()!,e.GetProperty("name").GetString()!,"rsa","org.keycloak.keys.KeyProvider",new Dictionary<string,IReadOnlyCollection<string>>())).ToList();}catch{return Array.Empty<KeycloakComponentDto>();}
    }
    public async Task<KeycloakComponentDto> RegisterPassiveAsync(string realm,string kid,RsaKeySize size,string privatePem,string publicPem,CancellationToken ct){
        var token=await GetAdminTokenAsync(ct);
        var body=new{name=kid,providerId="rsa",providerType="org.keycloak.keys.KeyProvider",config=new Dictionary<string,List<string>>{["kid"]=[kid],["priority"]=["100"],["enabled"]=["true"],["active"]=["false"],["algorithm"]=["RS256"],["privateKey"]=[privatePem],["certificate"]=[publicPem]}};
        var req=new HttpRequestMessage(HttpMethod.Post,$"{AdminBase}/{realm}/components"){Content=JsonContent.Create(body)}; if(!string.IsNullOrEmpty(token)) req.Headers.Add("Authorization",$"Bearer {token}");
        var res=await http.SendAsync(req,ct); res.EnsureSuccessStatusCode(); var loc=res.Headers.Location?.ToString()??""; var id=loc.Split('/').LastOrDefault()??kid;
        return new KeycloakComponentDto(id,kid,"rsa","org.keycloak.keys.KeyProvider",new Dictionary<string,IReadOnlyCollection<string>>());
    }
    public Task ActivateAsync(string realm,string componentId,CancellationToken ct)=>UpdateAsync(realm,componentId,ct);
    public Task PassivateAsync(string realm,string componentId,CancellationToken ct)=>UpdateAsync(realm,componentId,ct);
    public Task DisableAsync(string realm,string componentId,CancellationToken ct)=>UpdateAsync(realm,componentId,ct);
    public async Task RemoveAsync(string realm,string componentId,CancellationToken ct){var t=await GetAdminTokenAsync(ct); var req=new HttpRequestMessage(HttpMethod.Delete,$"{AdminBase}/{realm}/components/{componentId}"); if(!string.IsNullOrEmpty(t)) req.Headers.Add("Authorization",$"Bearer {t}"); await http.SendAsync(req,ct);}
    private async Task UpdateAsync(string realm,string id,CancellationToken ct){var t=await GetAdminTokenAsync(ct); var req=new HttpRequestMessage(HttpMethod.Get,$"{AdminBase}/{realm}/components/{id}"); if(!string.IsNullOrEmpty(t)) req.Headers.Add("Authorization",$"Bearer {t}"); var res=await http.SendAsync(req,ct); if(!res.IsSuccessStatusCode) return; var el=JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct)).RootElement; var body=JsonSerializer.Deserialize<Dictionary<string,object>>(el.GetRawText())??new(); var put=new HttpRequestMessage(HttpMethod.Put,$"{AdminBase}/{realm}/components/{id}"){Content=JsonContent.Create(body)}; if(!string.IsNullOrEmpty(t)) put.Headers.Add("Authorization",$"Bearer {t}"); await http.SendAsync(put,ct);}
    public async Task<JwksVerificationResult> VerifyInJwksAsync(string realm,string kid,string publicPem,CancellationToken ct){var s=await GetJwksAsync(realm,ct); var f=s.Keys.FirstOrDefault(k=>k.Kid==kid); return f is null?new(false,false,"kid not in JWKS"):new(true,true);}
    public async Task<JwksSnapshot> GetJwksAsync(string realm,CancellationToken ct){try{var res=await http.GetAsync(JwksUrl(realm),ct); if(!res.IsSuccessStatusCode) return new(DateTimeOffset.UtcNow,Array.Empty<JwkEntry>()); var doc=JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct)); var keys=doc.RootElement.TryGetProperty("keys",out var ks)?ks.EnumerateArray().Select(k=>new JwkEntry(k.TryGetProperty("kid",out var kid)?kid.GetString()!:"",k.TryGetProperty("kty",out var kty)?kty.GetString()!:"",k.TryGetProperty("alg",out var alg)?alg.GetString()!:"",k.TryGetProperty("use",out var use)?use.GetString()!:"",k.TryGetProperty("n",out var n)?n.GetString()!:"",k.TryGetProperty("e",out var e2)?e2.GetString()!:"")).ToList():new List<JwkEntry>(); return new(DateTimeOffset.UtcNow,keys);}catch{return new(DateTimeOffset.UtcNow,Array.Empty<JwkEntry>());}}
}
