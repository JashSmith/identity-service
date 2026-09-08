namespace Identity.Infrastructure.Vault;
public sealed class VaultOptions{public string Address{get;set;}="http://localhost:8200";public string Token{get;set;}="";public string Mount{get;set;}="secret";public string Prefix{get;set;}="identity/keys";public TimeSpan Timeout{get;set;}=TimeSpan.FromSeconds(10);}
