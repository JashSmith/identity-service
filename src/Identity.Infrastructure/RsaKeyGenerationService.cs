using System.Security.Cryptography;
using System.Text;
using Identity.Domain;

namespace Identity.Infrastructure;

/// <summary>RSA generation + import. Produces public PEM/fingerprint and a transient private PEM caller must dispose.</summary>
public sealed class RsaKeyGenerationService : Identity.Application.IKeyGenerationService
{
    public (string PublicPem, Identity.Application.TransientPrivatePem Private, string PublicFingerprint) Generate(
        RsaKeySize size, string kid)
    {
        using var rsa = RSA.Create((int)size);
        var publicPem = ExportPublicPem(rsa);
        var privatePem = ExportPrivatePem(rsa);
        var fingerprint = Sha256Fingerprint(publicPem);
        return (publicPem, new Identity.Application.TransientPrivatePem(privatePem), fingerprint);
    }

    public (string PublicPem, Identity.Application.TransientPrivatePem Private, RsaKeySize Size, string
        PublicFingerprint) ParseImport(string privatePem, string kid)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privatePem);
        var size = rsa.KeySize switch
        {
            2048 => RsaKeySize.Rsa2048, 3072 => RsaKeySize.Rsa3072, 4096 => RsaKeySize.Rsa4096,
            _ => throw new ArgumentException($"Unsupported RSA size {rsa.KeySize}.", nameof(privatePem))
        };
        var publicPem = ExportPublicPem(rsa);
        // Re-export private as PKCS#8 for canonical Vault storage.
        var canonicalPrivate = ExportPrivatePem(rsa);
        var fingerprint = Sha256Fingerprint(publicPem);
        return (publicPem, new Identity.Application.TransientPrivatePem(canonicalPrivate), size, fingerprint);
    }

    private static string ExportPublicPem(RSA rsa)
    {
        var spki = rsa.ExportSubjectPublicKeyInfo();
        return "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(spki, Base64FormattingOptions.InsertLineBreaks) +
               "\n-----END PUBLIC KEY-----";
    }

    private static string ExportPrivatePem(RSA rsa)
    {
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        return "-----BEGIN PRIVATE KEY-----\n" +
               Convert.ToBase64String(pkcs8, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PRIVATE KEY-----";
    }

    private static string Sha256Fingerprint(string publicPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicPem);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        return "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
    }
}