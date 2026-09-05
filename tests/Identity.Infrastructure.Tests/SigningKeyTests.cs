using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Identity.Infrastructure;

namespace Identity.Infrastructure.Tests;

public sealed class SigningKeyTests
{
    [Fact]
    public void Provider_reuses_persisted_key_across_instances()
    {
        var path = Path.Combine(Path.GetTempPath(), $"identity-keys-{Guid.NewGuid():N}.json");
        try
        {
            using var first = CreateProvider(path);
            var firstParameters = first.PublicKey.Parameters;

            using var second = CreateProvider(path);
            var secondParameters = second.PublicKey.Parameters;

            Assert.Equal(first.KeyId, second.KeyId);
            Assert.Equal(firstParameters.Modulus, secondParameters.Modulus);
            Assert.Equal(firstParameters.Exponent, secondParameters.Exponent);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Provider_rotates_and_keeps_previous_public_key_during_overlap()
    {
        var path = Path.Combine(Path.GetTempPath(), $"identity-keys-{Guid.NewGuid():N}.json");
        try
        {
            using (var initial = CreateProvider(path))
            {
                Assert.Single(initial.PublicKeys);
            }

            Thread.Sleep(TimeSpan.FromSeconds(2));
            using var rotated = CreateProvider(path);
            Assert.Equal(2, rotated.PublicKeys.Count);
            Assert.Contains(rotated.PublicKeys, key => key.KeyId == "development-key-1");
            Assert.NotEqual("development-key-1", rotated.KeyId);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Public_keys_are_valid_security_keys_with_key_ids()
    {
        var path = Path.Combine(Path.GetTempPath(), $"identity-keys-{Guid.NewGuid():N}.json");
        try
        {
            using var provider = CreateProvider(path);
            Assert.All(provider.PublicKeys, key =>
            {
                Assert.IsType<RsaSecurityKey>(key);
                Assert.False(string.IsNullOrWhiteSpace(key.KeyId));
                Assert.NotNull(key.Parameters.Modulus);
                Assert.NotNull(key.Parameters.Exponent);
            });
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    private static JwtSigningKeyProvider CreateProvider(string path)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Identity:Tokens:Issuer"] = "https://identity.test",
                ["Identity:Tokens:Audience"] = "identity-api",
                ["Identity:Tokens:KeyId"] = "development-key-1",
                ["Identity:Tokens:StoragePath"] = path,
                ["Identity:Tokens:ActiveKeyLifetime"] = "00:00:01",
                ["Identity:Tokens:KeyOverlapLifetime"] = "1.00:00:00",
                ["Identity:Tokens:AutomaticRotation"] = "true"
            })
            .Build();
        return new JwtSigningKeyProvider(configuration);
    }
}
