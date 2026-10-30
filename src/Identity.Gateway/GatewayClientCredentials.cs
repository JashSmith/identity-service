namespace Identity.Gateway;

/// <summary>
/// Decides which client credentials a proxied Keycloak token request is sent with.
/// The gateway authenticates as its own confidential client only for flows where the caller
/// already proves possession of a user credential (password grant) or a refresh token.
/// It never lends its secret to the client_credentials grant: machine clients must use their
/// own Keycloak client and secret.
/// </summary>
public static class GatewayClientCredentials
{
    public enum Outcome
    {
        /// <summary>The form is ready to be forwarded to Keycloak.</summary>
        Forward,

        /// <summary>The gateway client secret is not configured.</summary>
        MissingGatewaySecret,

        /// <summary>client_credentials was requested for the gateway's own client.</summary>
        ClientCredentialsNotAllowed
    }

    public static Outcome Apply(IDictionary<string, string> form, string gatewayClientId, string? gatewayClientSecret)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentException.ThrowIfNullOrWhiteSpace(gatewayClientId);

        form.TryGetValue("client_id", out var clientId);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            clientId = gatewayClientId;
        }

        // Callers that name another client authenticate as that client with their own secret.
        if (!string.Equals(clientId, gatewayClientId, StringComparison.OrdinalIgnoreCase))
        {
            return Outcome.Forward;
        }

        if (form.TryGetValue("grant_type", out var grantType) &&
            string.Equals(grantType, "client_credentials", StringComparison.OrdinalIgnoreCase))
        {
            return Outcome.ClientCredentialsNotAllowed;
        }

        if (string.IsNullOrWhiteSpace(gatewayClientSecret))
        {
            return Outcome.MissingGatewaySecret;
        }

        form["client_id"] = gatewayClientId;
        form["client_secret"] = gatewayClientSecret;
        return Outcome.Forward;
    }
}
