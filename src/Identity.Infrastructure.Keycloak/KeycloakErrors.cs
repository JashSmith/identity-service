using System.Net;
using Identity.Application;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Translates Keycloak Admin API failures into application errors. Keycloak's raw response bodies are
/// logged (truncated) for operators and never returned to API callers.
/// </summary>
public static class KeycloakErrors
{
    private const int MaxLoggedBodyLength = 500;

    public static readonly Error AdminTokenUnavailable = Error.Unavailable(
        "keycloak.admin_token_unavailable", "The gateway could not authenticate to Keycloak.");

    public static readonly Error Unreachable = Error.Unavailable(
        "keycloak.unreachable", "Keycloak could not be reached.");

    /// <summary>
    /// Maps a non-success Keycloak response for <paramref name="resource"/> (e.g. "role", "user") to an error
    /// whose code starts with that resource name.
    /// </summary>
    public static async Task<Error> FromResponseAsync(
        HttpResponseMessage response, string resource, ILogger logger, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);

        var body = response.Content is null ? string.Empty : await response.Content.ReadAsStringAsync(ct);
        if (body.Length > MaxLoggedBodyLength) body = body[..MaxLoggedBodyLength];
        logger.LogWarning("Keycloak answered {Status} for {Method} {Path}: {Body}",
            (int)response.StatusCode, response.RequestMessage?.Method, response.RequestMessage?.RequestUri?.AbsolutePath, body);

        return response.StatusCode switch
        {
            HttpStatusCode.NotFound => Error.NotFound($"{resource}.not_found", $"The {resource} was not found."),
            HttpStatusCode.Conflict => Error.Conflict($"{resource}.conflict", $"The {resource} conflicts with existing data."),
            HttpStatusCode.BadRequest => Error.Validation($"{resource}.rejected", $"Keycloak rejected the {resource} request."),
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => Error.Upstream(
                "keycloak.access_denied", "The gateway is not allowed to perform this Keycloak operation."),
            >= HttpStatusCode.InternalServerError => Error.Unavailable(
                "keycloak.error", "Keycloak failed to process the request."),
            _ => Error.Upstream("keycloak.unexpected_status", "Keycloak returned an unexpected response."),
        };
    }
}
