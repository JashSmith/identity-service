namespace Identity.Contracts;

/// <summary>
/// An application (service, module or web app) whose permissions the gateway manages. Backed by a
/// Keycloak client; <see cref="ClientId"/> is also the first segment of every permission it owns.
/// </summary>
/// <param name="Kind">"service" (machine-to-machine only), "web" (user sign-in through SSO) or "hybrid".</param>
/// <param name="LoginTheme">Keycloak login theme shown when users sign in to this application; null uses the realm theme.</param>
public sealed record ApplicationDto(
    string ClientId,
    string DisplayName,
    string? Description,
    string Kind,
    bool Enabled,
    IReadOnlyCollection<string> RedirectUris,
    string? LoginTheme);

public sealed record CreateApplicationRequest(
    string ClientId,
    string DisplayName,
    string? Description,
    string Kind = "service",
    IReadOnlyCollection<string>? RedirectUris = null,
    string? LoginTheme = null);

/// <summary>Changes the given fields; null keeps the current value.</summary>
public sealed record UpdateApplicationRequest(
    string? DisplayName,
    string? Description,
    bool? Enabled,
    IReadOnlyCollection<string>? RedirectUris,
    string? LoginTheme);

/// <summary>Returned once on creation and on secret rotation; the secret is not readable afterwards through this API.</summary>
public sealed record ApplicationSecretResponse(ApplicationDto Application, string ClientSecret);
