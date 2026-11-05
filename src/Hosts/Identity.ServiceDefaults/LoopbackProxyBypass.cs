using System.Net;

namespace Identity.ServiceDefaults;

/// <summary>
/// Keeps loopback traffic (localhost, 127.0.0.1, ::1) away from any HTTP proxy. Without HTTP_PROXY/NO_PROXY variables,
/// .NET on Windows follows the system (WinINET) proxy, and a proxy without "bypass local addresses" receives even
/// requests to localhost - which it can never reach: the AppHost's calls to Aspire's orchestrator (DCP) then time out
/// after two minutes, and the gateway cannot reach Keycloak on localhost. No proxy can serve the caller's own loopback,
/// so bypassing it is correct everywhere. Shared by the AppHost (linked file) and the services (AddServiceDefaults).
/// </summary>
public static class LoopbackProxyBypass
{
    private static int _installed;

    /// <summary>Wraps <see cref="HttpClient.DefaultProxy"/> once; call before the first HttpClient is created.</summary>
    public static void Install()
    {
        if (Interlocked.Exchange(ref _installed, 1) == 1) return;
        HttpClient.DefaultProxy = new BypassingProxy(HttpClient.DefaultProxy);
    }

    public static bool IsLoopback(Uri uri) =>
        uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        uri.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);

    internal sealed class BypassingProxy(IWebProxy inner) : IWebProxy
    {
        public ICredentials? Credentials
        {
            get => inner.Credentials;
            set => inner.Credentials = value;
        }

        // IWebProxy contract: returning the destination itself means "connect directly".
        public Uri? GetProxy(Uri destination) => IsLoopback(destination) ? destination : inner.GetProxy(destination);

        public bool IsBypassed(Uri host) => IsLoopback(host) || inner.IsBypassed(host);
    }
}
