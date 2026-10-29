using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace VPNyan;

internal static class TunnelIpv6Probe
{
    private static readonly Uri[] Targets = { new("https://cp.cloudflare.com/generate_204"), new("https://www.gstatic.com/generate_204") };

    internal static async Task<bool> CheckAsync(EngineRequest request, CancellationToken token)
    {
        // Test literal IPv6 destinations through the selected protocol worker, before the TUN exists.
        // A successful IPv4 health check cannot establish that this server can carry IPv6.
        using var handler = new SocketsHttpHandler {
            UseProxy = true, Proxy = new WebProxy($"socks5://127.0.0.1:{request.ProbePort}") {
                Credentials = new NetworkCredential(request.ProbeUser, request.ProbePassword) },
            AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(3), MaxResponseHeadersLength = 8 };
        return await CheckAsync(handler, (host, cancellation) => Dns.GetHostAddressesAsync(host, cancellation), Targets, token);
    }

    internal static async Task<bool> CheckAsync(HttpMessageHandler handler,
        Func<string, CancellationToken, Task<IPAddress[]>> resolve, IReadOnlyList<Uri> targets, CancellationToken token)
    {
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        var allTasks = targets.Select(ProbeAsync).ToArray();
        var tasks = allTasks.ToList();
        try
        {
            while (tasks.Count > 0)
            {
                var completed = await Task.WhenAny(tasks); tasks.Remove(completed);
                if (await completed) { token.ThrowIfCancellationRequested(); return true; }
            }
            token.ThrowIfCancellationRequested();
            return false;
        }
        finally { budget.Cancel(); await Task.WhenAll(allTasks); }

        async Task<bool> ProbeAsync(Uri target)
        {
            try
            {
                var address = (await resolve(target.IdnHost, budget.Token)).FirstOrDefault(ip =>
                    ip.AddressFamily == AddressFamily.InterNetworkV6 && !IPAddress.IsLoopback(ip) &&
                    !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast && !ip.IsIPv4MappedToIPv6);
                if (address == null) return false;
                using var message = new HttpRequestMessage(HttpMethod.Get, new UriBuilder(target) { Host = address.ToString() }.Uri);
                // HttpClient uses Host for both SNI and normal certificate-name validation.
                message.Headers.Host = target.IdnHost;
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, budget.Token);
                if (response.StatusCode != HttpStatusCode.NoContent) return false;
                using var stream = await response.Content.ReadAsStreamAsync(budget.Token);
                return await stream.ReadAsync(new byte[1], budget.Token) == 0;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or OperationCanceledException) { return false; }
        }
    }
}
