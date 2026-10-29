using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using VPNyan;

internal static class TunnelIpv6Checks
{
    internal static async Task RunAsync(Action<bool, string> check)
    {
        var targets = new[] { new Uri("https://first.example.test/generate_204"), new Uri("https://second.example.test/generate_204") };
        Task<IPAddress[]> Resolve(string host, CancellationToken token) => Task.FromResult(new[] { IPAddress.Parse("192.0.2.1"), IPAddress.Parse("2001:db8::1") });
        var requests = 0;
        using (var handler = new Handler((request, token) => {
            Interlocked.Increment(ref requests);
            check(IPAddress.Parse(request.RequestUri!.Host.Trim('[', ']')).AddressFamily == AddressFamily.InterNetworkV6,
                "IPv6 capability checks use a literal IPv6 destination instead of silently falling back to IPv4");
            check(targets.Any(uri => uri.IdnHost == request.Headers.Host), "IPv6 probes retain the original TLS SNI/certificate name via Host");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent) { Content = new ByteArrayContent(Array.Empty<byte>()) });
        })) check(await TunnelIpv6Probe.CheckAsync(handler, Resolve, targets, CancellationToken.None) && requests > 0, "A validated IPv6 204 keeps dual-stack enabled");

        using (var handler = new Handler((request, token) => Task.FromException<HttpResponseMessage>(new HttpRequestException("TLS closed"))))
            check(!await TunnelIpv6Probe.CheckAsync(handler, Resolve, targets, CancellationToken.None), "IPv6 TLS failures select IPv4 compatibility mode");
        foreach (var status in new[] { HttpStatusCode.OK, HttpStatusCode.Redirect, HttpStatusCode.NoContent })
        {
            using var handler = new Handler((request, token) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("unexpected page") }));
            check(!await TunnelIpv6Probe.CheckAsync(handler, Resolve, targets, CancellationToken.None), "HTML, redirects and nonempty 204 cannot confirm IPv6");
        }
        using (var handler = new Handler((request, token) => throw new Exception("IPv4-only DNS must not send a request")))
            check(!await TunnelIpv6Probe.CheckAsync(handler, (host, token) => Task.FromResult(new[] { IPAddress.Loopback, IPAddress.IPv6Loopback, IPAddress.Parse("fe80::1") }), targets, CancellationToken.None),
                "Missing usable IPv6 DNS answers cannot accidentally confirm loopback/link-local reachability");
        using (var cancel = new CancellationTokenSource())
        using (var handler = new Handler(async (request, token) => { cancel.Cancel(); await Task.Delay(Timeout.Infinite, token); return new HttpResponseMessage(); }))
        {
            var cancelled = false;
            try { await TunnelIpv6Probe.CheckAsync(handler, Resolve, targets, cancel.Token); } catch (OperationCanceledException) { cancelled = true; }
            check(cancelled, "Cancelling connection startup cancels all IPv6 probes");
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
}
