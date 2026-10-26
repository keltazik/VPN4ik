using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

namespace VPNyan;

// First successful HTTPS reply wins. A blocked IP service must not make a working VPN look disconnected.
internal sealed class ConnectionProbe : IDisposable
{
    private readonly HttpClient client;
    private readonly TimeSpan attemptTimeout, hedgeDelay;
    private readonly IReadOnlyList<Uri> endpoints;
    internal static readonly Uri[] DefaultEndpoints =
    {
        new("https://api.ipify.org"), new("https://checkip.amazonaws.com"),
        new("https://ipv4.icanhazip.com"), new("https://www.gstatic.com/generate_204")
    };
    internal ConnectionProbe(HttpMessageHandler handler, IReadOnlyList<Uri>? endpoints = null, TimeSpan? attemptTimeout = null, TimeSpan? hedgeDelay = null)
    {
        client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        this.endpoints = endpoints ?? DefaultEndpoints;
        this.attemptTimeout = attemptTimeout ?? TimeSpan.FromSeconds(8);
        this.hedgeDelay = hedgeDelay ?? TimeSpan.FromMilliseconds(300);
        if (this.endpoints.Count is < 1 or > 8 || this.endpoints.Any(uri => uri.Scheme != "https")) throw new ArgumentException("HTTPS probe targets required.");
    }
    internal async Task<string> CheckAsync(CancellationToken token)
    {
        using var winner = CancellationTokenSource.CreateLinkedTokenSource(token);
        var tasks = endpoints.Select((uri, index) => TryAsync(uri, index, winner.Token)).ToArray();
        var pending = tasks.ToList();
        try
        {
            while (pending.Count > 0)
            {
                var completed = await Task.WhenAny(pending); pending.Remove(completed);
                var ip = await completed;
                if (ip != null) { token.ThrowIfCancellationRequested(); return ip; }
            }
            token.ThrowIfCancellationRequested();
            throw new HttpRequestException("Несколько независимых HTTPS-проверок не подтвердили доступ через VPN.");
        }
        finally { winner.Cancel(); _ = ObserveAsync(tasks); }
    }
    private async Task<string?> TryAsync(Uri uri, int index, CancellationToken token)
    {
        try
        {
            if (index > 0) await Task.Delay(TimeSpan.FromTicks(hedgeDelay.Ticks * index), token);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(attemptTimeout);
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            response.EnsureSuccessStatusCode();
            // A 204 from our fixed HTTPS connectivity endpoint proves access without inventing an external IP.
            if (uri.Host == "www.gstatic.com" && uri.AbsolutePath == "/generate_204")
                return response.StatusCode == HttpStatusCode.NoContent && response.Content.Headers.ContentLength is null or 0 ? "" : null;
            if (response.Content.Headers.ContentLength > 128) return null;
            await using var input = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var body = new MemoryStream(); var bytes = new byte[129]; int read;
            while ((read = await input.ReadAsync(bytes, timeout.Token)) > 0)
            {
                if (body.Length + read > 128) return null;
                body.Write(bytes, 0, read);
            }
            var value = Encoding.UTF8.GetString(body.ToArray()).Trim();
            return IPAddress.TryParse(value, out var address) && address.ToString() == value ? value : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or ObjectDisposedException) { return null; }
    }
    private static async Task ObserveAsync(Task<string?>[] tasks) { try { await Task.WhenAll(tasks); } catch { } }
    public void Dispose() => client.Dispose();
}
