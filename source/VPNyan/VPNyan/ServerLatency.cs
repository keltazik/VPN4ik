using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;

namespace VPNyan;

internal enum LatencyKind { Https, Tcp }

internal sealed record LatencyResult(string Key, int Milliseconds, string Detail, LatencyKind Kind = LatencyKind.Tcp,
    bool PotentiallyInaccurate = false)
{
    internal bool Measured => Milliseconds >= 0;
}

internal static class PingPolicy
{
    internal const string WarningMessage = "При включённом VPN задержка может быть неточной из-за маршрутизации. TCP-проверка всё равно выполняется.";

    internal static bool IsTunAdapter(string name, string description, NetworkInterfaceType type, OperationalStatus status)
    {
        if (status != OperationalStatus.Up) return false;
        var identity = (name + " " + description).ToLowerInvariant();
        // Radmin VPN is a LAN adapter; it does not imply an Internet VPN route.
        if (identity.Contains("teredo") || identity.Contains("isatap") || identity.Contains("6to4")) return false;
        return type == NetworkInterfaceType.Tunnel || identity.Contains("wintun") || identity.Contains("wireguard") ||
            identity.Contains("tap-windows") || identity.Contains("openvpn") || identity.Contains("vpn4ik-tun") ||
            identity.Contains("happ-xray") || identity.Contains("sing-box") || identity.Contains("singbox") ||
            System.Text.RegularExpressions.Regex.IsMatch(name, @"^(?:u?tun)\d*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    internal static bool IsTunActive() => NetworkInterface.GetAllNetworkInterfaces().Any(adapter =>
        IsTunAdapter(adapter.Name, adapter.Description, adapter.NetworkInterfaceType, adapter.OperationalStatus));
}

internal static class ServerLatency
{
    internal static bool SupportsTcpPing(string protocol) => protocol.ToLowerInvariant() is not ("wireguard" or "hysteria" or "hysteria2" or "hy2");
    internal const int BatchSize = 24;
    internal const int Parallelism = 6;
    internal static readonly TimeSpan BatchDeadline = TimeSpan.FromSeconds(6);

    internal static async Task MeasureAsync(IReadOnlyList<(string Key, SubscriptionProfile Profile)> profiles,
        Action<LatencyResult> publish, CancellationToken cancellationToken, Action<string>? diagnostic = null,
        Func<bool>? tunActive = null)
    {
        tunActive ??= PingPolicy.IsTunActive;
        var startedWithVpn = tunActive();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(BatchDeadline);
        var dnsCache = new ConcurrentDictionary<string, Task<IPAddress[]>>(StringComparer.OrdinalIgnoreCase);
        var upstream = XraySession.SelectUpstreamInterface();
        await Parallel.ForEachAsync(profiles.Take(BatchSize), new ParallelOptions
        { MaxDegreeOfParallelism = Parallelism, CancellationToken = deadline.Token }, async (item, token) =>
        {
            if (!SupportsTcpPing(item.Profile.Protocol))
            {
                publish(new LatencyResult(item.Key, -1, "Протокол использует UDP; TCP-пинг к нему неприменим."));
                return;
            }
            var vpnDuringAttempt = startedWithVpn || tunActive();
            LatencyResult result;
            try
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(token);
                attempt.CancelAfter(TimeSpan.FromMilliseconds(1800));
                var addresses = await dnsCache.GetOrAdd(item.Profile.Address,
                    host => Dns.GetHostAddressesAsync(host, deadline.Token)).WaitAsync(attempt.Token);
                result = new LatencyResult(item.Key, -1, "TCP-пинг: нет ответа. Можно попробовать подключиться к серверу.");
                foreach (var address in addresses.OrderBy(a => a.AddressFamily != AddressFamily.InterNetwork))
                {
                    result = await MeasureTcpAsync(item.Key, address, item.Profile.Port, upstream, attempt.Token);
                    if (result.Measured || attempt.IsCancellationRequested) break;
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            { result = new LatencyResult(item.Key, -1, "TCP-пинг: нет ответа. Это не означает, что VPN-сервер не работает."); }
            cancellationToken.ThrowIfCancellationRequested();
            if (vpnDuringAttempt || tunActive())
                result = result with { PotentiallyInaccurate = true, Detail = result.Detail + " " + PingPolicy.WarningMessage };
            publish(result);
        });
    }

    private static async Task<LatencyResult> MeasureTcpAsync(string key, IPAddress address, int port, string upstream, CancellationToken cancellationToken)
    {
        if (port is < 1 or > 65535) return new LatencyResult(key, -1, "Не указан порт сервера.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(1200));
        try
        {
            using var socket = new TcpClient(address.AddressFamily);
            if (upstream != "auto" && !IPAddress.IsLoopback(address))
            {
                var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(a => a.Name == upstream);
                if (adapter != null)
                {
                    var ipv4 = address.AddressFamily == AddressFamily.InterNetwork;
                    var index = ipv4 ? adapter.GetIPProperties().GetIPv4Properties().Index : adapter.GetIPProperties().GetIPv6Properties().Index;
                    const SocketOptionName unicastInterface = (SocketOptionName)31;
                    socket.Client.SetSocketOption(ipv4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6, unicastInterface,
                        ipv4 ? IPAddress.HostToNetworkOrder(index) : index);
                }
            }
            var clock = Stopwatch.StartNew();
            await socket.ConnectAsync(address, port, deadline.Token);
            return new LatencyResult(key, (int)Math.Max(1, clock.ElapsedMilliseconds),
                "TCP-пинг до порта сервера. Успешное VPN-подключение проверяется отдельно при подключении.");
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or NetworkInformationException)
        { return new LatencyResult(key, -1, "TCP-пинг: нет ответа. Это не означает, что VPN-сервер не работает."); }
    }
}
