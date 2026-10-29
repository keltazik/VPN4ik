using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace VPNyan;

internal static class ServerEndpointSelector
{
    internal static Task<IPAddress> SelectAsync(IPAddress[] addresses, int port, CancellationToken token) =>
        SelectAsync(addresses, async (address, cancellation) => {
            using var budget=CancellationTokenSource.CreateLinkedTokenSource(cancellation);budget.CancelAfter(TimeSpan.FromMilliseconds(1200));
            using var socket=new Socket(address.AddressFamily,SocketType.Stream,ProtocolType.Tcp);
            // Measure the physical path, rather than a competing VPN's early TUN acknowledgement.
            var name=XraySession.SelectUpstreamInterface(address);
            var adapter=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(a=>a.Name==name);
            if(adapter==null)return null;
            var properties=adapter.GetIPProperties();
            var index=address.AddressFamily==AddressFamily.InterNetwork?properties.GetIPv4Properties()?.Index:properties.GetIPv6Properties()?.Index;
            if(index==null)return null;
            socket.SetSocketOption(address.AddressFamily==AddressFamily.InterNetwork?SocketOptionLevel.IP:SocketOptionLevel.IPv6,
                (SocketOptionName)31,address.AddressFamily==AddressFamily.InterNetwork?IPAddress.HostToNetworkOrder(index.Value):index.Value);
            var timer=Stopwatch.StartNew();await socket.ConnectAsync(address,port,budget.Token).ConfigureAwait(false);
            return timer.Elapsed;
        }, token);

    internal static async Task<IPAddress> SelectAsync(IPAddress[] addresses,
        Func<IPAddress,CancellationToken,Task<TimeSpan?>> measure, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var ipv4=addresses.Where(ip=>ip.AddressFamily==AddressFamily.InterNetwork).Distinct().Take(16).ToArray();
        var candidates=ipv4.Length>0?ipv4:addresses.Distinct().Take(16).ToArray();
        if(candidates.Length==0)throw new InvalidOperationException("Не найден сетевой адрес сервера.");
        if(candidates.Length==1)return candidates[0];
        var results=await Task.WhenAll(candidates.Select(async address=> {
            try {return (Address:address,Time:await measure(address,token).ConfigureAwait(false));}
            catch(Exception ex) when(ex is SocketException or NetworkInformationException or OperationCanceledException) {return (Address:address,Time:(TimeSpan?)null);}
        })).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        return results.Where(item=>item.Time.HasValue).OrderBy(item=>item.Time).Select(item=>item.Address).FirstOrDefault()??candidates[0];
    }
}
