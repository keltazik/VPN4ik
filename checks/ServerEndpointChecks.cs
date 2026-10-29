using System.Net;
using System.Net.Sockets;
using VPNyan;

internal static class ServerEndpointChecks
{
    internal static async Task RunAsync(Action<bool,string> check)
    {
        var first=IPAddress.Parse("192.0.2.1");var faster=IPAddress.Parse("192.0.2.2");var ipv6=IPAddress.Parse("2001:db8::1");
        check(await ServerEndpointSelector.SelectAsync(new[]{first,faster},(ip,ct)=>Task.FromResult<TimeSpan?>(TimeSpan.FromMilliseconds(ip.Equals(first)?100:40)),CancellationToken.None)==faster,
            "Round-robin DNS chooses the faster physical TCP endpoint instead of blindly keeping the first answer");
        check(await ServerEndpointSelector.SelectAsync(new[]{ipv6,first},(ip,ct)=>throw new Exception("Single IPv4 must not be probed"),CancellationToken.None)==first,
            "Endpoint selection retains IPv4 preference and skips needless probes for a single candidate");
        check(await ServerEndpointSelector.SelectAsync(new[]{first,faster},(ip,ct)=>ip.Equals(first)?Task.FromException<TimeSpan?>(new SocketException()):Task.FromResult<TimeSpan?>(TimeSpan.FromMilliseconds(50)),CancellationToken.None)==faster,
            "An unreachable first DNS endpoint does not prevent using another working endpoint");
        check(await ServerEndpointSelector.SelectAsync(new[]{first,faster},(ip,ct)=>Task.FromException<TimeSpan?>(new OperationCanceledException()),CancellationToken.None)==first,
            "Inconclusive TCP races retain the previous address fallback rather than declaring the whole server dead");
        var calls=0;
        await ServerEndpointSelector.SelectAsync(new[]{first,first,faster},(ip,ct)=>{calls++;return Task.FromResult<TimeSpan?>(TimeSpan.Zero);},CancellationToken.None);
        check(calls==2,"Duplicate DNS answers are probed only once");
        check(await ServerEndpointSelector.SelectAsync(new[]{first,faster},(ip,ct)=>Task.FromResult<TimeSpan?>(TimeSpan.FromMilliseconds(40)),CancellationToken.None)==first,
            "Equal endpoint measurements keep deterministic DNS order");
        using var cancel=new CancellationTokenSource();cancel.Cancel();var cancelled=false;
        try {await ServerEndpointSelector.SelectAsync(new[]{first,faster},(ip,ct)=>Task.FromResult<TimeSpan?>(TimeSpan.Zero),cancel.Token);}catch(OperationCanceledException){cancelled=true;}
        check(cancelled,"Cancelling startup cannot silently select an endpoint");
    }
}
