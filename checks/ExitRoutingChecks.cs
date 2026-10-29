using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VPNyan;

internal static class ExitRoutingChecks
{
    internal static async Task<int> RunAsync(string report,string expectedIp)
    {
        var interfaceName=XraySession.SelectUpstreamInterface();
        var adapter=NetworkInterface.GetAllNetworkInterfaces().Single(a=>a.Name==interfaceName);
        var index=adapter.GetIPProperties().GetIPv4Properties()!.Index;
        var results=new List<object>();var exits=new Dictionary<string,string>();
        foreach(var physical in new[]{false,true})
        {
            using var handler=new SocketsHttpHandler{UseProxy=false,AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(5)};
            handler.ConnectCallback=async(context,token)=>{
                var addresses=(await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host,token)).Where(ip=>ip.AddressFamily==AddressFamily.InterNetwork).ToArray();
                foreach(var address in addresses)
                {
                    var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                    try {
                        if(physical)socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(index));
                        await socket.ConnectAsync(address,context.DnsEndPoint.Port,token);return new NetworkStream(socket,ownsSocket:true);
                    }catch {socket.Dispose();token.ThrowIfCancellationRequested();}
                }
                throw new HttpRequestException("No confirmed socket connection.");
            };
            using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(10),MaxResponseContentBufferSize=1500000};
            foreach(var target in new[]{"https://api.ipify.org","https://ipv4.icanhazip.com","https://speed.cloudflare.com/meta"})
            {
                var key=(physical?"physical":"system")+":"+new Uri(target).Host;
                try {
                    var text=(await client.GetStringAsync(target)).Trim();
                    if(target.EndsWith("/meta")) {using var json=JsonDocument.Parse(text);text=json.RootElement.GetProperty("clientIp").GetString()!;}
                    if(!IPAddress.TryParse(text,out var ip))throw new InvalidDataException("Unexpected IP response.");
                    exits[key]=ip.ToString();
                    results.Add(new{Path=physical?"physical":"system",Site=new Uri(target).Host,Verified=true,
                        MatchesReportedIp=ip.ToString()==expectedIp,ExitHash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ip.ToString())))[..12]});
                }catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException or JsonException or InvalidDataException){results.Add(new{Path=physical?"physical":"system",Site=new Uri(target).Host,Verified=false,ErrorType=ex.GetType().Name});}
                File.WriteAllText(report,JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));
            }
        }
        File.WriteAllBytes(report+".exits.dpapi",ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(exits),null,DataProtectionScope.CurrentUser));
        Console.WriteLine(JsonSerializer.Serialize(results));return 0;
    }
}
