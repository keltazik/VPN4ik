using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using VPNyan;

internal static class EndpointThroughputChecks
{
    internal static async Task<int> RunAsync(string source,string report,int index)
    {
        EngineHost.VerifyFiles();
        var profile=SubscriptionStore.Load(source).SelectMany(s=>s.Profiles).ElementAt(index);
        var addresses=(await Dns.GetHostAddressesAsync(profile.Address)).Where(a=>a.AddressFamily==AddressFamily.InterNetwork).Distinct().Take(8).ToArray();
        File.WriteAllBytes(report+".endpoints.dpapi",ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(addresses.Select(ip=>ip.ToString())),null,DataProtectionScope.CurrentUser));
        var requests=addresses.Select(ip=>new EngineRequest{Profile=profile,EnableTun=false,EndpointAddress=ip.ToString(),
            ProbePort=HiddifyChecks.Port(),UpstreamInterface=XraySession.SelectUpstreamInterface(ip)}).ToArray();
        var batch=new EngineRequest{EnableTun=false,Probes=requests.ToList()};
        using var process=new Process{StartInfo=new ProcessStartInfo(EngineHost.EnginePath){UseShellExecute=false,CreateNoWindow=true,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=EngineHost.EngineDirectory}};
        foreach(var arg in new[]{"run","-format=json","-c","stdin:"})process.StartInfo.ArgumentList.Add(arg);
        using var deadline=new CancellationTokenSource(TimeSpan.FromMinutes(4));var token=deadline.Token;
        var routeBefore=JsonSerializer.Serialize(XraySession.RouteDiagnostic());
        var results=new List<object>();
        process.Start();var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        try
        {
            await process.StandardInput.WriteAsync(XrayConfiguration.Build(batch));process.StandardInput.Close();
            var payload=RandomNumberGenerator.GetBytes(262144);
            var target=(await Dns.GetHostAddressesAsync("speed.cloudflare.com",token)).First(ip=>ip.AddressFamily==AddressFamily.InterNetwork);
            for(var itemIndex=0;itemIndex<requests.Length;itemIndex++)
            {
                var request=requests[itemIndex];
                await SystemProxyLease.WaitForListenerAsync(request.ProbePort,token);
                using var client=new HttpClient(new SocketsHttpHandler{UseProxy=true,
                    Proxy=new WebProxy($"socks5://127.0.0.1:{request.ProbePort}"){Credentials=new NetworkCredential(request.ProbeUser,request.ProbePassword)},
                    AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(5)}){Timeout=TimeSpan.FromSeconds(16)};
                var result=new Dictionary<string,object?>{["EndpointIndex"]=itemIndex,["ActiveEndpoint"]=request.EndpointAddress==Environment.GetEnvironmentVariable("VPN4IK_DIAGNOSTIC_ENDPOINT")};
                // Record TCP RTT without revealing provider addresses in diagnostic output.
                using(var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp))
                {
                    var adapter=System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Single(a=>a.Name==request.UpstreamInterface);
                    socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(adapter.GetIPProperties().GetIPv4Properties()!.Index));
                    var ping=Stopwatch.StartNew();
                    try {await socket.ConnectAsync(addresses[itemIndex],profile.Port,token).AsTask().WaitAsync(TimeSpan.FromSeconds(2),token);result["TcpMs"]=ping.ElapsedMilliseconds;}
                    catch(Exception ex) when(ex is SocketException or TimeoutException){result["TcpFailed"]=true;}
                }
                for(var round=0;round<2;round++)
                {
                    var clock=Stopwatch.StartNew();
                    try
                    {
                        using var message=new HttpRequestMessage(HttpMethod.Post,$"https://{target}/__up");message.Headers.Host="speed.cloudflare.com";
                        message.Headers.ExpectContinue=false;message.Content=new ByteArrayContent(payload);
                        using var response=await client.SendAsync(message,token);response.EnsureSuccessStatusCode();
                        result["UploadMbps"+round]=Math.Round(payload.Length*8d/clock.Elapsed.TotalSeconds/1e6,3);
                    }
                    catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException){result["UploadFailed"+round]=ex.GetType().Name;}
                }
                results.Add(result);Console.WriteLine(JsonSerializer.Serialize(result));
                File.WriteAllText(report,JsonSerializer.Serialize(new{EndpointCount=addresses.Length,Results=results,
                    SystemRouteUnchanged=routeBefore==JsonSerializer.Serialize(XraySession.RouteDiagnostic())},new JsonSerializerOptions{WriteIndented=true}));
            }
        }
        finally {if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync();await Task.WhenAll(stdout,stderr);}
        return 0;
    }
}
