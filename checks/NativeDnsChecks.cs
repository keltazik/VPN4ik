using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPNyan;

internal static class NativeDnsChecks
{
    internal static async Task<int> RunAsync(SubscriptionProfile? profile = null, Dictionary<string,object?>? report = null)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(profile == null ? 15 : 60));
        var token = deadline.Token;
        using var tcpDns = new TcpListener(IPAddress.Loopback,0); tcpDns.Start();
        var dnsRequests = 0;
        async Task ServeDns()
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    using var client = await tcpDns.AcceptTcpClientAsync(token); using var stream = client.GetStream();
                    var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix,token);
                    var query = new byte[(prefix[0]<<8)|prefix[1]]; await stream.ReadExactlyAsync(query,token);
                    var type = (query[^4]<<8)|query[^3]; var address = IPAddress.Parse(type == 28 ? "2001:db8::80" : "192.0.2.80").GetAddressBytes();
                    var reply = query.ToList(); reply[2]=0x81; reply[3]=0x80; reply[7]=1;
                    reply.AddRange(new byte[]{0xc0,0x0c,0,(byte)type,0,1,0,0,0,60,0,(byte)address.Length}); reply.AddRange(address);
                    var bytes=reply.ToArray(); await stream.WriteAsync(new byte[]{(byte)(bytes.Length>>8),(byte)bytes.Length},token); await stream.WriteAsync(bytes,token);
                    Interlocked.Increment(ref dnsRequests);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException) { }
        }
        var serving = profile == null ? ServeDns() : Task.CompletedTask;
        using var socksReserve = new TcpListener(IPAddress.Loopback,0); socksReserve.Start();
        using var udpReserve = new UdpClient(new IPEndPoint(IPAddress.Loopback,0)); var udpPort = ((IPEndPoint)udpReserve.Client.LocalEndPoint!).Port;
        var request = new EngineRequest { Profile=profile ?? SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#DNS").Single(),
            ProbePort=((IPEndPoint)socksReserve.LocalEndpoint).Port, EnableTun=true };
        if(profile != null)
        {
            request.UpstreamInterface=XraySession.SelectUpstreamInterface();
            request.EndpointAddress=(await Dns.GetHostAddressesAsync(profile.Address,token)).First(a=>a.AddressFamily==AddressFamily.InterNetwork).ToString();
        }
        var config=JsonNode.Parse(XrayConfiguration.Build(request))!;
        // Keep production DNS routing; replace only the TUN input with a loopback UDP listener.
        config["inbounds"]![1]=new JsonObject { ["tag"]="vpn4ik-tun",["listen"]="127.0.0.1",["port"]=udpPort,["protocol"]="dokodemo-door",
            ["settings"]=new JsonObject{["address"]="172.31.255.1",["port"]=53,["network"]="udp"} };
        if(profile==null)
        {
            config["outbounds"]![0]=new JsonObject{["tag"]="proxy",["protocol"]="freedom",["settings"]=new JsonObject()};
            config["dns"]!["servers"]=new JsonArray("tcp://127.0.0.1:"+((IPEndPoint)tcpDns.LocalEndpoint).Port);
        }
        socksReserve.Stop(); udpReserve.Dispose();
        using var engine=new Process { StartInfo=new ProcessStartInfo(EngineHost.EnginePath){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=EngineHost.EngineDirectory} };
        engine.StartInfo.ArgumentList.Add("run");engine.StartInfo.ArgumentList.Add("-format=json");engine.StartInfo.ArgumentList.Add("-c");engine.StartInfo.ArgumentList.Add("stdin:");
        engine.Start();var output=engine.StandardOutput.ReadToEndAsync();var errors=engine.StandardError.ReadToEndAsync();
        try
        {
            await engine.StandardInput.WriteAsync(config.ToJsonString());engine.StandardInput.Close();
            await SystemProxyLease.WaitForListenerAsync(request.ProbePort,token);
            var results=new List<object>();
            foreach(var type in new[]{1,28,65})
            {
                var query=Convert.FromHexString("123401000001000000000000076578616d706c6503636f6d0000010001");query[^3]=(byte)type;
                using var udp=new UdpClient(AddressFamily.InterNetwork);udp.Connect(IPAddress.Loopback,udpPort);
                var clock=Stopwatch.StartNew();await udp.SendAsync(query,token);var response=await udp.ReceiveAsync(token);
                if(response.Buffer.Length<12 || response.Buffer[0]!=0x12 || response.Buffer[1]!=0x34 || (response.Buffer[3]&15)!=0) throw new IOException("DNS response failed.");
                var answers=(response.Buffer[6]<<8)|response.Buffer[7];
                if(profile==null && type!=65 && answers!=1) throw new IOException("Synthetic DNS record lost.");
                results.Add(new{Type=type,Answers=answers,Milliseconds=clock.ElapsedMilliseconds});
            }
            if(profile==null && dnsRequests<2)throw new IOException("DNS did not use the TCP-only upstream.");
            if(report!=null)
            {
                report["Dns"]=results;
                using var handler=new SocketsHttpHandler { UseProxy=true,AllowAutoRedirect=false,Proxy=new WebProxy("socks5://127.0.0.1:"+request.ProbePort){Credentials=new NetworkCredential(request.ProbeUser,request.ProbePassword)} };
                using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(12)};
                var sites=new List<object>();
                foreach(var site in new[]{"https://example.com","https://www.microsoft.com","https://www.google.com"})
                {
                    var clock=Stopwatch.StartNew();using var response=await http.GetAsync(site,HttpCompletionOption.ResponseHeadersRead,token);response.EnsureSuccessStatusCode();
                    await using var body=await response.Content.ReadAsStreamAsync(token);var buffer=new byte[32768];var bytes=0;int read;
                    while(bytes<1024*1024 && (read=await body.ReadAsync(buffer,token))>0)bytes+=read;
                    sites.Add(new{Site=new Uri(site).Host,Status=(int)response.StatusCode,Bytes=bytes,Milliseconds=clock.ElapsedMilliseconds});
                }
                report["Sites"]=sites;
            }
            return 3;
        }
        finally
        {
            if(!engine.HasExited)engine.Kill(true);await engine.WaitForExitAsync();await Task.WhenAll(output,errors);
            deadline.Cancel();tcpDns.Stop();await serving;
        }
    }
    internal static async Task<int> ProviderAsync(string source,string path)
    {
        var profiles=SubscriptionStore.Load(source).SelectMany(s=>s.Profiles).ToArray();var reports=new List<Dictionary<string,object?>>();
        foreach(var index in profiles.Select((p,i)=>(p,i)).Where(item=>item.p.Name.Contains("Латв",StringComparison.OrdinalIgnoreCase)).Select(item=>item.i))
        {
            var report=new Dictionary<string,object?>{["Index"]=index,["Mode"]="SOCKS + loopback DNS, no TUN"};
            try { await RunAsync(profiles[index],report);report["Verified"]=true; }catch(Exception ex){report["Verified"]=false;report["ErrorType"]=ex.GetType().Name;}
            reports.Add(report);
        }
        File.WriteAllText(path,JsonSerializer.Serialize(reports,new JsonSerializerOptions{WriteIndented=true}));
        return reports.Count>0 && reports.All(r=>r["Verified"] is true)?0:1;
    }
}