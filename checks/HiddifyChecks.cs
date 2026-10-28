using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using VPNyan;

internal static class HiddifyChecks
{
    private static EngineRequest Request() => new() { EnableTun=true,UseHiddifyCore=true,ProbePort=49151,
        Profile=SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#Fixture").Single(),
        EndpointAddress="192.0.2.1" };
    internal static void Offline(Action<bool,string> require)
    {
        var request=Request(); var config=JsonNode.Parse(HiddifyCore.Build(request))!;
        var tun=config["inbounds"]![0]!;
        require((string?)tun["type"]=="tun" && (string?)tun["stack"]=="mixed" && (bool)tun["strict_route"]! && (bool)tun["auto_route"]!,
            "Hiddify owns mixed-stack TUN with strict automatic routing");
        require((string?)tun["interface_name"]==XrayConfiguration.InterfaceName && tun["address"]!.AsArray().Count==2,"Hiddify uses the application's verified interface name and dual-stack addresses");
        require(config["experimental"]!["clash_api"]==null && config["ntp"]==null && config["route"]!["rule_set"]==null &&
            (string?)config["experimental"]!["monitoring"]!["urls"]![0]=="http://127.0.0.1:1/" &&
            (string?)config["experimental"]!["monitoring"]!["url_test_timeout"]=="1ns","Hiddify config disables implicit public URL tests and has no control API, external rules or NTP downloads");
        require(config["dns"]!["servers"]!.AsArray().Count==4 && (string?)config["dns"]!["servers"]![0]!["type"]=="tcp" &&
            (string?)config["dns"]!["servers"]![0]!["detour"]=="proxy","Hiddify DNS uses authenticated VPN transport and preserves fallback resolvers");
        var worker=HiddifyCore.WorkerRequest(request);
        var transport=JsonNode.Parse(XrayConfiguration.Build(worker))!;
        require(!worker.EnableTun && !worker.EnableSystemProxy && !worker.UseHiddifyCore && worker.EnableUdpProbe &&
            transport["inbounds"]!.AsArray().Count==1 && (bool)transport["inbounds"]![0]!["settings"]!["udp"]!,"Protocol worker exposes only its authenticated TCP/UDP bridge, without a second TUN/proxy lease");
        require((string?)transport["outbounds"]![0]!["settings"]!["vnext"]![0]!["users"]![0]!["id"]=="00000000-0000-4000-8000-000000000001", "Existing sanitized protocol credentials survive the Hiddify bridge");
        foreach(var mode in new[]{"Bypass","Include"})
        {
            request.Routing.SplitTunnelEnabled=true;request.Routing.SplitTunnelMode=mode;
            request.Routing.SplitApplications=new(){"chrome","C:/Apps/My Browser/browser.exe"};
            request.Routing.SplitDomains=new(){"example.org"};request.Routing.SplitNetworks=new(){"192.0.2.0/24"};
            config=JsonNode.Parse(HiddifyCore.Build(request))!;
            require((string?)config["route"]!["final"]==(mode=="Include"?"direct":"proxy") && config["route"]!["rules"]!.AsArray().Any(r=>r?["process_path"]!=null),
                "Hiddify preserves process paths, domains and include/bypass mode: "+mode);
            require(config["route"]!["rules"]!.AsArray().Any(r=>(string?)r?["process_name"]?[0]=="chrome.exe"),"Normalized process names regain their Windows executable suffix: "+mode);
        }
        request.Routing.SplitTunnelEnabled=false;request.EnableTun=false;request.EnableSystemProxy=true;request.HttpProxyPort=49152;
        config=JsonNode.Parse(HiddifyCore.Build(request))!;
        require(config["inbounds"]!.AsArray().Count==1 && (string?)config["inbounds"]![0]!["listen"]=="127.0.0.1" &&
            (string?)config["inbounds"]![0]!["type"]=="http","Proxy mode stays loopback-only and does not create TUN");
        require(new AppSettings().UseHiddifyCore && new AppSettings{UseHiddifyCore=false}.Copy().UseHiddifyCore==false,
            "Hiddify is the new default and the existing Xray backend remains available internally");
        foreach(var file in HiddifyCore.Files) require(file.Hash.Length==64,"Hiddify native file has a pinned digest: "+file.File);
    }

    internal static async Task<int> NativeAsync()
    {
        HiddifyCore.EnsureInstalled(); var count=1;
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(55)); var token=deadline.Token;
        await using var direct=new NativeRoutingChecks.TestHttpServer("direct",token);
        await using var selected=new NativeRoutingChecks.TestHttpServer("proxy",token);
        foreach(var scenario in new[]{"all","all-bound-interface","bypass-ip","include-ip","include-miss","bypass-domain","bypass-process"})
        {
            var request=Request();request.ProbePort=Port();var frontPort=Port();
            if(scenario=="all-bound-interface") request.UpstreamInterface=XraySession.SelectUpstreamInterface();
            request.Routing.SplitTunnelEnabled=scenario!="all";request.Routing.SplitTunnelMode=scenario.StartsWith("include")?"Include":"Bypass";
            if(scenario.EndsWith("ip")) request.Routing.SplitNetworks.Add("127.0.0.1");
            if(scenario.EndsWith("miss")) request.Routing.SplitNetworks.Add("192.0.2.0/24");
            if(scenario.EndsWith("domain")) request.Routing.SplitDomains.Add("localhost");
            if(scenario.EndsWith("process")) request.Routing.SplitApplications.Add(Process.GetCurrentProcess().ProcessName);
            var native=JsonNode.Parse(HiddifyCore.Build(request))!;
            native["inbounds"]![0]=new JsonObject{["type"]="http",["tag"]="vpn4ik-tun",["listen"]="127.0.0.1",["listen_port"]=frontPort};
            var worker=JsonNode.Parse(XrayConfiguration.Build(HiddifyCore.WorkerRequest(request)))!;
            worker["outbounds"]![0]=new JsonObject{["tag"]="proxy",["protocol"]="freedom",["settings"]=new JsonObject{["redirect"]="127.0.0.1:"+selected.Port}};
            await using var engines=await Pair.StartAsync(worker,native,request.ProbePort,frontPort,token);
            using var client=new HttpClient(new SocketsHttpHandler{Proxy=new WebProxy("http://127.0.0.1:"+frontPort),UseProxy=true}){Timeout=TimeSpan.FromSeconds(5)};
            var expected=scenario is "bypass-ip" or "include-miss" or "bypass-domain" or "bypass-process"?"direct":"proxy";
            var host=scenario=="bypass-domain"?"localhost":"127.0.0.1";
            string body;
            try { body=await client.GetStringAsync($"http://{host}:{direct.Port}/test",token); }
            catch(Exception ex) { await engines.DisposeAsync();throw new IOException("Hiddify request failed: "+scenario+" / "+engines.Diagnostics,ex); }
            if(body!=expected) throw new IOException("Hiddify routing failed: "+scenario+" / "+body); count++;
            using var metrics=new HttpClient(new SocketsHttpHandler{Proxy=new WebProxy("socks5://127.0.0.1:"+request.ProbePort){Credentials=new NetworkCredential(request.ProbeUser,request.ProbePassword)},UseProxy=true});
            var counters=TrafficMeter.Parse(await metrics.GetStringAsync("http://metrics.vpn4ik.invalid/debug/vars",token));
            if(expected=="proxy" ? counters.Download<=0 : counters.Download!=0) throw new IOException("Hiddify per-server traffic counters failed: "+scenario);count++;
        }
        count+=await DatagramAsync(token);
        count+=await DnsAsync(token);
        return count;
    }

    private static async Task<int> DnsAsync(CancellationToken token)
    {
        using var dns=new TcpListener(IPAddress.Loopback,0);dns.Start();
        var dnsPort=((IPEndPoint)dns.LocalEndpoint).Port;
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);
        var serving=Task.Run(async()=>
        {
            try
            {
                while(!stop.IsCancellationRequested)
                {
                    using var client=await dns.AcceptTcpClientAsync(stop.Token);using var stream=client.GetStream();
                    var prefix=new byte[2];await stream.ReadExactlyAsync(prefix,stop.Token);
                    var query=new byte[(prefix[0]<<8)|prefix[1]];await stream.ReadExactlyAsync(query,stop.Token);
                    var type=query[^3];var data=type==28?IPAddress.Parse("2001:db8::123").GetAddressBytes():new byte[]{192,0,2,123};
                    var answer=new List<byte>(query);answer[2]=0x81;answer[3]=0x80;answer[6]=0;answer[7]=1;
                    answer.AddRange(new byte[]{0xc0,0x0c,0,type,0,1,0,0,0,60,0,(byte)data.Length});answer.AddRange(data);
                    await stream.WriteAsync(new byte[]{(byte)(answer.Count>>8),(byte)answer.Count},stop.Token);
                    await stream.WriteAsync(answer.ToArray(),stop.Token);
                }
            }
            catch(Exception ex) when(ex is OperationCanceledException or SocketException or EndOfStreamException) { }
        },stop.Token);
        try
        {
            var request=Request();request.ProbePort=Port();var frontPort=Port();
            var native=JsonNode.Parse(HiddifyCore.Build(request))!;
            native["inbounds"]![0]=new JsonObject{["type"]="direct",["tag"]="vpn4ik-tun",["listen"]="127.0.0.1",["listen_port"]=frontPort,["override_address"]="127.0.0.1",["override_port"]=53};
            for(var i=0;i<2;i++) {native["dns"]!["servers"]![i]!["server"]="127.0.0.1";native["dns"]!["servers"]![i]!["server_port"]=i==0?Port():dnsPort;}
            var worker=JsonNode.Parse(XrayConfiguration.Build(HiddifyCore.WorkerRequest(request)))!;
            worker["outbounds"]![0]=new JsonObject{["tag"]="proxy",["protocol"]="freedom",["settings"]=new JsonObject()};
            await using var engines=await Pair.StartAsync(worker,native,request.ProbePort,frontPort,token);
            foreach(var type in new[]{1,28})
            {
                using var udp=new UdpClient(AddressFamily.InterNetwork);
                var query=Convert.FromHexString("123401000001000000000000076578616d706c6503636f6d0000010001");query[^3]=(byte)type;
                await udp.SendAsync(query,new IPEndPoint(IPAddress.Loopback,frontPort),token);
                var response=await udp.ReceiveAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(8),token);
                if(response.Buffer.Length<12 || (response.Buffer[3]&15)!=0 || response.Buffer[7]!=1) throw new IOException("Hiddify DNS TCP fallback failed.");
            }
            return 2;
        }
        finally { stop.Cancel();dns.Stop();await serving; }
    }

    private static async Task<int> DatagramAsync(CancellationToken token)
    {
        var request=Request();request.ProbePort=Port();
        using var echo=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var echoPort=((IPEndPoint)echo.Client.LocalEndPoint!).Port;
        var frontPort=Port();
        var native=JsonNode.Parse(HiddifyCore.Build(request))!;
        native["inbounds"]![0]=new JsonObject{["type"]="direct",["tag"]="vpn4ik-tun",["listen"]="127.0.0.1",["listen_port"]=frontPort,
            ["override_address"]="127.0.0.1",["override_port"]=echoPort};
        var worker=JsonNode.Parse(XrayConfiguration.Build(HiddifyCore.WorkerRequest(request)))!;
        worker["outbounds"]![0]=new JsonObject{["tag"]="proxy",["protocol"]="freedom",["settings"]=new JsonObject()};
        await using var engines=await Pair.StartAsync(worker,native,request.ProbePort,frontPort,token);
        using var udp=new UdpClient(AddressFamily.InterNetwork);
        var payload=System.Text.Encoding.ASCII.GetBytes("VPN4ik UDP fixture");
        await udp.SendAsync(payload,new IPEndPoint(IPAddress.Loopback,frontPort),token);
        var received=await echo.ReceiveAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(5),token);
        if(!received.Buffer.SequenceEqual(payload))throw new IOException("UDP bridge corrupted its payload.");
        await echo.SendAsync(received.Buffer,received.RemoteEndPoint,token);
        var returned=await udp.ReceiveAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(5),token);
        if(!returned.Buffer.SequenceEqual(payload))throw new IOException("UDP bridge response failed.");
        return 2;
    }
    internal static int Port(){using var reserve=new TcpListener(IPAddress.Loopback,0);reserve.Start();return ((IPEndPoint)reserve.LocalEndpoint).Port;}

    internal sealed class Pair : IAsyncDisposable
    {
        private readonly List<Process> processes=new();private readonly List<Task<string>> logs=new();
        internal string Diagnostics=>string.Join(" ",logs.Select(l=>l.IsCompletedSuccessfully?l.Result:"pending"));
        internal static async Task<Pair> StartAsync(JsonNode worker,JsonNode native,int workerPort,int frontPort,CancellationToken token)
        {
            var pair=new Pair();
            try
            {
                var xray=new Process{StartInfo=new ProcessStartInfo(EngineHost.EnginePath){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardError=true,RedirectStandardOutput=true,WorkingDirectory=EngineHost.EngineDirectory}};
                foreach(var arg in new[]{"run","-format=json","-c","stdin:"}) xray.StartInfo.ArgumentList.Add(arg);
                await pair.StartAsync(xray,worker.ToJsonString(),token);
                await SystemProxyLease.WaitForListenerAsync(workerPort,token);
                var core=HiddifyCore.CreateProcess();core.StartInfo.CreateNoWindow=true;
                await pair.StartAsync(core,native.ToJsonString(),token);
                await SystemProxyLease.WaitForListenerAsync(frontPort,token);
                return pair;
            }
            catch
            {
                await pair.DisposeAsync();
                throw new IOException("Hiddify native startup failed: "+string.Join(" ",pair.logs.Select(l=>l.IsCompletedSuccessfully?l.Result:"")));
            }
        }
        private async Task StartAsync(Process process,string config,CancellationToken token)
        {
            if(!process.Start())throw new IOException("Native process did not start.");processes.Add(process);
            logs.Add(process.StandardOutput.ReadToEndAsync());logs.Add(process.StandardError.ReadToEndAsync());
            await process.StandardInput.WriteAsync(config.AsMemory(),token);process.StandardInput.Close();
        }
        public async ValueTask DisposeAsync()
        {
            foreach(var process in processes.AsEnumerable().Reverse())
            {if(!process.HasExited) process.Kill(true);await process.WaitForExitAsync();process.Dispose();}
            processes.Clear();await Task.WhenAll(logs);
        }
    }
}
