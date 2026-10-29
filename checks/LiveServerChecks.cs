using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPNyan;

// Explicitly invoked diagnostics only; ordinary tests never load saved user profiles or contact external servers.
internal static class LiveServerChecks
{
    internal static async Task<int> RunAsync(string source,string report,string path)
    {
        var selection=path.Split('@',2);path=selection[0];
        var indices=selection.Length==2?selection[1].Split(',').Select(int.Parse).ToHashSet():null;
        if(path is not ("physical" or "system" or "physical-web" or "physical-doh" or "physical-dns-alt" or "physical-ipv6"))throw new ArgumentException("Unknown diagnostic path.");
        EngineHost.VerifyFiles();HiddifyCore.EnsureInstalled();
        var profiles=SubscriptionStore.Load(source).SelectMany(s=>s.Profiles).ToArray();
        var results=new object[profiles.Length];using var slots=new SemaphoreSlim(2);
        await Task.WhenAll(profiles.Select(async(profile,index)=>
        {
            if(indices!=null&&!indices.Contains(index))return;
            await slots.WaitAsync();
            try { results[index]=await VerifyAsync(profile,index,path,report); }
            finally { slots.Release(); }
        }));
        File.WriteAllText(report,JsonSerializer.Serialize(results.Where(r=>r!=null),new JsonSerializerOptions{WriteIndented=true}));
        return 0; // The report records failures per server; completing a diagnostic is not a successful connection.
    }

    private static async Task<Dictionary<string,object?>> VerifyAsync(SubscriptionProfile profile,int index,string path,string report)
    {
        var result=new Dictionary<string,object?>{["Index"]=index,["Path"]=path,["Mode"]="Hiddify HTTP -> authenticated Xray SOCKS; no system TUN/proxy"};
        HiddifyChecks.Pair? pair=null;var clock=Stopwatch.StartNew();
        var stage="resolve endpoint";
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(35));var token=deadline.Token;
        var routeBefore=JsonSerializer.Serialize(XraySession.RouteDiagnostic());
        try
        {
            var addresses=await Dns.GetHostAddressesAsync(profile.Address,token);
            var endpoint=addresses.FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetwork)??addresses.FirstOrDefault()??throw new IOException("No endpoint addresses.");
            var request=new EngineRequest{Profile=profile,EnableTun=false,EnableSystemProxy=false,UseHiddifyCore=true,
                ProbePort=HiddifyChecks.Port(),HttpProxyPort=HiddifyChecks.Port(),EndpointAddress=endpoint.ToString(),Diagnostics=true,
                UpstreamInterface=path.StartsWith("physical",StringComparison.Ordinal)?XraySession.SelectUpstreamInterface(endpoint):"auto"};
            if(path=="physical-dns-alt")request.Routing.DnsServers="8.8.8.8\n9.9.9.9";
            result["PhysicalInterfaceSelected"]=request.UpstreamInterface!="auto";
            stage="start Hiddify/Xray";
            var worker=JsonNode.Parse(XrayConfiguration.Build(HiddifyCore.WorkerRequest(request)))!;
            var frontend=JsonNode.Parse(HiddifyCore.Build(request))!;
            if(path=="physical-doh")
                foreach(var dns in frontend["dns"]!["servers"]!.AsArray().OfType<JsonObject>())
                    if((string?)dns["type"]=="tcp" && (string?)dns["server"] is "1.1.1.1" or "2606:4700:4700::1111")
                    {dns["type"]="https";dns["server_port"]=443;dns["path"]="/dns-query";dns["tls"]=new JsonObject{["enabled"]=true,["server_name"]="cloudflare-dns.com"};}
            pair=await HiddifyChecks.Pair.StartAsync(worker,frontend,request.ProbePort,request.HttpProxyPort,token);
            if(path=="physical-ipv6") result["WorkerIpv6Available"]=await TunnelIpv6Probe.CheckAsync(request,token);
            stage="HTTPS through Hiddify/Xray";
            using var probe=new ConnectionProbe(new SocketsHttpHandler{UseProxy=true,Proxy=new WebProxy($"http://127.0.0.1:{request.HttpProxyPort}"),AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(5)});
            var measurements=new List<long>();
            result["HttpsMs"]=measurements;
            var healthProbe=false;
            try
            {
                for(var attempt=0;attempt<2;attempt++)
                {var timer=Stopwatch.StartNew();await probe.CheckAsync(token);measurements.Add(timer.ElapsedMilliseconds);}
                healthProbe=true;
            }
            catch(HttpRequestException){result["HealthProbeFailure"]="No successful verification endpoint";}
            result["HealthProbePassed"]=healthProbe;
            var websiteVerified=false;
            if(path=="physical-web" && !healthProbe)
            {
                stage="ordinary HTTPS sites";
                using var http=new HttpClient(new SocketsHttpHandler{UseProxy=true,Proxy=new WebProxy($"http://127.0.0.1:{request.HttpProxyPort}"),AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(7)};
                var sites=new List<object>();result["Sites"]=sites;
                foreach(var target in new[]{"https://example.com","https://www.microsoft.com"})
                {
                    var timer=Stopwatch.StartNew();
                    try{using var reply=await http.GetAsync(target,HttpCompletionOption.ResponseHeadersRead,token);var status=(int)reply.StatusCode;websiteVerified|=status is >=200 and <400;sites.Add(new{Site=new Uri(target).Host,Status=status,Milliseconds=timer.ElapsedMilliseconds});}
                    catch(Exception ex)when(ex is HttpRequestException or OperationCanceledException){sites.Add(new{Site=new Uri(target).Host,ErrorType=ex.GetType().Name});}
                }
            }
            result["WebsiteVerified"]=websiteVerified;
            stage="traffic statistics";
            using var metrics=new HttpClient(new SocketsHttpHandler{UseProxy=true,Proxy=new WebProxy($"socks5://127.0.0.1:{request.ProbePort}"){
                Credentials=new NetworkCredential(request.ProbeUser,request.ProbePassword)}}){Timeout=TimeSpan.FromSeconds(3)};
            var traffic=TrafficMeter.Parse(await metrics.GetStringAsync("http://metrics.vpn4ik.invalid/debug/vars",token));
            result["TrafficVerified"]=traffic.Download>0&&traffic.Upload>0;
            result["Verified"]=(healthProbe||websiteVerified)&&traffic.Download>0&&traffic.Upload>0;
        }
        catch(Exception ex){result["Verified"]=false;result["ErrorType"]=ex.GetType().Name;result["Stage"]=stage;}
        finally
        {
            if(pair!=null)
            {
                try{await pair.DisposeAsync();result["Disconnected"]=true;}catch{result["Disconnected"]=false;}
                var redactor=new SecretRedactor(profile.Configuration);
                var messages=System.Text.Encoding.UTF8.GetBytes(string.Join('\n',pair.Diagnostics.Split('\n').TakeLast(30).Select(redactor.Clean)));
                try{File.WriteAllBytes(report+"."+index+".logs.dpapi",ProtectedData.Protect(messages,null,DataProtectionScope.CurrentUser));}
                finally{Array.Clear(messages,0,messages.Length);}
            }
            result["ElapsedMs"]=clock.ElapsedMilliseconds;
            result["SystemRouteUnchanged"]=routeBefore==JsonSerializer.Serialize(XraySession.RouteDiagnostic());
            Console.WriteLine("Server "+(index+1)+": Hiddify path="+path+"; verified="+result.GetValueOrDefault("Verified")+"; stage="+stage);
        }
        return result;
    }
}
