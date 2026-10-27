using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using VPNyan;

internal static class NativeRoutingChecks
{
    // Only loopback listeners and a non-elevated Xray process. No TUN, system routes or external requests.
    internal static async Task<int> RunAsync()
    {
        EngineHost.VerifyFiles();
        await HysteriaChecks.ValidateNativeAsync(XrayConfiguration.Build(new EngineRequest
        { Profile = SubscriptionParser.Parse(HysteriaChecks.ProfileJson).Single(), EnableTun = false, ProbePort = 49152 }));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await using var direct = new TestHttpServer("direct", timeout.Token);
        await using var proxy = new TestHttpServer("proxy", timeout.Token);
        var assertions = 1;
        foreach (var scenario in new[] { "all", "bypass-ip", "include-ip", "include-miss", "bypass-domain", "bypass-process" })
        {
            using var reserve = new TcpListener(IPAddress.Loopback, 0); reserve.Start();
            using var control = new TcpListener(IPAddress.Loopback, 0); control.Start();
            var inputPort = ((IPEndPoint)reserve.LocalEndpoint).Port;
            var request = new EngineRequest
            {
                EnableTun = true, ProbePort = ((IPEndPoint)control.LocalEndpoint).Port,
                Profile = new SubscriptionProfile { Protocol = "socks", Configuration = "{\"outbounds\":[{\"protocol\":\"socks\",\"settings\":{\"servers\":[{\"address\":\"127.0.0.1\",\"port\":1080}]}}]}" }
            };
            request.Routing.SplitTunnelEnabled = scenario != "all";
            request.Routing.SplitTunnelMode = scenario.StartsWith("include") ? "Include" : "Bypass";
            if (scenario.EndsWith("ip")) request.Routing.SplitNetworks.Add("127.0.0.1");
            if (scenario.EndsWith("miss")) request.Routing.SplitNetworks.Add("192.0.2.1");
            if (scenario.EndsWith("domain")) request.Routing.SplitDomains.Add("localhost");
            if (scenario.EndsWith("process")) request.Routing.SplitApplications.Add(Process.GetCurrentProcess().ProcessName);
            var config = JsonNode.Parse(XrayConfiguration.Build(request))!;
            // Exercise the generated routing with a SOCKS input in place of the TUN input.
            config["inbounds"]![1] = new JsonObject { ["tag"] = "vpn4ik-tun", ["listen"] = "127.0.0.1", ["port"] = inputPort,
                ["protocol"] = "socks", ["settings"] = new JsonObject { ["auth"] = "noauth" } };
            config["outbounds"]![0] = new JsonObject { ["tag"] = "proxy", ["protocol"] = "freedom",
                ["settings"] = new JsonObject { ["redirect"] = "127.0.0.1:" + proxy.Port } };
            reserve.Stop(); control.Stop();
            using var engine = new Process { StartInfo = new ProcessStartInfo(EngineHost.EnginePath)
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    WorkingDirectory = EngineHost.EngineDirectory } };
            engine.StartInfo.ArgumentList.Add("run"); engine.StartInfo.ArgumentList.Add("-format=json");
            engine.StartInfo.ArgumentList.Add("-c"); engine.StartInfo.ArgumentList.Add("stdin:");
            engine.Start();
            var output = engine.StandardOutput.ReadToEndAsync(); var errors = engine.StandardError.ReadToEndAsync();
            try
            {
                await engine.StandardInput.WriteAsync(config.ToJsonString()); engine.StandardInput.Close();
                using var handler = new SocketsHttpHandler { Proxy = new WebProxy($"socks5://127.0.0.1:{inputPort}"), UseProxy = true };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                string? response = null;
                string? lastFailure = null;
                for (var attempt = 0; attempt < 30; attempt++)
                {
                    if (engine.HasExited) throw new Exception("Native routing engine rejected configuration: " + await errors);
                    try { response = await client.GetStringAsync($"http://{(scenario.EndsWith("domain") ? "localhost" : "127.0.0.1")}:{direct.Port}/", timeout.Token); break; }
                    catch (HttpRequestException ex) { lastFailure = ex.ToString(); await Task.Delay(60, timeout.Token); }
                }
                if (response == null)
                {
                    engine.Kill(true); await engine.WaitForExitAsync(timeout.Token);
                    throw new Exception("Local routing request failed: " + lastFailure + "\n" + await output + await errors);
                }
                var expected = scenario is "bypass-ip" or "bypass-domain" or "bypass-process" or "include-miss" ? "direct" : "proxy";
                if (response != expected) throw new Exception($"Native routing {scenario}: expected {expected}, got {response}");
                assertions++;
                using var metricsHandler = new SocketsHttpHandler { UseProxy = true, Proxy = new WebProxy($"socks5://127.0.0.1:{request.ProbePort}")
                    { Credentials = new NetworkCredential(request.ProbeUser, request.ProbePassword) } };
                using var metricsClient = new HttpClient(metricsHandler) { Timeout = TimeSpan.FromSeconds(2) };
                var counters = TrafficMeter.Parse(await metricsClient.GetStringAsync("http://metrics.vpn4ik.invalid/debug/vars", timeout.Token));
                if (expected == "proxy" && (counters.Download <= 0 || counters.Upload <= 0)) throw new Exception("Native traffic counters must measure both directions");
                if (expected == "direct" && (counters.Download != 0 || counters.Upload != 0)) throw new Exception("Direct split traffic must not inflate VPN counters");
                assertions++;
            }
            finally
            {
                if (!engine.HasExited) engine.Kill(true);
                await engine.WaitForExitAsync(timeout.Token);
                await Task.WhenAll(output, errors);
            }
        }
        return assertions + await NativeDnsChecks.RunAsync() + await CheckHttpProxyAsync(direct.Port);
    }

    private static async Task<int> CheckHttpProxyAsync(int targetPort)
    {
        using var reserve = new TcpListener(IPAddress.Loopback,0); reserve.Start();
        using var control = new TcpListener(IPAddress.Loopback,0); control.Start();
        var port=((IPEndPoint)reserve.LocalEndpoint).Port;
        var request=new EngineRequest { EnableTun=false,EnableSystemProxy=true,HttpProxyPort=port,ProbePort=((IPEndPoint)control.LocalEndpoint).Port,
            Routing=new AppSettings{ConnectionMode="proxy"}, Profile=SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#HTTP").Single() };
        var config=JsonNode.Parse(XrayConfiguration.Build(request))!;
        config["outbounds"]![0]=new JsonObject{["tag"]="proxy",["protocol"]="freedom",["settings"]=new JsonObject{["redirect"]="127.0.0.1:"+targetPort}};
        reserve.Stop(); control.Stop();
        using var engine=new Process{StartInfo=new ProcessStartInfo(EngineHost.EnginePath){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=EngineHost.EngineDirectory}};
        foreach(var arg in new[]{"run","-format=json","-c","stdin:"})engine.StartInfo.ArgumentList.Add(arg);
        engine.Start();var output=engine.StandardOutput.ReadToEndAsync();var errors=engine.StandardError.ReadToEndAsync();
        try
        {
            await engine.StandardInput.WriteAsync(config.ToJsonString());engine.StandardInput.Close();
            await SystemProxyLease.WaitForListenerAsync(port,CancellationToken.None);
            using var handler=new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+port)};
            using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(3)};
            if(await http.GetStringAsync("http://example.invalid/")!="direct")throw new Exception("HTTP proxy did not forward the request.");
            return 1;
        }
        finally { if(!engine.HasExited)engine.Kill(true);await engine.WaitForExitAsync();await Task.WhenAll(output,errors); }
    }
    private sealed class TestHttpServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop;
        private readonly Task loop;
        internal int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
        internal TestHttpServer(string body, CancellationToken cancellationToken)
        {
            stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            listener.Start();
            loop = Task.Run(async () =>
            {
                try
                {
                    while (!stop.IsCancellationRequested)
                    {
                        using var socket = await listener.AcceptTcpClientAsync(stop.Token);
                        using var stream = socket.GetStream();
                        var buffer = new byte[8192];
                        var length = 0;
                        while (length < buffer.Length)
                        {
                            var read = await stream.ReadAsync(buffer.AsMemory(length), stop.Token);
                            if (read == 0) break;
                            length += read;
                            if (Encoding.ASCII.GetString(buffer, 0, length).Contains("\r\n\r\n")) break;
                        }
                        var response = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
                        await stream.WriteAsync(response, stop.Token);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
            });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await loop; stop.Dispose(); }
    }
}
