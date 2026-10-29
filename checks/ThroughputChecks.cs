using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPNyan;

// Explicit, bounded live diagnostics. Never invoked by ordinary checks.
internal static class ThroughputChecks
{
    internal static async Task<int> RunAsync(string source, string report, int index)
    {
        EngineHost.VerifyFiles(); HiddifyCore.EnsureInstalled();
        var profiles = SubscriptionStore.Load(source).SelectMany(s => s.Profiles).ToArray();
        if (index < 0 || index >= profiles.Length) throw new ArgumentOutOfRangeException(nameof(index));
        var profile = profiles[index];
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4)); var token = deadline.Token;
        var endpoint = (await Dns.GetHostAddressesAsync(profile.Address, token)).First(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        var request = new EngineRequest { Profile = profile, EnableTun = false, UseHiddifyCore = true,
            ProbePort = HiddifyChecks.Port(), HttpProxyPort = HiddifyChecks.Port(), EndpointAddress = endpoint.ToString(),
            UpstreamInterface = XraySession.SelectUpstreamInterface(endpoint) };
        var routeBefore = JsonSerializer.Serialize(XraySession.RouteDiagnostic());
        var worker = JsonNode.Parse(XrayConfiguration.Build(HiddifyCore.WorkerRequest(request)))!;
        var frontend = JsonNode.Parse(HiddifyCore.Build(request))!;
        var nativePort=HiddifyChecks.Port();
        var nativeOutbound=NativeVless(worker["outbounds"]![0]!,request);
        if(nativeOutbound!=null)
        {
            frontend["outbounds"]!.AsArray().Add(nativeOutbound);
            frontend["inbounds"]!.AsArray().Add(new JsonObject{["type"]="http",["tag"]="native-check",["listen"]="127.0.0.1",["listen_port"]=nativePort});
            frontend["route"]!["rules"]!.AsArray().Insert(0,new JsonObject{["inbound"]=new JsonArray("native-check"),["outbound"]="native-proxy"});
        }
        var results = new List<object>();
        await using var pair = await HiddifyChecks.Pair.StartAsync(worker, frontend, request.ProbePort, request.HttpProxyPort, token);
        var proxy = new WebProxy($"socks5://127.0.0.1:{request.ProbePort}") { Credentials = new NetworkCredential(request.ProbeUser, request.ProbePassword) };
        var paths = new[] { (Name: "physical", Proxy: (IWebProxy?)null), (Name: "system-tun", Proxy: (IWebProxy?)null), (Name: "xray-socks", Proxy: (IWebProxy?)proxy),
            (Name: "hiddify-http", Proxy: (IWebProxy?)new WebProxy($"http://127.0.0.1:{request.HttpProxyPort}")),
            (Name: "hiddify-native", Proxy: (IWebProxy?)new WebProxy($"http://127.0.0.1:{nativePort}")) }.Where(path=>path.Name!="hiddify-native"||nativeOutbound!=null);
        var testAddress=(await Dns.GetHostAddressesAsync("speed.cloudflare.com",token)).First(ip=>ip.AddressFamily==AddressFamily.InterNetwork);
        var physical=System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Single(a=>a.Name==request.UpstreamInterface);
        var physicalIndex=physical.GetIPProperties().GetIPv4Properties()!.Index;
        var payload = RandomNumberGenerator.GetBytes(524288);
        foreach (var round in new[] { 1, 2 })
        foreach (var path in round == 1 ? paths : paths.Reverse())
        {
            var handler=new SocketsHttpHandler { UseProxy = path.Proxy != null, Proxy = path.Proxy,
                AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(5) };
            if(path.Name=="physical") handler.ConnectCallback=async(context,cancellation)=> {
                var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                try {
                    socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(physicalIndex)); // Windows IP_UNICAST_IF.
                    await socket.ConnectAsync(testAddress,443,cancellation);return new NetworkStream(socket,ownsSocket:true);
                } catch {socket.Dispose();throw;}
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
            foreach (var direction in new[] { "download", "upload" })
            {
                var clock = Stopwatch.StartNew(); long bytes = 0;
                var item = new Dictionary<string, object?> { ["Round"] = round, ["Path"] = path.Name, ["Direction"] = direction };
                try
                {
                    using var message = new HttpRequestMessage(direction == "download" ? HttpMethod.Get : HttpMethod.Post,
                        direction == "download" ? $"https://{testAddress}/__down?bytes=5000000" : $"https://{testAddress}/__up");
                    message.Headers.Host="speed.cloudflare.com";
                    message.Headers.ExpectContinue = false;
                    if (direction == "upload") message.Content = new ByteArrayContent(payload);
                    using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, token);
                    item["Status"] = (int)response.StatusCode; response.EnsureSuccessStatusCode();
                    using var stream = await response.Content.ReadAsStreamAsync(token);
                    var buffer = new byte[65536]; int read;
                    using var bodyTimeout = CancellationTokenSource.CreateLinkedTokenSource(token); bodyTimeout.CancelAfter(TimeSpan.FromSeconds(20));
                    while ((read = await stream.ReadAsync(buffer, bodyTimeout.Token)) > 0) bytes += read;
                    if (direction == "download" && bytes != 5000000) throw new IOException("Unexpected payload size");
                    if (direction == "upload") bytes = payload.Length;
                    item["Succeeded"] = true; item["Mbps"] = Math.Round(bytes * 8d / clock.Elapsed.TotalSeconds / 1e6, 3);
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException)
                { item["Succeeded"] = false; item["ErrorType"] = ex.GetType().Name; }
                item["Milliseconds"] = clock.ElapsedMilliseconds; item["Bytes"] = bytes; results.Add(item);
                Console.WriteLine(JsonSerializer.Serialize(item));
                File.WriteAllText(report, JsonSerializer.Serialize(new { Index = index, Results = results,
                    SystemRouteUnchanged = routeBefore == JsonSerializer.Serialize(XraySession.RouteDiagnostic()) }, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        return 0;
    }

    private static JsonObject? NativeVless(JsonNode outbound,EngineRequest request)
    {
        var stream=outbound["streamSettings"]!;
        if((string?)outbound["protocol"]!="vless" || (string?)stream["network"]!="grpc")return null;
        var user=outbound["settings"]!["vnext"]![0]!["users"]![0]!;
        Console.WriteLine(JsonSerializer.Serialize(new{Protocol=(string?)outbound["protocol"],Network=(string?)stream["network"],Security=(string?)stream["security"],HasFlow=!string.IsNullOrEmpty((string?)user["flow"]),HasAuthority=!string.IsNullOrEmpty((string?)stream["grpcSettings"]?["authority"]),MultiMode=(bool?)stream["grpcSettings"]?["multiMode"]}));
        var security=(string?)stream["security"];
        if((string?)outbound["protocol"]!="vless" || (string?)stream["network"]!="grpc" || security is not ("tls" or "reality") ||
            !string.IsNullOrEmpty((string?)user["flow"]) || !string.IsNullOrEmpty((string?)stream["grpcSettings"]?["authority"]) ||
            (bool?)stream["grpcSettings"]?["multiMode"]==true || !string.IsNullOrEmpty((string?)stream["realitySettings"]?["mldsa65Verify"])) return null;
        var tls=stream[security=="reality"?"realitySettings":"tlsSettings"]!;
        var nativeTls=new JsonObject { ["enabled"]=true,["server_name"]=tls["serverName"]!.DeepClone(),["alpn"]=tls["alpn"]?.DeepClone(),
            ["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]=(string?)tls["fingerprint"]??"chrome"} };
        if(security=="reality") nativeTls["reality"]=new JsonObject{["enabled"]=true,["public_key"]=(tls["publicKey"]??tls["password"])!.DeepClone(),["short_id"]=tls["shortId"]?.DeepClone()};
        Console.WriteLine("Native comparison: VLESS gRPC; same endpoint and TLS identity.");
        return new JsonObject { ["type"]="vless",["tag"]="native-proxy",["server"]=request.EndpointAddress,
            ["server_port"]=outbound["settings"]!["vnext"]![0]!["port"]!.DeepClone(),["uuid"]=user["id"]!.DeepClone(),
            ["bind_interface"]=request.UpstreamInterface,
            ["tls"]=nativeTls,
            ["transport"]=new JsonObject{["type"]="grpc",["service_name"]=stream["grpcSettings"]!["serviceName"]!.DeepClone()} };
    }
}
