using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using VPNyan;

internal static class NativeProfileCompatibilityChecks
{
    internal static async Task<int> RunAsync()
    {
        var count=0;
        foreach(var network in new[]{"ws","grpc","tcp"})
        {
            await HysteriaChecks.ValidateNativeAsync(ProfileCompatibilityChecks.Build(ProfileCompatibilityChecks.Vmess(network)).ToJsonString());
            count++;
        }
        // A real VMess server requires the same transport as the imported share.
        // Dropping the TCP header breaks this exchange even though both processes start.
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(35));
        await using var target=new NativeRoutingChecks.TestHttpServer("profile-compatibility",deadline.Token);
        foreach(var network in new[]{"tcp","ws"})
        {
            var serverPort=HiddifyChecks.Port();var clientPort=HiddifyChecks.Port();
            var profile=SubscriptionParser.Parse(ProfileCompatibilityChecks.Vmess(network,"",serverPort)).Single();
            var request=new EngineRequest { Profile=profile,EnableTun=false,ProbePort=clientPort,EndpointAddress="127.0.0.1",Diagnostics=true };
            var clientConfig=JsonNode.Parse(XrayConfiguration.Build(request))!;
            // Server transport is authored independently of the client conversion.
            var serverStream=JsonNode.Parse(network=="tcp" ? """
                {"network":"tcp","security":"none","tcpSettings":{"header":{"type":"http","request":{"path":["/fixture"],"headers":{"Host":["front.example.test"]}}}}}
                """ : """
                {"network":"ws","security":"none","wsSettings":{"path":"/fixture"}}
                """)!;
            var serverConfig=new JsonObject {
                ["log"]=new JsonObject{["loglevel"]="info"},
                ["inbounds"]=new JsonArray(new JsonObject{["listen"]="127.0.0.1",["port"]=serverPort,["protocol"]="vmess",
                    ["settings"]=new JsonObject{["clients"]=new JsonArray(new JsonObject{["id"]=ProfileCompatibilityChecks.UserId,["alterId"]=0})},
                    ["streamSettings"]=serverStream}),
                ["outbounds"]=new JsonArray(new JsonObject{["protocol"]="freedom",["settings"]=new JsonObject{
                    ["finalRules"]=new JsonArray(new JsonObject{["action"]="allow",["ip"]=new JsonArray("127.0.0.1"),["port"]=target.Port.ToString()},
                        new JsonObject{["action"]="block"})}}) };
            await using var server=await Core.StartAsync(serverConfig,serverPort,deadline.Token);
            await using var client=await Core.StartAsync(clientConfig,clientPort,deadline.Token);
            using var handler=new SocketsHttpHandler{UseProxy=true,Proxy=new WebProxy($"socks5://127.0.0.1:{clientPort}"){
                Credentials=new NetworkCredential(request.ProbeUser,request.ProbePassword)}};
            using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(5)};
            string body;
            try { body=await http.GetStringAsync($"http://127.0.0.1:{target.Port}/",deadline.Token); }
            catch { await client.DisposeAsync(); await server.DisposeAsync(); throw new IOException("VMess "+network+" native exchange failed. Client: "+client.Diagnostics+" Server: "+server.Diagnostics); }
            if(body!="profile-compatibility") throw new IOException("Imported VMess "+network+" profile failed its native transport exchange.");
            count++;
        }
        return count;
    }

    private sealed class Core : IAsyncDisposable
    {
        private readonly Process process;
        private readonly Task<string> stdout,stderr;
        private bool disposed;
        internal string Diagnostics { get { var text=string.Join(" ",new[]{stdout,stderr}.Where(t=>t.IsCompletedSuccessfully).Select(t=>t.Result));return text[..Math.Min(text.Length,2400)]; } }
        private Core(Process process){this.process=process;stdout=process.StandardOutput.ReadToEndAsync();stderr=process.StandardError.ReadToEndAsync();}
        internal static async Task<Core> StartAsync(JsonNode config,int port,CancellationToken token)
        {
            var process=new Process{StartInfo=new ProcessStartInfo(EngineHost.EnginePath){UseShellExecute=false,CreateNoWindow=true,
                RedirectStandardInput=true,RedirectStandardError=true,RedirectStandardOutput=true,WorkingDirectory=EngineHost.EngineDirectory}};
            foreach(var arg in new[]{"run","-format=json","-c","stdin:"})process.StartInfo.ArgumentList.Add(arg);
            process.Start();var core=new Core(process);
            try{await process.StandardInput.WriteAsync(config.ToJsonString());process.StandardInput.Close();await SystemProxyLease.WaitForListenerAsync(port,token);return core;}
            catch{await core.DisposeAsync();throw;}
        }
        public async ValueTask DisposeAsync()
        {if(disposed)return;disposed=true;if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync();await Task.WhenAll(stdout,stderr);process.Dispose();}
    }
}
