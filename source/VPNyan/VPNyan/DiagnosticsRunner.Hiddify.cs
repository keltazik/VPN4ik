using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VPNyan;

internal static partial class DiagnosticsRunner
{
    // Only loopback fixtures. Exercises the real private-console helper without a TUN, proxy lease or UAC.
    internal static async Task<int> RunHiddifyWorkerAsync(string reportPath,bool waitForParentDeath)
    {
        var report=new Dictionary<string,object?>();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(35));var token=timeout.Token;
        using var http=new TcpListener(IPAddress.Loopback,0);http.Start();
        var httpPort=((IPEndPoint)http.LocalEndpoint).Port;
        var serving=Task.Run(async()=>
        {
            try
            {
                while(!token.IsCancellationRequested)
                {
                    using var client=await http.AcceptTcpClientAsync(token);using var stream=client.GetStream();
                    var buffer=new byte[4096];await stream.ReadAsync(buffer,token);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nverified"),token);
                }
            }
            catch(Exception ex) when(ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
        },token);
        Process? fixture=null;XraySession? session=null;var children=new List<Process>();
        Task<string>? fixtureOutput=null,fixtureError=null;
        using var job=new EngineJob();
        static int Port(){using var socket=new TcpListener(IPAddress.Loopback,0);socket.Start();return ((IPEndPoint)socket.LocalEndpoint).Port;}
        try
        {
            EngineHost.VerifyFiles();HiddifyCore.EnsureInstalled();
            var upstream=Port();
            fixture=new Process { StartInfo=new ProcessStartInfo(EngineHost.EnginePath) {UseShellExecute=false,CreateNoWindow=true,
                RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=EngineHost.EngineDirectory} };
            foreach(var arg in new[]{"run","-format=json","-c","stdin:"})fixture.StartInfo.ArgumentList.Add(arg);
            fixture.Start();job.Assign(fixture);
            fixtureOutput=fixture.StandardOutput.ReadToEndAsync();fixtureError=fixture.StandardError.ReadToEndAsync();
            await fixture.StandardInput.WriteAsync(new JsonObject { ["inbounds"]=new JsonArray(new JsonObject {
                ["protocol"]="socks",["listen"]="127.0.0.1",["port"]=upstream,["settings"]=new JsonObject { ["auth"]="noauth",["udp"]=true } }),
                ["outbounds"]=new JsonArray(new JsonObject { ["protocol"]="freedom",["settings"]=new JsonObject() }) }.ToJsonString());
            fixture.StandardInput.Close();await SystemProxyLease.WaitForListenerAsync(upstream,token);
            var request=new EngineRequest { UseHiddifyCore=true,EnableTun=false,EnableSystemProxy=false,ProbePort=Port(),HttpProxyPort=Port(),
                Profile=new SubscriptionProfile { Protocol="SOCKS",Address="127.0.0.1",Port=upstream,
                    Configuration=new JsonObject { ["outbounds"]=new JsonArray(new JsonObject { ["protocol"]="socks",["settings"]=new JsonObject {
                        ["servers"]=new JsonArray(new JsonObject { ["address"]="127.0.0.1",["port"]=upstream }) } }) }.ToJsonString() } };
            session=new XraySession();await session.StartOwnedBridgeDiagnosticAsync(request,token);
            foreach(var id in session.OwnedProcessIds.Append(session.HelperProcessId!.Value))
            {var process=Process.GetProcessById(id);_=process.Handle;children.Add(process);}
            using var client=new HttpClient(new SocketsHttpHandler { Proxy=new WebProxy("http://127.0.0.1:"+request.HttpProxyPort),UseProxy=true });
            report["HttpVerified"]=await client.GetStringAsync("http://127.0.0.1:"+httpPort,token)=="verified";
            var traffic=await session.ReadTrafficAsync(token);report["TrafficVerified"]=traffic.Download>0 && traffic.Upload>0;
            report["OwnedProcesses"]=session.OwnedProcessIds;report["HelperProcess"]=session.HelperProcessId;report["FixtureProcess"]=fixture.Id;
            report["NoTun"]=!request.EnableTun;report["NoSystemProxy"]=!request.EnableSystemProxy;
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(reportPath))!);
            if(waitForParentDeath)
            { report["Ready"]=true;File.WriteAllText(reportPath,JsonSerializer.Serialize(report));await Task.Delay(Timeout.Infinite,token); }
            var clock=Stopwatch.StartNew();await session.DisposeAsync();session=null;
            report["StopMilliseconds"]=clock.ElapsedMilliseconds;
            report["AllOwnedStopped"]=children.All(p=>p.HasExited);
            report["ExitCodes"]=children.Select(p=>p.HasExited?p.ExitCode:int.MinValue).ToArray();
            report["Verified"]=report["HttpVerified"] is true && report["TrafficVerified"] is true && report["AllOwnedStopped"] is true && children.All(p=>p.ExitCode==0);
        }
        catch(Exception ex) { report["Verified"]=false;report["Error"]=SecretRedactor.Generic(ex.Message); }
        finally
        {
            if(session!=null)try{await session.DisposeAsync();}catch{}
            foreach(var child in children)child.Dispose();
            if(fixture!=null){if(!fixture.HasExited)fixture.Kill(true);await fixture.WaitForExitAsync();fixture.Dispose();}
            if(fixtureOutput!=null && fixtureError!=null)await Task.WhenAll(fixtureOutput,fixtureError);
            timeout.Cancel();http.Stop();await serving;
            File.WriteAllText(reportPath,JsonSerializer.Serialize(report,new JsonSerializerOptions {WriteIndented=true}));
        }
        return report.TryGetValue("Verified",out var verified) && verified is true?0:1;
    }
}
