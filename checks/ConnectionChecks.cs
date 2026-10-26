using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using VPNyan;

internal static class ConnectionChecks
{
    internal static void Run(string fixtures, Action<bool,string> check)
    {
        var previous=SynchronizationContext.Current;SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        try {Await(ProbeCases(check));Configuration(check);HealthUi(fixtures,check);}finally{SynchronizationContext.SetSynchronizationContext(previous);}
    }
    private static async Task ProbeCases(Action<bool,string> check)
    {
        var urls=new[]{new Uri("https://first.example.test"),new Uri("https://second.example.test")};
        using(var probe=new ConnectionProbe(new Handler((request,token)=>Task.FromResult(request.RequestUri!.Host.StartsWith("first")?Reply(HttpStatusCode.ServiceUnavailable,"unavailable"):Reply(HttpStatusCode.OK,"192.0.2.42\n"))),urls,hedgeDelay:TimeSpan.FromMilliseconds(10)))
            check(await probe.CheckAsync(CancellationToken.None)=="192.0.2.42","A blocked primary IP service falls back to an independent valid HTTPS response");
        var cancelled=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using(var probe=new ConnectionProbe(new Handler(async(request,token)=>
        {
            if(request.RequestUri!.Host.StartsWith("first")){try{await Task.Delay(Timeout.Infinite,token);}finally{cancelled.TrySetResult();}}
            return Reply(HttpStatusCode.OK,"192.0.2.43");
        }),urls,hedgeDelay:TimeSpan.FromMilliseconds(20)))
        {
            var clock=Stopwatch.StartNew();var ip=await probe.CheckAsync(CancellationToken.None);
            check(ip=="192.0.2.43"&&clock.Elapsed<TimeSpan.FromSeconds(2),"A stalled IP service cannot delay the faster backup response");
            await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(2));check(true,"Successful checks cancel losing requests instead of leaving stale work running");
        }
        var connectivity=new[]{urls[0],new Uri("https://www.gstatic.com/generate_204")};
        using(var probe=new ConnectionProbe(new Handler((request,token)=>Task.FromResult(request.RequestUri!.Host=="www.gstatic.com"?Reply(HttpStatusCode.NoContent,""):Reply(HttpStatusCode.OK,"<html>blocked</html>"))),connectivity,hedgeDelay:TimeSpan.Zero))
            check(await probe.CheckAsync(CancellationToken.None)=="","A genuine HTTPS 204 confirms connectivity when external-IP services are unavailable, without fabricating an IP");
        foreach(var body in new[]{"<html>login</html>","1","192.0.2.1 extra",new string('x',1024)})
        {
            using var probe=new ConnectionProbe(new Handler((_,_)=>Task.FromResult(Reply(HttpStatusCode.OK,body))),urls,hedgeDelay:TimeSpan.Zero);
            var rejected=false;try{await probe.CheckAsync(CancellationToken.None);}catch(HttpRequestException){rejected=true;}
            check(rejected,"Malformed and oversized IP responses never count as verified connectivity");
        }
        using(var probe=new ConnectionProbe(new Handler((_,_)=>Task.FromResult(Reply(HttpStatusCode.OK,"captive portal"))),connectivity,hedgeDelay:TimeSpan.Zero))
        {var rejected=false;try{await probe.CheckAsync(CancellationToken.None);}catch(HttpRequestException){rejected=true;}check(rejected,"The connectivity fallback requires the expected 204 status, not any successful HTML page");}
        using(var probe=new ConnectionProbe(new Handler(async(_,token)=>{await Task.Delay(Timeout.Infinite,token);return Reply(HttpStatusCode.OK,"");}),urls,TimeSpan.FromMilliseconds(25),TimeSpan.Zero))
        {var failed=false;try{await probe.CheckAsync(CancellationToken.None);}catch(HttpRequestException){failed=true;}check(failed,"All unreachable endpoints fail within the bounded attempt timeout");}
        using(var probe=new ConnectionProbe(new Handler(async(_,token)=>{await Task.Delay(Timeout.Infinite,token);return Reply(HttpStatusCode.OK,"");}),urls,hedgeDelay:TimeSpan.Zero))
        using(var stop=new CancellationTokenSource(TimeSpan.FromMilliseconds(25)))
        {var observed=false;try{await probe.CheckAsync(stop.Token);}catch(OperationCanceledException){observed=true;}check(observed,"User cancellation propagates as cancellation rather than a connectivity failure");}
    }
    private static void Configuration(Action<bool,string> check)
    {
        var root=JsonNode.Parse("""
        {"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"vpn.example.test","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"test","user_agent":"fixture","idle_timeout":60},"sockopt":{"tcpKeepAliveIdle":45,"tcpKeepAliveInterval":15,"tcpUserTimeout":30000,"dialerProxy":"unsafe","interface":"not-provider-controlled","customSockopt":[{}]}}}]}
        """)!;
        var profile=SubscriptionParser.Parse(root.ToJsonString()).Single();
        var request=new EngineRequest{Profile=profile,EnableTun=false,ProbePort=49152,EndpointAddress="192.0.2.10",UpstreamInterface="fixture-uplink"};
        var built=JsonNode.Parse(XrayConfiguration.Build(request))!;var stream=built["outbounds"]![0]!["streamSettings"]!;
        check(stream["sockopt"]!["tcpKeepAliveIdle"]!.GetValue<int>()==45&&stream["sockopt"]!["tcpUserTimeout"]!.GetValue<int>()==30000,"Provider TCP keep-alive and user-timeout settings survive profile sanitization");
        check(stream["sockopt"]!["interface"]!.GetValue<string>()=="fixture-uplink"&&stream["sockopt"]!["dialerProxy"]==null&&stream["sockopt"]!["customSockopt"]==null,"Physical uplink binding is application-controlled and arbitrary provider socket operations stay excluded");
        check(stream["tlsSettings"]!["serverName"]!.GetValue<string>()=="vpn.example.test"&&built["outbounds"]![0]!["settings"]!["vnext"]![0]!["address"]!.GetValue<string>()=="192.0.2.10","Resolving a server to an IP preserves its original TLS server name");
        check(stream["grpcSettings"]!["user_agent"]!.GetValue<string>()=="fixture","gRPC preserves the provider's client identification");
        root["outbounds"]![0]!["streamSettings"]!["sockopt"]!["tcpUserTimeout"]="unsafe";profile.Configuration=root.ToJsonString();
        var rejected=false;try{XrayConfiguration.Build(request);}catch(InvalidDataException){rejected=true;}check(rejected,"Invalid TCP keep-alive values are rejected before engine startup");
    }
    private static void HealthUi(string fixtures,Action<bool,string> check)
    {
        var session=new Session();var window=new MainWindow(false,Path.Combine(fixtures,"connection-health-"+Guid.NewGuid().ToString("N")),()=>session);
        window.ApplySubscription(new Subscription{Url="local:health",Profiles=SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#Health")});Await(window.Connect());
        var method=typeof(MainWindow).GetMethod("RecheckConnectionAsync",BindingFlags.NonPublic|BindingFlags.Instance)!;
        Await((Task)method.Invoke(window,new object[]{session})!);
        check(session.IsRunning&&session.Stops==0&&((TextBlock)window.FindName("StatusText")).Text.Contains("Перепроверяю"),"A single periodic check failure preserves the established tunnel and requests a recheck");
        Await((Task)method.Invoke(window,new object[]{session})!);
        check(session.IsRunning&&session.Stops==0&&((TextBlock)window.FindName("StatusText")).Text.Contains("Нет подтверждённого"),"Repeated independent-check failures show degraded access without tearing down the user's VPN");
        Await(window.Disconnect());window.Close();Pump();
    }
    private sealed class Session:IVpnSession
    {
        public bool IsRunning{get;private set;}public int Stops;public event Action<string>? Log{add{}remove{}}
        public Task<string> StartAsync(SubscriptionProfile profile,int mtu,CancellationToken token,bool enableTun=true,bool elevate=true,bool diagnostics=false,AppSettings? routing=null){IsRunning=true;return Task.FromResult("192.0.2.1");}
        public Task<string> ProbeAsync(CancellationToken token,bool useProxy=true)=>Task.FromException<string>(new HttpRequestException("fixture failure"));
        public Task<TrafficCounters> ReadTrafficAsync(CancellationToken token)=>Task.FromResult(new TrafficCounters(0,0));
        public ValueTask DisposeAsync(){Stops++;IsRunning=false;return ValueTask.CompletedTask;}
    }
    private sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request,token);}
    private static HttpResponseMessage Reply(HttpStatusCode code,string body)=>new(code){Content=new StringContent(body)};
    private static void Await(Task task){var deadline=DateTime.UtcNow.AddSeconds(15);while(!task.IsCompleted){if(DateTime.UtcNow>deadline)throw new TimeoutException("Connection check timed out");Pump();Thread.Sleep(5);}task.GetAwaiter().GetResult();}
    private static void Pump(){var frame=new DispatcherFrame();Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background,new Action(()=>frame.Continue=false));Dispatcher.PushFrame(frame);}
}
