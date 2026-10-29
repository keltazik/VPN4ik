using System.IO;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using VPNyan;

internal static class ProfileCompatibilityChecks
{
    internal const string UserId = "00000000-0000-4000-8000-000000000001";
    internal static string Vmess(string network, string security = "tls", int port = 443) => "vmess://" +
        Convert.ToBase64String(Encoding.UTF8.GetBytes(new JsonObject {
            ["v"]="2",["ps"]="Compatibility fixture",["add"]="vpn.example.test",["port"]=port.ToString(),["id"]=UserId,
            ["aid"]="0",["scy"]="auto",["net"]=network,["type"]=network=="grpc"?"multi":"http",
            ["host"]="front.example.test",["path"]="/fixture",["tls"]=security,["sni"]="tls.example.test",
            ["fp"]="firefox",["alpn"]="http/1.1,h2" }.ToJsonString()));

    internal static JsonNode Build(string text)
    {
        var profile=SubscriptionParser.Parse(text).Single();
        return JsonNode.Parse(XrayConfiguration.Build(new EngineRequest { Profile=profile,EnableTun=false,ProbePort=49152 }))!;
    }

    internal static void Offline(Action<bool,string> check)
    {
        var vmess=Build(Vmess("ws"))["outbounds"]![0]!;
        var tls=vmess["streamSettings"]!["tlsSettings"]!;
        check((string?)tls["fingerprint"]=="firefox", "VMess share fingerprint is preserved instead of replaced with chrome");
        check(tls["alpn"]!.AsArray().Select(n=>(string?)n).SequenceEqual(new[]{"http/1.1","h2"}), "VMess share ALPN is preserved in provider order");
        check((string?)tls["serverName"]=="tls.example.test", "VMess SNI stays distinct from front host and server address");
        var noSni=JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(Vmess("ws")[8..])))!;
        noSni.AsObject().Remove("sni");noSni["add"]="192.0.2.10";
        var noSniLink="vmess://"+Convert.ToBase64String(Encoding.UTF8.GetBytes(noSni.ToJsonString()));
        check((string?)Build(noSniLink)["outbounds"]![0]!["streamSettings"]!["tlsSettings"]!["serverName"]=="front.example.test", "VMess share without explicit SNI uses its front host instead of an IP certificate name");
        check((string?)Build($"vless://{UserId}@192.0.2.10:443?type=ws&security=tls&host=front.example.test")["outbounds"]![0]!["streamSettings"]!["tlsSettings"]!["serverName"]=="front.example.test", "VLESS front host supplies SNI only when the share omits an explicit value");
        check((int?)vmess["settings"]!["vnext"]![0]!["users"]![0]!["alterId"]==0, "VMess numeric-string alterId is parsed without being discarded");
        check((string?)vmess["streamSettings"]!["wsSettings"]!["host"]=="front.example.test" &&
            (string?)vmess["streamSettings"]!["wsSettings"]!["path"]=="/fixture", "WebSocket front host and path survive import and sanitization");
        var grpc=Build(Vmess("grpc"))["outbounds"]![0]!["streamSettings"]!["grpcSettings"]!;
        check((string?)grpc["authority"]=="front.example.test" && (bool?)grpc["multiMode"]==true, "VMess gRPC authority and multi mode survive share conversion");
        var tcp=Build(Vmess("tcp",""))["outbounds"]![0]!["streamSettings"]!["tcpSettings"]!["header"]!;
        check((string?)tcp["type"]=="http" && (string?)tcp["request"]!["path"]![0]=="/fixture" &&
            (string?)tcp["request"]!["headers"]!["Host"]![0]=="front.example.test", "VMess TCP HTTP camouflage is retained on the wire");

        var link=$"vless://{UserId}@vpn.example.test:443?security=reality&type=grpc&flow=xtls-rprx-vision&sni=front.example.test&fp=firefox&pbk=fixture-key&sid=abcd&spx=%2Fprobe%3Fx%3D1&serviceName=svc%2Ftest&authority=grpc.example.test&mode=multi";
        var outbound=Build(link)["outbounds"]![0]!;var stream=outbound["streamSettings"]!;var reality=stream["realitySettings"]!;
        check((string?)outbound["settings"]!["vnext"]![0]!["users"]![0]!["flow"]=="xtls-rprx-vision", "VLESS flow is not lost while preserving transport options");
        check((string?)reality["serverName"]=="front.example.test" && (string?)reality["fingerprint"]=="firefox" &&
            (string?)reality["publicKey"]=="fixture-key" && (string?)reality["shortId"]=="abcd" && (string?)reality["spiderX"]=="/probe?x=1", "REALITY SNI fingerprint public key short ID and encoded spiderX stay intact");
        check((string?)stream["grpcSettings"]!["serviceName"]=="svc/test" && (string?)stream["grpcSettings"]!["authority"]=="grpc.example.test", "gRPC share service and authority are decoded exactly once");

        var json=new JsonObject { ["outbounds"]=new JsonArray(new JsonObject {
            ["protocol"]="vless",["settings"]=new JsonObject{["vnext"]=new JsonArray(new JsonObject{["address"]="vpn.example.test",["port"]=443,["users"]=new JsonArray(new JsonObject{["id"]=UserId,["encryption"]="none"})})},
            ["streamSettings"]=new JsonObject{["network"]="tcp",["method"]="websocket",["wsSettings"]=new JsonObject{["host"]="front.example.test",["path"]="/fixture?ed=2048"}}
        }) };
        stream=Build(json.ToJsonString())["outbounds"]![0]!["streamSettings"]!;
        check((string?)stream["network"]=="ws" && (string?)stream["wsSettings"]!["path"]=="/fixture?ed=2048", "Xray method overrides legacy network and accepts the websocket alias with early-data path");
        var original=json["outbounds"]![0]!["streamSettings"]!.AsObject();original["method"]="raw";
        original["rawSettings"]=new JsonObject{["header"]=new JsonObject{["type"]="http",["request"]=new JsonObject{["path"]=new JsonArray("/raw"),["headers"]=new JsonObject{["Host"]=new JsonArray("front.example.test")}}}};
        stream=Build(json.ToJsonString())["outbounds"]![0]!["streamSettings"]!;
        check((string?)stream["rawSettings"]?["header"]?["type"]=="http", "JSON RAW HTTP camouflage is retained alongside the modern method field");
        original["rawSettings"]!["header"]!["type"]="unknown";
        Reject(()=>Build(json.ToJsonString()),check,"Unknown RAW header types fail before launching the core");
        Reject(()=>Build($"vless://{UserId}@vpn.example.test:443?security=tls&allowInsecure=1"),check,"Share-link certificate bypass is rejected consistently with JSON rather than silently changed");
        Reject(()=>Build($"vless://{UserId}@vpn.example.test:443?type=xhttp&extra=%7B%7D"),check,"Unsupported XHTTP share extras are not silently removed");
        check(!XraySession.HasTunRoutes(true,ip=>ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork), "An IPv4-only default route cannot confirm a dual-stack TUN");
        check(XraySession.HasTunRoutes(false,ip=>ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork), "A Windows stack with IPv6 disabled can still verify its IPv4 TUN");
        check(XraySession.HasTunRoutes(true,_=>true) && !XraySession.HasTunRoutes(true,_=>false), "TUN verification requires every enabled address family and rejects missing routes");
        var physical=new[]{("wifi",(uint)3,100L),("ethernet",(uint)4,1000L)};
        check(XraySession.ChooseUpstreamInterface(physical,3)=="wifi", "Physical route selection follows the selected Windows route rather than the fastest unrelated adapter");
        check(XraySession.ChooseUpstreamInterface(physical,99)=="ethernet", "A route owned by another VPN never becomes the physical uplink");
        check(XraySession.ChooseUpstreamInterface(Array.Empty<(string,uint,long)>(),3)=="auto", "No eligible hardware adapter preserves core automatic interface detection");
        check(XraySession.ReadInterfaceIndex(()=>throw new System.Net.NetworkInformation.NetworkInformationException(10043))==null,
            "An IPv6-only or disabled adapter cannot crash the route diagnostic with WSAEPROTONOSUPPORT");
        check(XraySession.ReadInterfaceIndex(()=>7)==7, "Route diagnostics preserve readable interface indices");
    }

    private static void Reject(Action action,Action<bool,string> check,string label)
    {var rejected=false;try{action();}catch(InvalidDataException){rejected=true;}check(rejected,label);}
}
