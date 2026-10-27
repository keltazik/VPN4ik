using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Controls;
using VPNyan;

internal static class ModeChecks
{
    internal static void Run(string fixtures, Action<bool,string> check)
    {
        var settings = new AppSettings { ConnectionMode = "proxy", UseLocalDns = true };
        check(settings.Copy().ConnectionMode == "proxy" && settings.Copy().UseLocalDns, "Mode and local DNS survive settings copies");
        var migration = Path.Combine(fixtures, "dns-migration.json");
        File.WriteAllText(migration, "{\"DnsServers\":\"1.1.1.1\\n2606:4700:4700::1111\"}");
        check(AppSettings.LoadFromPath(migration).DnsServers == "1.1.1.1\n1.0.0.1", "Former factory IPv6 DNS pair migrates to two IPv4 upstreams");
        File.WriteAllText(migration, "{\"DnsServers\":\"2001:db8::53\"}");
        check(AppSettings.LoadFromPath(migration).DnsServers == "2001:db8::53", "User-defined IPv6 DNS is not silently replaced");
        var profile = SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#Mode").Single();
        var request = new EngineRequest { Profile = profile, ProbePort = 49152 };
        var config = JsonNode.Parse(XrayConfiguration.Build(request))!;
        check(config["inbounds"]![1]!["settings"]!["dns"]![0]!.ToString() == "172.31.255.1", "Windows TUN uses the in-tunnel DNS endpoint, not a fragile remote IPv6 DNS address");
        check(config["dns"]!["servers"]!.AsArray().All(s => s!["address"]!.ToString().StartsWith("tcp://")), "Remote DNS is carried by TCP, without requiring provider UDP support");
        var rules = config["routing"]!["rules"]!.AsArray();
        check(rules.First(r => r?["port"]?.ToString() == "53")!["outboundTag"]!.ToString() == "vpn4ik-dns" && rules.First(r => r?["inboundTag"]?[0]?.ToString() == "vpn4ik-dns-query")!["outboundTag"]!.ToString() == "proxy", "DNS interception and internal upstream queries use separate routes and cannot form a routing loop");
        request.Routing.UseLocalDns = true; config = JsonNode.Parse(XrayConfiguration.Build(request))!;
        check(config["dns"]!["servers"]![0]!.ToString() == "localhost" && config["outbounds"]!.AsArray().Any(o => o?["tag"]?.ToString() == "direct"), "Explicit local DNS uses the physical system resolver and a direct path");
        request.EnableTun = false; request.EnableSystemProxy = true; request.HttpProxyPort = 49153; request.Routing.ConnectionMode = "proxy";
        config = JsonNode.Parse(XrayConfiguration.Build(request))!;
        check(!config.ToJsonString().Contains("autoSystemRoutingTable") && config["inbounds"]!.AsArray().Any(i => i?["protocol"]?.ToString() == "http" && i?["listen"]?.ToString() == "127.0.0.1"), "Proxy mode opens only a loopback HTTP proxy and never creates a TUN or routes");
        request.EnableTun = true; var rejected = false; try { XrayConfiguration.Build(request); } catch (InvalidDataException) { rejected = true; }
        check(rejected, "A helper cannot enable system proxy and TUN simultaneously");
        var old = new ProxyState(1,"old.example:3128","*.internal","https://pac.example.test/proxy.pac");
        var backend = new Backend(old); var path = Path.Combine(fixtures,"proxy-restore.dpapi"); var gate = "Local\\VPN4ik.ProxyCheck." + Guid.NewGuid().ToString("N");
        using (SystemProxyLease.Start(49153,backend,path,gate))
        {
            check(backend.State.Server!.Contains("127.0.0.1:49153") && backend.State.Pac == null && File.Exists(path), "Proxy activation saves encrypted recovery before changing the Windows proxy");
            var busy = false; try { using var other = SystemProxyLease.Start(49154,backend,path,gate); } catch (IOException) { busy = true; }
            check(busy,"Concurrent proxy helpers cannot overwrite each other's saved state");
        }
        check(backend.State == old && !File.Exists(path), "Disconnect restores the previous proxy, bypass rules and PAC URL exactly");
        using (SystemProxyLease.Start(49153,backend,path,gate)) backend.State = new ProxyState(1,"user-changed:8080","user-bypass",null);
        check(backend.State.Server == "user-changed:8080", "Disconnect never overwrites a proxy selected externally after connection");
        backend.State = new ProxyState(1,"http=127.0.0.1:49153;https=127.0.0.1:49153",null,null);
        File.WriteAllBytes(path,ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(new { Server=backend.State.Server, Previous=old }),null,DataProtectionScope.CurrentUser));
        using (SystemProxyLease.Start(49154,backend,path,gate)) { }
        check(backend.State == old, "A stale proxy left by a terminated helper is recovered before the next connection");
        var window = new MainWindow(false,Path.Combine(fixtures,"mode-ui"));
        check(window.SetConnectionMode("proxy") && ((TextBlock)window.FindName("ConnectionModeLabel")).Text == "Прокси", "Home mode selection updates its label and persists immediately");
        check(AppSettings.LoadFromPath(Path.Combine(fixtures,"mode-ui","settings.json")).ConnectionMode == "proxy", "Proxy choice persists without a Save button");
        check(!window.SetConnectionMode("unavailable-engine"),"Unavailable engines cannot be selected as working modes");
        window.Close();
    }
    private sealed class Backend(ProxyState initial) : IProxySettingsBackend
    {
        internal ProxyState State = initial;
        public ProxyState Read() => State;
        public void Write(ProxyState state) => State = state;
    }
}