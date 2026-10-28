using System.Diagnostics;
using System.IO;
using System.Formats.Tar;
using System.IO.Compression;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace VPNyan;

/// <summary>Official Hiddify TUN/routing core; the existing authenticated Xray worker owns server protocols and statistics.</summary>
internal static class HiddifyCore
{
    internal const string Version = "5.0.3";
    internal static string DirectoryPath => Path.Combine(EngineHost.EngineDirectory,"Hiddify");
    internal static string ExecutablePath => Path.Combine(DirectoryPath,"HiddifyCli.exe");
    internal static readonly (string File,string Hash)[] Files = {
        ("HiddifyCli.exe","90948CC26D38307C02A733F8392F68CF148533888462B45CD112755C35FE265C"),
        ("hiddify-core.dll","26B82248A8F414DDD78B8306AF5674AB21BF611B26B201B32B560065111EB2B1"),
        ("libcronet.dll","3217C6260FBCA5F16072E0B79735742F40109A63BB0FF88FD6B96DD6B54A2928"),
        ("wintun.dll","E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") };

    internal static void EnsureInstalled(string? verificationDirectory = null)
    {
        var destination=verificationDirectory??DirectoryPath;
        var identity=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(destination))))[..20];
        using var gate=new Mutex(false,"Local\\VPN4ik.Hiddify."+identity);
        var owns=false;
        try
        {
            try { owns=gate.WaitOne(TimeSpan.FromSeconds(30)); } catch(AbandonedMutexException) { owns=true; }
            if(!owns) throw new IOException("Не удалось запустить VPN-службу.");
            try { VerifyFiles(destination); return; } catch(InvalidDataException) { }
            using var source=typeof(HiddifyCore).Assembly.GetManifestResourceStream("VPNyan.Hiddify.native.tar.gz")
                ?? throw new InvalidDataException("В сборке отсутствует VPN-движок. Запусти полную сборку приложения.");
            if(Convert.ToHexString(SHA256.HashData(source))!="645EF71FB7E6E51CDD8B29B43C9DDEA241B2324DCF441DF7210D3332E39F2443")
                throw new InvalidDataException("Файлы VPN-движка изменены. Нужна исходная сборка приложения.");
            source.Position=0;
            Directory.CreateDirectory(destination);
            var stage=Path.Combine(destination,"stage-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(stage);
            try
            {
                using(var gzip=new GZipStream(source,CompressionMode.Decompress,leaveOpen:true))
                using(var reader=new TarReader(gzip))
                {
                    var seen=new HashSet<string>(StringComparer.Ordinal);
                    while(reader.GetNextEntry() is { } entry)
                    {
                        var name=entry.Name.StartsWith("./",StringComparison.Ordinal)?entry.Name[2..]:entry.Name;
                        if(!Files.Take(3).Any(f=>f.File==name) || !seen.Add(name) ||
                            entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.Length>128L*1024*1024 || entry.DataStream==null)
                            throw new InvalidDataException("Некорректный файл обновления.");
                        using var output=File.Create(Path.Combine(stage,name)); entry.DataStream.CopyTo(output);
                    }
                    if(seen.Count!=3) throw new InvalidDataException("Некорректный файл обновления.");
                }
                File.Copy(Path.Combine(EngineHost.EngineDirectory,"wintun.dll"),Path.Combine(stage,"wintun.dll"));
                foreach(var (file,hash) in Files)
                {
                    using var input=File.OpenRead(Path.Combine(stage,file));
                    if(Convert.ToHexString(SHA256.HashData(input))!=hash) throw new InvalidDataException("Файлы VPN-движка изменены. Нужна исходная сборка приложения.");
                }
                using(var license=typeof(HiddifyCore).Assembly.GetManifestResourceStream("VPNyan.Hiddify.LICENSE.txt")!)
                using(var output=File.Create(Path.Combine(stage,"LICENSE.txt"))) license.CopyTo(output);
                foreach(var file in Files.Select(f=>f.File).Append("LICENSE.txt")) File.Move(Path.Combine(stage,file),Path.Combine(destination,file),true);
            }
            finally
            {
                if(Path.GetFullPath(stage).StartsWith(Path.GetFullPath(destination)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
                    Directory.Delete(stage,true);
            }
            VerifyFiles(destination);
        }
        finally { if(owns) gate.ReleaseMutex(); }
    }
    internal static void VerifyFiles(string? directory = null)
    {
        foreach(var (file,hash) in Files)
        {
            var path=Path.Combine(directory??DirectoryPath,file);
            if(!File.Exists(path)) throw new InvalidDataException("В сборке отсутствует VPN-движок. Запусти полную сборку приложения.");
            using var input=File.OpenRead(path);
            if(Convert.ToHexString(SHA256.HashData(input))!=hash)
                throw new InvalidDataException("Файлы VPN-движка изменены. Нужна исходная сборка приложения.");
        }
    }
    internal static Process CreateProcess() => new() { StartInfo = CreateStartInfo() };
    private static ProcessStartInfo CreateStartInfo()
    {
        var start=new ProcessStartInfo(ExecutablePath) {
            UseShellExecute=false,CreateNoWindow=false,WindowStyle=ProcessWindowStyle.Hidden,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,
            StandardOutputEncoding=System.Text.Encoding.UTF8,StandardErrorEncoding=System.Text.Encoding.UTF8,
            WorkingDirectory=DirectoryPath };
        foreach(var arg in new[]{"srun","--disable-color","-c","stdin"}) start.ArgumentList.Add(arg);
        return start;
    }
    internal static EngineRequest WorkerRequest(EngineRequest request) => new() {
        Profile=request.Profile,EnableTun=false,EnableSystemProxy=false,EnableUdpProbe=true,
        Mtu=request.Mtu,ProbePort=request.ProbePort,ProbeUser=request.ProbeUser,ProbePassword=request.ProbePassword,
        EndpointAddress=request.EndpointAddress,UpstreamInterface=request.UpstreamInterface,
        Diagnostics=request.Diagnostics,Routing=request.Routing.Copy() };

    internal static string Build(EngineRequest request)
    {
        if(request.Probes!=null || request.ProbePort is <1024 or >65535 || request.Mtu is <1280 or >1500 ||
            request.HttpProxyPort is <0 or >65535 || request.HttpProxyPort==request.ProbePort ||
            (request.EnableSystemProxy && (request.EnableTun || request.HttpProxyPort<1024)))
            throw new InvalidDataException("Некорректные параметры VPN-движка.");
        RoutingSettings.Validate(request.Routing);
        var settings=request.Routing;
        var inbounds=new JsonArray();
        if(request.EnableTun) inbounds.Add(new JsonObject {
            ["type"]="tun",["tag"]="vpn4ik-tun",["interface_name"]=XrayConfiguration.InterfaceName,
            ["address"]=new JsonArray("172.19.0.1/28","fdfe:dcba:9876::1/126"),
            ["mtu"]=request.Mtu,["auto_route"]=true,["strict_route"]=true,["stack"]="mixed" });
        if(request.HttpProxyPort>0) inbounds.Add(new JsonObject {
            ["type"]="http",["tag"]="vpn4ik-system-proxy",["listen"]="127.0.0.1",["listen_port"]=request.HttpProxyPort });
        var direct=new JsonObject { ["type"]="direct",["tag"]="direct" };
        if(request.UpstreamInterface!="auto" && !string.IsNullOrWhiteSpace(request.UpstreamInterface)) direct["bind_interface"]=request.UpstreamInterface;
        var outbounds=new JsonArray(new JsonObject {
            ["type"]="socks",["tag"]="proxy",["server"]="127.0.0.1",["server_port"]=request.ProbePort,
            ["version"]="5",["username"]=request.ProbeUser,["password"]=request.ProbePassword },direct);
        var rules=new JsonArray(new JsonObject { ["domain"]=new JsonArray("localhost"),["action"]="resolve",["server"]="vpn4ik-localhost",["strategy"]="prefer_ipv4" },
            new JsonObject { ["action"]="sniff" },
            new JsonObject { ["protocol"]="dns",["action"]="hijack-dns" },
            new JsonObject { ["port"]=53,["action"]="hijack-dns" });
        if(settings.BypassLocalNetwork) rules.Add(new JsonObject { ["ip_is_private"]=true,["outbound"]="direct" });
        var target=settings.SplitTunnelMode=="Include" ? "proxy" : "direct";
        if(settings.SplitTunnelEnabled)
        {
            foreach(var group in settings.SplitApplications.GroupBy(path=>path.Contains('/')||path.Contains('\\')))
                rules.Add(Rule(group.Key ? "process_path" : "process_name",group.Select(path=>group.Key?path.Replace('/','\\'):
                    path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||path.EndsWith(".com",StringComparison.OrdinalIgnoreCase)?path:path+".exe"),target));
            if(settings.SplitDomains.Count>0) rules.Add(Rule("domain_suffix",settings.SplitDomains,target));
            if(settings.SplitNetworks.Count>0) rules.Add(Rule("ip_cidr",settings.SplitNetworks,target));
        }
        var dnsServers=new JsonArray();
        var addresses=RoutingSettings.Dns(settings.DnsServers);
        if(settings.UseLocalDns)
        {
            var adapter=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(a=>a.Name==request.UpstreamInterface);
            var local=adapter?.GetIPProperties().DnsAddresses.Where(ip=>ip.AddressFamily==AddressFamily.InterNetwork || ip.AddressFamily==AddressFamily.InterNetworkV6)
                .Select(ip=>ip.ToString()).Distinct().Take(4).ToArray();
            if(local is {Length:>0}) addresses=local;
        }
        var tags=new JsonArray();
        foreach(var (address,index) in addresses.Select((address,index)=>(address,index)))
        {
            var tag="vpn4ik-dns-"+index; tags.Add(tag);
            var dns=new JsonObject { ["type"]=settings.UseLocalDns?"udp":"tcp",["tag"]=tag,["server"]=address,["server_port"]=53 };
            if(!settings.UseLocalDns) dns["detour"]="proxy";
            else if(direct["bind_interface"]!=null) dns["bind_interface"]=request.UpstreamInterface;
            dnsServers.Add(dns);
        }
        // Hiddify's sequential resolver group retains the user's fallback servers without external bootstrap downloads.
        dnsServers.Add(new JsonObject { ["type"]="group",["tag"]="vpn4ik-dns",["servers"]=tags,["mode"]="sequential" });
        dnsServers.Add(new JsonObject { ["type"]="hosts",["tag"]="vpn4ik-localhost",["predefined"]=new JsonObject { ["localhost"]=new JsonArray("127.0.0.1","::1") } });
        var route=new JsonObject { ["rules"]=rules,["final"]=settings.SplitTunnelEnabled && settings.SplitTunnelMode=="Include"?"direct":"proxy",
            ["default_domain_resolver"]="vpn4ik-dns" };
        if(request.UpstreamInterface=="auto" || string.IsNullOrWhiteSpace(request.UpstreamInterface)) route["auto_detect_interface"]=true;
        else route["default_interface"]=request.UpstreamInterface;
        return new JsonObject {
            ["log"]=new JsonObject { ["level"]=request.Diagnostics?"info":"warn",["disabled"]=false,["timestamp"]=true },
            // Core 5.0.3 starts its URL monitor unconditionally. A local-only target with an already-expired
            // dial budget prevents its implicit public probes/IP lookup; our existing verified HTTPS monitor remains authoritative.
            ["experimental"]=new JsonObject { ["monitoring"]=new JsonObject {
                ["urls"]=new JsonArray("http://127.0.0.1:1/"),["url_test_timeout"]="1ns",["interval"]="8760h",["idle_timeout"]="8760h",["workers"]=1 } },
            ["inbounds"]=inbounds,["outbounds"]=outbounds,["route"]=route,
            ["dns"]=new JsonObject { ["servers"]=dnsServers,["final"]="vpn4ik-dns",["strategy"]="prefer_ipv4",["independent_cache"]=true,
                ["rules"]=new JsonArray(new JsonObject { ["domain"]=new JsonArray("localhost"),["server"]="vpn4ik-localhost" }) }
        }.ToJsonString();
    }
    private static JsonObject Rule(string field,IEnumerable<string> values,string target) => new() {
        [field]=new JsonArray(values.Select(value=>(JsonNode)JsonValue.Create(value)!).ToArray()),["outbound"]=target };
}
