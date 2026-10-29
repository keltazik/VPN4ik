using System.IO;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace VPNyan;

internal sealed class EngineRequest
{
    public SubscriptionProfile Profile { get; set; } = new();
    public bool EnableTun { get; set; } = true;
    public int Mtu { get; set; } = 1500;
    public int ProbePort { get; set; }
    public bool EnableSystemProxy { get; set; }
    public bool UseHiddifyCore { get; set; }
    public bool EnableUdpProbe { get; set; }
    public bool TunIpv6Available { get; set; } = true;
    public int HttpProxyPort { get; set; }
    public string ProbeUser { get; set; } = Guid.NewGuid().ToString("N");
    public string ProbePassword { get; set; } = Guid.NewGuid().ToString("N");
    public string? EndpointAddress { get; set; }
    public bool Diagnostics { get; set; }
    public string UpstreamInterface { get; set; } = "auto";
    public List<EngineRequest>? Probes { get; set; }
    public AppSettings Routing { get; set; } = new();
}

internal static class XrayConfiguration
{
    internal const string InterfaceName = "VPN4ik-TUN";
    internal static bool Supports(string protocol) => protocol.ToLowerInvariant() is "vless" or "vmess" or "trojan" or "shadowsocks" or "socks" or "hysteria" or "hysteria2" or "hy2";

    internal static string Build(EngineRequest request)
    {
        if (request.Probes != null) return BuildProbes(request);
        if (request.Mtu is < 1280 or > 1500 || request.ProbePort is < 1024 or > 65535)
            throw new InvalidDataException("Некорректные параметры VPN-движка.");
        RoutingSettings.Validate(request.Routing);
        if (request.EnableSystemProxy && (request.EnableTun || request.HttpProxyPort is < 1024 or > 65535 || request.HttpProxyPort == request.ProbePort))
            throw new InvalidDataException("Некорректные параметры системного прокси.");
        var profile = request.Profile;
        if (!Supports(profile.Protocol)) throw new InvalidDataException("Подключение этого протокола пока не поддерживается.");
        if (string.IsNullOrWhiteSpace(profile.Configuration)) throw new InvalidDataException("В профиле нет конфигурации подключения. Обнови подписку.");
        var source = profile.Configuration.TrimStart();
        var outbound = source.StartsWith('{') ? ReadJson(source) : ReadLink(source);
        // Only protocol data is admitted. Provider scripts, file paths, listeners and arbitrary
        // top-level features are never executed in the elevated engine process.
        outbound = SanitizeOutbound(outbound);
        if (!string.IsNullOrWhiteSpace(request.UpstreamInterface) && request.UpstreamInterface != "auto")
        {
            var stream = outbound["streamSettings"]!.AsObject();
            var socket = stream["sockopt"] as JsonObject ?? new JsonObject();
            socket["interface"] = request.UpstreamInterface; stream["sockopt"] = socket.DeepClone();
        }
        if (!string.IsNullOrEmpty(request.EndpointAddress))
        {
            if (!IPAddress.TryParse(request.EndpointAddress, out _)) throw new InvalidDataException("Не разрешён адрес сервера.");
            var settings = outbound["settings"]!.AsObject();
            if (outbound["protocol"]!.GetValue<string>() == "hysteria") settings["address"] = request.EndpointAddress;
            else
            {
                var list = settings["vnext"] ?? settings["servers"];
                list![0]!["address"] = request.EndpointAddress;
            }
        }
        outbound["tag"] = "proxy";
        var inbounds = new JsonArray
        {
            new JsonObject
            {
                ["tag"] = "vpn4ik-check", ["listen"] = "127.0.0.1", ["port"] = request.ProbePort, ["protocol"] = "socks",
                ["settings"] = new JsonObject { ["auth"] = "password", ["udp"] = request.EnableUdpProbe,
                    ["accounts"] = new JsonArray(new JsonObject { ["user"] = request.ProbeUser, ["pass"] = request.ProbePassword }) }
            }
        };
        if (request.EnableSystemProxy)
            inbounds.Add(new JsonObject
            {
                ["tag"] = "vpn4ik-system-proxy", ["listen"] = "127.0.0.1", ["port"] = request.HttpProxyPort,
                ["protocol"] = "http", ["settings"] = new JsonObject(),
                ["sniffing"] = new JsonObject { ["enabled"] = request.Routing.SniffDomains, ["destOverride"] = new JsonArray("http", "tls"), ["routeOnly"] = true }
            });
        if (request.EnableTun)
            inbounds.Add(new JsonObject
            {
                ["tag"] = "vpn4ik-tun", ["protocol"] = "tun",
                ["sniffing"] = new JsonObject { ["enabled"] = request.Routing.SniffDomains && request.Routing.SplitTunnelEnabled && request.Routing.SplitDomains.Count > 0,
                    ["destOverride"] = new JsonArray("http", "tls", "quic"), ["routeOnly"] = true },
                ["settings"] = new JsonObject
                {
                    ["name"] = InterfaceName, ["desc"] = "VPN4ik", ["mtu"] = request.Mtu,
                    ["gateway"] = new JsonArray("172.31.255.1/30", "fd42:7670:3469::1/126"),
                    ["dns"] = new JsonArray("172.31.255.2"),
                    ["autoSystemRoutingTable"] = new JsonArray("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"),
                    ["autoOutboundsInterface"] = request.UpstreamInterface, ["autoSystemWfpBlockLeak"] = new JsonArray("dns", "misconfigtun")
                }
            });
        var rules = new JsonArray
        {
            new JsonObject { ["type"] = "field", ["inboundTag"] = new JsonArray("vpn4ik-check"),
                ["domain"] = new JsonArray("full:metrics.vpn4ik.invalid"), ["outboundTag"] = "vpn4ik-metrics" },
            new JsonObject { ["type"] = "field", ["inboundTag"] = new JsonArray("vpn4ik-check"), ["outboundTag"] = "proxy" }
        };
        var outbounds = new JsonArray(outbound);
        if (request.EnableTun)
        {
            // Resolve inside Xray, using TCP via the selected server instead of requiring UDP/IPv6 DNS support.
            rules.Add(new JsonObject { ["type"] = "field", ["inboundTag"] = new JsonArray("vpn4ik-tun"), ["port"] = "53", ["outboundTag"] = "vpn4ik-dns" });
            rules.Add(new JsonObject { ["type"] = "field", ["inboundTag"] = new JsonArray("vpn4ik-dns-query"), ["outboundTag"] = request.Routing.UseLocalDns ? "direct" : "proxy" });
            outbounds.Add(new JsonObject { ["tag"] = "vpn4ik-dns", ["protocol"] = "dns", ["settings"] = new JsonObject() });
        }
        if (request.EnableTun || request.EnableSystemProxy)
        {
            RoutingSettings.AddRules(rules, request.Routing);
            if (request.Routing.SplitTunnelEnabled || request.Routing.BypassLocalNetwork || request.Routing.UseLocalDns)
                outbounds.Add(new JsonObject { ["tag"] = "direct", ["protocol"] = "freedom", ["settings"] = new JsonObject() });
        }
        return new JsonObject
        {
            ["dns"] = request.EnableTun ? BuildDns(request.Routing) : null,
            ["log"] = new JsonObject { ["access"] = "none", ["loglevel"] = request.Diagnostics ? "info" : "warning", ["dnsLog"] = false },
            ["inbounds"] = inbounds, ["outbounds"] = outbounds,
            ["stats"] = new JsonObject(),
            ["policy"] = new JsonObject { ["system"] = new JsonObject { ["statsOutboundUplink"] = true, ["statsOutboundDownlink"] = true } },
            ["metrics"] = new JsonObject { ["tag"] = "vpn4ik-metrics" },
            ["routing"] = new JsonObject { ["domainStrategy"] = "AsIs", ["rules"] = rules }
        }.ToJsonString();
    }

    private static JsonObject BuildDns(AppSettings settings)
    {
        var servers = new JsonArray();
        if (settings.UseLocalDns) servers.Add("localhost");
        else foreach (var ip in RoutingSettings.Dns(settings.DnsServers))
            servers.Add(new JsonObject { ["address"] = "tcp://" + (ip.Contains(':') ? "[" + ip + "]" : ip), ["timeoutMs"] = 2000 });
        return new JsonObject { ["servers"] = servers, ["queryStrategy"] = "UseIP", ["tag"] = "vpn4ik-dns-query" };
    }

    private static string BuildProbes(EngineRequest batch)
    {
        if (batch.EnableTun || batch.Probes is not { Count: > 0 and <= 32 } || batch.Probes.Any(p => p.EnableTun || p.Probes != null))
            throw new InvalidDataException("Некорректная проверка задержки.");
        var inbounds = new JsonArray();
        var outbounds = new JsonArray();
        var rules = new JsonArray();
        foreach (var (probe, index) in batch.Probes.Select((p, i) => (p, i)))
        {
            var single = JsonNode.Parse(Build(probe))!;
            var inbound = single["inbounds"]![0]!.DeepClone();
            var outbound = single["outbounds"]![0]!.DeepClone();
            var tag = "latency-" + index;
            inbound["tag"] = tag;
            outbound["tag"] = tag;
            if (probe.UpstreamInterface != "auto")
                outbound["streamSettings"]!["sockopt"] = new JsonObject { ["interface"] = probe.UpstreamInterface };
            inbounds.Add(inbound);
            outbounds.Add(outbound);
            rules.Add(new JsonObject { ["type"] = "field", ["inboundTag"] = new JsonArray(tag), ["outboundTag"] = tag });
        }
        return new JsonObject
        {
            ["log"] = new JsonObject { ["access"] = "none", ["loglevel"] = "warning" },
            ["inbounds"] = inbounds, ["outbounds"] = outbounds,
            ["routing"] = new JsonObject { ["domainStrategy"] = "AsIs", ["rules"] = rules }
        }.ToJsonString();
    }

    private static JsonObject ReadJson(string json)
    {
        var root = JsonNode.Parse(json) as JsonObject ?? throw new InvalidDataException("Некорректный JSON профиля.");
        return root["outbounds"]?.AsArray().OfType<JsonObject>().FirstOrDefault(o => Supports(o["protocol"]?.GetValue<string>() ?? ""))
            ?? throw new InvalidDataException("В профиле не найден прокси-сервер.");
    }

    private static JsonObject Copy(JsonObject? source, params string[] keys)
    {
        var result = new JsonObject();
        if (source == null) return result;
        foreach (var key in keys)
            if (source.TryGetPropertyValue(key, out var node)) result[key] = node?.DeepClone();
        return result;
    }

    private static JsonObject SanitizeOutbound(JsonObject source)
    {
        var protocol = source["protocol"]?.GetValue<string>()?.ToLowerInvariant() ?? "";
        if (protocol is "hy2" or "hysteria2") protocol = "hysteria";
        if (!Supports(protocol)) throw new InvalidDataException("Неизвестный протокол подключения.");
        var settings = source["settings"] as JsonObject ?? throw new InvalidDataException("В профиле нет параметров сервера.");
        var listKey = protocol is "vless" or "vmess" ? "vnext" : "servers";
        var endpoint = protocol == "hysteria" ? settings : settings[listKey]?.AsArray().FirstOrDefault() as JsonObject ?? throw new InvalidDataException("В профиле не задан сервер.");
        var cleanEndpoint = Copy(endpoint, "address", "port");
        var address = cleanEndpoint["address"]?.GetValue<string>() ?? "";
        var port = cleanEndpoint["port"]?.GetValue<int>() ?? 0;
        if (Uri.CheckHostName(address) == UriHostNameType.Unknown || port is < 1 or > 65535)
            throw new InvalidDataException("Некорректный адрес сервера.");
        if (protocol == "hysteria")
        {
            if (settings["version"]?.GetValue<int>() != 2) throw new InvalidDataException("Поддерживается Hysteria версии 2.");
            cleanEndpoint["version"] = 2;
        }
        else if (listKey == "vnext")
        {
            var user = endpoint["users"]?.AsArray().FirstOrDefault() as JsonObject ?? throw new InvalidDataException("В профиле нет ключа пользователя.");
            cleanEndpoint["users"] = new JsonArray(Copy(user, "id", "encryption", "flow", "security", "alterId", "level"));
        }
        else
        {
            foreach (var field in new[] { "password", "method", "email", "level", "ota", "uot" })
                if (endpoint[field] != null) cleanEndpoint[field] = endpoint[field]!.DeepClone();
            if (endpoint["users"] is JsonArray users)
                cleanEndpoint["users"] = new JsonArray(users.OfType<JsonObject>().Select(u => (JsonNode)Copy(u, "user", "pass")).ToArray());
        }
        var result = new JsonObject { ["protocol"] = protocol, ["settings"] = protocol == "hysteria" ? cleanEndpoint : new JsonObject { [listKey] = new JsonArray(cleanEndpoint) } };
        var stream = source["streamSettings"] as JsonObject ?? new JsonObject();
        // Current Xray accepts method as the newer name and gives it precedence over network.
        var network = (stream["method"] ?? stream["network"])?.GetValue<string>()?.ToLowerInvariant() ?? "tcp";
        if (network == "websocket") network = "ws";
        if (network is not ("tcp" or "raw" or "grpc" or "ws" or "httpupgrade" or "xhttp" or "splithttp" or "hysteria"))
            throw new InvalidDataException("Этот транспорт подключения пока не поддерживается.");
        var security = stream["security"]?.GetValue<string>()?.ToLowerInvariant() ?? "none";
        if (security is not ("none" or "tls" or "reality")) throw new InvalidDataException("Неизвестный режим шифрования профиля.");
        var cleanStream = new JsonObject { ["network"] = network, ["security"] = security };
        if (network is "tcp" or "raw")
        {
            var rawKey = stream["rawSettings"] != null ? "rawSettings" : "tcpSettings";
            if (stream[rawKey] is JsonObject raw && raw["header"] != null)
            {
                var header = raw["header"] as JsonObject ?? throw new InvalidDataException("Некорректная маскировка TCP.");
                var type = header["type"]?.GetValue<string>() ?? "none";
                if (type is not ("none" or "http")) throw new InvalidDataException("Этот тип маскировки TCP не поддерживается.");
                var cleanHeader = new JsonObject { ["type"] = type };
                if (type == "http" && header["request"] is JsonObject request)
                    cleanHeader["request"] = Copy(request, "version", "method", "path", "headers");
                cleanStream[rawKey] = new JsonObject { ["header"] = cleanHeader };
            }
        }
        if (security == "tls")
        {
            var tls = stream["tlsSettings"] as JsonObject;
            if (tls?["allowInsecure"]?.GetValue<bool>() == true)
                throw new InvalidDataException("Профиль отключает проверку сертификата TLS. Нужна безопасная конфигурация сервера.");
            var tlsSettings = Copy(tls, "serverName", "alpn", "fingerprint", "verifyPeerCertByName", "pinnedPeerCertSha256", "disableSystemRoot", "enableSessionResumption");
            if (string.IsNullOrWhiteSpace(tlsSettings["serverName"]?.GetValue<string>()) && Uri.CheckHostName(address) == UriHostNameType.Dns) tlsSettings["serverName"] = address;
            cleanStream["tlsSettings"] = tlsSettings;
        }
        if (protocol == "hysteria")
        {
            if (network != "hysteria" || security != "tls") throw new InvalidDataException("Для Hysteria2 требуются транспорт Hysteria и TLS.");
            var hysteria = stream["hysteriaSettings"] as JsonObject;
            if (hysteria?["version"]?.GetValue<int>() != 2 || string.IsNullOrWhiteSpace(hysteria["auth"]?.GetValue<string>()))
                throw new InvalidDataException("В профиле Hysteria2 нет параметров авторизации.");
            cleanStream["hysteriaSettings"] = Copy(hysteria, "version", "auth", "udpIdleTimeout");
            if (stream["finalmask"] is JsonObject mask)
            {
                if (mask["udp"] != null || mask["tcp"] != null) throw new InvalidDataException("Этот вариант маскировки Hysteria2 пока не поддерживается.");
                if (mask["quicParams"] is JsonObject quic)
                    cleanStream["finalmask"] = new JsonObject { ["quicParams"] = Copy(quic,
                        "debug", "bbrProfile", "congestion", "maxIdleTimeout", "keepAlivePeriod", "maxIncomingStreams",
                        "maxStreamReceiveWindow", "initStreamReceiveWindow", "maxConnectionReceiveWindow", "initConnectionReceiveWindow", "up", "down") };
            }
        }
        if (security == "reality")
        {
            var reality = Copy(stream["realitySettings"] as JsonObject, "serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX", "mldsa65Verify");
            if (string.IsNullOrWhiteSpace(reality["serverName"]?.GetValue<string>()) && Uri.CheckHostName(address) == UriHostNameType.Dns) reality["serverName"] = address;
            cleanStream["realitySettings"] = reality;
        }
        if (network == "grpc") cleanStream["grpcSettings"] = Copy(stream["grpcSettings"] as JsonObject,
            "serviceName", "authority", "multiMode", "user_agent", "idle_timeout", "health_check_timeout", "permit_without_stream", "initial_windows_size");
        if (stream["sockopt"] is JsonObject sourceSocket)
        {
            var socket = new JsonObject();
            foreach (var key in new[] { "tcpKeepAliveIdle", "tcpKeepAliveInterval", "tcpUserTimeout" })
                if (sourceSocket[key] != null)
                {
                    if (sourceSocket[key] is not JsonValue value || !value.TryGetValue<int>(out var number) || number < -1 || number > (key == "tcpUserTimeout" ? 600000 : 86400))
                        throw new InvalidDataException("Некорректные параметры поддержания TCP-соединения.");
                    socket[key] = number;
                }
            if (socket.Count > 0) cleanStream["sockopt"] = socket;
        }
        if (network is "ws" or "httpupgrade")
        {
            var key = network == "ws" ? "wsSettings" : "httpupgradeSettings";
            cleanStream[key] = Copy(stream[key] as JsonObject, "path", "host", "headers");
        }
        if (network is "xhttp" or "splithttp")
        {
            var xhttp = stream["xhttpSettings"] as JsonObject ?? stream["splithttpSettings"] as JsonObject;
            if (xhttp?["extra"] != null) throw new InvalidDataException("Расширенные параметры XHTTP пока не поддерживаются.");
            cleanStream["xhttpSettings"] = Copy(xhttp, "host", "path", "mode");
        }
        result["streamSettings"] = cleanStream;
        return result;
    }

    private static JsonObject ReadLink(string link)
    {
        if (link.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            var vmess = JsonNode.Parse(Decode(link[8..]))!.AsObject();
            var rawPort = vmess["port"]?.ToString();
            if (!int.TryParse(rawPort, out var vmessPort)) throw new InvalidDataException("Некорректный порт VMess.");
            if (!int.TryParse(vmess["aid"]?.ToString() ?? "0", out var alterId) || alterId < 0)
                throw new InvalidDataException("Некорректный alterId VMess.");
            RejectInsecure(vmess["allowInsecure"]?.ToString() ?? "");
            RejectInsecure(vmess["insecure"]?.ToString() ?? "");
            var raw = new JsonObject { ["protocol"] = "vmess", ["settings"] = new JsonObject { ["vnext"] = new JsonArray(new JsonObject
                { ["address"] = vmess["add"]?.DeepClone(), ["port"] = vmessPort, ["users"] = new JsonArray(new JsonObject
                    { ["id"] = vmess["id"]?.DeepClone(), ["alterId"] = alterId, ["security"] = vmess["scy"]?.DeepClone() ?? JsonValue.Create("auto") }) }) } };
            var net = (vmess["net"]?.ToString() ?? "tcp").ToLowerInvariant();
            raw["streamSettings"] = new JsonObject { ["network"] = net, ["security"] = vmess["tls"]?.ToString() == "tls" ? "tls" : "none",
                ["tlsSettings"] = new JsonObject { ["serverName"] = ShareServerName(vmess["sni"]?.ToString(), vmess["host"]?.ToString(), vmess["add"]?.ToString() ?? ""),
                    ["fingerprint"] = vmess["fp"]?.DeepClone() ?? JsonValue.Create("chrome"), ["alpn"] = Alpn(vmess["alpn"]?.ToString()) },
                ["wsSettings"] = new JsonObject { ["path"] = vmess["path"]?.DeepClone(), ["host"] = vmess["host"]?.DeepClone() },
                ["grpcSettings"] = new JsonObject { ["serviceName"] = vmess["path"]?.DeepClone(),
                    ["authority"] = vmess["host"]?.DeepClone(), ["multiMode"] = vmess["type"]?.ToString() == "multi" } };
            if (net is "tcp" or "raw") raw["streamSettings"]!["tcpSettings"] = new JsonObject {
                ["header"] = TcpHeader(vmess["type"]?.ToString() ?? "none", vmess["host"]?.ToString() ?? "", vmess["path"]?.ToString() ?? "/") };
            return raw;
        }
        if (link.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
        {
            var authority = link[5..].Split('#', '?')[0];
            if (!authority.Contains('@')) link = "ss://" + Decode(authority);
        }
        if (!Uri.TryCreate(link, UriKind.Absolute, out var uri)) throw new InvalidDataException("Некорректная ссылка профиля.");
        var protocol = uri.Scheme == "ss" ? "shadowsocks" : uri.Scheme;
        if (protocol is "hy2" or "hysteria2") protocol = "hysteria";
        var endpoint = new JsonObject { ["address"] = uri.Host.Trim('[', ']'), ["port"] = uri.Port < 0 && protocol == "hysteria" ? 443 : uri.Port };
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2))
            .GroupBy(p => Uri.UnescapeDataString(p[0])).ToDictionary(g => g.Key, g => Uri.UnescapeDataString(g.Last().Length == 2 ? g.Last()[1] : ""));
        string Q(string key, string fallback = "") => query.TryGetValue(key, out var value) ? value : fallback;
        var credentials = Uri.UnescapeDataString(uri.UserInfo);
        RejectInsecure(Q("insecure"));
        RejectInsecure(Q("allowInsecure"));
        if (protocol == "hysteria")
        {
            if (Q("insecure") is "1" or "true" || Q("allowInsecure") is "1" or "true")
                throw new InvalidDataException("Профиль отключает проверку сертификата TLS.");
            if (Q("obfs") != "") throw new InvalidDataException("Этот вариант маскировки Hysteria2 пока не поддерживается.");
            endpoint["version"] = 2;
            return new JsonObject { ["protocol"] = protocol, ["settings"] = endpoint,
                ["streamSettings"] = new JsonObject { ["network"] = "hysteria", ["security"] = "tls",
                    ["hysteriaSettings"] = new JsonObject { ["version"] = 2, ["auth"] = credentials },
                    ["tlsSettings"] = new JsonObject { ["serverName"] = Q("sni", uri.Host), ["alpn"] = new JsonArray("h3") } } };
        }
        var settings = new JsonObject();
        if (protocol is "vless" or "vmess")
        {
            endpoint["users"] = new JsonArray(new JsonObject { ["id"] = credentials, ["encryption"] = Q("encryption", "none"), ["flow"] = Q("flow") });
            settings["vnext"] = new JsonArray(endpoint);
        }
        else
        {
            if (protocol == "shadowsocks")
            {
                if (!credentials.Contains(':')) credentials = Decode(credentials);
                var pair = credentials.Split(':', 2);
                if (pair.Length != 2) throw new InvalidDataException("Некорректный ключ Shadowsocks.");
                endpoint["method"] = pair[0]; endpoint["password"] = pair[1];
            }
            else if (protocol == "trojan") endpoint["password"] = credentials;
            else if (protocol == "socks")
            {
                var pair = credentials.Split(':', 2);
                endpoint["users"] = new JsonArray(new JsonObject { ["user"] = pair[0], ["pass"] = pair.Length > 1 ? pair[1] : "" });
            }
            settings["servers"] = new JsonArray(endpoint);
        }
        var security = Q("security", protocol == "trojan" ? "tls" : "none");
        var network = Q("type", "tcp").ToLowerInvariant();
        if (network is "xhttp" or "splithttp" && Q("extra") != "")
            throw new InvalidDataException("Расширенные параметры XHTTP пока не поддерживаются.");
        return new JsonObject { ["protocol"] = protocol, ["settings"] = settings,
            ["streamSettings"] = new JsonObject { ["network"] = network, ["security"] = security,
                ["tlsSettings"] = new JsonObject { ["serverName"] = ShareServerName(Q("sni"), Q("host", Q("authority")), uri.Host.Trim('[', ']')), ["fingerprint"] = Q("fp", "chrome"), ["alpn"] = Alpn(Q("alpn", "h2,http/1.1")) },
                ["realitySettings"] = new JsonObject { ["serverName"] = Q("sni", uri.Host), ["fingerprint"] = Q("fp", "chrome"), ["publicKey"] = Q("pbk"), ["shortId"] = Q("sid"), ["spiderX"] = Q("spx", "/") },
                ["grpcSettings"] = new JsonObject { ["serviceName"] = Q("serviceName"), ["authority"] = Q("authority"), ["multiMode"] = Q("mode") == "multi" },
                ["tcpSettings"] = network is "tcp" or "raw" ? new JsonObject { ["header"] = TcpHeader(Q("headerType", "none"), Q("host"), Q("path", "/")) } : null,
                ["wsSettings"] = new JsonObject { ["path"] = Q("path", "/"), ["host"] = Q("host") },
                ["httpupgradeSettings"] = new JsonObject { ["path"] = Q("path", "/"), ["host"] = Q("host") },
                ["xhttpSettings"] = new JsonObject { ["path"] = Q("path", "/"), ["host"] = Q("host"), ["mode"] = Q("mode", "auto") } } };
    }

    private static JsonArray? Alpn(string? value) => string.IsNullOrWhiteSpace(value) ? null :
        new JsonArray(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(v => (JsonNode)JsonValue.Create(v)!).ToArray());

    private static string ShareServerName(string? sni, string? host, string address)
    {
        if (!string.IsNullOrWhiteSpace(sni)) return sni;
        var front = host?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return front != null && Uri.CheckHostName(front) != UriHostNameType.Unknown ? front : address;
    }

    private static void RejectInsecure(string value)
    {
        if (value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Профиль отключает проверку сертификата TLS. Нужна безопасная конфигурация сервера.");
    }

    private static JsonObject TcpHeader(string type, string host, string path)
    {
        if (string.IsNullOrWhiteSpace(type) || type == "none") return new JsonObject { ["type"] = "none" };
        if (type != "http") throw new InvalidDataException("Этот тип маскировки TCP не поддерживается.");
        var request = new JsonObject { ["path"] = new JsonArray(string.IsNullOrEmpty(path) ? "/" : path) };
        if (!string.IsNullOrWhiteSpace(host)) request["headers"] = new JsonObject {
            ["Host"] = new JsonArray(host.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(v => (JsonNode)JsonValue.Create(v)!).ToArray()) };
        return new JsonObject { ["type"] = "http", ["request"] = request };
    }

    private static string Decode(string value)
    {
        value = value.Replace('-', '+').Replace('_', '/');
        return Encoding.UTF8.GetString(Convert.FromBase64String(value.PadRight(value.Length + (4 - value.Length % 4) % 4, '=')));
    }
}
