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
        var profile = request.Profile;
        if (!Supports(profile.Protocol)) throw new InvalidDataException("Подключение этого протокола пока не поддерживается.");
        if (string.IsNullOrWhiteSpace(profile.Configuration)) throw new InvalidDataException("В профиле нет конфигурации подключения. Обнови подписку.");
        var source = profile.Configuration.TrimStart();
        var outbound = source.StartsWith('{') ? ReadJson(source) : ReadLink(source);
        // Only protocol data is admitted. Provider scripts, file paths, listeners and arbitrary
        // top-level features are never executed in the elevated engine process.
        outbound = SanitizeOutbound(outbound);
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
                ["settings"] = new JsonObject { ["auth"] = "password", ["udp"] = false,
                    ["accounts"] = new JsonArray(new JsonObject { ["user"] = request.ProbeUser, ["pass"] = request.ProbePassword }) }
            }
        };
        if (request.EnableTun)
            inbounds.Add(new JsonObject
            {
                ["tag"] = "vpn4ik-tun", ["protocol"] = "tun",
                ["sniffing"] = new JsonObject { ["enabled"] = request.Routing.SplitTunnelEnabled && request.Routing.SplitDomains.Count > 0,
                    ["destOverride"] = new JsonArray("http", "tls", "quic"), ["routeOnly"] = true },
                ["settings"] = new JsonObject
                {
                    ["name"] = InterfaceName, ["desc"] = "VPN4ik", ["mtu"] = request.Mtu,
                    ["gateway"] = new JsonArray("172.31.255.1/30", "fd42:7670:3469::1/126"),
                    ["dns"] = new JsonArray(RoutingSettings.Dns(request.Routing.DnsServers).Select(value => (JsonNode)JsonValue.Create(value)!).ToArray()),
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
            RoutingSettings.AddRules(rules, request.Routing);
            if (request.Routing.SplitTunnelEnabled || request.Routing.BypassLocalNetwork)
                outbounds.Add(new JsonObject { ["tag"] = "direct", ["protocol"] = "freedom", ["settings"] = new JsonObject() });
        }
        return new JsonObject
        {
            ["log"] = new JsonObject { ["access"] = "none", ["loglevel"] = request.Diagnostics ? "info" : "warning", ["dnsLog"] = false },
            ["inbounds"] = inbounds, ["outbounds"] = outbounds,
            ["stats"] = new JsonObject(),
            ["policy"] = new JsonObject { ["system"] = new JsonObject { ["statsOutboundUplink"] = true, ["statsOutboundDownlink"] = true } },
            ["metrics"] = new JsonObject { ["tag"] = "vpn4ik-metrics" },
            ["routing"] = new JsonObject { ["domainStrategy"] = "AsIs", ["rules"] = rules }
        }.ToJsonString();
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
        var network = stream["network"]?.GetValue<string>()?.ToLowerInvariant() ?? "tcp";
        if (network is not ("tcp" or "raw" or "grpc" or "ws" or "httpupgrade" or "xhttp" or "splithttp" or "hysteria"))
            throw new InvalidDataException("Этот транспорт подключения пока не поддерживается.");
        var security = stream["security"]?.GetValue<string>()?.ToLowerInvariant() ?? "none";
        if (security is not ("none" or "tls" or "reality")) throw new InvalidDataException("Неизвестный режим шифрования профиля.");
        var cleanStream = new JsonObject { ["network"] = network, ["security"] = security };
        if (security == "tls")
        {
            var tls = stream["tlsSettings"] as JsonObject;
            if (tls?["allowInsecure"]?.GetValue<bool>() == true)
                throw new InvalidDataException("Профиль отключает проверку сертификата TLS. Нужна безопасная конфигурация сервера.");
            cleanStream["tlsSettings"] = Copy(tls, "serverName", "alpn", "fingerprint", "verifyPeerCertByName", "pinnedPeerCertSha256", "disableSystemRoot", "enableSessionResumption");
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
        if (security == "reality") cleanStream["realitySettings"] = Copy(stream["realitySettings"] as JsonObject,
            "serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX", "mldsa65Verify");
        if (network == "grpc") cleanStream["grpcSettings"] = Copy(stream["grpcSettings"] as JsonObject,
            "serviceName", "authority", "multiMode", "idle_timeout", "health_check_timeout", "permit_without_stream", "initial_windows_size");
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
            var raw = new JsonObject { ["protocol"] = "vmess", ["settings"] = new JsonObject { ["vnext"] = new JsonArray(new JsonObject
                { ["address"] = vmess["add"]?.DeepClone(), ["port"] = vmessPort, ["users"] = new JsonArray(new JsonObject
                    { ["id"] = vmess["id"]?.DeepClone(), ["security"] = vmess["scy"]?.DeepClone() ?? JsonValue.Create("auto") }) }) } };
            var net = vmess["net"]?.ToString() ?? "tcp";
            raw["streamSettings"] = new JsonObject { ["network"] = net, ["security"] = vmess["tls"]?.ToString() == "tls" ? "tls" : "none",
                ["tlsSettings"] = new JsonObject { ["serverName"] = vmess["sni"]?.DeepClone(), ["fingerprint"] = "chrome" },
                ["wsSettings"] = new JsonObject { ["path"] = vmess["path"]?.DeepClone(), ["host"] = vmess["host"]?.DeepClone() },
                ["grpcSettings"] = new JsonObject { ["serviceName"] = vmess["path"]?.DeepClone() } };
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
        var network = Q("type", "tcp");
        return new JsonObject { ["protocol"] = protocol, ["settings"] = settings,
            ["streamSettings"] = new JsonObject { ["network"] = network, ["security"] = security,
                ["tlsSettings"] = new JsonObject { ["serverName"] = Q("sni", uri.Host), ["fingerprint"] = Q("fp", "chrome"), ["alpn"] = new JsonArray(Q("alpn", "h2,http/1.1").Split(',').Select(v => (JsonNode)JsonValue.Create(v)!).ToArray()) },
                ["realitySettings"] = new JsonObject { ["serverName"] = Q("sni", uri.Host), ["fingerprint"] = Q("fp", "chrome"), ["publicKey"] = Q("pbk"), ["shortId"] = Q("sid"), ["spiderX"] = Q("spx", "/") },
                ["grpcSettings"] = new JsonObject { ["serviceName"] = Q("serviceName"), ["authority"] = Q("authority"), ["multiMode"] = Q("mode") == "multi" },
                ["wsSettings"] = new JsonObject { ["path"] = Q("path", "/"), ["host"] = Q("host") },
                ["httpupgradeSettings"] = new JsonObject { ["path"] = Q("path", "/"), ["host"] = Q("host") },
                ["xhttpSettings"] = new JsonObject { ["path"] = Q("path", "/"), ["host"] = Q("host"), ["mode"] = Q("mode", "auto") } } };
    }

    private static string Decode(string value)
    {
        value = value.Replace('-', '+').Replace('_', '/');
        return Encoding.UTF8.GetString(Convert.FromBase64String(value.PadRight(value.Length + (4 - value.Length % 4) % 4, '=')));
    }
}
