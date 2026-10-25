using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace VPNyan;

internal static class RoutingSettings
{
    internal static string[] Lines(string text) => text.Replace("\r", "").Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    internal static List<string> Parse(string text, string kind)
    {
        var lines = Lines(text);
        if (lines.Length > 256) throw new InvalidDataException("В одном списке можно задать до 256 правил.");
        return lines.Select(value => Normalize(value, kind)).Distinct(StringComparer.Ordinal).ToList();
    }

    private static string Normalize(string value, string kind)
    {
        if (value.Length > 512 || value.Any(char.IsControl)) throw new InvalidDataException("Слишком длинное или некорректное правило.");
        if (kind == "process")
        {
            value = value.Trim('"').Replace('\\', '/');
            if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("Укажи имя приложения.");
            if (value.Contains('/'))
            {
                if (!Path.IsPathFullyQualified(value) || value.Contains(".."))
                    throw new InvalidDataException("Для приложения укажи имя .exe или полный путь к нему.");
                return value;
            }
            if (value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || value is "." or "..")
                throw new InvalidDataException("Некорректное имя приложения.");
            return value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? value[..^4] : value;
        }
        if (kind == "domain")
        {
            value = value.TrimEnd('.');
            if (value.StartsWith("*.")) value = value[2..];
            if (Uri.CheckHostName(value) != UriHostNameType.Dns)
                throw new InvalidDataException("Укажи домен без https:// и пути, например example.org.");
            return new System.Globalization.IdnMapping().GetAscii(value).ToLowerInvariant();
        }
        var parts = value.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address))
            throw new InvalidDataException("Укажи IP или подсеть CIDR, например 192.168.0.0/16.");
        if (parts.Length == 1) return address.ToString();
        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (!int.TryParse(parts[1], out var prefix) || prefix < 0 || prefix > maxPrefix)
            throw new InvalidDataException("Некорректная длина маски подсети.");
        return address + "/" + prefix;
    }

    internal static string[] Dns(string text)
    {
        var values = Lines(text);
        if (values.Length is < 1 or > 4 || values.Any(value => !IPAddress.TryParse(value, out _)))
            throw new InvalidDataException("DNS: укажи от одного до четырёх IP-адресов, каждый с новой строки.");
        return values.Select(value => IPAddress.Parse(value).ToString()).Distinct().ToArray();
    }

    internal static void Validate(AppSettings settings, bool requireRules = true)
    {
        _ = Dns(settings.DnsServers);
        if (settings.SplitTunnelMode is not ("Bypass" or "Include")) throw new InvalidDataException("Неизвестный режим маршрутизации.");
        _ = Parse(string.Join('\n', settings.SplitApplications), "process");
        _ = Parse(string.Join('\n', settings.SplitDomains), "domain");
        _ = Parse(string.Join('\n', settings.SplitNetworks), "ip");
        if (requireRules && settings.SplitTunnelEnabled && settings.SplitTunnelMode == "Include" &&
            settings.SplitApplications.Count + settings.SplitDomains.Count + settings.SplitNetworks.Count == 0)
            throw new InvalidDataException("Для режима «Только выбранное через VPN» добавь хотя бы одно правило.");
    }

    internal static JsonObject Rule(string field, IEnumerable<string> values, string target) => new()
    {
        ["type"] = "field", ["inboundTag"] = new JsonArray("vpn4ik-tun"),
        [field] = new JsonArray(values.Select(value => (JsonNode)JsonValue.Create(value)!).ToArray()), ["outboundTag"] = target
    };

    internal static void AddRules(JsonArray rules, AppSettings settings)
    {
        if (settings.BypassLocalNetwork)
            rules.Add(Rule("ip", new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10" }, "direct"));
        var target = settings.SplitTunnelMode == "Include" ? "proxy" : "direct";
        if (settings.SplitTunnelEnabled)
        {
            if (settings.SplitApplications.Count > 0) rules.Add(Rule("process", settings.SplitApplications, target));
            if (settings.SplitDomains.Count > 0) rules.Add(Rule("domain", settings.SplitDomains.Select(domain => "domain:" + domain), target));
            if (settings.SplitNetworks.Count > 0) rules.Add(Rule("ip", settings.SplitNetworks, target));
        }
        rules.Add(Rule("network", new[] { "tcp", "udp" }, settings.SplitTunnelEnabled && settings.SplitTunnelMode == "Include" ? "direct" : "proxy"));
    }
}
