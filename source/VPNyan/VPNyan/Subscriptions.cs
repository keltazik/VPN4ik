using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VPNyan;

public sealed class SubscriptionProfile
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Address { get; set; } = "";
    public int Port { get; set; }
    // Preserve the full source configuration, including transport, TLS and routing.
    public string Configuration { get; set; } = "";
}

public sealed class Subscription
{
    public string DisplayName { get; set; } = "";
    public List<string> DeletedProfileIds { get; set; } = new();
    public int IgnoredRoutingLines { get; set; }
    public string Url { get; set; } = "";
    public DateTime UpdatedAt { get; set; }
    public List<SubscriptionProfile> Profiles { get; set; } = new();
}

internal sealed record ParsedSubscription(List<SubscriptionProfile> Profiles, int IgnoredRoutingLines);

internal static class SubscriptionParser
{
    internal const int MaxBytes = 4 * 1024 * 1024;
    private static readonly HashSet<string> Protocols = new(StringComparer.OrdinalIgnoreCase)
        { "vless", "vmess", "trojan", "shadowsocks", "socks", "hysteria", "hysteria2", "hy2" };
    private static readonly HashSet<string> ServiceProtocols = new(StringComparer.OrdinalIgnoreCase)
        { "freedom", "blackhole", "dns" };

    internal static Uri ParseUrl(string value)
    {
        // Accept a URL copied from Markdown as well as a plain address.
        var match = System.Text.RegularExpressions.Regex.Match(value.Trim(), @"^\[[^\]]*\]\((https://[^\s)]+)\)$");
        if (match.Success) value = match.Groups[1].Value;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme != "https" || string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidDataException("Вставь HTTPS-ссылку на подписку.");
        return uri;
    }

    internal static List<SubscriptionProfile> Parse(string body) => ParseDocument(body).Profiles;

    internal static ParsedSubscription ParseDocument(string body)
    {
        if (Encoding.UTF8.GetByteCount(body) > MaxBytes)
            throw new InvalidDataException("Подписка слишком большая (максимум 4 МБ).");
        body = body.Trim().TrimStart('\uFEFF');
        if (body.Length == 0) throw new InvalidDataException("Сервер вернул пустую подписку.");
        if (!body.StartsWith('[') && !body.StartsWith('{') && !body.Contains("://"))
        {
            try { body = DecodeBase64(body).Trim().TrimStart('\uFEFF'); }
            catch (FormatException) { throw new InvalidDataException("Не удалось распознать формат подписки."); }
        }
        var profiles = new List<SubscriptionProfile>();
        var ignoredRouting = 0;
        try
        {
            if (body.StartsWith('[') || body.StartsWith('{'))
            {
                using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 64 });
                if (document.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var config in document.RootElement.EnumerateArray())
                        if (ParseConfig(config) is { } profile) profiles.Add(profile);
                }
                else if (ParseConfig(document.RootElement) is { } profile) profiles.Add(profile);
            }
            else
            {
                foreach (var line in body.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.StartsWith('#')) continue;
                    // These deep links configure another client's routing, not a VPN server.
                    // Recognize only documented control prefixes; never fetch or execute their payload.
                    if (System.Text.RegularExpressions.Regex.IsMatch(line,
                        @"^(?:(?:incy|happ))?://(?:routing|autorouting|onadd)(?:[/?]|$)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                    { ignoredRouting++; continue; }
                    profiles.Add(ParseLink(line));
                }
            }
        }
        catch (JsonException) { throw new InvalidDataException("В подписке некорректный JSON."); }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or KeyNotFoundException or OverflowException)
        { throw new InvalidDataException("В подписке некорректная конфигурация сервера."); }
        if (profiles.Count == 0)
            throw new InvalidDataException(ignoredRouting > 0
                ? "В подписке есть только служебные настройки маршрутизации. Ссылок на VPN-серверы нет; прежние серверы сохранены."
                : "В подписке нет поддерживаемых прокси-серверов. Если провайдер вернул служебный профиль, проверь срок подписки и ссылку для Xray/V2Ray.");
        if (profiles.Count > 1000) throw new InvalidDataException("В подписке больше 1000 серверов.");
        return new(profiles.DistinctBy(p => p.Id).ToList(), ignoredRouting);
    }

    private static SubscriptionProfile? ParseConfig(JsonElement config)
    {
        if (config.ValueKind != JsonValueKind.Object || !config.TryGetProperty("outbounds", out var outbounds) ||
            outbounds.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Ожидается конфигурация Xray с массивом outbounds.");
        var outbound = outbounds.EnumerateArray().FirstOrDefault(o => Protocols.Contains(Text(o, "protocol")));
        if (outbound.ValueKind == JsonValueKind.Undefined)
        {
            // Providers can put a direct/block-only informational profile before the real servers.
            // Skip only known service profiles; malformed or unknown formats remain errors.
            if (outbounds.GetArrayLength() > 0 && outbounds.EnumerateArray().All(o => ServiceProtocols.Contains(Text(o, "protocol"))))
                return null;
            throw new InvalidDataException("В конфигурации нет поддерживаемого прокси-сервера.");
        }
        var protocol = Text(outbound, "protocol");
        var settings = outbound.GetProperty("settings");
        if (protocol.Equals("hysteria", StringComparison.OrdinalIgnoreCase))
        {
            if (!settings.TryGetProperty("version", out var version) || version.GetInt32() != 2)
                throw new InvalidDataException("Поддерживается Hysteria версии 2.");
            return Create(Text(config, "remarks"), protocol, Text(settings, "address"),
                settings.GetProperty("port").GetInt32(), config.GetRawText());
        }
        var entries = settings.TryGetProperty("vnext", out var vnext) ? vnext : settings.GetProperty("servers");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() == 0)
            throw new InvalidDataException("В конфигурации не указан адрес сервера.");
        var endpoint = entries[0];
        return Create(Text(config, "remarks"), protocol, Text(endpoint, "address"),
            endpoint.GetProperty("port").GetInt32(), config.GetRawText());
    }

    private static SubscriptionProfile ParseLink(string link)
    {
        var separator = link.IndexOf("://", StringComparison.Ordinal);
        if (separator < 1) throw new InvalidDataException("Ожидается список ссылок на серверы или JSON Xray.");
        var protocol = link[..separator].ToLowerInvariant();
        if (protocol == "ss") protocol = "shadowsocks";
        if (!Protocols.Contains(protocol))
            throw new InvalidDataException("Этот формат подписки пока не поддерживается. Нужен JSON Xray или список ссылок VLESS, VMess, Trojan, Shadowsocks, SOCKS, Hysteria2.");
        if (protocol == "vmess")
        {
            using var doc = JsonDocument.Parse(DecodeBase64(link[(separator + 3)..]));
            var root = doc.RootElement;
            var portValue = root.GetProperty("port");
            var port = portValue.ValueKind == JsonValueKind.Number ? portValue.GetInt32() : int.Parse(portValue.GetString()!);
            return Create(Text(root, "ps"), protocol, Text(root, "add"), port, link);
        }
        // SIP002 Shadowsocks permits a base64 authority as well as base64 userinfo.
        var parseable = link;
        if (protocol == "shadowsocks")
        {
            var remainder = link[(separator + 3)..];
            var end = remainder.IndexOfAny(new[] { '#', '?' });
            var authority = end < 0 ? remainder : remainder[..end];
            if (!authority.Contains('@'))
                parseable = "ss://" + DecodeBase64(authority) + (end < 0 ? "" : remainder[end..]);
        }
        if (!Uri.TryCreate(parseable, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidDataException("Некорректная ссылка на сервер.");
        var defaultPort = protocol is "hysteria2" or "hy2" ? 443 : -1;
        return Create(Uri.UnescapeDataString(uri.Fragment.TrimStart('#')), protocol,
            uri.Host.Trim('[', ']'), uri.Port == -1 ? defaultPort : uri.Port, link);
    }

    private static SubscriptionProfile Create(string name, string protocol, string address, int port, string configuration)
    {
        if (string.IsNullOrWhiteSpace(address) || Uri.CheckHostName(address) == UriHostNameType.Unknown || port is < 1 or > 65535)
            throw new InvalidDataException("Некорректный адрес или порт сервера.");
        return new SubscriptionProfile
        {
            Id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(configuration))),
            Name = string.IsNullOrWhiteSpace(name) ? $"{protocol.ToUpperInvariant()} · {address}" : name,
            Protocol = protocol.ToUpperInvariant(), Address = address, Port = port, Configuration = configuration
        };
    }

    private static string Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";

    private static string DecodeBase64(string value)
    {
        value = string.Concat(value.Where(c => !char.IsWhiteSpace(c))).Replace('-', '+').Replace('_', '/');
        value = value.PadRight(value.Length + (4 - value.Length % 4) % 4, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(value));
    }
}

internal sealed class SubscriptionClient : IDisposable
{
    private readonly HttpClient client;
    internal SubscriptionClient(HttpMessageHandler? handler = null)
    {
        client = handler == null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = System.Net.DecompressionMethods.All })
            : new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);
        // Subscription providers use this compatibility identifier to return Xray JSON.
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Happ/1.0 VPN4ik/0.2");
    }

    internal async Task<Subscription> DownloadAsync(string url, CancellationToken cancellationToken = default)
    {
        var source = SubscriptionParser.ParseUrl(url);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var target = source;
        for (var redirects = 0; redirects <= 5; redirects++)
        {
            using var response = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            {
                if (redirects == 5 || response.Headers.Location == null)
                    throw new InvalidDataException("Слишком много перенаправлений подписки.");
                target = SubscriptionParser.ParseUrl(new Uri(target, response.Headers.Location).AbsoluteUri);
                continue;
            }
            if (!response.IsSuccessStatusCode)
                throw new InvalidDataException($"Сервер подписки ответил HTTP {(int)response.StatusCode}. Проверь ссылку и срок подписки.");
            if (response.Content.Headers.ContentLength > SubscriptionParser.MaxBytes)
                throw new InvalidDataException("Подписка слишком большая (максимум 4 МБ).");
            await using var input = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = await input.ReadAsync(chunk, timeout.Token)) > 0)
            {
                if (buffer.Length + read > SubscriptionParser.MaxBytes)
                    throw new InvalidDataException("Подписка слишком большая (максимум 4 МБ).");
                buffer.Write(chunk, 0, read);
            }
            var parsed = SubscriptionParser.ParseDocument(Encoding.UTF8.GetString(buffer.ToArray()));
            return new Subscription { Url = source.AbsoluteUri, UpdatedAt = DateTime.UtcNow,
                Profiles = parsed.Profiles, IgnoredRoutingLines = parsed.IgnoredRoutingLines };
        }
        throw new InvalidDataException("Не удалось загрузить подписку.");
    }

    public void Dispose() => client.Dispose();
}
