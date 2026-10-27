using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Windows.Controls;
using VPNyan;

internal static class SubscriptionRegressionChecks
{
    private const string Server = """
        {"remarks":"Тестовый сервер","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"vpn.example.test","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}]},"streamSettings":{"network":"grpc","security":"reality","realitySettings":{"serverName":"example.test","publicKey":"test-key"},"grpcSettings":{"serviceName":"test-service"}}},{"protocol":"freedom"}]}
        """;
    private const string Notice = """
        {"remarks":"Информация о подписке","outbounds":[{"protocol":"freedom"},{"protocol":"blackhole"}]}
        """;
    private const string Link = "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=reality&type=grpc&serviceName=test-service#Test";

    internal static async Task RunAsync(Action<bool, string> require)
    {
        var single = SubscriptionParser.Parse(Server).Single();
        require(single.Protocol == "VLESS" && single.Address == "vpn.example.test", "Ordinary Xray JSON remains supported");
        foreach (var body in new[] { $"[{Notice},{Server}]", $"[{Server},{Notice}]", $"[{Notice},{Server},{Notice}]" })
        {
            var profiles = SubscriptionParser.Parse(body);
            require(profiles.Count == 1 && profiles[0].Id == single.Id,
                "An informational Xray profile must not prevent importing a real server");
            require(profiles[0].Configuration.Contains("test-service") && profiles[0].Configuration.Contains("test-key"),
                "Skipping notices preserves transport and Reality settings");
        }
        require(SubscriptionParser.Parse($"[{Notice},{Server},{Server}]").Count == 1,
            "Real servers are still deduplicated in a subscription with notices");
        foreach (var body in new[] { Notice, $"[{Notice}]", "[]" })
            Reject(() => SubscriptionParser.Parse(body), require, "Informational profiles alone cannot become VPN servers");
        Reject(() => SubscriptionParser.Parse($"[{Notice},{{\"outbounds\":[{{\"protocol\":\"vless\",\"settings\":{{\"vnext\":[]}}}}]}}]"),
            require, "Malformed proxy settings must still be rejected");
        Reject(() => SubscriptionParser.Parse($"[{Server},null]"), require, "Malformed JSON entries cannot be silently skipped");
        Reject(() => SubscriptionParser.Parse("{\"remarks\":\"not an Xray config\"}"), require, "JSON without outbounds is rejected");
        Reject(() => SubscriptionParser.Parse("<html>Sign in</html>"), require, "Provider HTML is never imported as a server");
        Reject(() => SubscriptionParser.Parse("vless://user@vpn.example.test:0"), require, "Invalid server ports are rejected");
        require(SubscriptionParser.Parse(Link).Single().Protocol == "VLESS", "Share links remain supported");
        require(SubscriptionParser.Parse(Convert.ToBase64String(Encoding.UTF8.GetBytes(Link))).Single().Address == "vpn.example.test",
            "Base64 share subscriptions remain supported");
        require(SubscriptionParser.Parse("\uFEFF[" + Notice + "," + Server + "]").Count == 1,
            "A UTF-8 BOM is accepted before a mixed JSON subscription");

        foreach (var control in new[] { "incy://routing/onadd/eyJydWxlcyI6W119", "incy://routing/off", "incy://autorouting/add/https://example.test/routing.json",
            "happ://routing/add/eyJydWxlcyI6W119", "://onadd/https://example.test/routing.json", "INCY://ROUTING/add?data=eyJydWxlcyI6W119" })
        {
            foreach (var mixed in new[] { Link + "\n" + control, control + "\r\n" + Link, Convert.ToBase64String(Encoding.UTF8.GetBytes(Link + "\n" + control)) })
            {
                var parsed = SubscriptionParser.ParseDocument(mixed);
                require(parsed.Profiles.Count == 1 && parsed.Profiles[0].Configuration == Link && parsed.IgnoredRoutingLines == 1,
                    "Mixed subscriptions preserve a real server while recognizing client routing metadata");
            }
        }
        Reject(() => SubscriptionParser.Parse("incy://routing/onadd/eyJydWxlcyI6W119"), require, "Routing metadata alone never becomes a VPN server or an empty successful import");
        Reject(() => SubscriptionParser.Parse(Link + "\nincy://crypt1/unsupported"), require, "Unimplemented INCY imports cannot be silently discarded as routing");
        Reject(() => SubscriptionParser.Parse(Link + "\nhttp://routing/onadd/abc"), require, "Unrelated schemes are not mistaken for routing control lines");
        Reject(() => SubscriptionParser.Parse("incy://routing/off\nvless://user@vpn.example.test:0"), require, "Recognizing metadata does not hide invalid real server configurations");

        var mixedRequests = 0;
        using (var client = new SubscriptionClient(new Handler(_ =>
        {
            mixedRequests++;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Convert.ToBase64String(Encoding.UTF8.GetBytes(Link + "\nincy://autorouting/onadd/https://example.test/never-fetch"))) };
        })))
        {
            var result = await client.DownloadAsync("https://example.test/mixed");
            require(result.Profiles.Count == 1 && result.IgnoredRoutingLines == 1 && mixedRequests == 1,
                "Downloading a mixed base64 subscription records metadata without fetching its external routing URL");
        }

        using (var client = new SubscriptionClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent($"[{Notice},{Server}]") })))
        {
            var result = await client.DownloadAsync("https://example.test/subscription");
            require(result.Profiles.Count == 1 && result.Url == "https://example.test/subscription",
                "Downloading a mixed provider response imports only real servers");
        }
        var requests = 0;
        var hitVpnRequests = 0;
        using (var client = new SubscriptionClient(new Handler(_ =>
        {
            hitVpnRequests++;
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        })))
        {
            var hitVpnUrl = "https://hvpn.io/" + new string('A', 64);
            await RejectAsync(() => client.DownloadAsync(hitVpnUrl), require,
                "HitVPN embedded app links receive an unsupported-format error instead of HTTP 404");
            require(hitVpnRequests == 0, "HitVPN credentials embedded in app links are never sent to the web endpoint");
        }
        require(!SubscriptionParser.IsHitVpnAppLink(new Uri("https://example.test/" + new string('A', 64))) &&
            !SubscriptionParser.IsHitVpnAppLink(new Uri("https://hvpn.io/sub/test")),
            "HitVPN detection does not capture other providers or ordinary multisegment subscription URLs");
        using (var client = new SubscriptionClient(new Handler(request =>
        {
            requests++;
            if (request.RequestUri!.AbsolutePath == "/subscription")
                return new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("/xray", UriKind.Relative) } };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($"[{Notice},{Server}]") };
        })))
        {
            var result = await client.DownloadAsync("https://example.test/subscription");
            require(result.Profiles.Count == 1 && requests == 2 && result.Url == "https://example.test/subscription",
                "HTTPS redirects still preserve the original subscription URL");
        }
        using (var client = new SubscriptionClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.Found)
        { Headers = { Location = new Uri("http://example.test/insecure") } })))
            await RejectAsync(() => client.DownloadAsync("https://example.test/subscription"), require,
                "Redirects cannot downgrade a subscription to HTTP");
        using (var client = new SubscriptionClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(Notice) })))
            await RejectAsync(() => client.DownloadAsync("https://example.test/subscription"), require,
                "A provider response containing only a notice cannot replace stored servers");
        using (var client = new SubscriptionClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden))))
            await RejectAsync(() => client.DownloadAsync("https://example.test/subscription"), require,
                "Provider HTTP errors remain visible");
    }

    internal static void CheckMixedUi(string fixtures, Action<bool, string> require)
    {
        var directory = Path.Combine(fixtures, "mixed-subscription-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        var settingsPath = Path.Combine(directory, "settings.json");
        new AppSettings { StoragePath = settingsPath, SplitTunnelEnabled = true, SplitDomains = new() { "example.test" } }.SaveOrThrow();
        var parsed = SubscriptionParser.ParseDocument(Link + "\nincy://routing/onadd/https://example.test/untrusted-settings");
        var window = new MainWindow(false, directory);
        window.ApplySubscription(new Subscription { Url = "https://example.test/mixed", Profiles = parsed.Profiles, IgnoredRoutingLines = parsed.IgnoredRoutingLines });
        require(((ListBox)window.FindName("ServerSelect")).Items.Count == 1 && ((TextBlock)window.FindName("SubscriptionStatusText")).Text.Contains("пропущена"),
            "Mixed subscription displays its real server and a clear notice about unapplied provider routing");
        require(SubscriptionStore.Load(Path.Combine(directory, "subscriptions.dpapi")).Single().IgnoredRoutingLines == 1,
            "Protected source storage preserves the ignored-routing notice through subscription copying");
        var settings = AppSettings.LoadFromPath(settingsPath);
        require(settings.SplitTunnelEnabled && settings.SplitDomains.SequenceEqual(new[] { "example.test" }),
            "Provider routing metadata never changes user split-tunnel settings");
        window.Close();
    }

    private static void Reject(Action action, Action<bool, string> require, string name)
    {
        try { action(); }
        catch (InvalidDataException) { require(true, name); return; }
        require(false, name);
    }

    private static async Task RejectAsync(Func<Task> action, Action<bool, string> require, string name)
    {
        try { await action(); }
        catch (InvalidDataException) { require(true, name); return; }
        require(false, name);
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response(request));
    }
}
