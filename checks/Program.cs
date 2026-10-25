using System.IO;
using System.Windows;
using System.Windows.Threading;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Net;
using System.Net.Http;
using System.Text;
using VPNyan;

internal static class Program
{
    private static int passed;
    private static readonly string testDataDirectory = Path.Combine(Environment.CurrentDirectory, ".checks-data", "run-" + Guid.NewGuid().ToString("N"));

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Contains("--native-routing"))
            {
                var native = NativeRoutingChecks.RunAsync().GetAwaiter().GetResult();
                Console.WriteLine($"PASS: {native} native routing/statistics checks (loopback only, no TUN or external requests).");
                return 0;
            }
            // Caller must isolate APPDATA/LOCALAPPDATA before invoking this executable.
            var fixtures = Path.Combine(Environment.CurrentDirectory, ".checks-data");
            Directory.CreateDirectory(fixtures);
            CheckProfile(fixtures, "ipv4.conf", "Endpoint=192.0.2.1:51820", "192.0.2.1");
            CheckProfile(fixtures, "ipv6.conf", "Endpoint = [2001:db8::1]:51820 # comment", "2001:db8::1");
            CheckProfile(fixtures, "host.conf", "  endpoint\t= vpn.example.test:1234", "vpn.example.test");
            RejectProfile(fixtures, "missing.conf", "Address = 10.0.0.2/32");
            RejectProfile(fixtures, "port.conf", "Endpoint = vpn.example.test");
            RejectProfile(fixtures, "zero.conf", "Endpoint = vpn.example.test:0");
            RejectProfile(fixtures, "bad name.conf", "Endpoint = vpn.example.test:51820");

            var server = new ServerItem { Ping = 0 };
            server.UpdatePingDisplay();
            Require(server.PingDisplay == "0 ms", "Sub-millisecond ping must not become timeout");
            server.SetLatency(new LatencyResult("test", -1, "Замер не прошёл"));
            Require(server.PingDisplay == "Нет замера" && server.PingColor == "#A78762", "Failed latency measurement does not label a working server offline");
            server.SetLatency(new LatencyResult("test", 42, "TCP connection", LatencyKind.Tcp));
            Require(server.PingDisplay == "42 ms" && !server.LatencyViaVpn && server.PingDetail.Contains("TCP"), "TCP ping displays milliseconds without claiming VPN verification");
            CheckPingPolicy();
            CheckSubscriptions(fixtures);
            CheckEngineConfiguration();
            CheckRoutingAndTraffic();
            CheckActivity(fixtures);

            var app = new VPNyan.App();
            app.InitializeComponent();
            app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Require(!typeof(MainWindow).Assembly.GetManifestResourceNames().Any(name => name.EndsWith(".conf")),
                "Private VPN profiles must not be embedded in the application");
            var window = new MainWindow(false, testDataDirectory);
            window.Measure(new Size(1000, 900));
            window.Arrange(new Rect(0, 0, 1000, 900));
            window.UpdateLayout();
            Require(window.FindName("ImportConfigButton") != null, "Import button must be available");
            Require(((ListBox)window.FindName("ServerSelect")).Items.Count == 0,
                "A fresh install must not advertise nonexistent servers");
            CheckServerList(window, fixtures);
            window.ShowSection("home");
            foreach (var size in new[] { new Size(1040, 740), new Size(760, 540), new Size(820, 620), new Size(1440, 900) })
                CheckLayout(window, fixtures, size);
            CheckSections(window, fixtures);
            var wasClosed = false;
            window.Closed += (_, _) => wasClosed = true;
            window.Close();
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background,
                new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
            Require(wasClosed, "Close must complete and dispose the tray without recursive Close");
            Console.WriteLine($"PASS: {passed} offline checks (no TUN or network requests).");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static readonly string Config = """
        {"remarks":"🇸🇪 Швеция","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.test","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}]},"streamSettings":{"network":"grpc","security":"reality","grpcSettings":{"serviceName":"test-service"},"realitySettings":{"serverName":"example.test","publicKey":"test-key"}}},{"protocol":"freedom"}]}
        """;

    private static void CheckSubscriptions(string fixtures)
    {
        var profiles = SubscriptionParser.Parse("[" + Config + "]");
        Require(profiles.Count == 1 && profiles[0].Name == "🇸🇪 Швеция" && profiles[0].Protocol == "VLESS", "Xray JSON names and protocol");
        Require(profiles[0].Configuration.Contains("test-service") && profiles[0].Configuration.Contains("test-key"), "Full transport and Reality configuration preserved");
        Require(SubscriptionParser.Parse(Config).Count == 1, "Single Xray JSON object");
        var links = "#profile-title: Test\nvless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=reality#%D0%A8%D0%B2%D0%B5%D1%86%D0%B8%D1%8F\ntrojan://password@[2001:db8::1]:443#IPv6";
        var decoded = SubscriptionParser.Parse(Convert.ToBase64String(Encoding.UTF8.GetBytes(links)));
        Require(decoded.Count == 2 && decoded[0].Name == "Швеция" && decoded[1].Address == "2001:db8::1", "Base64 subscription, Unicode names and IPv6");
        Require(SubscriptionParser.Parse(links + "\n" + links).Count == 2, "Duplicate links eliminated");
        var vmess = "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"ps\":\"VMess test\",\"add\":\"vpn.example.test\",\"port\":\"443\"}"));
        Require(SubscriptionParser.Parse(vmess)[0].Protocol == "VMESS", "Legacy VMess share format");
        Require(SubscriptionParser.Parse("ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-256-gcm:password@vpn.example.test:8388")) + "#Test")[0].Port == 8388, "Shadowsocks encoded authority");
        Require(SubscriptionParser.Parse("hysteria2://password@vpn.example.test#HY2")[0].Port == 443, "Hysteria2 default port");
        Reject(() => SubscriptionParser.Parse("<html>Sign in</html>"), "HTML must not appear as a server");
        Reject(() => SubscriptionParser.Parse("[]"), "Empty subscription rejected");
        Reject(() => SubscriptionParser.Parse("[{\"outbounds\":[{\"protocol\":\"freedom\"}]}]"), "Direct outbound must not become a server");
        Reject(() => SubscriptionParser.Parse("vless://user@vpn.example.test:0#Bad"), "Invalid port rejected");
        Reject(() => SubscriptionParser.Parse("[{"), "Malformed JSON rejected");
        Reject(() => SubscriptionParser.Parse(new string('x', SubscriptionParser.MaxBytes + 1)), "Oversized subscription rejected");
        Reject(() => SubscriptionParser.ParseUrl("http://example.test/sub"), "Subscription HTTPS required");
        Require(SubscriptionParser.ParseUrl("[Test](https://example.test/sub)").AbsoluteUri == "https://example.test/sub", "Pasted Markdown URL accepted");
        var subscription = new Subscription { Url = "https://example.test/private-token", Profiles = profiles, UpdatedAt = DateTime.UtcNow };
        var protectedPath = Path.Combine(fixtures, "store.dpapi");
        SubscriptionStore.Save(protectedPath, new[] { subscription });
        Require(!Encoding.UTF8.GetString(File.ReadAllBytes(protectedPath)).Contains("private-token"), "Subscription URL encrypted at rest");
        Require(SubscriptionStore.Load(protectedPath)[0].Profiles[0].Configuration == profiles[0].Configuration, "Protected subscription roundtrip");
        using (var client = new SubscriptionClient(new ResponseHandler(request =>
        {
            Require(request.Headers.UserAgent.ToString().Contains("Happ/"), "Subscription compatibility user agent");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[" + Config + "]") };
        })))
            Require(client.DownloadAsync(subscription.Url).GetAwaiter().GetResult().Profiles.Count == 1, "HTTP subscription download and parsing");
        using (var client = new SubscriptionClient(new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.Found)
        { Headers = { Location = new Uri("http://example.test/insecure") } })))
            Reject(() => client.DownloadAsync(subscription.Url).GetAwaiter().GetResult(), "HTTPS redirect downgrade rejected");
        using (var client = new SubscriptionClient(new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden))))
            Reject(() => client.DownloadAsync(subscription.Url).GetAwaiter().GetResult(), "Provider access denied reported");
        var privatePath = Path.Combine(fixtures, "subscription-private.txt");
        if (File.Exists(privatePath) && new FileInfo(privatePath).Length > 0)
        {
            var actual = SubscriptionParser.Parse(File.ReadAllText(privatePath));
            Require(actual.Count == 9 && actual.All(p => p.Protocol == "VLESS"), "User subscription: all nine Xray profiles parsed");
        }
    }

    private static void CheckServerList(MainWindow window, string fixtures)
    {
        var list = (ListBox)window.FindName("ServerSelect");
        var subscription = new Subscription { Url = "https://example.test/sub", UpdatedAt = DateTime.UtcNow,
            Profiles = SubscriptionParser.Parse(Config) };
        window.ApplySubscription(subscription);
        Require(list.Items.Count == 1 && ((ServerItem)list.SelectedItem).Protocol == "VLESS", "Import populates and selects server");
        Require(!File.ReadAllText(Path.Combine(testDataDirectory, "settings.json")).Contains(subscription.Url), "Selection settings must not expose the subscription URL");
        window.ApplySubscription(subscription);
        Require(list.Items.Count == 1, "Refresh replaces a subscription without duplicates");
        window.Connect().GetAwaiter().GetResult();
        Require(((TextBlock)window.FindName("StatusText")).Text.Contains("обычном запуске"), "Offline UI checks never start a network engine or UAC");
        // A new process must restore the imported list and selection without downloading again.
        var reloaded = new MainWindow(false, testDataDirectory);
        Require(((ListBox)reloaded.FindName("ServerSelect")).Items.Count == 1, "Imported servers restored after restart");
        reloaded.Close();
        PumpDispatcher();
        var actualPath = Path.Combine(fixtures, "subscription-private.txt");
        if (File.Exists(actualPath) && new FileInfo(actualPath).Length > 0)
        {
            subscription.Profiles = SubscriptionParser.Parse(File.ReadAllText(actualPath));
            window.ApplySubscription(subscription);
            Require(list.Items.Count == 9, "Real subscription displays nine servers in the WPF list");
        }
        else
        {
            subscription.Profiles = Enumerable.Range(1, 9).Select(i => new SubscriptionProfile
            { Id = i.ToString(), Name = "Проверка сервера " + i, Address = "vpn.example.test", Port = 443, Protocol = "VLESS" }).ToList();
            window.ApplySubscription(subscription);
        }
        var before = list.Items.Count;
        // Bad updates are parsed before the current list/store can be replaced.
        Reject(() => window.ApplySubscription(new Subscription { Url = "https://example.test/sub",
            Profiles = SubscriptionParser.Parse("<html>error</html>") }), "Bad update rejected");
        Require(list.Items.Count == before, "Failed update keeps the previous servers");
            var search = (TextBox)window.FindName("ServerSearchText");
            search.Text = "NO-SUCH-SERVER";
            Require(list.Items.Count == 0 && ((TextBlock)window.FindName("EmptyServersText")).Visibility == Visibility.Visible,
                "Search reports an empty result without changing stored servers");
            search.Clear();
            Require(list.Items.Count == before && list.SelectedItem != null, "Clearing search restores the server list and selection");
    }

    private static void CheckLayout(MainWindow window, string fixtures, Size size)
    {
        var root = (FrameworkElement)window.Content;
        root.Measure(size);
        root.Arrange(new Rect(size));
        root.UpdateLayout();
        foreach (var name in new[] { "TimeConnectedText", "StatusText", "MenuToggleButton", "ServerSelect", "BestServerButton" })
        {
            var control = (FrameworkElement)window.FindName(name);
            var bounds = control.TransformToAncestor(root).TransformBounds(new Rect(control.RenderSize));
            Require(bounds.Left >= 0 && bounds.Top >= 0 && bounds.Right <= size.Width + 1 && bounds.Bottom <= size.Height + 1 && bounds.Height > 0,
                $"{name} visible at {size.Width}x{size.Height}");
        }
        Require(!Descendants((DependencyObject)window.FindName("ContentGrid")).OfType<ScrollViewer>().Any(viewer => viewer.ScrollableHeight > 0 && !IsInside(viewer, (ListBox)window.FindName("ServerSelect"))),
            "Only the server list may scroll");
        var left = (FrameworkElement)window.FindName("ServersPanel");
        var right = (FrameworkElement)window.FindName("ConnectionPanel");
        Require(left.TransformToAncestor(root).TransformBounds(new Rect(left.RenderSize)).Right < right.TransformToAncestor(root).TransformBounds(new Rect(right.RenderSize)).Left,
            "Server list stays to the left of the connection panel");
        CheckOrnamentHitBox(window, root);
        var list = (ListBox)window.FindName("ServerSelect");
        var scroller = Descendants(list).OfType<ScrollViewer>().First();
        scroller.ScrollToEnd();
        root.UpdateLayout();
        Require(Math.Abs(scroller.VerticalOffset - scroller.ScrollableHeight) < 1, "Custom scrollbar can reach the last server");
        scroller.ScrollToHome();
        root.UpdateLayout();
        var scrollBar = Descendants(scroller).OfType<System.Windows.Controls.Primitives.ScrollBar>().First(bar => bar.Orientation == Orientation.Vertical);
        var track = (System.Windows.Controls.Primitives.Track)scrollBar.Template.FindName("PART_Track", scrollBar);
        track.Thumb.ApplyTemplate();
        var thumb = (Border)track.Thumb.Template.FindName("ThumbBorder", track.Thumb);
        Require(thumb?.Background is SolidColorBrush brush && brush.Color == (Color)ColorConverter.ConvertFromString("#9B7448"), "Scrollbar uses the gold theme instead of the system template");
        var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(root);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var output = File.Create(Path.Combine(fixtures, $"layout-{size.Width}x{size.Height}.png"));
        encoder.Save(output);
    }

    private static void CheckOrnamentHitBox(MainWindow window, FrameworkElement root)
    {
        var image = (AlphaHitImage)window.FindName("OrnamentImage");
        var center = new Point(image.ActualWidth / 2, image.ActualHeight / 2);
        var corner = new Point(image.ActualWidth * 0.05, image.ActualHeight * 0.05);
        var edge = new Point(image.ActualWidth * 0.1, image.ActualHeight * 0.5);
        Require(image.ContainsVisiblePoint(center), "Visible ornament center is clickable");
        Require(!image.ContainsVisiblePoint(corner) && !image.ContainsVisiblePoint(edge), "Transparent ornament margins are not clickable");
        var centerHit = VisualTreeHelper.HitTest(root, image.TransformToAncestor(root).Transform(center));
        var cornerHit = VisualTreeHelper.HitTest(root, image.TransformToAncestor(root).Transform(corner));
        Require(ReferenceEquals(centerHit?.VisualHit, image) && !ReferenceEquals(cornerHit?.VisualHit, image),
            "WPF hit testing follows the PNG alpha mask");
        var scale = (ScaleTransform)image.RenderTransform;
        scale.ScaleX = scale.ScaleY = 1.04;
        var scaledCornerHit = VisualTreeHelper.HitTest(root, image.TransformToAncestor(root).Transform(corner));
        Require(!ReferenceEquals(scaledCornerHit?.VisualHit, image), "Hover scaling keeps the transparent margin inactive");
        scale.ScaleX = scale.ScaleY = 1;
    }

    private static void CheckEngineConfiguration()
    {
        var profile = SubscriptionParser.Parse(Config)[0];
        var request = new EngineRequest { Profile = profile, ProbePort = 49152 };
        var config = System.Text.Json.Nodes.JsonNode.Parse(XrayConfiguration.Build(request))!;
        Require(config["inbounds"]!.AsArray().Any(i => i?["protocol"]?.ToString() == "tun"), "Native Xray TUN included");
        Require(config["outbounds"]!.AsArray().Count == 1 && config["outbounds"]![0]!["tag"]!.ToString() == "proxy", "All application traffic uses the selected proxy");
        Require(config["outbounds"]![0]!["streamSettings"]!["grpcSettings"]!["serviceName"]!.ToString() == "test-service", "gRPC service preserved");
        profile.Configuration = Config.Replace("\"remarks\":", "\"env\":{\"UNTRUSTED\":\"value\"},\"lua\":\"untrusted-script\",\"remarks\":")
            .Replace("\"serverName\":\"example.test\"", "\"masterKeyLog\":\"untrusted-path\",\"serverName\":\"example.test\"");
        var clean = XrayConfiguration.Build(request);
        Require(!clean.Contains("UNTRUSTED") && !clean.Contains("untrusted-script") && !clean.Contains("untrusted-path"), "Untrusted scripts, environment changes and file destinations stripped from engine configuration");
        request.EnableTun = false;
        Require(!XrayConfiguration.Build(request).Contains("autoSystemRoutingTable"), "Proxy verification does not change system routes");
        request.Mtu = 999;
        Reject(() => XrayConfiguration.Build(request), "Invalid MTU rejected before elevation");
        var vless = SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=reality&sni=example.test&pbk=TEST&sid=abcd&type=grpc&serviceName=demo#Demo")[0];
        Require(XrayConfiguration.Build(new EngineRequest { Profile = vless, ProbePort = 49152 }).Contains("demo"), "VLESS share link becomes a usable engine configuration");
        var batch = new EngineRequest { EnableTun = false, Probes = new()
        {
            new EngineRequest { Profile = vless, EnableTun = false, ProbePort = 49152 },
            new EngineRequest { Profile = vless, EnableTun = false, ProbePort = 49153 }
        } };
        var latencyConfig = System.Text.Json.Nodes.JsonNode.Parse(XrayConfiguration.Build(batch))!;
        Require(!latencyConfig.ToJsonString().Contains("autoSystemRoutingTable") && latencyConfig["inbounds"]!.AsArray().Count == 2, "Background latency checks do not create a TUN or system routes");
        Require(latencyConfig["routing"]!["rules"]![1]!["inboundTag"]![0]!.ToString() == latencyConfig["outbounds"]![1]!["tag"]!.ToString(), "Each latency probe routes through its own server");
        batch.EnableTun = true;
        Reject(() => XrayConfiguration.Build(batch), "Latency batch cannot enable TUN");
    }

    private static void CheckRoutingAndTraffic()
    {
        var settings = new AppSettings { SplitTunnelEnabled = true, SplitApplications = new() { "chrome" },
            SplitDomains = new() { "example.org" }, SplitNetworks = new() { "192.0.2.0/24" } };
        var request = new EngineRequest { Profile = SubscriptionParser.Parse(Config)[0], ProbePort = 49152, Routing = settings };
        var config = System.Text.Json.Nodes.JsonNode.Parse(XrayConfiguration.Build(request))!;
        var rules = config["routing"]!["rules"]!.AsArray();
        Require(rules[0]!["domain"]![0]!.ToString() == "full:metrics.vpn4ik.invalid" &&
            rules[0]!["inboundTag"]![0]!.ToString() == "vpn4ik-check" && config["metrics"]!["listen"] == null,
            "Statistics are accessible through authenticated control SOCKS only, without a new public listener");
        Require(rules[1]!["outboundTag"]!.ToString() == "proxy", "Connection verification always uses proxy before split rules");
        Require(rules.Any(rule => rule?["process"]?[0]?.ToString() == "chrome" && rule["outboundTag"]!.ToString() == "direct"), "Process bypass rule targets direct");
        Require(rules.Any(rule => rule?["domain"]?[0]?.ToString() == "domain:example.org" && rule["outboundTag"]!.ToString() == "direct"), "Domain bypass includes subdomains");
        Require(config["inbounds"]![1]!["sniffing"]!["routeOnly"]!.GetValue<bool>(), "Domain routing sniffs without changing the connection destination");
        settings.SplitTunnelMode = "Include";
        config = System.Text.Json.Nodes.JsonNode.Parse(XrayConfiguration.Build(request))!;
        rules = config["routing"]!["rules"]!.AsArray();
        Require(rules[^1]!["outboundTag"]!.ToString() == "direct" && rules[2]!["outboundTag"]!.ToString() == "proxy", "Include mode proxies matches and sends the rest direct");
        settings.BypassLocalNetwork = true;
        config = System.Text.Json.Nodes.JsonNode.Parse(XrayConfiguration.Build(request))!;
        Require(config["routing"]!["rules"]![2]!["ip"]!.AsArray().Any(ip => ip!.ToString() == "fc00::/7"), "Local bypass covers both IP versions");
        Require(RoutingSettings.Parse("chrome.exe\nC:\\Program Files\\App\\App.exe", "process").SequenceEqual(new[] { "chrome", "C:/Program Files/App/App.exe" }), "Application names and paths normalize for native routing");
        Require(RoutingSettings.Parse("*.Example.org\nexample.org", "domain").SequenceEqual(new[] { "example.org" }), "Domain rules normalize and deduplicate");
        Reject(() => RoutingSettings.Parse("https://example.org/path", "domain"), "URLs cannot silently become wrong domain rules");
        Reject(() => RoutingSettings.Parse("192.0.2.0/99", "ip"), "Invalid CIDR rejected");
        Reject(() => RoutingSettings.Dns("not-a-dns"), "Invalid DNS rejected");
        Reject(() => RoutingSettings.Validate(new AppSettings { SplitTunnelEnabled = true, SplitTunnelMode = "Include" }), "Empty include rules cannot silently bypass everything");
        var copy = settings.Copy(); copy.SplitApplications.Clear();
        Require(settings.SplitApplications.Count == 1, "Editing routing drafts does not mutate live connection settings");
        var meter = new TrafficMeter();
        Require(meter.Sample(new(1_000_000, 2_000_000), 100).DownloadBytesPerSecond == 0, "First sample establishes a baseline without a speed spike");
        var sample = meter.Sample(new(1_125_000, 2_250_000), 101);
        Require(sample.Upload == 125_000 && sample.Download == 250_000 && sample.UploadBytesPerSecond == 125_000 && sample.DownloadBytesPerSecond == 250_000, "Traffic directions and session totals use actual counter deltas");
        sample = meter.Sample(new(1_375_000, 2_750_000), 103);
        Require(sample.UploadBytesPerSecond == 125_000 && sample.DownloadBytesPerSecond == 250_000, "Speed uses elapsed monotonic time even when a timer tick is delayed");
        sample = meter.Sample(new(0, 0), 104);
        Require(sample.UploadBytesPerSecond == 0 && sample.Download == 750_000, "Counter reset does not create a negative speed or erase session totals");
        Require(TrafficMeter.Speed(125_000, "Mbps").StartsWith(1d.ToString("F2")) && TrafficMeter.Speed(1_000_000, "MB/s").StartsWith(1d.ToString("F2")), "Mbps and MB/s use correct bit and byte conversion");
        var counters = TrafficMeter.Parse("{\"stats\":{\"outbound\":{\"proxy\":{\"uplink\":5000000000,\"downlink\":7000000000},\"direct\":{\"downlink\":9999999999}}}}");
        Require(counters.Upload == 5_000_000_000 && counters.Download == 7_000_000_000, "64-bit VPN counters exclude direct split traffic");
        meter.Reset(); Require(meter.Sample(new(123, 456), 200).Upload == 0, "Reconnect resets session totals");
    }

    private static void CheckActivity(string fixtures)
    {
        var directory = Path.Combine(fixtures, "activity-" + Guid.NewGuid().ToString("N"));
        var store = new ActivityStore(directory);
        var record = store.Begin("Test server", "VLESS");
        Require(record.ConnectedAt == null && record.Result == "Подключение", "A connection attempt is not recorded as successful");
        store.Connected(record, "192.0.2.15");
        store.End(record, "Отключено");
        var redactor = new SecretRedactor("{\"password\":\"private-password\",\"id\":\"00000000-0000-4000-8000-000000000001\"}");
        store.Add("Движок", redactor.Clean("private-password 00000000-0000-4000-8000-000000000001 https://example.test/private-token"));
        Require(!store.Logs[0].Message.Contains("private-password") && !store.Logs[0].Message.Contains("private-token"), "Logs redact credentials and subscription links");
        var reloaded = new ActivityStore(directory);
        Require(reloaded.History.Count == 1 && reloaded.History[0].Result == "Отключено" && reloaded.Logs.Count == 1, "History and logs survive restart");
        var interrupted = store.Begin("Interrupted", "VLESS");
        store.Connected(interrupted, "192.0.2.16");
        var recovered = new ActivityStore(directory).History[0];
        Require(recovered.Result == "Прервано" && recovered.EndedAt == null, "Crash recovery does not invent a disconnection time");
    }

    private static void CheckSections(MainWindow window, string fixtures)
    {
        var root = (FrameworkElement)window.Content;
        void Click(string name) => ((System.Windows.Controls.Primitives.ButtonBase)window.FindName(name)).RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        var toggle = (System.Windows.Controls.Primitives.ToggleButton)window.FindName("MenuToggleButton");
        Require(window.FindName("SidebarOverlay") == null && ((FrameworkElement)window.FindName("NavigationRail")).Visibility == Visibility.Visible, "Navigation is a permanent rail without an overlay");
        toggle.IsChecked = true;
        Click("MenuToggleButton");
        WaitForAnimation(70);
        Require(((ColumnDefinition)window.FindName("NavigationColumn")).Width.Value is > 64 and < 208, "Navigation expands gradually");
        WaitForAnimation(240);
        Require(((ColumnDefinition)window.FindName("NavigationColumn")).Width.Value == 208, "Arrow expands navigation labels");
        CheckLayout(window, fixtures, new Size(760, 540));
        var iconBox = (Border)window.FindName("ImportIconBox");
        var cross = (Grid)iconBox.Child;
        foreach (FrameworkElement stroke in cross.Children)
        {
            var bounds = stroke.TransformToAncestor(iconBox).TransformBounds(new Rect(stroke.RenderSize));
            Require(Math.Abs(bounds.Left + bounds.Width / 2 - iconBox.ActualWidth / 2) <= 1 &&
                Math.Abs(bounds.Top + bounds.Height / 2 - iconBox.ActualHeight / 2) <= 1, "Plus stays centered inside the square");
        }
        foreach (var control in new Control[] { toggle, (Control)window.FindName("ImportMenuButton"), (Control)window.FindName("BestServerButton") })
        {
            Require(control.FocusVisualStyle != null && !control.Template.Triggers.OfType<Trigger>().Any(t => t.Property == UIElement.IsKeyboardFocusedProperty),
                "Mouse focus does not leave a hover highlight; keyboard focus keeps its own visual");
        }
        var ornament = (AlphaHitImage)window.FindName("OrnamentImage");
        Require(ornament.ToolTip == null && !ToolTipService.GetIsEnabled(ornament), "Hovering the ornament cannot show a tooltip");
        foreach (var section in new[] { "import", "settings", "logs", "history" })
        {
            window.ShowSection(section);
            Require(((FrameworkElement)window.FindName("ContentGrid")).Visibility == Visibility.Collapsed && ((FrameworkElement)window.FindName("SectionPanel")).Visibility == Visibility.Visible,
                section + " opens inside the application");
            Require(toggle.IsChecked == true, "Selecting a section preserves expanded navigation");
            foreach (var size in new[] { new Size(1040, 740), new Size(760, 540) })
            {
                root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout();
                var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(root);
                var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                using var output = File.Create(Path.Combine(fixtures, $"{section}-{size.Width}x{size.Height}.png")); encoder.Save(output);
                var back = (FrameworkElement)window.FindName("SectionBackButton");
                Require(back.TransformToAncestor(root).TransformBounds(new Rect(back.RenderSize)).Bottom <= size.Height, "Section back arrow stays visible");
            }
            if (section == "import")
                Require(IsInside((DependencyObject)window.FindName("ImportConfigButton"), (DependencyObject)window.FindName("ImportPage")), "File import moved into the import section");
            if (section == "settings")
            {
                ((TextBox)window.FindName("MtuText")).Text = "1400";
                Require(window.FindName("SaveSettingsButton") == null && AppSettings.LoadFromPath(Path.Combine(testDataDirectory, "settings.json")).TunMtu == 1400, "Valid MTU saves without a save button");
                ((TextBox)window.FindName("MtuText")).Text = "14";
                Require(AppSettings.LoadFromPath(Path.Combine(testDataDirectory, "settings.json")).TunMtu == 1400, "Incomplete MTU does not overwrite the last valid value");
                foreach (var checkbox in Descendants((DependencyObject)window.FindName("SettingsPage")).OfType<CheckBox>())
                {
                    var property = checkbox.GetBindingExpression(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty)!.ParentBinding.Path.Path;
                    var expected = checkbox.IsChecked != true;
                    checkbox.IsChecked = expected;
                    checkbox.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
                    var saved = AppSettings.LoadFromPath(Path.Combine(testDataDirectory, "settings.json"));
                    Require((bool)typeof(AppSettings).GetProperty(property)!.GetValue(saved)! == expected && saved.TunMtu == 1400,
                        property + " immediately persists on toggle, even with an incomplete MTU");
                }
                window.ShowSection("home"); window.ShowSection("settings"); PumpDispatcher();
                Require(((TextBox)window.FindName("MtuText")).Text == "1400", "Reopening settings restores the saved values");
                ((TextBox)window.FindName("SplitApplicationsText")).Text = "chrome.exe";
                ((TextBox)window.FindName("SplitDomainsText")).Text = "example.org";
                ((TextBox)window.FindName("SplitNetworksText")).Text = "192.0.2.0/24";
                Click("IncludeModeButton"); Click("MegabytesUnitButton"); Click("Ping30Button");
                ((TextBox)window.FindName("DnsServersText")).Text = "8.8.8.8\n1.1.1.1";
                var extra = AppSettings.LoadFromPath(Path.Combine(testDataDirectory, "settings.json"));
                Require(extra.SplitTunnelMode == "Include" && extra.SplitApplications.SequenceEqual(new[] { "chrome" }) &&
                    extra.SplitDomains.SequenceEqual(new[] { "example.org" }) && extra.SplitNetworks.SequenceEqual(new[] { "192.0.2.0/24" }), "Routing editors immediately persist usable native rules");
                Require(extra.TrafficUnit == "MB/s" && extra.PingIntervalSeconds == 30 && extra.DnsServers.StartsWith("8.8.8.8"), "Speed units, ping interval and DNS persist immediately");
                ((TextBox)window.FindName("DnsServersText")).Text = "invalid";
                Require(AppSettings.LoadFromPath(Path.Combine(testDataDirectory, "settings.json")).DnsServers == extra.DnsServers, "Invalid DNS editing preserves the previous configuration");
                window.ShowSection("home"); window.ShowSection("settings");
                foreach (var category in new[] { "general", "connection", "routing", "display" })
                {
                    window.ShowSettingsCategory(category);
                    foreach (var size in new[] { new Size(1040, 740), new Size(760, 540) })
                    {
                        root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout();
                        var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(root);
                        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                        using var output = File.Create(Path.Combine(fixtures, $"settings-{category}-{size.Width}x{size.Height}.png")); encoder.Save(output);
                        var status = (FrameworkElement)window.FindName("SettingsStatusText");
                        Require(status.TransformToAncestor(root).TransformBounds(new Rect(status.RenderSize)).Bottom <= size.Height, category + " feedback stays visible at minimum size");
                    }
                }
            }
        }
        Click("SectionBackButton");
        Require(((FrameworkElement)window.FindName("ContentGrid")).Visibility == Visibility.Visible, "Back returns to the server list");
        toggle.IsChecked = false;
        Click("MenuToggleButton");
        WaitForAnimation(70);
        Require(((ColumnDefinition)window.FindName("NavigationColumn")).Width.Value is > 64 and < 208, "Navigation collapses gradually");
        // Reverse an unfinished animation to catch jumps and stale completion callbacks.
        toggle.IsChecked = true; Click("MenuToggleButton"); WaitForAnimation(50);
        toggle.IsChecked = false; Click("MenuToggleButton"); WaitForAnimation(300);
        Require(((ColumnDefinition)window.FindName("NavigationColumn")).Width.Value == 64 && ((FrameworkElement)window.FindName("NavigationRail")).Visibility == Visibility.Visible, "Collapsing labels keeps the navigation icons visible");
        var hoverKey = (DependencyPropertyKey)typeof(UIElement).GetField("IsMouseOverPropertyKey", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!.GetValue(null)!;
        foreach (var (name, surface, expected) in new[] { ("CloseWindowButton", "Surface", "#C42B3A"), ("MinimizeButton", "Surface", "#392E39"), ("ImportSubscriptionButton", "ButtonBorder", "#352933") })
        {
            var button = (Button)window.FindName(name);
            button.ApplyTemplate();
            button.SetValue(hoverKey, true);
            var border = (Border)button.Template.FindName(surface, button);
            Require(border.BorderThickness == new Thickness(0) && ((SolidColorBrush)border.Background).Color == (Color)ColorConverter.ConvertFromString(expected), name + " hover uses only the intended background, without an outline");
            button.SetValue(hoverKey, false);
        }
        var connectionState = typeof(MainWindow).GetField("isConnected", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        connectionState.SetValue(window, true);
        try
        {
            window.UpdatePings().GetAwaiter().GetResult();
            Require(((FrameworkElement)window.FindName("PingWarning")).Visibility == Visibility.Collapsed, "Blocked automatic ping stays quiet");
            window.UpdatePings(true).GetAwaiter().GetResult();
            Require(((FrameworkElement)window.FindName("PingWarning")).Visibility == Visibility.Visible &&
                ((TextBlock)window.FindName("PingWarningText")).Text == PingPolicy.BlockedMessage, "Manual ping while connected shows an in-app warning");
            var size = new Size(760, 540);
            root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout();
            var bitmap = new RenderTargetBitmap(760, 540, 96, 96, PixelFormats.Pbgra32); bitmap.Render(root);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var output = File.Create(Path.Combine(fixtures, "ping-warning-760x540.png")); encoder.Save(output);
        }
        finally { connectionState.SetValue(window, false); }
    }

    private static void CheckPingPolicy()
    {
        var ethernet = System.Net.NetworkInformation.NetworkInterfaceType.Ethernet;
        var up = System.Net.NetworkInformation.OperationalStatus.Up;
        Require(PingPolicy.IsTunAdapter("VPN4ik-TUN", "Virtual adapter", ethernet, up), "Own active TUN blocks ping");
        Require(PingPolicy.IsTunAdapter("happ-xray", "Virtual adapter", ethernet, up), "Happ active TUN blocks ping");
        Require(PingPolicy.IsTunAdapter("Custom name", "Wintun Userspace Tunnel", ethernet, up), "Renamed Wintun adapter blocks ping");
        Require(!PingPolicy.IsTunAdapter("VPN4ik-TUN", "Wintun", ethernet, System.Net.NetworkInformation.OperationalStatus.Down), "Inactive TUN does not block ping");
        Require(!PingPolicy.IsTunAdapter("Radmin VPN", "Famatech Radmin VPN Ethernet Adapter", ethernet, up), "Virtual LAN does not falsely block ping");
        Require(!PingPolicy.IsTunAdapter("Ethernet", "Realtek Ethernet", ethernet, up), "Ordinary Ethernet allows ping");
        var published = false;
        try
        {
            ServerLatency.MeasureAsync(new[] { ("test", new SubscriptionProfile { Address = "must-not-resolve.invalid", Port = 443 }) },
                _ => published = true, CancellationToken.None, tunActive: () => true).GetAwaiter().GetResult();
            throw new Exception("Active TUN must reject ping before DNS and socket creation");
        }
        catch (PingUnavailableException ex)
        { Require(!published && ex.Message == PingPolicy.BlockedMessage, "Active TUN rejects ping before DNS and socket creation with Happ-style warning"); }
    }

    private static void WaitForAnimation(int milliseconds)
    {
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(milliseconds) };
        timer.Tick += (_, _) => { timer.Stop(); frame.Continue = false; };
        timer.Start();
        Dispatcher.PushFrame(frame);
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }

    private static bool IsInside(DependencyObject child, DependencyObject parent)
    {
        for (DependencyObject? current = child; current != null; current = VisualTreeHelper.GetParent(current))
            if (ReferenceEquals(current, parent)) return true;
        return false;
    }

    private static void PumpDispatcher()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }

    private static void Reject(Action action, string description)
    {
        try { action(); }
        catch (InvalidDataException) { passed++; return; }
        throw new Exception(description);
    }

    private sealed class ResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(response(request));
    }

    private static void CheckProfile(string folder, string name, string text, string host)
    {
        var path = Path.Combine(folder, name);
        File.WriteAllText(path, text);
        var server = MainWindow.ReadServer(path);
        Require(server.Address == host && server.TunnelName == Path.GetFileNameWithoutExtension(name), name);
    }

    private static void RejectProfile(string folder, string name, string text)
    {
        var path = Path.Combine(folder, name);
        File.WriteAllText(path, text);
        try { MainWindow.ReadServer(path); }
        catch (InvalidDataException) { passed++; return; }
        throw new Exception("Invalid profile accepted: " + name);
    }

    private static void Require(bool condition, string description)
    {
        if (!condition) throw new Exception(description);
        passed++;
    }
}
