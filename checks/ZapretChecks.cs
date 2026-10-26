using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using VPNyan;

internal static class ZapretChecks
{
    private const string Link = "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#";
    internal static void Run(string fixtures, Action<bool, string> check)
    {
        var saved = SynchronizationContext.Current; SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        try { Profiles(fixtures, check); Lifecycle(fixtures, check); } finally { SynchronizationContext.SetSynchronizationContext(saved); }
    }
    private static string Folder(string fixtures)
    {
        var root = Path.Combine(fixtures, "zapret fixture " + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "bin")); Directory.CreateDirectory(Path.Combine(root, "lists"));
        File.WriteAllText(Path.Combine(root, "service.bat"), "set \"LOCAL_VERSION=1.10.4\"");
        File.WriteAllText(Path.Combine(root, "bin", "winws.exe"), "test fixture only, never executed"); File.WriteAllText(Path.Combine(root, "bin", "WinDivert.dll"), "test");
        File.WriteAllText(Path.Combine(root, "lists", "ipset-all.txt"), "192.0.2.0/24\n");
        File.WriteAllText(Path.Combine(root, "general.bat"), "start \"zapret\" /min \"%BIN%winws.exe\" --wf-tcp=443,%GameFilterTCP% ^\r\n--hostlist=\"%LISTS%list-general-user.txt\" --new --filter-udp=%GameFilterUDP%\r\necho never executed\r\n");
        return root;
    }
    private static void Profiles(string fixtures, Action<bool, string> check)
    {
        var folder = Folder(fixtures); var info = ZapretProfiles.Read(folder);
        check(info.Version == "1.10.4" && info.Profiles.Single().FileName == "general.bat", "Zapret detects Flowseal version and strategies without running BAT scripts");
        var args = ZapretProfiles.BuildArguments(folder, "general.bat");
        check(args.Contains("--wf-tcp=443,12") && args.Contains("--filter-udp=12") && args.Contains("--hostlist=" + Path.Combine(folder, "lists", "list-general-user.txt")), "Strategy parsing preserves quoted paths with spaces and disabled game-filter ranges");
        foreach (var value in new[] { "C:\\folder with spaces\\", "hello\"world", "C:\\Need it\\bin\\winws.exe", "--flag=one two" })
            check(ZapretProfiles.SplitCommandLine("test " + ZapretProfiles.Quote(value))[1] == value, "Windows argument quoting round-trips backslashes, quotes and spaces");
        Reject(() => ZapretProfiles.BuildArguments(folder, "../outside.bat")); check(true, "Strategy paths cannot escape the selected zapret folder");
        File.WriteAllText(Path.Combine(folder, "general unsafe.bat"), "start \"x\" /min \"%BIN%winws.exe\" --wf-save=C:\\outside.txt");
        Reject(() => ZapretProfiles.BuildArguments(folder, "general unsafe.bat")); check(true, "Strategy cannot request arbitrary output files or shell commands");
        File.WriteAllText(Path.Combine(folder, "general fake.bat"), "start \"zapret\" /min \"%BIN%winws.exe\" --dpi-desync-fake-tls=^! --wf-tcp=443\r\n");
        check(ZapretProfiles.BuildArguments(folder, "general fake.bat").Contains("--dpi-desync-fake-tls=!"), "Flowseal's escaped literal exclamation marker is preserved without executing shell substitutions");
        ZapretProfiles.EnsureUserLists(folder);
        check(ZapretProfiles.ReadList(folder, "domains") == "" && File.ReadAllText(Path.Combine(folder, "lists", "list-general-user.txt")).Contains("vpn4ik-empty.invalid"), "Empty user lists use a safe nonmatching sentinel instead of matching all traffic");
        ZapretProfiles.WriteList(folder, "domains", "example.test\n*.example.org");
        check(ZapretProfiles.ReadList(folder, "domains").Contains("example.test"), "Domain lists save to the chosen installation");
        var before = ZapretProfiles.ReadList(folder, "domains");
        Reject(() => ZapretProfiles.WriteList(folder, "domains", "https://example.test/path"));
        check(ZapretProfiles.ReadList(folder, "domains") == before, "Invalid list editing preserves the previous file");
        ZapretProfiles.Configure(folder, "all", "none");
        check(ZapretProfiles.ReadGameMode(folder) == "all" && ZapretProfiles.ReadIpSetMode(folder) == "none", "Game and IPSet modes are stored in Flowseal files");
        check(ZapretProfiles.BuildArguments(folder, "general.bat").Contains("--wf-tcp=443,1024-65535"), "Enabled game filtering expands its ranges correctly");
        ZapretProfiles.Configure(folder, "udp", "loaded");
        check(ZapretProfiles.ReadIpSetMode(folder) == "loaded" && File.ReadAllText(Path.Combine(folder, "lists", "ipset-all.txt")).Contains("192.0.2.0/24"), "Disabling IPSet retains a backup that can be restored");
        var data = Path.Combine(fixtures, "zapret-ui-" + Guid.NewGuid().ToString("N")); var controller = new FakeZapret { Running = false };
        var window = new MainWindow(false, data, zapret: controller);
        Await(window.LoadZapretFolderAsync(folder, true)); window.ShowSection("zapret"); Pump();
        check(((FrameworkElement)window.FindName("ZapretPage")).Visibility == Visibility.Visible && ((System.Windows.Controls.RadioButton)window.FindName("ZapretMenuButton")).IsChecked == true, "Zapret has a dedicated navigation page");
        check(((System.Windows.Controls.CheckBox)window.FindName("DisableZapretOnConnectBox")).IsChecked == false, "Auto-disable zapret is off by default");
        Render(window, Path.Combine(fixtures, "zapret-760x540.png"), new Size(760,540));
        ((System.Windows.Controls.Primitives.ToggleButton)window.FindName("MenuToggleButton")).IsChecked = true;
        typeof(MainWindow).GetMethod("ApplyNavigationLayout", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(window, new object[] { false });
        var animationDeadline = DateTime.UtcNow.AddMilliseconds(250); while (DateTime.UtcNow < animationDeadline) { Pump(); Thread.Sleep(5); }
        Render(window, Path.Combine(fixtures, "zapret-1040x740.png"), new Size(1040,740));
        var checkbox = (System.Windows.Controls.CheckBox)window.FindName("DisableZapretOnConnectBox"); checkbox.IsChecked = true; checkbox.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        check(AppSettings.LoadFromPath(Path.Combine(data, "settings.json")).DisableZapretOnConnect, "Zapret compatibility settings save immediately");
        ((System.Windows.Controls.TextBox)window.FindName("ZapretDomainsText")).Text = "saved.example.test";
        Await(window.SaveZapretListsAsync(false));
        check(ZapretProfiles.ReadList(folder, "domains").Contains("saved.example.test"), "The GUI automatically saves user lists to their selected installation");
        Await(window.ManageZapretAsync("start"));
        check(controller.Running && controller.Actions.Last() == "start", "The GUI start action uses the dedicated zapret controller");
        Await(window.ManageZapretAsync("stop"));
        check(!controller.Running && controller.Actions.Last() == "stop", "The GUI stop action targets the configured installation");
        Await(window.ResetAllAsync());
        var reset = AppSettings.LoadFromPath(Path.Combine(data, "settings.json"));
        check(!reset.DisableZapretOnConnect && reset.ZapretFolder == "" && File.Exists(Path.Combine(folder, "bin", "winws.exe")) && ZapretProfiles.ReadList(folder, "domains").Contains("saved.example.test"), "Full VPN4ik reset clears zapret integration settings and preserves the external installation and lists");
        window.Close(); Pump();
    }
    private static void Lifecycle(string fixtures, Action<bool, string> check)
    {
        foreach (var scenario in new[] { "warning", "pause", "stop-failure", "start-failure", "initially-off", "switch", "manual-stop", "stop-vpn-failure", "no-restore", "foreign" })
        {
            var data = Path.Combine(fixtures, "zapret-vpn-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(data);
            new AppSettings { StoragePath = Path.Combine(data, "settings.json"), ZapretFolder = "C:\\test-zapret", ZapretStrategy = "general.bat", DisableZapretOnConnect = scenario != "warning", RestoreZapretAfterVpn = scenario != "no-restore" }.SaveOrThrow();
            var zapret = new FakeZapret { Running = scenario is not ("initially-off" or "foreign"), OtherProcesses = scenario == "foreign" ? 1 : 0, FailPause = scenario == "stop-failure", HoldPause = scenario == "pause" };
            var first = new FakeSession(zapret) { FailStart = scenario == "start-failure", FailStop = scenario == "stop-vpn-failure" }; var second = new FakeSession(zapret);
            var queue = new Queue<IVpnSession>(new[] { first, second });
            var window = new MainWindow(false, data, () => queue.Dequeue(), zapret);
            window.ApplySubscription(new Subscription { Url = "local:zapret-test", Profiles = SubscriptionParser.Parse(Link + "First\n" + Link + "Second") });
            var connect = window.Connect();
            if (zapret.HoldPause)
            {
                check(first.Starts == 0 && !connect.IsCompleted, "VPN waits for confirmed zapret shutdown"); zapret.PauseGate.TrySetResult();
            }
            Await(connect);
            if (scenario == "warning")
                check(first.IsRunning && zapret.Actions.Count == 0 && zapret.Running && ((TextBlock)window.FindName("PingWarningText")).Text.Contains("Автоотключение"), "Default mode warns at VPN connection without modifying zapret");
            else if (scenario == "stop-failure") check(first.Starts == 0 && zapret.Running, "Failed zapret shutdown prevents starting the VPN");
            else if (scenario == "start-failure") check(!first.IsRunning && zapret.Running && zapret.Actions.SequenceEqual(new[] { "pause", "resume" }), "A failed VPN start restores the zapret state it paused");
            else if (scenario == "initially-off") check(first.IsRunning && zapret.Actions.Count == 0, "An initially stopped zapret is neither started nor paused");
            else if (scenario == "foreign") check(first.Starts == 0 && zapret.Actions.Count == 0, "Automatic shutdown cannot target an instance from another folder");
            else
            {
                check(first.IsRunning && !first.ZapretWasRunningAtStart, "VPN starts only after zapret is stopped");
                if (scenario == "switch")
                {
                    var list = (ListBox)window.FindName("ServerSelect"); Await(window.SwitchToServerAsync(list.Items.Cast<ServerItem>().Single(server => server.Name == "Second")));
                    check(second.IsRunning && zapret.Actions.SequenceEqual(new[] { "pause" }), "Switching VPN servers does not briefly re-enable zapret");
                }
                if (scenario == "manual-stop") Await(window.ManageZapretAsync("stop"));
                if (scenario == "stop-vpn-failure")
                {
                    Await(window.Disconnect()); check(first.IsRunning && !zapret.Running && !zapret.Actions.Contains("resume"), "Zapret is not restored while the VPN failed to stop"); first.FailStop = false;
                }
            }
            Await(window.Disconnect());
            if (scenario is "pause" or "switch" or "stop-vpn-failure") check(zapret.Running && zapret.Actions.Count(action => action == "resume") == 1, "Successful VPN disconnect restores the exact paused zapret once");
            if (scenario is "manual-stop" or "no-restore") check(!zapret.Running && !zapret.Actions.Contains("resume"), "Manual stop and the disabled restore setting prevent unwanted restarts");
            if (scenario == "initially-off") check(!zapret.Running, "VPN disconnect never starts an initially disabled zapret");
            window.Close(); Pump();
        }
    }
    private sealed class FakeZapret : IZapretController
    {
        internal bool Running, FailPause, HoldPause; internal int OtherProcesses; internal List<string> Actions = new(); internal TaskCompletionSource PauseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ZapretState State() => new() { Processes = Running ? new() { new(1234, 1, new[] { "--wf-tcp=443" }) } : new(), OtherProcesses = OtherProcesses };
        public Task<ZapretState> ReadAsync(string folder, CancellationToken token) => Task.FromResult(State());
        public async Task<ZapretResult> RunAsync(ZapretRequest request, CancellationToken token)
        {
            Actions.Add(request.Action);
            if (request.Action == "pause")
            {
                if (HoldPause) await PauseGate.Task;
                if (FailPause) return new() { Success = false, Message = "Отключение zapret не подтверждено.", State = State() };
                Running = false;
                return new() { Success = true, State = State(), Lease = request.CaptureRestore ? new() { Folder = request.Folder, Processes = new() { new[] { "--wf-tcp=443" } } } : null };
            }
            if (request.Action is "start" or "restart" or "resume") Running = true;
            if (request.Action == "stop") Running = false;
            return new() { Success = true, State = State() };
        }
    }
    private sealed class FakeSession(FakeZapret zapret) : IVpnSession
    {
        public bool IsRunning { get; private set; } public event Action<string>? Log { add { } remove { } }
        internal int Starts; internal bool FailStart, FailStop, ZapretWasRunningAtStart;
        public Task<string> StartAsync(SubscriptionProfile profile, int mtu, CancellationToken token, bool enableTun = true, bool elevate = true, bool diagnostics = false, AppSettings? routing = null)
        { Starts++; ZapretWasRunningAtStart = zapret.Running; if (FailStart) throw new IOException("Test failure"); IsRunning = true; return Task.FromResult("192.0.2.1"); }
        public Task<string> ProbeAsync(CancellationToken token, bool useProxy = true) => Task.FromResult("192.0.2.1");
        public Task<TrafficCounters> ReadTrafficAsync(CancellationToken token) => Task.FromResult(new TrafficCounters(0,0));
        public ValueTask DisposeAsync() { if (FailStop) throw new IOException("Test stop failure"); IsRunning = false; return ValueTask.CompletedTask; }
    }
    internal static int VerifyFolder(string folder)
    {
        var info = ZapretProfiles.Read(folder);
        foreach (var profile in info.Profiles) _ = ZapretProfiles.BuildArguments(info.Folder, profile.FileName);
        var state = ZapretNative.ReadState(info.Folder);
        Console.WriteLine($"Flowseal {info.Version}: {info.Profiles.Count} strategies parsed; running processes {state.Processes.Count}; services {state.Services.Count}; unreadable processes {state.UnreadableProcesses}. No strategy or driver was started."); return 0;
    }
    internal static async Task VerifyProcessesAsync()
    {
        if (System.Diagnostics.Process.GetProcessesByName("winws").Length > 0) { Console.WriteLine("SKIP: a real zapret process is running; no process was modified."); return; }
        var fixtures = Path.Combine(Environment.CurrentDirectory, ".checks-data");
        var first = Folder(fixtures); var second = Folder(fixtures);
        foreach (var folder in new[] { first, second })
        {
            foreach (var file in Directory.EnumerateFiles(AppContext.BaseDirectory))
            {
                var name = Path.GetFileName(file);
                if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) File.Copy(file, Path.Combine(folder, "bin", name), true);
            }
            File.Copy(Environment.ProcessPath!, Path.Combine(folder, "bin", "winws.exe"), true);
            File.WriteAllText(Path.Combine(folder, "general.bat"), "start \"zapret fixture\" /min \"%BIN%winws.exe\" --wf-tcp=443 --vpn4ik-zapret-test-fixture\r\n");
        }
        System.Diagnostics.Process? foreign = null;
        try
        {
            var start = await ZapretNative.ExecuteAsync(new() { Action = "start", Folder = first, Strategy = "general.bat" });
            if (!start.Success || start.State.Processes.Count != 1) throw new Exception("Native fixture start failed: " + start.Message);
            var pause = await ZapretNative.ExecuteAsync(new() { Action = "pause", Folder = first, CaptureRestore = true });
            if (!pause.Success || pause.State.Running || pause.Lease?.Processes.Count != 1) throw new Exception("Native fixture pause did not capture its command line: " + pause.Message);
            var resume = await ZapretNative.ExecuteAsync(new() { Action = "resume", Folder = first, Lease = pause.Lease });
            if (!resume.Success || resume.State.Processes.Count != 1) throw new Exception("Native fixture restore failed: " + resume.Message);
            var other = new System.Diagnostics.ProcessStartInfo(Path.Combine(second, "bin", "winws.exe")) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.Combine(second, "bin") };
            other.ArgumentList.Add("--wf-tcp=443"); other.ArgumentList.Add("--vpn4ik-zapret-test-fixture"); foreign = System.Diagnostics.Process.Start(other) ?? throw new Exception("Fixture failed");
            await Task.Delay(500);
            var stop = await ZapretNative.ExecuteAsync(new() { Action = "stop", Folder = first });
            if (!stop.Success || stop.State.Running || foreign.HasExited) throw new Exception("Scoped fixture stop changed another installation");
            var blocked = await ZapretNative.ExecuteAsync(new() { Action = "start", Folder = first, Strategy = "general.bat" });
            if (blocked.Success || foreign.HasExited) throw new Exception("Another running installation did not prevent a duplicate start");
            Console.WriteLine("PASS: native process start, command-line capture, pause/restore, scoped shutdown and protection of another installation. Test stubs only; no WinDivert or VPN.");
        }
        finally
        {
            await ZapretNative.ExecuteAsync(new() { Action = "stop", Folder = first });
            await ZapretNative.ExecuteAsync(new() { Action = "stop", Folder = second });
            if (foreign != null) { if (!foreign.HasExited) foreign.Kill(); foreign.Dispose(); }
        }
    }
    private static void Reject(Action action) { try { action(); } catch (InvalidDataException) { return; } throw new Exception("Unsafe zapret input accepted"); }
    private static void Await(Task task) { var timeout = DateTime.UtcNow.AddSeconds(20); while (!task.IsCompleted) { if (DateTime.UtcNow > timeout) throw new TimeoutException("Zapret test timed out"); Pump(); Thread.Sleep(5); } task.GetAwaiter().GetResult(); }
    private static void Pump() { var frame = new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false)); Dispatcher.PushFrame(frame); }
    private static void Render(MainWindow window, string path, Size size)
    {
        var root = (FrameworkElement)window.Content; root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout();
        var bitmap = new RenderTargetBitmap((int)size.Width,(int)size.Height,96,96,PixelFormats.Pbgra32); bitmap.Render(root);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap)); using var output = File.Create(path); encoder.Save(output);
    }
}
