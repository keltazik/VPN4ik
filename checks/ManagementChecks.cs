using System.Collections.ObjectModel;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using VPNyan;

internal static class ManagementChecks
{
    private const string Link = "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls&sni=example.test#";

    internal static void Run(string fixtures, Action<bool, string> check)
    {
        var context = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        try { CheckData(fixtures, check); CheckSwitching(fixtures, check); }
        finally { SynchronizationContext.SetSynchronizationContext(context); }
    }

    private static void CheckData(string fixtures, Action<bool, string> check)
    {
        var directory = Path.Combine(fixtures, "management-" + Guid.NewGuid().ToString("N"));
        var window = new MainWindow(false, directory);
        var list = (ListBox)window.FindName("ServerSelect");
        var sources = (ItemsControl)window.FindName("ImportedSourcesList");
        var source = new Subscription { Url = "https://example.test/private-source-token", Profiles = SubscriptionParser.Parse(Link + "Alpha\n" + Link + "Bravo") };
        window.ApplySubscription(source);
        window.ApplySubscription(new Subscription { Url = "local:test", DisplayName = "friends.json", Profiles = SubscriptionParser.Parse(Link + "Charlie") });
        var managed = Path.Combine(directory, "family.conf");
        File.WriteAllText(managed, "[Peer]\nEndpoint=192.0.2.1:51820");
        var rows = (ObservableCollection<ServerItem>)list.ItemsSource;
        rows.Add(MainWindow.ReadServer(managed));
        window.ShowSection("import");
        check(sources.Items.Count == 3 && sources.Items.Cast<ImportedSourceItem>().Any(s => s.Name == "friends.json"), "Import page lists subscriptions, Xray files and WireGuard files");
        check(sources.Items.Cast<ImportedSourceItem>().All(s => !s.Name.Contains("private-source-token")), "Source list does not expose subscription access tokens");
        var alpha = rows.First(s => s.Name == "Alpha");
        Await(window.DeleteServerAsync(alpha));
        check(rows.Count == 3 && !rows.Any(s => s.Name == "Alpha"), "Deleting one server preserves the other sources");
        window.ApplySubscription(source);
        check(!rows.Any(s => s.Name == "Alpha"), "Refreshing an unchanged subscription preserves explicit server deletions");
        check(SubscriptionStore.Load(Path.Combine(directory, "subscriptions.dpapi")).First(s => s.Url == source.Url).DeletedProfileIds.Contains(alpha.ProfileId), "Deleted server IDs persist in the protected store");
        var bravo = rows.First(s => s.Name == "Bravo");
        var before = File.ReadAllBytes(Path.Combine(directory, "subscriptions.dpapi"));
        try { Await(window.EditServerAsync(bravo, "<html>invalid</html>")); throw new Exception("Invalid edit accepted."); }
        catch (InvalidDataException) { }
        check(before.SequenceEqual(File.ReadAllBytes(Path.Combine(directory, "subscriptions.dpapi"))), "Invalid editing leaves the saved subscription unchanged");
        Await(window.EditServerAsync(bravo, Link + "Delta"));
        check(rows.Any(s => s.Name == "Delta") && !rows.Any(s => s.Name == "Bravo"), "Editing replaces the selected profile and its saved identity");
        Await(window.EditServerAsync(rows.Single(s => s.Protocol == "WireGuard"), "[Peer]\nEndpoint=198.51.100.1:1234"));
        check(File.ReadAllText(managed).Contains(":1234") && rows.Single(s => s.Protocol == "WireGuard").Port == 1234, "WireGuard edits update the managed file and visible endpoint");
        var outside = Path.Combine(fixtures, "external-original.conf"); File.WriteAllText(outside, "Endpoint=192.0.2.1:443");
        try { Await(window.DeleteSourceAsync(new("outside", "outside", "", false, outside))); throw new Exception("External path deleted."); }
        catch (InvalidDataException) { }
        check(File.Exists(outside), "Deleting a config never deletes the original outside app storage");
        rows.First(s => s.Protocol != "WireGuard").SetLatency(new("fast", 12, "TCP"));
        rows.Last(s => s.Protocol != "WireGuard").SetLatency(new("slow", 90, "TCP"));
        window.ApplyServerSort("ping");
        check(list.Items.Cast<ServerItem>().First().Ping == 12 && list.Items.Cast<ServerItem>().Last().Ping < 0, "Ping sorting puts fast servers first and missing measurements last");
        window.ApplyServerSort("name");
        check(list.Items.Cast<ServerItem>().Select(s => s.DisplayName).SequenceEqual(list.Items.Cast<ServerItem>().Select(s => s.DisplayName).OrderBy(n => n, StringComparer.CurrentCultureIgnoreCase)), "Name sorting is deterministic");
        check(AppSettings.LoadFromPath(Path.Combine(directory, "settings.json")).ServerSort == "name", "Sort mode persists automatically");
        check(window.Icon != null && ((FrameworkElement)window.FindName("OrnamentMotion")).Effect == null, "Window has the app icon and the ornament has no blur effect");
        Click(window, "ResetAllButton");
        check(((FrameworkElement)window.FindName("ActionOverlay")).Visibility == Visibility.Visible && rows.Count > 0, "Full reset requires an in-app confirmation");
        Click(window, "DialogCancel"); Pump();
        check(rows.Count == 3 && File.Exists(managed), "Cancelling full reset preserves data");
        window.ShowSection("import"); Render(window, Path.Combine(fixtures, "sources-management-760x540.png"), new Size(760, 540));
        ((ScrollViewer)window.FindName("ImportPage")).ScrollToEnd(); Pump();
        Render(window, Path.Combine(fixtures, "sources-management-760x540.png"), new Size(760, 540));
        Set(window, "contextServer", rows.First(s => s.Protocol != "WireGuard"));
        Call(window, "PrepareServerMenu");
        var menu = (ContextMenu)Get(window, "ServerContextMenu")!;
        menu.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        menu.Arrange(new Rect(menu.DesiredSize)); menu.UpdateLayout();
        RenderElement(menu, Path.Combine(fixtures, "server-context-menu.png"), menu.RenderSize);
        check(menu.ActualWidth >= 220 && menu.ActualHeight > 200, "Themed server menu lays out all actions and its server heading");
        Call(window, "ContextEdit_Click", window, new RoutedEventArgs());
        Render(window, Path.Combine(fixtures, "server-editor-760x540.png"), new Size(760, 540));
        Click(window, "DialogCancel");
        window.ShowSection("settings"); window.ShowSettingsCategory("routing");
        Click(window, "AddRunningProcessButton");
        PumpUntil(() => ((Button)window.FindName("DialogPrimary")).IsEnabled || ((TextBlock)window.FindName("DialogError")).Text.StartsWith("Не удалось"));
        var processList = (ListBox)window.FindName("ProcessPickerList");
        check(processList.Items.Count > 0, "Process picker enumerates running processes without elevation");
        var choices = (List<ProcessChoice>)processList.ItemsSource;
        check(choices.All(process=>process.Icon.IsFrozen)&&choices.Any(process=>process.Icon is BitmapSource),"Process picker provides frozen application icons from executable files for cross-thread UI use");
        check(ReferenceEquals(ProcessIcons.Load(""),ProcessIcons.Fallback)&&ProcessIcons.Fallback.IsFrozen,"Inaccessible process paths use a frozen themed fallback icon");
        choices[0].Selected = true;
        Render(window, Path.Combine(fixtures, "process-picker-760x540.png"), new Size(760, 540));
        var rule = RoutingSettings.Parse(choices[0].Rule, "process").Single();
        Click(window, "DialogPrimary");
        check(AppSettings.LoadFromPath(Path.Combine(directory, "settings.json")).SplitApplications.Contains(rule), "Picking a running process immediately saves the split-tunnel rule");
        window.ShowSection("import");
        Await(window.DeleteSourceAsync(sources.Items.Cast<ImportedSourceItem>().First(s => s.Key == source.Url)));
        check(rows.Count == 2 && !SubscriptionStore.Load(Path.Combine(directory, "subscriptions.dpapi")).Any(s => s.Url == source.Url), "Deleting a subscription removes its access URL and all its servers");
        Await(window.DeleteSourceAsync(sources.Items.Cast<ImportedSourceItem>().First(s => s.ConfigPath == managed)));
        check(!File.Exists(managed) && File.Exists(outside), "Deleting WireGuard removes only the managed copy");
        Await(window.ResetAllAsync());
        check(rows.Count == 0 && sources.Items.Count == 0 && SubscriptionStore.Load(Path.Combine(directory, "subscriptions.dpapi")).Count == 0, "Full reset clears stored subscriptions and visible sources");
        check(((ListBox)window.FindName("LogsList")).Items.Count == 0 && ((ListBox)window.FindName("HistoryList")).Items.Count == 0 && !File.Exists(Path.Combine(directory, "activity.dpapi")), "Full reset clears logs and history on disk and in memory");
        var defaults = AppSettings.LoadFromPath(Path.Combine(directory, "settings.json"));
        check(!defaults.AutoConnect && !defaults.StartWithWindows && !defaults.SplitTunnelEnabled && defaults.SplitApplications.Count == 0 && defaults.ServerSort == "original", "Reset restores defaults and removes split-tunnel rules");
        window.Close(); Pump();
    }

    private static void CheckSwitching(string fixtures, Action<bool, string> check)
    {
        foreach (var failure in new[] { "none", "stop", "start" })
        {
            var first = new FakeSession { HoldStop = failure == "none", FailStop = failure == "stop" };
            var second = new FakeSession { FailStart = failure == "start" };
            var queue = new Queue<IVpnSession>(new[] { first, second });
            var window = new MainWindow(false, Path.Combine(fixtures, "switch-" + Guid.NewGuid().ToString("N")), () => queue.Dequeue());
            window.ApplySubscription(new Subscription { Url = "local:switch", Profiles = SubscriptionParser.Parse(Link + "First\n" + Link + "Second") });
            var list = (ListBox)window.FindName("ServerSelect"); var rows = (ObservableCollection<ServerItem>)list.ItemsSource;
            Await(window.Connect());
            check(first.IsRunning && list.IsEnabled, "Server selection remains available while connected");
            ((TextBox)window.FindName("ServerSearchText")).Text = "NO-MATCH";
            ((TextBox)window.FindName("ServerSearchText")).Clear();
            check(first.IsRunning && second.Starts == 0, "Filtering does not accidentally switch an active VPN");
            window.ApplyServerSort("name");
            check(first.IsRunning && second.Starts == 0, "Sorting does not accidentally switch an active VPN");
            var switching = window.SwitchToServerAsync(rows.Single(s => s.Name == "Second"));
            if (first.HoldStop)
            {
                check(!switching.IsCompleted && first.StopEntered && second.Starts == 0 && !list.IsEnabled, "Switch waits for confirmed old-tunnel shutdown");
                Await(window.Connect()); check(second.Starts == 0, "A duplicate connect cannot race a pending switch");
                first.StopGate.TrySetResult();
            }
            Await(switching);
            if (failure == "stop")
            {
                check(first.IsRunning && second.Starts == 0 && ((ServerItem)list.SelectedItem).Name == "First", "Failed shutdown keeps the old connection and restores its selection");
                first.FailStop = false;
            }
            else if (failure == "start") check(!first.IsRunning && !second.IsRunning && Get(window, "activeServer") == null, "Failed new connection cannot leave a phantom active tunnel");
            else
            {
                check(!first.IsRunning && second.IsRunning && second.Starts == 1 && ((ServerItem)list.SelectedItem).Name == "Second", "Exactly one new session starts after the previous tunnel stops");
                Await(window.DeleteServerAsync(rows.Single(s => s.Name == "First")));
                check(second.IsRunning, "Deleting another server does not disconnect the active one");
                second.Emit("queued engine log"); Await(window.ResetAllAsync()); Pump();
                second.Emit("late engine log"); Pump();
                check(!second.IsRunning && ((ListBox)window.FindName("LogsList")).Items.Count == 0, "Reset stops the owned session and ignores late log callbacks");
            }
            first.HoldStop = false; Await(window.Disconnect()); window.Close(); Pump();
        }
    }

    private sealed class FakeSession : IVpnSession
    {
        public bool IsRunning { get; private set; }
        public int Starts;
        public bool HoldStop, FailStop, FailStart, StopEntered;
        public TaskCompletionSource StopGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public event Action<string>? Log;
        public void Emit(string text) => Log?.Invoke(text);
        public Task<string> StartAsync(SubscriptionProfile profile, int mtu, CancellationToken cancellationToken, bool enableTun = true, bool elevate = true, bool diagnostics = false, AppSettings? routing = null)
        { Starts++; if (FailStart) throw new IOException("Test connection failure"); IsRunning = true; return Task.FromResult("192.0.2.1"); }
        public Task<string> ProbeAsync(CancellationToken cancellationToken, bool useProxy = true) => Task.FromResult("192.0.2.1");
        public Task<TrafficCounters> ReadTrafficAsync(CancellationToken cancellationToken) => Task.FromResult(new TrafficCounters(0, 0));
        public async ValueTask DisposeAsync() { StopEntered = true; if (FailStop) throw new IOException("Test shutdown failure"); if (HoldStop) await StopGate.Task; IsRunning = false; }
    }

    private static void Click(MainWindow window, string name) => ((System.Windows.Controls.Primitives.ButtonBase)window.FindName(name)).RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
    private static object? Get(object instance, string name) => instance.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(instance);
    private static void Set(object instance, string name, object value) => instance.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(instance, value);
    private static void Call(object instance, string name, params object[] args) => instance.GetType().GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(instance, args);
    private static void Await(Task task) { PumpUntil(() => task.IsCompleted); task.GetAwaiter().GetResult(); }
    private static void PumpUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!condition()) { if (DateTime.UtcNow > deadline) throw new TimeoutException("Test action did not finish."); Pump(); Thread.Sleep(5); }
    }
    private static void Pump() { var frame = new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false)); Dispatcher.PushFrame(frame); }
    private static void Render(MainWindow window, string path, Size size)
    {
        var root = (FrameworkElement)window.Content; root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout();
        RenderElement(root, path, size);
    }
    private static void RenderElement(Visual visual, string path, Size size)
    {
        var bitmap = new RenderTargetBitmap((int)Math.Ceiling(size.Width), (int)Math.Ceiling(size.Height), 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap)); using var output = File.Create(path); encoder.Save(output);
    }
}
