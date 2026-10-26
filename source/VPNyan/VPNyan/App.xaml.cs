using System.IO;
using System.Text.Json;
using System.Windows;

namespace VPNyan;

public partial class App : System.Windows.Application
{
    private Mutex? instanceMutex;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args is ["--verify-zapret-status", var statusFolder, var statusResult])
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await DiagnosticsRunner.RunZapretStatusAsync(statusFolder, statusResult));
            return;
        }
        if (e.Args is ["--zapret-host", var zapretPipe, var zapretParent] && int.TryParse(zapretParent, out var zapretParentId))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await ZapretController.RunHostAsync(zapretPipe, zapretParentId));
            return;
        }
        if (e.Args is ["--apply-update", var updateJob])
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await UpdateInstaller.RunAsync(updateJob));
            return;
        }
        if (e.Args is ["--verify-startup", var startupResult])
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(DiagnosticsRunner.RunStartup(startupResult));
            return;
        }
        if (e.Args is ["--engine-host", var pipe, var parent] && int.TryParse(parent, out var parentId))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await EngineHost.RunAsync(pipe, parentId));
            return;
        }
        if (e.Args.Length >= 3 && e.Args[0] == "--verify-latency")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await DiagnosticsRunner.RunLatencyAsync(e.Args[1], e.Args[2], e.Args.Contains("--refresh")));
            return;
        }
        if (e.Args.Length >= 3 && e.Args[0] == "--verify-ui")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await DiagnosticsRunner.RunUiAsync(e.Args[1], e.Args[2], e.Args.Length > 3 ? e.Args[3] : ""));
            return;
        }
        if (e.Args.Length >= 3 && e.Args[0] == "--verify-profile")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var result = new Dictionary<string, object?>();
            XraySession? session = null;
            var diagnostics = new List<string>();
            try
            {
                var profile = SubscriptionStore.Load(e.Args[1]).SelectMany(s => s.Profiles)
                    .First(p => p.Name.Contains(e.Args.Length > 4 ? e.Args[4] : "", StringComparison.OrdinalIgnoreCase));
                var tun = e.Args.Contains("--tun");
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
                session = new XraySession();
                var redactor = new SecretRedactor(profile.Configuration);
                session.Log += line => { lock (diagnostics) { if (diagnostics.Count < 80) diagnostics.Add(redactor.Clean(line)); } };
                var ip = await session.StartAsync(profile, 1500, timeout.Token, tun, tun, true);
                result["Verified"] = session.IsRunning;
                result["Mode"] = tun ? "TUN" : "SOCKS";
                result["Profile"] = profile.Name;
                result["ExternalIp"] = ip;
                result["TunRouteDuringConnection"] = XraySession.HasTunRoute();
            }
            catch (Exception ex) { result["Verified"] = false; result["Error"] = ex.Message; result["Stage"] = session?.VerificationStage; result["RoutesOnFailure"] = XraySession.RouteDiagnostic(); }
            finally
            {
                if (session != null)
                {
                    try { await session.DisposeAsync(); result["Disconnected"] = true; }
                    catch (Exception ex) { result["Disconnected"] = false; result["DisconnectError"] = ex.Message; }
                }
                result["TunRouteAfterDisconnect"] = XraySession.HasTunRoute();
                result["Diagnostics"] = diagnostics;
                File.WriteAllText(e.Args[2], JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            }
            Shutdown(result.TryGetValue("Verified", out var verified) && verified is true ? 0 : 1);
            return;
        }
        instanceMutex = new Mutex(true, "Local\\VPN4ik-" + Environment.UserName, out var created);
        if (!created)
        {
            var existing = FindWindow(null, "VPN4ik");
            if (existing != IntPtr.Zero) { ShowWindow(existing, 9); SetForegroundWindow(existing); }
            Shutdown();
            return;
        }
        MainWindow = new MainWindow();
        MainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        instanceMutex?.Dispose();
        base.OnExit(e);
    }
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)] private static extern IntPtr FindWindow(string? className, string title);
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window, int command);
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr window);
}
