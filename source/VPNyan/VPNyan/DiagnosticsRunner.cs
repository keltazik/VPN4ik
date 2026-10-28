using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Size = System.Windows.Size;

namespace VPNyan;

internal static partial class DiagnosticsRunner
{
    internal static async Task<int> RunConnectionSeriesAsync(string source, string report, int index)
    {
        var result = new Dictionary<string,object?>(); XraySession? session = null; var messages = new List<string>();
        try
        {
            var profiles = SubscriptionStore.Load(source).SelectMany(item => item.Profiles).ToArray();
            if (index < 0 || index >= profiles.Length) throw new InvalidDataException();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
            session = new XraySession(); var redactor = new SecretRedactor(profiles[index].Configuration);
            session.Log += message => { lock(messages) if(messages.Count < 250) messages.Add(redactor.Clean(message)); };
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var ip = await session.StartAsync(profiles[index],1500,timeout.Token,enableTun:false,elevate:false,diagnostics:true);
            result["ConnectMilliseconds"] = clock.ElapsedMilliseconds; result["ExternalIpAvailable"] = ip != "";
            var checks = new List<long>();
            for (var attempt = 0; attempt < 3; attempt++)
            {
                await Task.Delay(1000,timeout.Token); clock.Restart(); await session.ProbeAsync(timeout.Token);
                if (!session.IsRunning) throw new IOException(); checks.Add(clock.ElapsedMilliseconds);
            }
            result["CheckMilliseconds"] = checks; result["Verified"] = true;
        }
        catch(Exception ex) { result["Verified"] = false; result["ErrorType"] = ex.GetType().Name; result["Stage"] = session?.VerificationStage; }
        finally
        {
            if(session != null) { try { await session.DisposeAsync(); result["Disconnected"] = true; } catch { result["Disconnected"] = false; } }
            result["ProfileIndex"] = index; result["Mode"] = "SOCKS physical uplink, no TUN";
            lock(messages) File.WriteAllBytes(report + ".logs.dpapi",System.Security.Cryptography.ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(messages),null,System.Security.Cryptography.DataProtectionScope.CurrentUser));
            File.WriteAllText(report,JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
        }
        return result.TryGetValue("Verified",out var success) && success is true ? 0 : 1;
    }
    internal static async Task<int> RunZapretStatusAsync(string folder, string resultPath)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var result = await new ZapretController(false).RunAsync(new ZapretRequest { Action = "status", Folder = folder }, timeout.Token);
            File.WriteAllText(resultPath, JsonSerializer.Serialize(new { result.Success, Processes = result.State.Processes.Count, Services = result.State.Services.Count, result.State.OtherProcesses, result.State.UnreadableProcesses }));
            return result.Success ? 0 : 1;
        }
        catch (Exception ex) { File.WriteAllText(resultPath, JsonSerializer.Serialize(new { Success = false, ErrorType = ex.GetType().Name })); return 1; }
    }

    // Offline packaging check: no profiles, monitoring, tray, UAC or connection.
    internal static int RunStartup(string resultPath)
    {
        resultPath = Path.GetFullPath(resultPath);
        var result = new Dictionary<string, object?>();
        MainWindow? window = null;
        try
        {
            var directory = Path.Combine(Path.GetDirectoryName(resultPath)!, "startup-" + Guid.NewGuid().ToString("N"));
            window = new MainWindow(false, directory);
            var root = (FrameworkElement)window.Content;
            root.Measure(new Size(1040, 740));
            root.Arrange(new Rect(0, 0, 1040, 740));
            root.UpdateLayout();
            var bitmap = new RenderTargetBitmap(1040, 740, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(root);
            EngineHost.VerifyFiles();
            HiddifyCore.EnsureInstalled(Path.Combine(directory,"Hiddify")); // Keep updater payload immutable for older installers.
            result["Runtime"] = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
            using var process = System.Diagnostics.Process.GetCurrentProcess();
            var modules = process.Modules.Cast<System.Diagnostics.ProcessModule>().ToArray();
            // The win-x64 single-file host can link CoreCLR directly into the EXE.
            result["CoreClrPath"] = modules.FirstOrDefault(m => m.ModuleName.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase))?.FileName
                ?? Environment.ProcessPath;
#pragma warning disable IL3000 // Empty Location intentionally verifies the bundled core library.
            result["CoreLibBundled"] = typeof(object).Assembly.Location.Length == 0;
#pragma warning restore IL3000
            result["WpfNativePath"] = modules.First(m => m.ModuleName.Equals("wpfgfx_cor3.dll", StringComparison.OrdinalIgnoreCase)).FileName;
            result["EngineDirectory"] = EngineHost.EngineDirectory;
            result["Verified"] = true;
        }
        catch (Exception ex) { result["Verified"] = false; result["Error"] = ex.Message; }
        finally
        {
            window?.Close();
            File.WriteAllText(resultPath, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        }
        return result.TryGetValue("Verified", out var verified) && verified is true ? 0 : 1;
    }

    internal static async Task<int> RunLatencyAsync(string source, string resultPath, bool refresh)
    {
        var rows = new Dictionary<string, object>();
        var diagnostics = new List<string>();
        var result = new Dictionary<string, object?>();
        var routeBefore = XraySession.HasTunRoute();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var subscriptions = SubscriptionStore.Load(source);
            if (refresh)
            {
                using var client = new SubscriptionClient();
                for (var i = 0; i < subscriptions.Count; i++)
                    if (subscriptions[i].Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        subscriptions[i] = await client.DownloadAsync(subscriptions[i].Url);
                SubscriptionStore.Save(source, subscriptions);
            }
            var profiles = subscriptions.SelectMany(s => s.Profiles).ToArray();
            var redactors = profiles.Select(p => new SecretRedactor(p.Configuration)).ToArray();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await ServerLatency.MeasureAsync(profiles.Select((p, i) => (i.ToString(), p)).ToArray(), row =>
            {
                lock (rows)
                {
                    var name = profiles[int.Parse(row.Key)].Name;
                    rows[row.Key] = new { Server = name, row.Milliseconds, row.Measured, Kind = row.Kind.ToString(), row.Detail, ArrivedMs = clock.ElapsedMilliseconds };
                }
            }, deadline.Token, text =>
            {
                foreach (var redactor in redactors) text = redactor.Clean(text);
                lock (diagnostics) { if (diagnostics.Count < 20) diagnostics.Add(text); }
            });
        }
        catch (Exception ex) { result["Error"] = SecretRedactor.Generic(ex.Message); }
        result["ElapsedMs"] = clock.ElapsedMilliseconds;
        result["Rows"] = rows.Values.ToArray();
        result["RouteUnchanged"] = routeBefore == XraySession.HasTunRoute();
        result["Diagnostics"] = diagnostics;
        File.WriteAllText(resultPath, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        return rows.Count > 0 && (bool)result["RouteUnchanged"]! ? 0 : 1;
    }

    // Explicit local verification command. It uses isolated settings/history and a protected
    // subscription snapshot; no permanent profile or startup setting is changed.
    internal static async Task<int> RunUiAsync(string source, string resultPath, string nameFilter)
    {
        var result = new Dictionary<string, object?>();
        MainWindow? window = null;
        var directory = Path.Combine(Path.GetDirectoryName(resultPath)!, "ui-check-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(directory);
            var subscriptions = SubscriptionStore.Load(source);
            var profile = subscriptions.SelectMany(s => s.Profiles).First(p => p.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase));
            SubscriptionStore.Save(Path.Combine(directory, "subscriptions.dpapi"), subscriptions);
            var serverKey = "subscription:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(subscriptions.First(s => s.Profiles.Contains(profile)).Url))) + ":" + profile.Id;
            new AppSettings { StoragePath = Path.Combine(directory, "settings.json"), LastServer = serverKey, ShowNotifications = false, MinimizeToTray = false }.SaveOrThrow();
            window = new MainWindow(true, directory);
            window.Show();
            window.Hide();
            await window.Connect();
            var status = ((TextBlock)window.FindName("StatusText")).Text;
            result["Status"] = status;
            result["Verified"] = status == "Подключено" && XraySession.HasTunRoute();
            var root = (FrameworkElement)window.Content;
            root.Measure(new Size(1040, 740)); root.Arrange(new Rect(0, 0, 1040, 740)); root.UpdateLayout();
            var bitmap = new RenderTargetBitmap(1040, 740, 96, 96, PixelFormats.Pbgra32); bitmap.Render(root);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using (var stream = File.Create(Path.ChangeExtension(resultPath, ".png"))) encoder.Save(stream);
            await window.Disconnect();
            result["StatusAfterDisconnect"] = ((TextBlock)window.FindName("StatusText")).Text;
            result["RouteAfterDisconnect"] = XraySession.HasTunRoute();
            var activity = new ActivityStore(directory);
            var record = activity.History.FirstOrDefault();
            result["HistoryRecordedRealSession"] = record?.ConnectedAt != null && record.EndedAt != null && record.Result == "Отключено";
            result["LogsRecorded"] = activity.Logs.Count;
        }
        catch (Exception ex) { result["Verified"] = false; result["Error"] = SecretRedactor.Generic(ex.Message); }
        finally
        {
            if (window != null) { await window.Disconnect(); window.Close(); }
            File.WriteAllText(resultPath, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        }
        return result.TryGetValue("Verified", out var verified) && verified is true ? 0 : 1;
    }
}
