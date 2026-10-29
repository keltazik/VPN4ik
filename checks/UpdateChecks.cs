using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using VPNyan;

internal static class UpdateChecks
{
    internal static void Run(string fixtures, Action<bool, string> check)
    {
        check(ReleaseVersion.Parse(ApplicationUpdates.CurrentVersion)?.Preview.Length==0,"The prepared release uses a stable application version without beta identifiers");
        using (var self = System.Diagnostics.Process.GetCurrentProcess())
        {
            Reject(() => UpdateInstaller.WaitForParentAsync(self.Id, 0, TimeSpan.FromMilliseconds(50)).GetAwaiter().GetResult());
            try { UpdateInstaller.WaitForParentAsync(self.Id, self.StartTime.ToUniversalTime().Ticks, TimeSpan.FromMilliseconds(50)).GetAwaiter().GetResult(); throw new Exception("Installer did not wait for parent"); }
            catch (OperationCanceledException) { }
            check(true, "Installer waits for the specific parent process and never kills it on timeout");
        }
        check(ReleaseVersion.Parse("1.0.0-beta.10")!.CompareTo(ReleaseVersion.Parse("1.0.0-beta.9")) > 0, "Update versions compare numeric preview identifiers correctly");
        check(ReleaseVersion.Parse("1.0.0")!.CompareTo(ReleaseVersion.Parse("1.0.0-beta.999")) > 0, "Stable release follows preview releases");
        check(ReleaseVersion.Parse("v1.0.0+build")!.CompareTo(ReleaseVersion.Parse("1.0.0")) == 0, "Version metadata never triggers a false update");
        check(ReleaseVersion.Parse("1.0.0-beta.01") == null && ReleaseVersion.Parse("1.0.0/../../x") == null, "Invalid versions cannot form release paths");
        var selected = Select(new[] { Release("1.0.0-beta.8"), Release("1.0.0-beta.10"), Release("1.0.0-beta.9"), Release("9.0.0", draft: true) });
        check(selected?.Version == "1.0.0-beta.10" && selected.CanInstall, "Release detection includes previews, ignores drafts and chooses highest version");
        check(Select(new[] { Release("1.0.0-beta.3") }) == null, "Older or current versions never show an update");
        check(Select(new[] { Release("1.0.0-beta.5", digest: "") }) is { CanInstall: false }, "Missing SHA-256 offers a release page instead of automatic installation");
        check(Select(new[] { Release("1.0.0-beta.5", download: "https://evil.example/app.exe") }) is { CanInstall: false }, "External release asset cannot be installed");
        check(!ApplicationUpdates.TrustedDownloadHost(new Uri("http://github.com/file")) && !ApplicationUpdates.TrustedDownloadHost(new Uri("https://github.com.evil.example/file")) && !ApplicationUpdates.TrustedDownloadHost(new Uri("https://github.com:444/file")), "Download redirects require HTTPS and an exact GitHub asset host");
        using (var client = new ApplicationUpdates(new ResponseHandler(JsonSerializer.SerializeToUtf8Bytes(new[] { Release("9.0.0") }))))
            check(client.CheckAsync(CancellationToken.None).GetAwaiter().GetResult()?.Version == "9.0.0", "Update checking uses anonymous GitHub release metadata without credentials");

        var root = Path.Combine(fixtures, "updates-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        var files = FixtureFiles();
        var archive = Archive(root, "valid.zip", files);
        var payload = Path.Combine(root, "payload");
        ApplicationUpdates.ExtractVerified(archive, payload, "1.0.0-beta.5", ApplicationUpdates.HashFile(archive));
        check(File.ReadAllText(Path.Combine(payload, "VPNyan.exe")) == "new app", "Verified archive extracts the application and engine into staging");
        Reject(() => ApplicationUpdates.ExtractVerified(archive, Path.Combine(root, "wrong-sha"), "1.0.0-beta.5", new string('0', 64)));
        check(!Directory.Exists(Path.Combine(root, "wrong-sha")), "Wrong archive SHA is rejected before extracting executable files");
        Reject(() => ApplicationUpdates.ExtractVerified(archive, Path.Combine(root, "wrong-version"), "1.0.0-beta.6", ApplicationUpdates.HashFile(archive)));
        check(true, "Archive manifest must match the announced release version");
        foreach (var bad in new[] { "VPN4ik/../../escape.exe", "VPN4ik/Engine/../VPNyan.exe", "VPN4ik/settings.json", "VPN4ik/Engine/xray.exe:stream", "VPN4ik/licenses/foo.txt/../../outside.txt" })
        {
            var malicious = Archive(root, Guid.NewGuid().ToString("N") + ".zip", files.Concat(new[] { new KeyValuePair<string, byte[]>(bad, new byte[] { 0 }) }));
            Reject(() => ApplicationUpdates.ExtractVerified(malicious, Path.Combine(root, Guid.NewGuid().ToString("N")), "1.0.0-beta.5", ApplicationUpdates.HashFile(malicious)));
            check(true, "Archive rejects traversal, alternate streams and user-data replacement: " + bad);
        }
        var duplicate = Archive(root, "duplicate.zip", files.Concat(new[] { new KeyValuePair<string, byte[]>("VPN4ik/vpnyan.exe", new byte[] { 1 }) }));
        Reject(() => ApplicationUpdates.ExtractVerified(duplicate, Path.Combine(root, "duplicate"), "1.0.0-beta.5", ApplicationUpdates.HashFile(duplicate)));
        check(true, "Windows case-insensitive duplicate filenames are rejected");
        var hashes = Directory.EnumerateFiles(payload, "*", SearchOption.AllDirectories).ToDictionary(path => Path.GetRelativePath(payload, path).Replace('\\', '/'), ApplicationUpdates.HashFile);
        var target = Path.Combine(root, "installed"); Directory.CreateDirectory(Path.Combine(target, "Engine"));
        File.WriteAllText(Path.Combine(target, "VPNyan.exe"), "old app"); File.WriteAllText(Path.Combine(target, "Engine", "xray.exe"), "old engine");
        File.WriteAllText(Path.Combine(target, "settings.json"), "keep settings"); File.WriteAllText(Path.Combine(target, "family.conf"), "keep config");
        var backup = Path.Combine(root, "backup");
        UpdateInstaller.InstallAsync(payload, target, backup, hashes, (_, _) => Task.CompletedTask).GetAwaiter().GetResult();
        check(File.ReadAllText(Path.Combine(target, "VPNyan.exe")) == "new app" && File.ReadAllText(Path.Combine(backup, "VPNyan.exe")) == "old app", "Installer replaces binaries and retains their previous versions");
        check(File.ReadAllText(Path.Combine(target, "settings.json")) == "keep settings" && File.ReadAllText(Path.Combine(target, "family.conf")) == "keep config", "Application updates preserve subscriptions, configs and settings");
        File.WriteAllText(Path.Combine(target, "VPNyan.exe"), "rollback app"); File.Delete(Path.Combine(target, "Engine", "geoip.dat"));
        try { UpdateInstaller.InstallAsync(payload, target, Path.Combine(root, "rollback"), hashes, (_, _) => throw new IOException("Test startup failure")).GetAwaiter().GetResult(); throw new Exception("Failed health check accepted"); }
        catch (IOException) { }
        check(File.ReadAllText(Path.Combine(target, "VPNyan.exe")) == "rollback app" && !File.Exists(Path.Combine(target, "Engine", "geoip.dat")), "Failed startup rolls back replacements and removes newly introduced files");
        check(!Directory.EnumerateFiles(target, "*.vpn4ik-update-*", SearchOption.AllDirectories).Any(), "Success and rollback remove pending replacement files");
        using (var held = new FileStream(Path.Combine(target, "VPNyan.exe"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var releaseLock = Task.Run(async () => { await Task.Delay(150); held.Dispose(); });
            UpdateInstaller.InstallAsync(payload, target, Path.Combine(root, "retry"), hashes, (_, _) => Task.CompletedTask).GetAwaiter().GetResult();
            releaseLock.GetAwaiter().GetResult();
        }
        check(File.ReadAllText(Path.Combine(target, "VPNyan.exe")) == "new app", "Installer tolerates temporary Windows file locks without killing processes");
        File.WriteAllText(Path.Combine(payload, "VPNyan.exe"), "tampered");
        Reject(() => UpdateInstaller.InstallAsync(payload, target, Path.Combine(root, "tampered"), hashes, (_, _) => Task.CompletedTask).GetAwaiter().GetResult());
        check(File.ReadAllText(Path.Combine(target, "VPNyan.exe")) == "new app", "Changed staging content is rejected before replacing installed files");

        var window = new MainWindow(false, Path.Combine(root, "ui"));
        check(((FrameworkElement)window.FindName("UpdateBanner")).Visibility == Visibility.Collapsed, "No fake update banner appears before detecting a new release");
        window.PresentUpdate(selected);
        check(((Button)window.FindName("InstallUpdateButton")).Content.ToString() == "Обновить", "Installable release offers the update button");
        Render(window, Path.Combine(fixtures, "update-banner-760x540.png"), new Size(760, 540));
        ((Button)window.FindName("DismissUpdateButton")).RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        window.PresentUpdate(selected);
        check(((FrameworkElement)window.FindName("UpdateBanner")).Visibility == Visibility.Collapsed, "Dismissal lasts for the current release during this session");
        window.PresentUpdate(Select(new[] { Release("1.0.0-beta.11", digest: "") }));
        check(((Button)window.FindName("InstallUpdateButton")).Content.ToString() == "Открыть релиз", "Unverifiable release offers the browser fallback");
        window.PresentUpdate(null); window.ShowSection("settings");
        ((FrameworkElement)window.Content).UpdateLayout();
        var auto = (CheckBox)window.FindName("UpdateAutoCheckBox");
        auto.GetBindingExpression(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty)!.UpdateTarget();
        auto.SetCurrentValue(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty, false);
        auto.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        var saved = AppSettings.LoadFromPath(Path.Combine(root, "ui", "settings.json"));
        check(!saved.CheckForUpdates && !saved.Copy().CheckForUpdates, "Automatic update checks can be disabled and save immediately");
        window.Close();
    }

    internal static async Task VerifyPortableAsync(string build)
    {
        var root = Path.Combine(Environment.CurrentDirectory, ".checks-data", "portable-update-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "installed"); var payload = Path.Combine(root, "payload");
        Directory.CreateDirectory(target); Directory.CreateDirectory(payload);
        foreach (var file in Directory.EnumerateFiles(build, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(build, file).Replace('\\', '/');
            if (!UpdateInstaller.AllowedFile(relative)) continue;
            foreach (var folder in new[] { payload, target })
            {
                var destination = Path.Combine(folder, relative.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(file, destination);
            }
        }
        var hashes = Directory.EnumerateFiles(payload, "*", SearchOption.AllDirectories).ToDictionary(path => Path.GetRelativePath(payload, path).Replace('\\', '/'), ApplicationUpdates.HashFile);
        var manifest = new { Version = ApplicationUpdates.CurrentVersion, DotNetBundled = true,
            ExecutableSHA256 = hashes["VPNyan.exe"], XraySHA256 = hashes["Engine/xray.exe"] };
        File.WriteAllBytes(Path.Combine(payload, "BUILD-INFO.json"), JsonSerializer.SerializeToUtf8Bytes(manifest));
        hashes["BUILD-INFO.json"] = ApplicationUpdates.HashFile(Path.Combine(payload, "BUILD-INFO.json"));
        // Real release ZIPs have a VPN4ik root directory.
        var wrapped = Path.Combine(root, "release.zip");
        using (var zip = ZipFile.Open(wrapped, ZipArchiveMode.Create))
            foreach (var file in Directory.EnumerateFiles(payload, "*", SearchOption.AllDirectories))
                zip.CreateEntryFromFile(file, "VPN4ik/" + Path.GetRelativePath(payload, file).Replace('\\', '/'), CompressionLevel.Fastest);
        using (var service = new ApplicationUpdates(new DownloadHandler(wrapped)))
        {
            var version = ApplicationUpdates.CurrentVersion;
            var release = new ApplicationRelease(version, new Uri(ApplicationUpdates.ReleasesPage), new Uri($"https://github.com/keltazik/VPN4ik/releases/download/v{version}/VPN4ik-v{version}-windows-x64.zip"), ApplicationUpdates.HashFile(wrapped), new FileInfo(wrapped).Length);
            var prepared = await service.PrepareAsync(release, null, CancellationToken.None);
            if (ApplicationUpdates.HashFile(Path.Combine(prepared, "payload", "VPNyan.exe")) != hashes["VPNyan.exe"]) throw new Exception("Prepared update differs from the portable build");
            Directory.Delete(prepared, true);
        }
        File.WriteAllText(Path.Combine(target, "README.md"), "old marker"); File.WriteAllText(Path.Combine(payload, "README.md"), "new marker");
        hashes["README.md"] = ApplicationUpdates.HashFile(Path.Combine(payload, "README.md"));
        File.WriteAllText(Path.Combine(target, "family.conf"), "isolated test config");
        await UpdateInstaller.InstallAsync(payload, target, Path.Combine(root, "backup"), hashes, UpdateInstaller.VerifyStartupAsync);
        if (File.ReadAllText(Path.Combine(target, "README.md")) != "new marker" || File.ReadAllText(Path.Combine(target, "family.conf")) != "isolated test config") throw new Exception("Portable update failed");
        File.WriteAllText(Path.Combine(target, "README.md"), "rollback marker");
        try
        {
            await UpdateInstaller.InstallAsync(payload, target, Path.Combine(root, "rollback"), hashes, (_, _) => throw new IOException("Simulated startup failure"));
            throw new Exception("Failed update accepted");
        }
        catch (IOException) { }
        if (File.ReadAllText(Path.Combine(target, "README.md")) != "rollback marker") throw new Exception("Portable rollback did not restore the previous file");
        await UpdateInstaller.VerifyStartupAsync(target, CancellationToken.None);
        Console.WriteLine("PASS: portable update download (fake transport), SHA/PE validation, installation, bundled WPF startup, rollback and preserved config (isolated copy; no TUN or user data).");
    }

    private static ApplicationRelease? Select(object[] releases) => ApplicationUpdates.SelectRelease(JsonSerializer.SerializeToUtf8Bytes(releases), "1.0.0-beta.4");
    internal static async Task VerifyPublishedAsync(string installed, string expected, string sha256)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(20), MaxResponseContentBufferSize = 2 * 1024 * 1024 };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("VPN4ik-Release-Checks/1.0");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2026-03-10");
        var json = await client.GetByteArrayAsync("https://api.github.com/repos/keltazik/VPN4ik/releases?per_page=30");
        var release = ApplicationUpdates.SelectRelease(json, installed);
        if (release?.Version != expected || !release.CanInstall || !release.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase))
            throw new Exception("Published update does not match the expected version and archive hash.");
        Console.WriteLine($"Published update OK: {installed} -> {release.Version}; automatic install available; archive SHA-256 matches.");
    }

    private static object Release(string version, bool draft = false, string digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", string? download = null) => new
    {
        tag_name = "v" + version, draft, published_at = "2026-10-27T00:00:00Z",
        assets = new[] { new { name = $"VPN4ik-v{version}-windows-x64.zip", state = "uploaded", size = 1024, digest,
            browser_download_url = download ?? $"https://github.com/keltazik/VPN4ik/releases/download/v{version}/VPN4ik-v{version}-windows-x64.zip" } }
    };
    private static Dictionary<string, byte[]> FixtureFiles()
    {
        var entries = new Dictionary<string, byte[]> { ["VPN4ik/VPNyan.exe"] = Encoding.UTF8.GetBytes("new app"), ["VPN4ik/Engine/xray.exe"] = Encoding.UTF8.GetBytes("new engine"),
            ["VPN4ik/Engine/wintun.dll"] = new byte[] { 1 }, ["VPN4ik/Engine/geoip.dat"] = new byte[] { 2 }, ["VPN4ik/Engine/geosite.dat"] = new byte[] { 3 } };
        entries["VPN4ik/BUILD-INFO.json"] = JsonSerializer.SerializeToUtf8Bytes(new { Version = "1.0.0-beta.5", DotNetBundled = true,
            ExecutableSHA256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(entries["VPN4ik/VPNyan.exe"])), XraySHA256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(entries["VPN4ik/Engine/xray.exe"])) });
        return entries;
    }
    private static string Archive(string root, string name, IEnumerable<KeyValuePair<string, byte[]>> entries)
    {
        var path = Path.Combine(root, name);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (key, bytes) in entries) { using var stream = archive.CreateEntry(key).Open(); stream.Write(bytes); }
        return path;
    }
    private static void Reject(Action action) { try { action(); } catch (InvalidDataException) { return; } throw new Exception("Invalid update accepted"); }
    private sealed class ResponseHandler(byte[] json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host != "api.github.com" || request.Headers.Authorization != null) throw new Exception("Unexpected update request");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(json) });
        }
    }
    private sealed class DownloadHandler(string archive) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(File.OpenRead(archive)) });
    }
    private static void Render(MainWindow window, string path, Size size)
    {
        var root = (FrameworkElement)window.Content; root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout();
        var image = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32); image.Render(root);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image)); using var output = File.Create(path); encoder.Save(output);
    }
}
