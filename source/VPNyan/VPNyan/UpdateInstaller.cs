using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace VPNyan;

internal sealed class UpdateJob
{
    public string Target { get; set; } = "";
    public string CurrentHash { get; set; } = "";
    public int ParentId { get; set; }
    public long ParentStarted { get; set; }
    public Dictionary<string, string> Files { get; set; } = new();
}

internal static class UpdateInstaller
{
    internal static void CleanCache()
    {
        try
        {
            if (!Directory.Exists(ApplicationUpdates.CacheRoot) || new DirectoryInfo(ApplicationUpdates.CacheRoot).LinkTarget != null) return;
            foreach (var directory in Directory.EnumerateDirectories(ApplicationUpdates.CacheRoot))
            {
                if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out _) ||
                    (!File.Exists(Path.Combine(directory, "complete")) && Directory.GetLastWriteTimeUtc(directory) > DateTime.UtcNow.AddDays(-1))) continue;
                try
                {
                    // Do not traverse filesystem links, including links planted in a cache after download.
                    var pending = new Stack<string>(); pending.Push(directory); var linked = false;
                    while (pending.Count > 0 && !linked)
                    {
                        var current = pending.Pop();
                        if (new DirectoryInfo(current).LinkTarget != null) { linked = true; break; }
                        foreach (var item in Directory.EnumerateFileSystemEntries(current))
                        {
                            FileSystemInfo info = Directory.Exists(item) ? new DirectoryInfo(item) : new FileInfo(item);
                            if (info.LinkTarget != null) { linked = true; break; }
                            if (info is DirectoryInfo) pending.Push(item);
                        }
                    }
                    if (!linked) Directory.Delete(directory, true);
                }
                catch { /* A running installer or antivirus may still hold a cache file. */ }
            }
        }
        catch { }
    }

    internal static bool AllowedFile(string relative) => relative is "VPNyan.exe" or "VPNyan.dll.config" or "BUILD-INFO.json" or "README.md" or "THIRD_PARTY.md" or "CHANGELOG.md" or "START-HERE.txt" ||
        relative is "Engine/xray.exe" or "Engine/wintun.dll" or "Engine/geoip.dat" or "Engine/geosite.dat" or "Engine/LICENSE" or "Engine/LICENSE-Wintun" ||
        relative.StartsWith("licenses/", StringComparison.Ordinal) && relative.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) && relative.Count(c => c == '/') == 1 && !relative.Contains("..");

    internal static void CheckWritable(string target)
    {
        var path = Path.Combine(target, ".vpn4ik-write-" + Guid.NewGuid().ToString("N"));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
    }

    internal static async Task VerifyStartupAsync(string directory, CancellationToken token)
    {
        var reportDirectory = Path.Combine(ApplicationUpdates.CacheRoot, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(reportDirectory);
        var report = Path.Combine(reportDirectory, "startup.json");
        var start = new ProcessStartInfo(Path.Combine(directory, "VPNyan.exe")) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = directory };
        start.ArgumentList.Add("--verify-startup"); start.ArgumentList.Add(report);
        using var process = Process.Start(start) ?? throw new IOException("Не удалось проверить запуск обновления.");
        try { await process.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(50), token); }
        catch { try { if (!process.HasExited) process.Kill(); } catch { } throw; }
        if (process.ExitCode != 0 || !File.Exists(report)) throw new InvalidDataException("Новая версия не прошла проверку запуска.");
        using var result = JsonDocument.Parse(File.ReadAllText(report));
        if (!result.RootElement.TryGetProperty("Verified", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !result.RootElement.TryGetProperty("CoreLibBundled", out var bundled) || bundled.ValueKind != JsonValueKind.True)
            throw new InvalidDataException("Новая версия не содержит встроенную среду .NET.");
    }

    internal static void Launch(string work, string executable)
    {
        var target = Path.GetDirectoryName(Path.GetFullPath(executable))!;
        CheckWritable(target);
        using var parent = Process.GetCurrentProcess();
        var payload = Path.Combine(work, "payload");
        var job = new UpdateJob { Target = target, CurrentHash = ApplicationUpdates.HashFile(executable), ParentId = parent.Id, ParentStarted = parent.StartTime.ToUniversalTime().Ticks };
        foreach (var file in Directory.EnumerateFiles(payload, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(payload, file).Replace('\\', '/');
            if (!AllowedFile(relative)) throw new InvalidDataException("Некорректный файл обновления.");
            job.Files.Add(relative, ApplicationUpdates.HashFile(file));
        }
        File.WriteAllText(Path.Combine(work, "job.json"), JsonSerializer.Serialize(job));
        var helper = Path.Combine(work, "installer.exe"); File.Copy(executable, helper, false);
        var start = new ProcessStartInfo(helper) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = work };
        start.ArgumentList.Add("--apply-update"); start.ArgumentList.Add(Path.Combine(work, "job.json"));
        using var installer = Process.Start(start) ?? throw new IOException("Не удалось запустить установку обновления.");
    }

    internal static async Task<int> RunAsync(string manifest)
    {
        string? target = null;
        try
        {
            var work = Path.GetDirectoryName(Path.GetFullPath(manifest))!;
            if (!string.Equals(Path.GetDirectoryName(work), Path.GetFullPath(ApplicationUpdates.CacheRoot), StringComparison.OrdinalIgnoreCase) ||
                !Guid.TryParseExact(Path.GetFileName(work), "N", out _) || Path.GetFileName(manifest) != "job.json" ||
                !string.Equals(Environment.ProcessPath, Path.Combine(work, "installer.exe"), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Некорректное задание обновления.");
            var job = JsonSerializer.Deserialize<UpdateJob>(File.ReadAllText(manifest)) ?? throw new InvalidDataException();
            if (job.ParentId <= 0 || job.Files.Count is < 4 or > 256 || !Path.IsPathFullyQualified(job.Target)) throw new InvalidDataException();
            target = Path.GetFullPath(job.Target);
            await WaitForParentAsync(job.ParentId, job.ParentStarted, TimeSpan.FromMinutes(2));
            if (!ApplicationUpdates.HashFile(Path.Combine(target, "VPNyan.exe")).Equals(job.CurrentHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Приложение уже заменено другим процессом.");
            await InstallAsync(Path.Combine(work, "payload"), target, Path.Combine(work, "backup"), job.Files, VerifyStartupAsync);
            var start = new ProcessStartInfo(Path.Combine(target, "VPNyan.exe")) { UseShellExecute = false, WorkingDirectory = target };
            start.ArgumentList.Add("--updated"); using var launched = Process.Start(start) ?? throw new IOException("Не удалось перезапустить приложение.");
            File.WriteAllText(Path.Combine(work, "complete"), "ok");
            return 0;
        }
        catch
        {
            System.Windows.MessageBox.Show("Не удалось завершить обновление VPN4ik. Запусти приложение вручную или скачай выпуск через GitHub. Если установка начиналась, резервная копия находится во временной папке VPN4ik-updates.", "Обновление VPN4ik", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            // Never restart while the old process may still own its VPN tunnel.
            return 1;
        }
    }

    internal static async Task WaitForParentAsync(int id, long started, TimeSpan timeout)
    {
        try
        {
            using var parent = Process.GetProcessById(id);
            if (parent.StartTime.ToUniversalTime().Ticks != started) throw new InvalidDataException("Процесс приложения изменился.");
            using var deadline = new CancellationTokenSource(timeout);
            await parent.WaitForExitAsync(deadline.Token);
        }
        catch (ArgumentException) { /* Parent already exited normally. */ }
    }

    internal static async Task InstallAsync(string payload, string target, string backup, IReadOnlyDictionary<string, string> files, Func<string, CancellationToken, Task> healthCheck)
    {
        var staged = new List<(string Path, string Pending, string? Backup)>(); var replaced = new List<(string Path, string? Backup)>();
        try
        {
            foreach (var (relative, hash) in files)
            {
                if (!AllowedFile(relative) || relative.Split('/').Any(part => part is "" or "." or ".." || part.Contains('\\') || part.Contains(':'))) throw new InvalidDataException("Недопустимый путь обновления.");
                var source = Path.Combine(payload, relative.Replace('/', Path.DirectorySeparatorChar));
                if (!ApplicationUpdates.HashFile(source).Equals(hash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Файлы подготовки изменились.");
                var destination = Path.Combine(target, relative.Replace('/', Path.DirectorySeparatorChar));
                RejectLinks(target, destination);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                string? saved = null;
                if (File.Exists(destination))
                {
                    saved = Path.Combine(backup, relative.Replace('/', Path.DirectorySeparatorChar)); Directory.CreateDirectory(Path.GetDirectoryName(saved)!); File.Copy(destination, saved, false);
                }
                var pending = destination + ".vpn4ik-update-" + Guid.NewGuid().ToString("N");
                staged.Add((destination, pending, saved)); File.Copy(source, pending, false);
                if (!ApplicationUpdates.HashFile(pending).Equals(hash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Копия файла обновления повреждена.");
            }
            foreach (var file in staged) { File.Move(file.Pending, file.Path, true); replaced.Add((file.Path, file.Backup)); }
            await healthCheck(target, CancellationToken.None);
        }
        catch
        {
            var failures = new List<Exception>();
            foreach (var file in replaced.AsEnumerable().Reverse())
                try { if (file.Backup == null) File.Delete(file.Path); else File.Copy(file.Backup, file.Path, true); }
                catch (Exception ex) { failures.Add(ex); }
            if (failures.Count > 0) throw new IOException("Не все прежние файлы восстановлены. Резервная копия сохранена.", new AggregateException(failures));
            throw;
        }
        finally { foreach (var file in staged) { try { File.Delete(file.Pending); } catch { } } }
    }

    private static void RejectLinks(string root, string destination)
    {
        var current = Path.GetFullPath(destination); var boundary = Path.GetFullPath(root);
        if (!current.StartsWith(boundary + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Путь вне папки приложения.");
        while (true)
        {
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            if (info.LinkTarget != null) throw new InvalidDataException("Обновление через ссылку каталога недоступно.");
            if (current.Equals(boundary, StringComparison.OrdinalIgnoreCase)) break;
            current = Path.GetDirectoryName(current) ?? throw new InvalidDataException();
        }
    }
}
