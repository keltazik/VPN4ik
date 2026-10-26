using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace VPNyan;

internal sealed record ZapretInstallation(string Folder, string Source)
{
    public override string ToString() => Folder + " · " + Source;
}

internal static class ZapretDiscovery
{
    // Search is bounded, never follows junctions, and never runs scripts or executables.
    internal static List<ZapretInstallation> Find(string saved, CancellationToken token, IEnumerable<string>? searchRoots = null)
    {
        var found = new List<ZapretInstallation>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? folder, string source)
        {
            token.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(folder)) return;
            try
            {
                var valid = ZapretProfiles.ValidateFolder(folder);
                _ = ZapretProfiles.Read(valid);
                if (seen.Add(valid)) found.Add(new(valid, source));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException) { }
        }
        Add(saved, "выбранная папка");
        if (searchRoots == null)
        {
            foreach (var process in Process.GetProcessesByName("winws"))
                using (process) { try { Add(ZapretNative.ProcessFolder(process.Id), "запущенный zapret"); } catch { } }
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            foreach (var name in services?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var key = services!.OpenSubKey(name);
                    if (key?.GetValue("ImagePath") is not string command || !command.Contains("winws.exe", StringComparison.OrdinalIgnoreCase)) continue;
                    var args = ZapretProfiles.SplitCommandLine(Environment.ExpandEnvironmentVariables(command));
                    if (args.Length > 0) Add(Path.GetDirectoryName(Path.GetDirectoryName(args[0])), "служба Windows");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException) { }
            }
        }
        var roots = searchRoots ?? DefaultRoots();
        var queue = new Queue<(string Folder, int Depth)>();
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase)) if (Directory.Exists(root)) queue.Enqueue((root, 0));
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var clock = Stopwatch.StartNew();
        while (queue.Count > 0 && visited.Count < 4000 && clock.Elapsed < TimeSpan.FromSeconds(8))
        {
            token.ThrowIfCancellationRequested();
            var (folder, depth) = queue.Dequeue();
            if (!visited.Add(folder)) continue;
            try
            {
                var info = new DirectoryInfo(folder);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                Add(folder, "найдено на компьютере");
                if (seen.Contains(Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar)) || depth >= 3) continue;
                var children = info.EnumerateDirectories().Take(400).ToArray();
                foreach (var child in children.OrderByDescending(item => item.Name.Contains("zapret", StringComparison.OrdinalIgnoreCase)).ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase))
                {
                    if ((child.Attributes & (FileAttributes.ReparsePoint | FileAttributes.System)) != 0 || Skip(child.Name)) continue;
                    queue.Enqueue((child.FullName, depth + 1));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        }
        return found;
    }
    private static bool Skip(string name) => name.StartsWith('.') || name is "Windows" or "Users" or "ProgramData" or "AppData" or "node_modules" or "WindowsApps" or "$Recycle.Bin" or "System Volume Information";
    private static IEnumerable<string> DefaultRoots()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        yield return Path.Combine(profile, "Downloads");
        yield return Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        foreach (var drive in DriveInfo.GetDrives()) if (drive.DriveType == DriveType.Fixed && drive.IsReady) yield return drive.RootDirectory.FullName;
    }
}
