using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Media;
using Microsoft.Win32.SafeHandles;

namespace VPNyan;

public sealed class ProcessChoice
{
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public ImageSource Icon { get; internal set; } = ProcessIcons.Fallback;
    public string Detail => Path == "" ? "Путь недоступен — будет добавлено имя процесса" : Path;
    public bool Selected { get; set; }
    public string Rule => Path == "" ? Name : Path.Replace('\\', '/');
}

internal static class ProcessCatalog
{
    internal static Task<List<ProcessChoice>> ListAsync() => Task.Run(() =>
    {
        var entries = new List<ProcessChoice>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id == 0 || process.ProcessName is "Idle" or "System" or "Registry" or "Memory Compression") continue;
                    var path = "";
                    try
                    {
                        using var handle = OpenProcess(0x1000, false, process.Id);
                        var text = new StringBuilder(32768); var count = text.Capacity;
                        if (!handle.IsInvalid && QueryFullProcessImageName(handle, 0, text, ref count)) path = text.ToString();
                    }
                    catch { /* Protected processes still have a usable name. */ }
                    entries.Add(new ProcessChoice { Name = path == "" ? process.ProcessName + ".exe" : System.IO.Path.GetFileName(path), Path = path });
                }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }
        var choices = entries.DistinctBy(entry => entry.Rule, StringComparer.OrdinalIgnoreCase).OrderBy(entry => entry.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        var icons = new Dictionary<string, ImageSource>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in choices)
        {
            if (!icons.TryGetValue(entry.Path, out var icon)) icons[entry.Path] = icon = ProcessIcons.Load(entry.Path);
            entry.Icon = icon;
        }
        return choices;
    });
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref int size);
}
