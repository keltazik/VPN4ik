using System.Diagnostics;

namespace VPNyan;

public sealed class ProcessChoice
{
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
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
                    try { path = process.MainModule?.FileName ?? ""; } catch { /* Protected processes still have a usable name. */ }
                    entries.Add(new ProcessChoice { Name = path == "" ? process.ProcessName + ".exe" : System.IO.Path.GetFileName(path), Path = path });
                }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }
        return entries.DistinctBy(entry => entry.Rule, StringComparer.OrdinalIgnoreCase).OrderBy(entry => entry.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    });
}
