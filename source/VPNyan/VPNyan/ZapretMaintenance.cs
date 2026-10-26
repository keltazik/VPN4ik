using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace VPNyan;

internal sealed class ZapretMaintenance : IDisposable
{
    internal const string Releases = "https://github.com/Flowseal/zapret-discord-youtube/releases/latest";
    private readonly HttpClient client;
    internal ZapretMaintenance(HttpMessageHandler? handler = null)
    {
        client = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(12) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("VPN4ik/" + ApplicationUpdates.CurrentVersion);
    }
    internal async Task<string> DownloadAsync(string kind, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(12)); token = timeout.Token;
        var path = kind switch { "version" => "version.txt", "ipset" => "ipset-service.txt", "hosts" => "hosts", _ => throw new InvalidDataException("Неизвестный файл обновления zapret.") };
        using var response = await client.GetAsync("https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/" + path, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        using var stream = await response.Content.ReadAsStreamAsync(token); using var output = new MemoryStream();
        var buffer = new byte[8192]; int count;
        while ((count = await stream.ReadAsync(buffer, token)) != 0) { if (output.Length + count > 1024 * 1024) throw new InvalidDataException("Файл обновления zapret слишком большой."); output.Write(buffer, 0, count); }
        var text = Encoding.UTF8.GetString(output.ToArray()).TrimStart('\uFEFF');
        if (kind == "version" && !Regex.IsMatch(text.Trim(), @"^\d{1,4}(?:\.\d{1,4}){1,3}$")) throw new InvalidDataException("Сервер вернул некорректную версию zapret.");
        if (kind == "ipset") ZapretProfiles.ValidateList("ips", text);
        if (kind == "hosts" && (text.Length < 10 || text.Contains('<') || text.Contains('\0'))) throw new InvalidDataException("Сервер вернул некорректный hosts. Системный файл не изменён.");
        return text.TrimEnd() + "\n";
    }
    internal static async Task<string> DiagnoseAsync(string folder, CancellationToken token)
    {
        var info = ZapretProfiles.Read(folder); var state = ZapretNative.ReadState(folder);
        var report = new List<string> { $"Flowseal {info.Version}", $"Процессы этой папки: {state.Processes.Count}; службы: {state.Services.Count}; другие экземпляры: {state.OtherProcesses}; недоступны: {state.UnreadableProcesses}.",
            Directory.EnumerateFiles(ZapretProfiles.SafePath(folder, "bin"), "*.sys").Any() ? "Драйвер WinDivert: файл найден." : "Драйвер WinDivert: .sys не найден в bin." };
        foreach (var name in new[] { "BFE", "WinDivert", "WinDivert14" }) report.Add(ZapretNative.DescribeService(name));
        using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings")) report.Add(key?.GetValue("ProxyEnable") is int enabled && enabled != 0 ? "Системный прокси включён: возможен конфликт." : "Системный прокси выключен.");
        using (var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            foreach (var name in services?.GetSubKeyNames().Where(name => name.Contains("Killer", StringComparison.OrdinalIgnoreCase) || name is "GoodbyeDPI" or "discordfix_zapret" or "winws1" or "winws2") ?? Array.Empty<string>()) report.Add("Возможный конфликт: служба " + name);
        foreach (var process in Process.GetProcessesByName("AdguardSvc")) { report.Add("AdGuard запущен: возможен конфликт."); process.Dispose(); }
        var valid = 0;
        foreach (var profile in info.Profiles) { token.ThrowIfCancellationRequested(); try { _ = ZapretProfiles.BuildArguments(folder, profile.FileName); valid++; } catch (InvalidDataException ex) { report.Add(profile.Name + ": " + ex.Message); } }
        report.Add($"Параметры стратегий: {valid}/{info.Profiles.Count} корректны.");
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("interface"); start.ArgumentList.Add("tcp"); start.ArgumentList.Add("show"); start.ArgumentList.Add("global");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(5));
        using var read = Process.Start(start);
        if (read != null)
        {
            try { var stdout = read.StandardOutput.ReadToEndAsync(timeout.Token); var stderr = read.StandardError.ReadToEndAsync(timeout.Token); await read.WaitForExitAsync(timeout.Token); report.Add("TCP Windows:\n" + await stdout); _ = await stderr; }
            catch (OperationCanceledException) { try { if (!read.HasExited) read.Kill(); } catch { } report.Add("Не удалось прочитать TCP-параметры за 5 секунд."); }
        }
        report.Add("Диагностика завершена. Службы, драйверы, Discord и системные настройки не изменялись.");
        return string.Join('\n', report);
    }
    public void Dispose() => client.Dispose();
}
