using System.Diagnostics;
using System.IO;
using System.Net.Http;

namespace VPNyan;

internal static class ZapretStrategyTests
{
    internal static async Task<string> RunAsync(string folder, IEnumerable<ZapretProfile> profiles, Func<ZapretRequest, Task<ZapretResult>> execute, Func<Task<string>> probe, Action restoreServices)
    {
        var pause = await execute(new() { Action = "pause", Folder = folder, CaptureRestore = true });
        if (!pause.Success)
        {
            if (pause.Lease?.HasEntries == true)
            {
                var restored = await execute(new() { Action = "resume", Folder = folder, Lease = pause.Lease });
                if (!restored.Success) throw new InvalidDataException(pause.Message + " Не удалось вернуть zapret: " + restored.Message);
            }
            throw new InvalidDataException(pause.Message);
        }
        var report = new List<string>(); var clock = Stopwatch.StartNew();
        try
        {
            foreach (var profile in profiles)
            {
                if (clock.Elapsed.TotalSeconds > 75) { report.Add("Лимит перебора 75 секунд; оставшиеся стратегии пропущены."); break; }
                try
                {
                    var started = await execute(new() { Action = "start", Folder = folder, Strategy = profile.FileName });
                    report.Add(profile.Name + ": " + (started.Success ? await probe() : started.Message));
                }
                finally
                {
                    var stopped = await execute(new() { Action = "stop", Folder = folder });
                    if (!stopped.Success) throw new InvalidDataException(stopped.Message);
                }
            }
        }
        finally
        {
            restoreServices();
            if (pause.Lease?.HasEntries == true)
            {
                var resumed = await execute(new() { Action = "resume", Folder = folder, Lease = pause.Lease });
                if (!resumed.Success) throw new InvalidDataException("Тест завершён, но прежний zapret не восстановлен: " + resumed.Message);
            }
        }
        report.Add("Это проверка HTTPS к YouTube и Discord, а не гарантия работы всех ресурсов. Прежнее состояние zapret восстановлено.");
        return string.Join('\n', report);
    }
    internal static async Task<string> ProbeAsync()
    {
        using var client = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromMilliseconds(1800) };
        var urls = new[] { ("YouTube", "https://www.youtube.com/generate_204"), ("Discord", "https://discord.com/api/v9/gateway") };
        var tests = await Task.WhenAll(urls.Select(async target =>
        {
            var timer = Stopwatch.StartNew();
            try { using var response = await client.GetAsync(target.Item2, HttpCompletionOption.ResponseHeadersRead); return target.Item1 + (response.IsSuccessStatusCode ? $" {timer.ElapsedMilliseconds} мс" : $" HTTP {(int)response.StatusCode}"); }
            catch (HttpRequestException) { return target.Item1 + " ошибка сети"; } catch (TaskCanceledException) { return target.Item1 + " тайм-аут"; }
        }));
        return string.Join(" · ", tests);
    }
}
