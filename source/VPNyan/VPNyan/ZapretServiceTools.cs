using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace VPNyan;

internal static partial class ZapretNative
{
    internal static string BuildServiceCommand(string folder, string strategy) => ZapretProfiles.Quote(ZapretProfiles.SafePath(folder, "bin/winws.exe")) + " " + string.Join(' ', ZapretProfiles.BuildArguments(folder, strategy).Select(ZapretProfiles.Quote));
    internal static void ValidateServiceCommand(string command, string folder)
    {
        var args = ZapretProfiles.SplitCommandLine(Environment.ExpandEnvironmentVariables(command));
        if (args.Length < 2 || !IsSelectedBinary(args[0], folder)) throw new InvalidDataException("Параметры службы относятся к другой папке.");
        ZapretProfiles.ValidateArguments(args.Skip(1).ToArray());
    }
    internal static string DescribeService(string name)
    {
        try { using var handle = new ServiceHandle(name, 4); return name + ": " + (handle.Status().State == 4 ? "работает" : "не запущена"); }
        catch (Win32Exception ex) { return name + (ex.NativeErrorCode == 1060 ? ": не установлена" : ": статус недоступен"); }
    }
    private static void VerifyServiceFolder(string name, string folder)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name);
        if (key?.GetValue("ImagePath") is not string command) throw new InvalidDataException("Служба zapret не найдена.");
        var args = ZapretProfiles.SplitCommandLine(Environment.ExpandEnvironmentVariables(command));
        if (args.Length < 1 || !IsSelectedBinary(args[0], folder)) throw new InvalidDataException("Эта служба относится к другой папке zapret. Выбери её папку.");
    }
    private static async Task InstallServiceAsync(string folder, string strategy)
    {
        var command = BuildServiceCommand(folder, strategy); var state = ReadState(folder);
        if (state.Running || state.OtherProcesses > 0 || state.UnreadableProcesses > 0) throw new InvalidDataException("Перед установкой службы выключи zapret. Другие экземпляры не изменены.");
        if (state.Services.Count > 1) throw new InvalidDataException("Найдено несколько служб в этой папке. Сначала удали лишние.");
        ZapretProfiles.EnsureUserLists(folder);
        var name = state.Services.SingleOrDefault()?.Name ?? "zapret";
        if (state.Services.Count == 0)
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\zapret"))
                if (key != null) throw new InvalidDataException("Служба zapret уже занята другой установкой. Чужая служба не изменена.");
            var manager = OpenSCManager(null, null, 2);
            if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var service = CreateService(manager, name, "zapret", 0xF01FF, 0x10, 2, 1, command, null, IntPtr.Zero, null, null, null);
                if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                CloseServiceHandle(service);
            }
            finally { CloseServiceHandle(manager); }
            try { using var service = new ServiceHandle(name, 4 | 16); service.Start(); await service.WaitAsync(4); }
            catch { using var service = new ServiceHandle(name, 4 | 0x10000); if (service.Status().State == 1) service.Delete(); throw; }
        }
        else
        {
            VerifyServiceFolder(name, folder);
            await StartAsync(folder, strategy);
            using var service = new ServiceHandle(name, 2); service.AutoStart();
        }
        using var metadata = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name, true);
        metadata?.SetValue("zapret-discord-youtube", Path.GetFileNameWithoutExtension(strategy), RegistryValueKind.String);
    }
    private static async Task RemoveServicesAsync(string folder)
    {
        var state = ReadState(folder);
        if (state.Services.Count > 8) throw new InvalidDataException("Слишком много служб в выбранной папке.");
        // Removal is scoped to this installation, never to shared WinDivert drivers.
        foreach (var entry in state.Services)
        {
            VerifyServiceFolder(entry.Name, folder);
            using var service = new ServiceHandle(entry.Name, 4 | 32 | 0x10000); service.Stop(); await service.WaitAsync(1); service.Delete();
        }
    }
    private static async Task EnableTimestampsAsync()
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "interface", "tcp", "set", "global", "timestamps=enabled" }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("Не удалось запустить netsh.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token); var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        try { await process.WaitForExitAsync(timeout.Token); _ = await stdout; _ = await stderr; }
        catch { try { if (!process.HasExited) process.Kill(); } catch { } throw; }
        if (process.ExitCode != 0) throw new InvalidDataException("Windows не включила TCP timestamps. Проверь системные политики.");
    }
    private static async Task<string> TestStrategiesAsync(string folder)
    {
        var state = ReadState(folder, true);
        if (state.OtherProcesses > 0 || state.UnreadableProcesses > 0) throw new InvalidDataException("Для теста выключи zapret из других папок. Их процессы не изменялись.");
        if (state.Services.Count > 1 || state.Processes.Count > 1) throw new InvalidDataException("Для тестирования оставь не более одного экземпляра zapret в выбранной папке.");
        var serviceCommands = new Dictionary<string, string>();
        foreach (var entry in state.Services)
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + entry.Name);
            var command = key?.GetValue("ImagePath") as string ?? throw new InvalidDataException("Не удалось сохранить стратегию службы.");
            ValidateServiceCommand(command, folder); serviceCommands[entry.Name] = command;
        }
        return await ZapretStrategyTests.RunAsync(folder, ZapretProfiles.Read(folder).Profiles, ExecuteAsync, ZapretStrategyTests.ProbeAsync, () =>
        {
            foreach (var (name, command) in serviceCommands)
            {
                VerifyServiceFolder(name, folder);
                using var service = new ServiceHandle(name, 4 | 2);
                if (service.Status().State != 1) throw new InvalidDataException("Тестовая служба ещё работает. Не удалось вернуть прежнюю стратегию.");
                service.ChangeCommand(command);
            }
        });
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateService(IntPtr manager, string name, string display, uint access, uint type, uint start, uint error, string command, string? group, IntPtr tag, string? dependencies, string? user, string? password);
}
