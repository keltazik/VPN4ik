using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace VPNyan;

internal sealed record ZapretProcess(int Id, long Started, string[] Arguments);
internal sealed record ZapretService(string Name, uint State, int ProcessId);
internal sealed class ZapretState
{
    public List<ZapretProcess> Processes { get; set; } = new();
    public List<ZapretService> Services { get; set; } = new();
    public int UnreadableProcesses { get; set; }
    public int OtherProcesses { get; set; }
    public bool Running => Processes.Count > 0 || Services.Any(service => service.State is 2 or 3 or 4);
}
internal sealed class ZapretLease
{
    public string Folder { get; set; } = "";
    public List<string> Services { get; set; } = new();
    public List<string[]> Processes { get; set; } = new();
    public bool HasEntries => Services.Count > 0 || Processes.Count > 0;
}
internal sealed class ZapretRequest
{
    public string Action { get; set; } = "";
    public string Folder { get; set; } = "";
    public string Strategy { get; set; } = "";
    public bool CaptureRestore { get; set; }
    public ZapretLease? Lease { get; set; }
    public string GameMode { get; set; } = "disabled";
    public string IpSetMode { get; set; } = "none";
    public string ListKind { get; set; } = "";
    public string ListText { get; set; } = "";
    public Dictionary<string, string> Lists { get; set; } = new();
}
internal sealed class ZapretResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public ZapretState State { get; set; } = new();
    public ZapretLease? Lease { get; set; }
}

internal static class ZapretNative
{
    internal static bool IsSelectedBinary(string path, string folder) => string.Equals(Path.GetFullPath(path), ZapretProfiles.SafePath(folder, "bin/winws.exe"), StringComparison.OrdinalIgnoreCase);

    internal static ZapretState ReadState(string folder, bool readArguments = false)
    {
        folder = ZapretProfiles.ValidateFolder(folder);
        var state = new ZapretState();
        using (var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
        {
            foreach (var name in services?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                try
                {
                    using var key = services!.OpenSubKey(name);
                    if (key?.GetValue("ImagePath") is not string command || !command.Contains("winws.exe", StringComparison.OrdinalIgnoreCase)) continue;
                    var parts = ZapretProfiles.SplitCommandLine(Environment.ExpandEnvironmentVariables(command));
                    if (parts.Length == 0 || !IsSelectedBinary(parts[0], folder)) continue;
                    using var service = new ServiceHandle(name, 4);
                    var status = service.Status(); state.Services.Add(new(name, status.State, (int)status.ProcessId));
                }
                catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or Win32Exception or IOException) { }
            }
        }
        foreach (var process in Process.GetProcessesByName("winws"))
        {
            using (process)
            {
                try
                {
                    using var handle = OpenProcess(0x1000, false, process.Id);
                    if (handle.IsInvalid) { state.UnreadableProcesses++; continue; }
                    var path = ImagePath(handle);
                    if (!IsSelectedBinary(path, folder)) { state.OtherProcesses++; continue; }
                    var args = readArguments ? ZapretProfiles.SplitCommandLine(CommandLine(handle)).Skip(1).ToArray() : Array.Empty<string>();
                    state.Processes.Add(new(process.Id, CreationTime(handle), args));
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException) { state.UnreadableProcesses++; }
            }
        }
        return state;
    }

    internal static async Task<ZapretResult> ExecuteAsync(ZapretRequest request)
    {
        var result = new ZapretResult();
        try
        {
            var folder = ZapretProfiles.ValidateFolder(request.Folder);
            if (request.Action == "configure") ZapretProfiles.Configure(folder, request.GameMode, request.IpSetMode);
            else if (request.Action == "list") ZapretProfiles.WriteList(folder, request.ListKind, request.ListText);
            else if (request.Action == "lists")
            {
                if (request.Lists.Count is < 1 or > 3) throw new InvalidDataException("Некорректные списки zapret.");
                foreach (var (kind, text) in request.Lists) ZapretProfiles.ValidateList(kind, text);
                foreach (var (kind, text) in request.Lists) ZapretProfiles.WriteList(folder, kind, text);
            }
            else if (request.Action is "stop" or "pause" or "restart")
            {
                if (request.Action == "restart") _ = ZapretProfiles.BuildArguments(folder, request.Strategy); // Validate before stopping.
                var state = ReadState(folder, request.CaptureRestore);
                if (state.UnreadableProcesses > 0) throw new InvalidDataException("Не удалось определить все процессы zapret. Отключение не подтверждено.");
                result.Lease = new ZapretLease { Folder = folder };
                var serviceIds = state.Services.Select(service => service.ProcessId).ToHashSet();
                var standalone = state.Processes.Where(process => !serviceIds.Contains(process.Id)).ToArray();
                if (state.Services.Count + standalone.Length > 8) throw new InvalidDataException("Слишком много экземпляров zapret в выбранной папке.");
                if (request.CaptureRestore) foreach (var process in standalone) ZapretProfiles.ValidateArguments(process.Arguments);
                foreach (var entry in state.Services.Where(service => service.State != 1))
                {
                    using var service = new ServiceHandle(entry.Name, 4 | 32);
                    service.Stop(); await service.WaitAsync(1);
                    result.Lease.Services.Add(entry.Name);
                }
                foreach (var entry in standalone)
                {
                    using var handle = OpenProcess(0x1000 | 1 | 0x100000, false, entry.Id);
                    if (handle.IsInvalid) { if (ProcessExists(entry.Id)) throw new Win32Exception(Marshal.GetLastWin32Error()); continue; }
                    if (!IsSelectedBinary(ImagePath(handle), folder) || CreationTime(handle) != entry.Started) throw new InvalidDataException("Процесс zapret изменился; операция отменена.");
                    if (!TerminateProcess(handle, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (WaitForSingleObject(handle, 10000) != 0) throw new IOException("Процесс zapret ещё не остановлен.");
                    if (request.CaptureRestore) result.Lease.Processes.Add(entry.Arguments);
                }
                var after = ReadState(folder);
                if (after.Running || after.UnreadableProcesses > 0) throw new IOException("zapret ещё работает. Подключение VPN не запущено.");
                if (request.Action == "restart") await StartAsync(folder, request.Strategy);
            }
            else if (request.Action == "start") await StartAsync(folder, request.Strategy);
            else if (request.Action == "resume")
            {
                if (request.Lease is not { } lease || !string.Equals(Path.GetFullPath(lease.Folder), folder, StringComparison.OrdinalIgnoreCase) || lease.Services.Count + lease.Processes.Count > 8)
                    throw new InvalidDataException("Некорректное состояние восстановления zapret.");
                var state = ReadState(folder, true);
                if (state.OtherProcesses > 0 || state.UnreadableProcesses > 0) throw new InvalidDataException("Обнаружен другой экземпляр zapret. Автоматический возврат отменён; выбери нужную папку.");
                if (state.Running)
                {
                    result.State = state; result.Success = true; result.Message = "zapret уже запущен. Его текущий запуск сохранён."; return result;
                }
                foreach (var name in lease.Services)
                {
                    if (!state.Services.Any(service => service.Name == name)) throw new InvalidDataException("Служба zapret больше не относится к выбранной папке.");
                    using var service = new ServiceHandle(name, 4 | 16); service.Start(); await service.WaitAsync(4);
                }
                foreach (var args in lease.Processes)
                {
                    ZapretProfiles.ValidateArguments(args);
                    if (!state.Processes.Any(process => process.Arguments.SequenceEqual(args))) await StartProcessAsync(folder, args);
                }
            }
            else if (request.Action != "status") throw new InvalidDataException("Неизвестная операция zapret.");
            result.State = ReadState(folder); result.Success = true; result.Message = "Готово.";
        }
        catch (Exception ex)
        {
            result.Message = ex is InvalidDataException ? ex.Message : ex is Win32Exception native ? $"Windows не выполнила действие zapret (код {native.NativeErrorCode})." : "Операция zapret не завершена. Прежние параметры сохранены, если замена не была завершена.";
            try { result.State = ReadState(request.Folder); } catch { }
        }
        return result;
    }

    private static async Task StartAsync(string folder, string strategy)
    {
        var args = ZapretProfiles.BuildArguments(folder, strategy);
        var state = ReadState(folder);
        if (state.Running) throw new InvalidDataException("zapret уже работает. Для смены стратегии нажми «Перезапустить».");
        if (state.OtherProcesses > 0) throw new InvalidDataException("zapret уже работает из другой папки. Выбери эту папку или выключи другой экземпляр вручную.");
        if (state.UnreadableProcesses > 0) throw new InvalidDataException("Не удалось проверить работающие процессы zapret.");
        if (state.Services.Count > 1) throw new InvalidDataException("В выбранной папке несколько служб zapret. Запусти нужную службу через её менеджер.");
        ZapretProfiles.EnsureUserLists(folder);
        if (state.Services.SingleOrDefault() is { } existing)
        {
            using var service = new ServiceHandle(existing.Name, 4 | 16 | 2);
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + existing.Name);
            var original = key?.GetValue("ImagePath") as string ?? throw new InvalidDataException("Не найдены параметры службы zapret.");
            try
            {
                service.ChangeCommand(ZapretProfiles.Quote(ZapretProfiles.SafePath(folder, "bin/winws.exe")) + " " + string.Join(' ', args.Select(ZapretProfiles.Quote)));
                service.Start(); await service.WaitAsync(4);
            }
            catch { if (service.Status().State == 1) service.ChangeCommand(original); throw; }
        }
        else await StartProcessAsync(folder, args);
    }
    private static async Task StartProcessAsync(string folder, string[] args)
    {
        var start = new ProcessStartInfo(ZapretProfiles.SafePath(folder, "bin/winws.exe")) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = ZapretProfiles.SafePath(folder, "bin") };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("Не удалось запустить zapret.");
        await Task.Delay(650);
        if (process.HasExited) throw new InvalidDataException($"zapret завершился сразу после запуска (код {process.ExitCode}). Проверь файлы сборки или выбери другую стратегию.");
    }
    private static bool ProcessExists(int id) { try { using var process = Process.GetProcessById(id); return !process.HasExited; } catch (ArgumentException) { return false; } }
    private static string ImagePath(SafeProcessHandle handle)
    { var text = new StringBuilder(32768); var length = text.Capacity; if (!QueryFullProcessImageName(handle, 0, text, ref length)) throw new Win32Exception(Marshal.GetLastWin32Error()); return text.ToString(); }
    private static long CreationTime(SafeProcessHandle handle)
    { if (!GetProcessTimes(handle, out var creation, out _, out _, out _)) throw new Win32Exception(Marshal.GetLastWin32Error()); return DateTime.FromFileTimeUtc(creation).Ticks; }
    private static string CommandLine(SafeProcessHandle handle)
    {
        NtQueryInformationProcess(handle, 60, IntPtr.Zero, 0, out var length);
        if (length is < 1 or > 131072) throw new IOException("Не удалось прочитать параметры работающего zapret.");
        var buffer = Marshal.AllocHGlobal((int)length);
        try { if (NtQueryInformationProcess(handle, 60, buffer, length, out _) != 0) throw new IOException("Не удалось прочитать параметры zapret."); var value = Marshal.PtrToStructure<UnicodeString>(buffer); return Marshal.PtrToStringUni(value.Buffer, value.Length / 2) ?? ""; }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private sealed class ServiceHandle : IDisposable
    {
        private readonly IntPtr manager, service;
        internal ServiceHandle(string name, uint access)
        {
            manager = OpenSCManager(null, null, 1); if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            service = OpenService(manager, name, access); if (service == IntPtr.Zero) { var error = Marshal.GetLastWin32Error(); CloseServiceHandle(manager); throw new Win32Exception(error); }
        }
        internal ServiceStatus Status() { if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _)) throw new Win32Exception(Marshal.GetLastWin32Error()); return status; }
        internal void Start() { if (Status().State == 4) return; if (!StartService(service, 0, IntPtr.Zero) && Marshal.GetLastWin32Error() != 1056) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        internal void Stop() { if (Status().State == 1) return; if (!ControlService(service, 1, out _) && Marshal.GetLastWin32Error() != 1062) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        internal void ChangeCommand(string command) { if (!ChangeServiceConfig(service, uint.MaxValue, uint.MaxValue, uint.MaxValue, command, null, IntPtr.Zero, null, null, null, null)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        internal async Task WaitAsync(uint expected) { var timer = Stopwatch.StartNew(); while (Status().State != expected) { if (timer.Elapsed.TotalSeconds > 20) throw new IOException("Служба zapret ещё не завершила переход."); await Task.Delay(200); } }
        public void Dispose() { CloseServiceHandle(service); CloseServiceHandle(manager); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { internal ushort Length, MaximumLength; internal IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { internal uint Type, State, Controls, Win32Exit, ServiceExit, CheckPoint, WaitHint, ProcessId, Flags; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(SafeProcessHandle process, int info, IntPtr buffer, uint size, out uint needed);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeProcessHandle process, uint exit);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool StartService(IntPtr service, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool ControlService(IntPtr service, uint control, out ServiceStatus status);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ChangeServiceConfig(IntPtr service, uint type, uint start, uint error, string command, string? group, IntPtr tag, string? dependencies, string? user, string? password, string? display);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
}
