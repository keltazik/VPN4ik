using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace VPNyan;

internal sealed record EngineMessage(string Type, string Text = "");

internal static class EngineHost
{
    internal const string Version = "26.10.21";
    internal static string EngineDirectory => Path.Combine(AppContext.BaseDirectory, "Engine");
    internal static string EnginePath => Path.Combine(EngineDirectory, "xray.exe");

    internal static void VerifyFiles()
    {
        foreach (var (file, expected) in new[] {
            ("xray.exe", "C77A00EB84FB93AE044C2D771A1CABCC033B81E487253FBC35B12DF6879C1E15"),
            ("wintun.dll", "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") })
        {
            var path = Path.Combine(EngineDirectory, file);
            if (!File.Exists(path)) throw new InvalidDataException("В сборке отсутствует VPN-движок. Запусти полную сборку приложения.");
            using var input = File.OpenRead(path);
            if (!Convert.ToHexString(SHA256.HashData(input)).Equals(expected, StringComparison.Ordinal))
                throw new InvalidDataException("Файлы VPN-движка изменены. Нужна исходная сборка приложения.");
        }
    }

    internal static async Task<int> RunAsync(string pipeName, int parentId)
    {
        if (!pipeName.StartsWith("VPN4ik-", StringComparison.Ordinal) || pipeName.Length > 64) return 2;
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        Process? engine = null;
        EngineJob? job = null;
        Semaphore? tunSession = null;
        bool ownsTunSession = false;
        SystemProxyLease? proxyLease = null;
        using var sendLock = new SemaphoreSlim(1);
        StreamWriter? writer = null;
        async Task Send(string type, string text = "")
        {
            await sendLock.WaitAsync();
            try { if (writer != null && pipe.IsConnected) await writer.WriteLineAsync(JsonSerializer.Serialize(new EngineMessage(type, text))); }
            finally { sendLock.Release(); }
        }
        try
        {
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await pipe.ConnectAsync(connectTimeout.Token);
            writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverId) || serverId != parentId)
                throw new InvalidDataException("Не подтверждён процесс приложения: канал управления.");
            using var parent = Process.GetProcessById(parentId);
            if (!string.Equals(parent.MainModule?.FileName, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Не подтверждён процесс приложения: путь программы.");
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true);
            await Send("hello");
            var line = await reader.ReadLineAsync(connectTimeout.Token);
            if (line == null || line.Length > SubscriptionParser.MaxBytes * 2) return 4;
            var request = JsonSerializer.Deserialize<EngineRequest>(line) ?? throw new InvalidDataException("Не получен профиль подключения.");
            VerifyFiles();
            var config = XrayConfiguration.Build(request);
            if (request.EnableTun)
            {
                tunSession = new Semaphore(1, 1, "Global\\VPN4ik.TunSession");
                ownsTunSession = tunSession.WaitOne(0);
                if (!ownsTunSession) throw new InvalidDataException("VPN4ik уже подключён в другом окне. Сначала отключи прежнее подключение.");
            }
            if (!AllocConsole()) throw new Win32Exception(Marshal.GetLastWin32Error());
            ShowWindow(GetConsoleWindow(), 0);
            System.Console.CancelKeyPress += IgnoreControlC;
            job = new EngineJob();
            engine = new Process { StartInfo = new ProcessStartInfo(EnginePath)
            {
                UseShellExecute = false, CreateNoWindow = false, WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = EngineDirectory, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            } };
            engine.StartInfo.ArgumentList.Add("run");
            engine.StartInfo.ArgumentList.Add("-format=json");
            engine.StartInfo.ArgumentList.Add("-c");
            engine.StartInfo.ArgumentList.Add("stdin:");
            engine.StartInfo.Environment["XRAY_LOCATION_ASSET"] = EngineDirectory;
            engine.StartInfo.Environment.Remove("XRAY_LOCATION_CONFDIR");
            engine.StartInfo.Environment.Remove("XRAY_LOCATION_CONFIG");
            if (!engine.Start()) throw new InvalidOperationException("Не удалось запустить Xray.");
            job.Assign(engine);
            await engine.StandardInput.WriteAsync(config);
            engine.StandardInput.Close();
            async Task Pump(StreamReader output)
            {
                while (await output.ReadLineAsync() is string text)
                {
                    try { await Send("log", text); }
                    catch (IOException) { return; }
                }
            }
            var stdout = Pump(engine.StandardOutput);
            var stderr = Pump(engine.StandardError);
            if (request.EnableSystemProxy)
            {
                await SystemProxyLease.WaitForListenerAsync(request.HttpProxyPort, connectTimeout.Token);
                proxyLease = SystemProxyLease.Start(request.HttpProxyPort);
            }
            await Send("started");
            var command = reader.ReadLineAsync();
            var exited = engine.WaitForExitAsync();
            // A broken UI pipe or parent death stops this owned engine too.
            await Task.WhenAny(command, exited, parent.WaitForExitAsync());
            if (!engine.HasExited) await StopEngineAsync(engine);
            await Task.WhenAll(stdout, stderr);
            await Send("stopped", engine.ExitCode.ToString());
            return 0;
        }
        catch (Exception ex)
        {
            try { await Send("error", ex is InvalidDataException ? ex.Message : $"VPN-движок не смог запуститься: {ex.GetType().Name}, код {(ex as Win32Exception)?.NativeErrorCode ?? 0}."); }
            catch { }
            return 1;
        }
        finally
        {
            if (engine != null)
            {
                try { if (!engine.HasExited) await StopEngineAsync(engine); } catch { }
                engine.Dispose();
            }
            job?.Dispose();
            proxyLease?.Dispose();
            if (ownsTunSession) tunSession?.Release();
            tunSession?.Dispose();
            writer?.Dispose();
            System.Console.CancelKeyPress -= IgnoreControlC;
            FreeConsole();
        }
    }

    private static void IgnoreControlC(object? sender, ConsoleCancelEventArgs e) => e.Cancel = true;

    private static async Task StopEngineAsync(Process engine)
    {
        if (engine.HasExited) return;
        // The hidden helper and Xray share a private console. Go handles Ctrl+C by
        // closing its TUN, restoring routes/DNS and releasing the WFP session.
        GenerateConsoleCtrlEvent(0, 0);
        try { await engine.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (TimeoutException)
        {
            engine.Kill(true);
            await engine.WaitForExitAsync();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AllocConsole();
    [DllImport("kernel32.dll")] private static extern bool FreeConsole();
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GenerateConsoleCtrlEvent(uint controlEvent, uint processGroupId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}

internal sealed class EngineJob : IDisposable
{
    private readonly IntPtr handle;
    internal EngineJob()
    {
        handle = CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        var info = new ExtendedLimits { Basic = new BasicLimits { LimitFlags = 0x2000 } }; // KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(handle, 9, ref info, (uint)Marshal.SizeOf<ExtendedLimits>()))
        { var error = Marshal.GetLastWin32Error(); Dispose(); throw new Win32Exception(error); }
    }
    internal void Assign(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public void Dispose() { if (handle != IntPtr.Zero) CloseHandle(handle); }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long ProcessTime, JobTime; public uint LimitFlags; public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint Priority, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}
