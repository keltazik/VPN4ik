using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VPNyan;

// Service state only: a running service does not prove a handshake or Internet access.
internal static class TunnelService
{
    private static Task<int>? pendingCommand;

    public static async Task WaitForPendingOperationAsync()
    {
        if (pendingCommand is { IsCompleted: false } pending)
            await pending.WaitAsync(TimeSpan.FromSeconds(30));
    }

    public static async Task RunAsync(string executable, string command, string argument)
    {
        await WaitForPendingOperationAsync();
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas"
        };
        start.ArgumentList.Add(command);
        start.ArgumentList.Add(argument);
        pendingCommand = RunProcessAsync(start);
        var exitCode = await pendingCommand.WaitAsync(TimeSpan.FromSeconds(30));
        if (exitCode != 0)
            throw new InvalidOperationException($"WireGuard завершился с кодом {exitCode}.");
    }

    private static async Task<int> RunProcessAsync(ProcessStartInfo start)
    {
        // Own the process until it exits, even if the caller's timeout expires.
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Не удалось запустить WireGuard.");
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    public static int? GetState(string tunnelName)
    {
        var manager = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service = OpenService(manager, "WireGuardTunnel$" + tunnelName, 0x0004);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 1060) return null; // Service does not exist.
                throw new Win32Exception(error);
            }
            try
            {
                if (!QueryServiceStatus(service, out var status))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return status.CurrentState;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    public static async Task WaitForStateAsync(string name, bool running)
    {
        var timer = Stopwatch.StartNew();
        while (timer.Elapsed < TimeSpan.FromSeconds(15))
        {
            var state = GetState(name);
            if (running ? state == 4 : state is null) return;
            await Task.Delay(250);
        }
        throw new TimeoutException("Не удалось подтвердить состояние службы WireGuard.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public int ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
            ServiceSpecificExitCode, CheckPoint, WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, int access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, int access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
