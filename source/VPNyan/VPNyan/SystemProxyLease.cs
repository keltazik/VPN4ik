using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;

namespace VPNyan;

internal sealed record ProxyState(int? Enabled, string? Server, string? Bypass, string? Pac);
internal interface IProxySettingsBackend
{
    ProxyState Read();
    void Write(ProxyState state);
}

// Runs in the owned, non-elevated engine helper. Parent/pipe death restores the previous proxy too.
internal sealed class SystemProxyLease : IDisposable
{
    private static string StatePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPN4ik", "proxy-restore.dpapi");
    private readonly IProxySettingsBackend backend;
    private readonly string path;
    private readonly Semaphore gate;
    private bool disposed;
    private ProxyRecovery? recovery;
    private sealed record ProxyRecovery(string Server, ProxyState Previous);
    private SystemProxyLease(IProxySettingsBackend backend, string path, string gateName)
    {
        this.backend = backend; this.path = path;
        gate = new Semaphore(1, 1, gateName);
        if (!gate.WaitOne(0)) { gate.Dispose(); throw new IOException("Другой сеанс VPN4ik уже управляет системным прокси."); }
    }
    internal static SystemProxyLease Start(int port, IProxySettingsBackend? backend = null, string? path = null, string? gateName = null)
    {
        if (port is < 1024 or > 65535) throw new InvalidDataException("Некорректный порт прокси.");
        var lease = new SystemProxyLease(backend ?? new WindowsProxySettings(), path ?? StatePath, gateName ?? "Local\\VPN4ik.SystemProxy");
        try
        {
            lease.Recover();
            var server = $"http=127.0.0.1:{port};https=127.0.0.1:{port}";
            lease.recovery = new ProxyRecovery(server, lease.backend.Read());
            Directory.CreateDirectory(Path.GetDirectoryName(lease.path)!);
            var bytes = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(lease.recovery), null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(lease.path + ".tmp", bytes); File.Move(lease.path + ".tmp", lease.path, true);
            try { lease.backend.Write(new ProxyState(1, server, "<local>;127.*;localhost;[::1]", null)); }
            catch { lease.backend.Write(lease.recovery.Previous); File.Delete(lease.path); throw; }
            return lease;
        }
        catch { lease.disposed = true; lease.gate.Release(); lease.gate.Dispose(); throw; }
    }
    internal static void RecoverAfterCrash()
    {
        if (!File.Exists(StatePath)) return;
        using var lease = new SystemProxyLease(new WindowsProxySettings(), StatePath, "Local\\VPN4ik.SystemProxy");
        lease.Recover();
    }
    private void Recover()
    {
        if (!File.Exists(path)) return;
        var pending = JsonSerializer.Deserialize<ProxyRecovery>(ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser))
            ?? throw new InvalidDataException("Не удалось восстановить прежний системный прокси.");
        Restore(pending);
    }
    private void Restore(ProxyRecovery pending)
    {
        var current = backend.Read();
        // Never overwrite a proxy changed by the user or another application since activation.
        if (current.Enabled == 1 && current.Server == pending.Server && current.Pac == null)
            backend.Write(pending.Previous);
        File.Delete(path);
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        try { if (recovery != null) Restore(recovery); }
        finally { gate.Release(); gate.Dispose(); }
    }
    internal static async Task WaitForListenerAsync(int port, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(8));
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            using var socket = new TcpClient(AddressFamily.InterNetwork);
            try { await socket.ConnectAsync(IPAddress.Loopback, port, timeout.Token); return; }
            catch (SocketException) { await Task.Delay(80, timeout.Token); }
        }
    }
}

internal sealed class WindowsProxySettings : IProxySettingsBackend
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    public ProxyState Read()
    {
        using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
        return new ProxyState((int?)key?.GetValue("ProxyEnable"), (string?)key?.GetValue("ProxyServer"), (string?)key?.GetValue("ProxyOverride"), (string?)key?.GetValue("AutoConfigURL"));
    }
    public void Write(ProxyState state)
    {
        using var key = Registry.CurrentUser.CreateSubKey(KeyPath, true);
        Set(key, "ProxyServer", state.Server); Set(key, "ProxyOverride", state.Bypass); Set(key, "AutoConfigURL", state.Pac);
        if (state.Enabled.HasValue) key.SetValue("ProxyEnable", state.Enabled.Value, RegistryValueKind.DWord); else key.DeleteValue("ProxyEnable", false);
        if (!InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0) || !InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0))
            throw new IOException("Windows не применила настройки системного прокси.");
    }
    private static void Set(RegistryKey key, string name, string? value)
    { if (value == null) key.DeleteValue(name, false); else key.SetValue(name, value, RegistryValueKind.String); }
    [DllImport("wininet.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int length);
}