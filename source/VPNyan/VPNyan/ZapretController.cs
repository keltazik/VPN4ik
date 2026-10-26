using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace VPNyan;

internal interface IZapretController
{
    Task<ZapretState> ReadAsync(string folder, CancellationToken token);
    Task<ZapretResult> RunAsync(ZapretRequest request, CancellationToken token);
}
internal sealed class ZapretController(bool elevate = true) : IZapretController
{
    private readonly SemaphoreSlim operations = new(1, 1);
    public Task<ZapretState> ReadAsync(string folder, CancellationToken token) => Task.Run(() => string.IsNullOrEmpty(folder) ? new ZapretState() : ZapretNative.ReadState(folder), token);

    public async Task<ZapretResult> RunAsync(ZapretRequest request, CancellationToken token)
    {
        await operations.WaitAsync(token);
        try
        {
            token.ThrowIfCancellationRequested();
            var name = "VPN4ik-Zapret-" + Guid.NewGuid().ToString("N");
            var security = new PipeSecurity();
            var owner = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Не определён пользователь Windows.");
            security.SetOwner(owner); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            using var pipe = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 8192, 8192, security);
            var start = new ProcessStartInfo(Environment.ProcessPath ?? throw new IOException("Не найдено приложение.")) { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden };
            if (elevate) start.Verb = "runas";
            start.ArgumentList.Add("--zapret-host"); start.ArgumentList.Add(name); start.ArgumentList.Add(Environment.ProcessId.ToString());
            using var host = await Task.Run(() => Process.Start(start)) ?? throw new IOException("Не удалось запустить управление zapret.");
            using var connect = CancellationTokenSource.CreateLinkedTokenSource(token); connect.CancelAfter(TimeSpan.FromSeconds(60));
            await pipe.WaitForConnectionAsync(connect.Token);
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var id) || id != host.Id) throw new IOException("Не подтверждён процесс управления zapret.");
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };
            if (await reader.ReadLineAsync(connect.Token) != "ready") throw new IOException("Не подтверждён канал управления zapret.");
            token.ThrowIfCancellationRequested();
            var json = JsonSerializer.Serialize(request);
            if (json.Length > 2 * 1024 * 1024) throw new InvalidDataException("Слишком большой запрос zapret.");
            await writer.WriteLineAsync(json);
            // Once the operation is submitted, collect its result/restore snapshot even if the user closes the UI.
            using var finish = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var response = await reader.ReadLineAsync(finish.Token);
            if (response == null || response.Length > 2 * 1024 * 1024) throw new IOException("Нет подтверждения операции zapret.");
            return JsonSerializer.Deserialize<ZapretResult>(response) ?? throw new IOException("Некорректный ответ управления zapret.");
        }
        finally { operations.Release(); }
    }

    internal static async Task<int> RunHostAsync(string name, int parentId)
    {
        if (!name.StartsWith("VPN4ik-Zapret-", StringComparison.Ordinal) || name.Length > 64 || parentId <= 0) return 2;
        try
        {
            using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await pipe.ConnectAsync(timeout.Token);
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var id) || id != parentId) return 3;
            using var parent = Process.GetProcessById(parentId);
            if (!string.Equals(parent.MainModule?.FileName, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)) return 3;
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };
            await writer.WriteLineAsync("ready");
            var json = await reader.ReadLineAsync(timeout.Token);
            if (parent.HasExited || json == null || json.Length > 2 * 1024 * 1024) return 4;
            var request = JsonSerializer.Deserialize<ZapretRequest>(json) ?? throw new InvalidDataException();
            var result = await ZapretNative.ExecuteAsync(request);
            await writer.WriteLineAsync(JsonSerializer.Serialize(result)); return result.Success ? 0 : 1;
        }
        catch { return 1; }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint id);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint id);
}

internal sealed class InactiveZapretController : IZapretController
{
    public Task<ZapretState> ReadAsync(string folder, CancellationToken token) => Task.FromResult(new ZapretState());
    public Task<ZapretResult> RunAsync(ZapretRequest request, CancellationToken token) => throw new InvalidOperationException("Управление zapret доступно при обычном запуске приложения.");
}
