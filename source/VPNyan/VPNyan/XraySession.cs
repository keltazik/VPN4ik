using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace VPNyan;

internal sealed class XraySession : IVpnSession
{
    private NamedPipeServerStream? pipe;
    private Process? host;
    private StreamWriter? writer;
    private Task? readerTask;
    private readonly TaskCompletionSource stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource hello = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private EngineRequest? request;
    private bool engineRunning;
    public bool IsRunning => engineRunning && host is { HasExited: false };
    public event Action<string>? Log;
    internal string VerificationStage { get; private set; } = "Запуск";

    public async Task<string> StartAsync(SubscriptionProfile profile, int mtu, CancellationToken cancellationToken,
        bool enableTun = true, bool elevate = true, bool diagnostics = false, AppSettings? routing = null)
    {
        EngineHost.VerifyFiles();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        request = new EngineRequest { Profile = profile, Mtu = mtu, EnableTun = enableTun, Diagnostics = diagnostics,
            Routing = routing?.Copy() ?? new AppSettings(), ProbePort = ((IPEndPoint)listener.LocalEndpoint).Port };
        listener.Stop();
        VerificationStage = "Разрешение адреса сервера";
        var addresses = await Dns.GetHostAddressesAsync(profile.Address, cancellationToken);
        request.EndpointAddress = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString() ?? addresses.FirstOrDefault()?.ToString()
            ?? throw new IOException("Не найден сетевой адрес сервера.");
        if (enableTun) request.UpstreamInterface = SelectUpstreamInterface();
        _ = XrayConfiguration.Build(request); // Reject unsupported/unsafe profiles before asking for UAC.
        await StartHostAsync(request, elevate, cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        while (!timeout.IsCancellationRequested)
        {
            if (!IsRunning) throw new InvalidOperationException("VPN-движок остановился до проверки соединения.");
            try
            {
                VerificationStage = "Ожидание маршрута TUN";
                if (enableTun && !HasTunRoute()) { await Task.Delay(400, timeout.Token); continue; }
                VerificationStage = "Проверка выбранного сервера";
                var ip = await ProbeAsync(timeout.Token);
                if (enableTun)
                {
                    VerificationStage = "Проверка системного маршрута";
                    // Include mode intentionally keeps this application's ordinary requests direct.
                    // The authenticated probe always uses proxy; the TUN route is verified separately.
                    if (!request.Routing.SplitTunnelEnabled)
                    {
                        var systemIp = await ProbeAsync(timeout.Token, useProxy: false);
                        if (systemIp != ip) throw new HttpRequestException("Маршрут VPN не подтверждён.");
                    }
                    if (!HasTunRoute()) throw new HttpRequestException("Маршрут VPN не подтверждён.");
                }
                if (!IsRunning) throw new IOException("VPN-движок остановился.");
                return ip;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !timeout.IsCancellationRequested)
            { Log?.Invoke("Проверка соединения: " + ex.GetType().Name + " · " + ex.Message); await Task.Delay(500, timeout.Token); }
        }
        throw new TimeoutException("Не удалось подтвердить доступ через VPN. Проверь сервер или выбери другой.");
    }

    internal async Task StartLatencyWorkerAsync(EngineRequest batch, CancellationToken cancellationToken)
    {
        EngineHost.VerifyFiles();
        if (batch.EnableTun || batch.Probes == null) throw new InvalidOperationException();
        _ = XrayConfiguration.Build(batch);
        await StartHostAsync(batch, false, cancellationToken);
    }

    private async Task StartHostAsync(EngineRequest engineRequest, bool elevate, CancellationToken cancellationToken)
    {
        var pipeName = "VPN4ik-" + Guid.NewGuid().ToString("N");
        // CurrentUserOnly also requires equal elevation and cannot cross a UAC boundary.
        // An explicit SID ACL plus mutually verified peer PIDs permits just this helper.
        var security = new PipeSecurity();
        var owner = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Не определён пользователь Windows.");
        security.SetOwner(owner);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 8192, 8192, security);
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Не найдено приложение.");
        var startInfo = new ProcessStartInfo(executable) { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden };
        if (elevate) startInfo.Verb = "runas";
        startInfo.ArgumentList.Add("--engine-host");
        startInfo.ArgumentList.Add(pipeName);
        startInfo.ArgumentList.Add(Environment.ProcessId.ToString());
        host = await Task.Run(() => Process.Start(startInfo), cancellationToken) ?? throw new InvalidOperationException("Не удалось запустить VPN-службу.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        await pipe.WaitForConnectionAsync(timeout.Token);
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientId) || clientId != host.Id)
            throw new InvalidOperationException("Не удалось подтвердить VPN-службу.");
        writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };
        readerTask = ReadMessagesAsync();
        await hello.Task.WaitAsync(timeout.Token);
        await writer.WriteLineAsync(JsonSerializer.Serialize(engineRequest));
        await started.Task.WaitAsync(timeout.Token);
    }

    private async Task ReadMessagesAsync()
    {
        try
        {
            using var reader = new StreamReader(pipe!, Encoding.UTF8, false, 8192, true);
            while (await reader.ReadLineAsync() is string line)
            {
                var message = JsonSerializer.Deserialize<EngineMessage>(line);
                if (message?.Type == "hello") hello.TrySetResult();
                else if (message?.Type == "started") { engineRunning = true; started.TrySetResult(); }
                else if (message?.Type == "log") Log?.Invoke(message.Text);
                else if (message?.Type == "error") { Log?.Invoke(message.Text); hello.TrySetException(new InvalidOperationException(message.Text)); started.TrySetException(new InvalidOperationException(message.Text)); }
                else if (message?.Type == "stopped") { engineRunning = false; stopped.TrySetResult(); break; }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        finally
        {
            engineRunning = false;
            hello.TrySetException(new IOException("VPN-служба закрыла канал управления."));
            started.TrySetException(new IOException("VPN-служба закрыла соединение."));
            stopped.TrySetResult();
        }
    }

    public async Task<string> ProbeAsync(CancellationToken cancellationToken, bool useProxy = true)
    {
        if (request == null) throw new InvalidOperationException();
        using var handler = new SocketsHttpHandler { UseProxy = useProxy, ConnectTimeout = TimeSpan.FromSeconds(8),
            Proxy = useProxy ? new WebProxy($"socks5://127.0.0.1:{request.ProbePort}") { Credentials = new NetworkCredential(request.ProbeUser, request.ProbePassword) } : null };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12) };
        using var response = await client.GetAsync("https://api.ipify.org", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        var bytes = new byte[128];
        using var body = new MemoryStream();
        int read;
        while ((read = await input.ReadAsync(bytes, cancellationToken)) != 0)
        {
            if (body.Length + read > 128) throw new HttpRequestException("Некорректный ответ проверки IP.");
            body.Write(bytes, 0, read);
        }
        var value = Encoding.UTF8.GetString(body.ToArray()).Trim();
        if (!IPAddress.TryParse(value, out var address) || address.ToString() != value)
            throw new HttpRequestException("Проверка внешнего IP не прошла.");
        return address.ToString();
    }

    public async Task<TrafficCounters> ReadTrafficAsync(CancellationToken cancellationToken)
    {
        if (request == null || !IsRunning) throw new IOException("VPN-движок остановлен.");
        using var handler = new SocketsHttpHandler { UseProxy = true, AllowAutoRedirect = false,
            Proxy = new WebProxy($"socks5://127.0.0.1:{request.ProbePort}") { Credentials = new NetworkCredential(request.ProbeUser, request.ProbePassword) } };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(1500), MaxResponseContentBufferSize = 1_048_576 };
        var json = await client.GetStringAsync("http://metrics.vpn4ik.invalid/debug/vars", cancellationToken);
        return TrafficMeter.Parse(json);
    }

    internal static bool HasTunRoute()
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(a => a.Name == XrayConfiguration.InterfaceName && a.OperationalStatus == OperationalStatus.Up);
        if (adapter == null) return false;
        var address = new byte[16];
        address[0] = 2; // AF_INET, native little-endian sockaddr_in.
        IPAddress.Parse("1.1.1.1").GetAddressBytes().CopyTo(address, 4);
        return GetBestInterfaceEx(address, out var index) == 0 && index == adapter.GetIPProperties().GetIPv4Properties().Index;
    }

    internal static string SelectUpstreamInterface()
    {
        // A running third-party TUN may itself own the default route. Bind to an
        // active hardware connection so VPN4ik does not depend on that other VPN.
        var physical = NetworkInterface.GetAllNetworkInterfaces()
            .Where(a => a.OperationalStatus == OperationalStatus.Up &&
                a.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 &&
                !System.Text.RegularExpressions.Regex.IsMatch(a.Description + " " + a.Name, "(?i)wintun|wireguard|radmin|\\bVPN\\b|\\bTAP\\b|\\bTUN\\b|Hyper-V Virtual") &&
                a.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)))
            .OrderByDescending(a => a.Speed).FirstOrDefault();
        return physical?.Name ?? "auto";
    }

    internal static object RouteDiagnostic()
    {
        var address = new byte[16]; address[0] = 2; IPAddress.Parse("1.1.1.1").GetAddressBytes().CopyTo(address, 4);
        var error = GetBestInterfaceEx(address, out var index);
        return new { BestInterface = index, Error = error, Adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Select(a => new { a.Name, Status = a.OperationalStatus.ToString(), Index = a.GetIPProperties().GetIPv4Properties()?.Index }).ToArray() };
    }

    internal async Task StopAsync()
    {
        if (writer != null && pipe?.IsConnected == true)
        {
            try { await writer.WriteLineAsync("stop"); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        }
        else pipe?.Dispose();
        if (host != null)
        {
            try { await host.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
            catch (TimeoutException) { throw new IOException("VPN-служба ещё не завершила отключение. Попробуй отключить повторно."); }
        }
        if (readerTask != null) await readerTask;
        engineRunning = false;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        try { writer?.Dispose(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        pipe?.Dispose(); host?.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("iphlpapi.dll")] private static extern uint GetBestInterfaceEx(byte[] address, out uint index);
}
