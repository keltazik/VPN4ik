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
    internal int[] OwnedProcessIds { get; private set; } = Array.Empty<int>();
    internal int? HelperProcessId => host?.Id;

    internal async Task StartOwnedBridgeDiagnosticAsync(EngineRequest test, CancellationToken token)
    {
        if(test.EnableTun || test.EnableSystemProxy || !test.UseHiddifyCore || test.Probes!=null || test.HttpProxyPort<1024)
            throw new InvalidOperationException("Некорректная проверка задержки.");
        EngineHost.VerifyFiles(); HiddifyCore.EnsureInstalled();
        _=XrayConfiguration.Build(HiddifyCore.WorkerRequest(test)); _=HiddifyCore.Build(test);
        request=test;await StartHostAsync(test,false,token);
        await SystemProxyLease.WaitForListenerAsync(test.HttpProxyPort,token);
    }

    public async Task<string> StartAsync(SubscriptionProfile profile, int mtu, CancellationToken cancellationToken,
        bool enableTun = true, bool elevate = true, bool diagnostics = false, AppSettings? routing = null)
    {
        EngineHost.VerifyFiles();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        request = new EngineRequest { Profile = profile, Mtu = mtu, EnableTun = enableTun, Diagnostics = diagnostics,
            Routing = routing?.Copy() ?? new AppSettings(), ProbePort = ((IPEndPoint)listener.LocalEndpoint).Port };
        // Saved presets belong to the editor; only the selected live rules travel to the helper.
        request.Routing.RoutingPresets.Clear();
        request.EnableSystemProxy = !enableTun && !diagnostics && request.Routing.ConnectionMode == "proxy";
        request.UseHiddifyCore = request.Routing.UseHiddifyCore && !diagnostics && (enableTun || request.EnableSystemProxy);
        if (request.UseHiddifyCore) await Task.Run(() => HiddifyCore.EnsureInstalled(), cancellationToken);
        if (request.EnableSystemProxy)
        {
            using var httpListener = new TcpListener(IPAddress.Loopback, 0); httpListener.Start();
            request.HttpProxyPort = ((IPEndPoint)httpListener.LocalEndpoint).Port;
        }
        listener.Stop();
        VerificationStage = "Разрешение адреса сервера";
        var addresses = await Dns.GetHostAddressesAsync(profile.Address, cancellationToken);
        VerificationStage = "Выбор сетевого адреса сервера";
        var tcpTransport = profile.Protocol.ToLowerInvariant() is not ("hysteria" or "hysteria2" or "hy2");
        request.EndpointAddress = tcpTransport ? (await ServerEndpointSelector.SelectAsync(addresses, profile.Port, cancellationToken)).ToString()
            : addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString() ?? addresses.FirstOrDefault()?.ToString()
                ?? throw new IOException("Не найден сетевой адрес сервера.");
        request.UpstreamInterface = SelectUpstreamInterface(IPAddress.Parse(request.EndpointAddress));
        _ = XrayConfiguration.Build(request.UseHiddifyCore ? HiddifyCore.WorkerRequest(request) : request); // Validate before UAC.
        if (request.UseHiddifyCore) _ = HiddifyCore.Build(request);
        await StartHostAsync(request, elevate, cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        while (!timeout.IsCancellationRequested)
        {
            if (!IsRunning) throw new InvalidOperationException("VPN-движок остановился до проверки соединения.");
            try
            {
                VerificationStage = "Ожидание маршрута TUN";
                if (enableTun && !HasTunRoute()) { await Task.Delay(150, timeout.Token); continue; }
                VerificationStage = "Проверка выбранного сервера";
                var proxyCheck = ProbeAsync(timeout.Token);
                string ip;
                if (enableTun && !request.Routing.SplitTunnelEnabled)
                {
                    VerificationStage = "Проверка сервера и системного маршрута";
                    var checks = await Task.WhenAll(proxyCheck, ProbeAsync(timeout.Token, useProxy: false));
                    ip = checks[0];
                    // Different exit IPs are possible. The direct probe validates the actual TUN route per socket.
                }
                else ip = await proxyCheck;
                if (enableTun)
                {
                    VerificationStage = "Проверка системного маршрута";
                    if (!HasTunRoute()) throw new HttpRequestException("Маршрут VPN не подтверждён.");
                }
                if (!IsRunning) throw new IOException("VPN-движок остановился.");
                return ip;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !timeout.IsCancellationRequested)
            { Log?.Invoke("Проверка соединения: " + ex.GetType().Name + " · " + ex.Message); await Task.Delay(250, timeout.Token); }
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
                else if (message?.Type == "started") { OwnedProcessIds=message.Text.Split(',').Select(text=>int.TryParse(text,out var id)?id:0).Where(id=>id>0).ToArray(); engineRunning = true; started.TrySetResult(); }
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

    private ConnectionProbe? proxyProbe, systemProbe;
    private HttpClient? metricsClient;
    public Task<string> ProbeAsync(CancellationToken cancellationToken, bool useProxy = true)
    {
        if (request == null) throw new InvalidOperationException();
        if (useProxy) return (proxyProbe ??= new ConnectionProbe(CreateProbeHandler(true))).CheckAsync(cancellationToken);
        return (systemProbe ??= new ConnectionProbe(CreateProbeHandler(false))).CheckAsync(cancellationToken);
    }
    private SocketsHttpHandler CreateProbeHandler(bool proxy, bool controlOnly = false)
    {
        if (request == null) throw new InvalidOperationException();
        var handler = new SocketsHttpHandler
        {
            UseProxy = proxy, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2), MaxResponseHeadersLength = 8,
            Proxy = proxy ? !controlOnly && request.UseHiddifyCore && request.EnableSystemProxy && !request.Routing.SplitTunnelEnabled && !request.Routing.BypassLocalNetwork
                ? new WebProxy($"http://127.0.0.1:{request.HttpProxyPort}")
                : new WebProxy($"socks5://127.0.0.1:{request.ProbePort}") { Credentials = new NetworkCredential(request.ProbeUser, request.ProbePassword) } : null
        };
        if (!proxy && request.EnableTun) handler.ConnectCallback = ConnectThroughTunAsync;
        return handler;
    }
    private static async ValueTask<Stream> ConnectThroughTunAsync(SocketsHttpConnectionContext context, CancellationToken token)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, token);
        foreach (var address in addresses.OrderBy(ip => ip.AddressFamily != AddressFamily.InterNetwork))
        {
            // The system-path check must actually use our TUN, even with another VPN installed.
            if (!HasTunRoute(address)) continue;
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, token);
                if (!HasTunRoute(address)) throw new IOException("Маршрут TUN изменился во время проверки.");
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (ex is SocketException or IOException) { socket.Dispose(); }
            catch { socket.Dispose(); throw; }
        }
        throw new HttpRequestException("Не подтверждён системный маршрут через VPN4ik-TUN.");
    }
    public async Task<TrafficCounters> ReadTrafficAsync(CancellationToken cancellationToken)
    {
        if (request == null || !IsRunning) throw new IOException("VPN-движок остановлен.");
        metricsClient ??= new HttpClient(CreateProbeHandler(true, controlOnly:true)) { Timeout = TimeSpan.FromMilliseconds(1500), MaxResponseContentBufferSize = 1_048_576 };
        var json = await metricsClient.GetStringAsync("http://metrics.vpn4ik.invalid/debug/vars", cancellationToken);
        return TrafficMeter.Parse(json);
    }

    internal static bool HasTunRoute() => HasTunRoutes(Socket.OSSupportsIPv6, HasTunRoute);
    // An IPv4-only route must not turn a dual-stack TUN green while IPv6 still escapes elsewhere.
    internal static bool HasTunRoutes(bool ipv6Enabled, Func<IPAddress, bool> route) =>
        route(IPAddress.Parse("1.1.1.1")) && (!ipv6Enabled || route(IPAddress.Parse("2606:4700:4700::1111")));
    internal static bool HasTunRoute(IPAddress destination)
    {
        try
        {
            var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(a => a.Name == XrayConfiguration.InterfaceName && a.OperationalStatus == OperationalStatus.Up);
            if (adapter == null) return false;
            var serialized = new IPEndPoint(destination, 0).Serialize();
            var address = new byte[serialized.Size]; for (var item = 0; item < address.Length; item++) address[item] = serialized[item];
            var properties = adapter.GetIPProperties();
            var expected = destination.AddressFamily == AddressFamily.InterNetwork ? properties.GetIPv4Properties()?.Index : properties.GetIPv6Properties()?.Index;
            return expected.HasValue && GetBestInterfaceEx(address, out var index) == 0 && index == expected.Value;
        }
        catch (NetworkInformationException) { return false; }
    }

    internal static string SelectUpstreamInterface(IPAddress? destination = null)
    {
        // A running third-party TUN may itself own the default route. Bind to an
        // active hardware connection so VPN4ik does not depend on that other VPN.
        destination ??= IPAddress.Parse("1.1.1.1");
        var physical = NetworkInterface.GetAllNetworkInterfaces()
            .Where(a => a.OperationalStatus == OperationalStatus.Up &&
                a.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 &&
                !System.Text.RegularExpressions.Regex.IsMatch(a.Description + " " + a.Name, "(?i)wintun|wireguard|radmin|\\bVPN\\b|\\bTAP\\b|\\bTUN\\b|Hyper-V Virtual") &&
                a.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == destination.AddressFamily &&
                    !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any)))
            .Select(a => (a.Name, Index: (uint?)(destination.AddressFamily == AddressFamily.InterNetwork
                ? a.GetIPProperties().GetIPv4Properties()?.Index : a.GetIPProperties().GetIPv6Properties()?.Index), a.Speed))
            .Where(a => a.Index.HasValue).Select(a => (a.Name, Index: a.Index!.Value, a.Speed)).ToArray();
        var serialized = new IPEndPoint(destination, 0).Serialize();
        var address = new byte[serialized.Size]; for (var i = 0; i < address.Length; i++) address[i] = serialized[i];
        uint? preferred = GetBestInterfaceEx(address, out var best) == 0 ? best : null;
        return ChooseUpstreamInterface(physical, preferred);
    }

    internal static string ChooseUpstreamInterface(IEnumerable<(string Name, uint Index, long Speed)> physical, uint? preferred)
    {
        var candidates = physical.ToArray();
        // Respect Windows' selected physical route before link speed. Never select a third-party TUN.
        return candidates.FirstOrDefault(a => a.Index == preferred).Name ??
            candidates.OrderByDescending(a => a.Speed).FirstOrDefault().Name ?? "auto";
    }

    internal static object RouteDiagnostic()
    {
        var address = new byte[16]; address[0] = 2; IPAddress.Parse("1.1.1.1").GetAddressBytes().CopyTo(address, 4);
        var error = GetBestInterfaceEx(address, out var index);
        return new { BestInterface = index, Error = error, Adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Select(a => new { a.Name, Status = a.OperationalStatus.ToString(), Index = ReadInterfaceIndex(() => a.GetIPProperties().GetIPv4Properties()?.Index) }).ToArray() };
    }

    internal static int? ReadInterfaceIndex(Func<int?> read)
    {
        // Disabled/IPv6-only adapters can throw WSAEPROTONOSUPPORT on Windows.
        // A diagnostic must retain the other interfaces instead of masking the original connection error.
        try { return read(); }
        catch (NetworkInformationException) { return null; }
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
        proxyProbe?.Dispose(); systemProbe?.Dispose(); metricsClient?.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("iphlpapi.dll")] private static extern uint GetBestInterfaceEx(byte[] address, out uint index);
}
