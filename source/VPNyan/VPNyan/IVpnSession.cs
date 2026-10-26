namespace VPNyan;

internal interface IVpnSession : IAsyncDisposable
{
    bool IsRunning { get; }
    event Action<string>? Log;
    Task<string> StartAsync(SubscriptionProfile profile, int mtu, CancellationToken cancellationToken,
        bool enableTun = true, bool elevate = true, bool diagnostics = false, AppSettings? routing = null);
    Task<string> ProbeAsync(CancellationToken cancellationToken, bool useProxy = true);
    Task<TrafficCounters> ReadTrafficAsync(CancellationToken cancellationToken);
}
