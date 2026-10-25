using System.Diagnostics;
using System.Text.Json;

namespace VPNyan;

internal sealed record TrafficCounters(long Upload, long Download);
internal sealed record TrafficSample(long Upload, long Download, double UploadBytesPerSecond, double DownloadBytesPerSecond);

internal sealed class TrafficMeter
{
    private TrafficCounters? previous;
    private double previousSeconds;
    private long uploaded, downloaded;

    internal void Reset() { previous = null; previousSeconds = 0; uploaded = downloaded = 0; }

    internal TrafficSample Sample(TrafficCounters counters, double seconds)
    {
        double upSpeed = 0, downSpeed = 0;
        if (previous != null && seconds > previousSeconds)
        {
            // A reset/recreated adapter must not create a negative delta or a giant spike.
            var up = counters.Upload >= previous.Upload ? counters.Upload - previous.Upload : 0;
            var down = counters.Download >= previous.Download ? counters.Download - previous.Download : 0;
            uploaded += up; downloaded += down;
            upSpeed = up / (seconds - previousSeconds); downSpeed = down / (seconds - previousSeconds);
        }
        previous = counters; previousSeconds = seconds;
        return new TrafficSample(uploaded, downloaded, upSpeed, downSpeed);
    }

    internal static double MonotonicSeconds => (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency;

    internal static TrafficCounters Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var stats = document.RootElement.GetProperty("stats").GetProperty("outbound");
        if (!stats.TryGetProperty("proxy", out var proxy)) return new(0, 0);
        long Read(string key) => proxy.TryGetProperty(key, out var value) && value.TryGetInt64(out var bytes) && bytes >= 0 ? bytes : 0;
        return new TrafficCounters(Read("uplink"), Read("downlink"));
    }

    internal static string Speed(double bytesPerSecond, string unit) => unit == "MB/s"
        ? $"{bytesPerSecond / 1_000_000:F2} MB/s" : $"{bytesPerSecond * 8 / 1_000_000:F2} Mbps";
}
