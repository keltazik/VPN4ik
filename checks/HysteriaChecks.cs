using System.Diagnostics;
using VPNyan;

internal static class HysteriaChecks
{
    internal const string ProfileJson = """
        {"remarks":"Hysteria test","outbounds":[{"protocol":"hysteria","settings":{"address":"vpn.example.test","port":443,"version":2},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.test","alpn":["h3"]},"hysteriaSettings":{"version":2,"auth":"test-hysteria-password"},"finalmask":{"quicParams":{"congestion":"bbr","maxIdleTimeout":30}}}},{"protocol":"freedom"}]}
        """;

    internal static async Task ValidateNativeAsync(string config)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(EngineHost.EnginePath)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = EngineHost.EngineDirectory } };
        foreach (var argument in new[] { "run", "-test", "-format=json", "-c", "stdin:" }) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        var output = process.StandardOutput.ReadToEndAsync(); var errors = process.StandardError.ReadToEndAsync();
        try
        {
            await process.StandardInput.WriteAsync(config); process.StandardInput.Close();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await Task.WhenAll(output, errors);
            if (process.ExitCode != 0) throw new InvalidOperationException("Native Xray rejected the generated configuration.");
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
    }
}
