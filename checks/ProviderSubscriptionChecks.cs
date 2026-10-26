using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VPNyan;

internal static class ProviderSubscriptionChecks
{
    internal static async Task<int> RunAsync(string protectedResponse, string resultPath)
    {
        EngineHost.VerifyFiles();
        var body = Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(protectedResponse), null, DataProtectionScope.CurrentUser));
        var profiles = SubscriptionParser.Parse(body);
        var valid = new List<SubscriptionProfile>();
        var failures = new List<object>();
        foreach (var (profile, index) in profiles.Select((profile, index) => (profile, index)))
        {
            try
            {
                var config = XrayConfiguration.Build(new EngineRequest { Profile = profile, EnableTun = false, ProbePort = 49152 });
                await HysteriaChecks.ValidateNativeAsync(config);
                valid.Add(profile);
            }
            catch (Exception ex)
            {
                failures.Add(new { Index = index, profile.Protocol, Error = new SecretRedactor(profile.Configuration).Clean(ex.Message) });
            }
        }
        var directory = Path.GetDirectoryName(Path.GetFullPath(resultPath))!;
        SubscriptionStore.Save(Path.Combine(directory, "provider-imported.dpapi"), new[] { new Subscription { Url = "https://example.test/provider-check", Profiles = profiles } });
        foreach (var protocol in new[] { "VLESS", "HYSTERIA" })
        {
            var candidate = valid.FirstOrDefault(profile => profile.Protocol == protocol);
            if (candidate == null) continue;
            SubscriptionStore.Save(Path.Combine(directory, "provider-" + protocol.ToLowerInvariant() + ".dpapi"),
                new[] { new Subscription { Url = "https://example.test/provider-check", Profiles = new() { candidate } } });
        }
        var report = new { Imported = profiles.Count, NativeConfigurationsValid = valid.Count,
            Protocols = profiles.GroupBy(p => p.Protocol).ToDictionary(g => g.Key, g => g.Count()), Failures = failures };
        File.WriteAllText(resultPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Provider response: {profiles.Count} imported; {valid.Count} accepted by native Xray; {failures.Count} rejected.");
        return failures.Count == 0 ? 0 : 1;
    }
}
