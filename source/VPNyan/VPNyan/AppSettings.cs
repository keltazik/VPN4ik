using System;
using System.IO;
using System.Text.Json;

namespace VPNyan
{
    public class AppSettings
    {
        internal string? StoragePath { get; set; }
        public bool KillSwitch { get; set; }
        public bool StartWithWindows { get; set; }
        public bool MinimizeToTray { get; set; } = true;
        public bool CloseToTray { get; set; }
        public bool StartMinimized { get; set; }
        public bool AutoConnect { get; set; }
        public bool ShowNotifications { get; set; } = true;
        public bool CheckForUpdates { get; set; } = true;
        public string ZapretFolder { get; set; } = "";
        public string ZapretStrategy { get; set; } = "";
        public bool DisableZapretOnConnect { get; set; }
        public bool RestoreZapretAfterVpn { get; set; } = true;
        public string LastServer { get; set; } = "";
        public string Theme { get; set; } = "dark";
        public string Language { get; set; } = "ru";
        public int TunMtu { get; set; } = 1500;
        public string ConnectionMode { get; set; } = "tun";
        public bool UseLocalDns { get; set; }
        public bool UseHiddifyCore { get; set; } = true;
        public bool NavigationExpanded { get; set; }
        public string ServerSort { get; set; } = "original";
        public bool AutoCheckPings { get; set; } = true;
        public int PingIntervalSeconds { get; set; } = 60;
        public string TrafficUnit { get; set; } = "Mbps";
        public bool BypassLocalNetwork { get; set; }
        public string DnsServers { get; set; } = "1.1.1.1\n1.0.0.1";
        public bool SplitTunnelEnabled { get; set; }
        public string SplitTunnelMode { get; set; } = "Bypass";
        public List<string> SplitApplications { get; set; } = new();
        public List<string> SplitDomains { get; set; } = new();
        public List<string> SplitNetworks { get; set; } = new();

        private static string SettingsPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "VPNyan", "settings.json");

        public void Save()
        {
            try { SaveOrThrow(); }
            catch { }
        }

        internal void SaveOrThrow()
        {
            var path = StoragePath ?? SettingsPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(path + ".tmp", path, true);
        }

        internal AppSettings Copy() => new()
        {
            KillSwitch = KillSwitch, StartWithWindows = StartWithWindows, MinimizeToTray = MinimizeToTray, CloseToTray = CloseToTray,
            StartMinimized = StartMinimized, AutoConnect = AutoConnect, ShowNotifications = ShowNotifications, CheckForUpdates = CheckForUpdates,
            ZapretFolder = ZapretFolder, ZapretStrategy = ZapretStrategy, DisableZapretOnConnect = DisableZapretOnConnect, RestoreZapretAfterVpn = RestoreZapretAfterVpn,
            LastServer = LastServer, Theme = Theme, Language = Language, TunMtu = TunMtu, ConnectionMode = ConnectionMode, UseLocalDns = UseLocalDns, UseHiddifyCore = UseHiddifyCore, NavigationExpanded = NavigationExpanded, ServerSort = ServerSort, StoragePath = StoragePath,
            AutoCheckPings = AutoCheckPings, PingIntervalSeconds = PingIntervalSeconds, TrafficUnit = TrafficUnit,
            BypassLocalNetwork = BypassLocalNetwork, DnsServers = DnsServers, SplitTunnelEnabled = SplitTunnelEnabled,
            SplitTunnelMode = SplitTunnelMode, SplitApplications = new(SplitApplications), SplitDomains = new(SplitDomains), SplitNetworks = new(SplitNetworks)
        };

        public static AppSettings Load() => LoadFromPath(null);

        internal static AppSettings LoadFromPath(string? storagePath)
        {
            try
            {
                var path = storagePath ?? SettingsPath;
                if (File.Exists(path))
                {
                    var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path)) ?? new AppSettings();
                    settings.StoragePath = storagePath;
                    if (settings.ConnectionMode is not ("tun" or "proxy")) settings.ConnectionMode = "tun";
                    if (settings.Language is not ("ru" or "en" or "hy")) settings.Language = "ru";
                    // Migrate only our former factory DNS pair; preserve user-defined resolvers.
                    if (settings.DnsServers.Replace("\r", "") == "1.1.1.1\n2606:4700:4700::1111") settings.DnsServers = "1.1.1.1\n1.0.0.1";
                    return settings;
                }
            }
            catch { }
            return new AppSettings { StoragePath = storagePath };
        }
    }
}
