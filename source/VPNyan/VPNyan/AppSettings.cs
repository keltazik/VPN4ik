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
        public string ConnectionVisual { get; set; } = "ornament";
        public string WordmarkStyle { get; set; } = "classic";
        public string Language { get; set; } = "ru";
        public bool UseSystemLanguage { get; set; }
        public bool AutoUpdateSubscriptions { get; set; }
        public int SubscriptionUpdateHours { get; set; } = 2;
        public bool NotifySubscriptionUpdates { get; set; }
        public bool RefreshSubscriptionsOnStartup { get; set; }
        public bool PingAfterSubscriptionUpdate { get; set; }
        public bool ShowMemoryUsage { get; set; }
        public bool SniffDomains { get; set; } = true;
        public List<RoutingPreset> RoutingPresets { get; set; } = new();
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
            try
            {
                File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(path + ".tmp", path, true);
            }
            finally { try { if(File.Exists(path+".tmp")) File.Delete(path+".tmp"); } catch { } }
        }

        internal AppSettings Copy() => new()
        {
            KillSwitch = KillSwitch, StartWithWindows = StartWithWindows, MinimizeToTray = MinimizeToTray, CloseToTray = CloseToTray,
            StartMinimized = StartMinimized, AutoConnect = AutoConnect, ShowNotifications = ShowNotifications, CheckForUpdates = CheckForUpdates,
            ZapretFolder = ZapretFolder, ZapretStrategy = ZapretStrategy, DisableZapretOnConnect = DisableZapretOnConnect, RestoreZapretAfterVpn = RestoreZapretAfterVpn,
            LastServer = LastServer, Theme = Theme, ConnectionVisual = ConnectionVisual, WordmarkStyle=WordmarkStyle, Language = Language, TunMtu = TunMtu, ConnectionMode = ConnectionMode, UseLocalDns = UseLocalDns, UseHiddifyCore = UseHiddifyCore, NavigationExpanded = NavigationExpanded, ServerSort = ServerSort, StoragePath = StoragePath,
            UseSystemLanguage = UseSystemLanguage, AutoUpdateSubscriptions = AutoUpdateSubscriptions, SubscriptionUpdateHours = SubscriptionUpdateHours,
            NotifySubscriptionUpdates = NotifySubscriptionUpdates, RefreshSubscriptionsOnStartup = RefreshSubscriptionsOnStartup,
            PingAfterSubscriptionUpdate = PingAfterSubscriptionUpdate, ShowMemoryUsage = ShowMemoryUsage, SniffDomains = SniffDomains,
            RoutingPresets = RoutingPresets.Select(p => p.Copy()).ToList(),
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
                    settings.Normalize();
                    if (settings.Language is not ("ru" or "en" or "hy")) settings.Language = "ru";
                    // Migrate only our former factory DNS pair; preserve user-defined resolvers.
                    if (settings.DnsServers.Replace("\r", "") == "1.1.1.1\n2606:4700:4700::1111") settings.DnsServers = "1.1.1.1\n1.0.0.1";
                    return settings;
                }
            }
            catch { }
            return new AppSettings { StoragePath = storagePath };
        }

        internal string EffectiveLanguage => UseSystemLanguage ? System.Globalization.CultureInfo.InstalledUICulture.TwoLetterISOLanguageName switch
        { "ru" => "ru", "hy" => "hy", _ => "en" } : Language;

        internal void Normalize()
        {
            if(WordmarkStyle is not ("classic" or "editorial" or "palatial" or "modern" or "signature" or "four"))WordmarkStyle="classic";
            if (Theme is not ("dark" or "wine" or "night" or "plum")) Theme="dark";
            if (ConnectionVisual is not ("ornament" or "halo" or "compact" or "button")) ConnectionVisual="ornament";
            if (ConnectionMode is not ("tun" or "proxy")) ConnectionMode = "tun";
            if (Language is not ("ru" or "en" or "hy")) Language = "ru";
            if (TunMtu is < 1280 or > 1500) TunMtu = 1500;
            if (PingIntervalSeconds is not (30 or 60 or 120)) PingIntervalSeconds = 60;
            if (SubscriptionUpdateHours is < 1 or > 24) SubscriptionUpdateHours = 2;
            if (ServerSort is not ("original" or "ping" or "name" or "country" or "protocol")) ServerSort = "original";
            SplitApplications ??= new(); SplitDomains ??= new(); SplitNetworks ??= new(); RoutingPresets ??= new();
            RoutingPresets=RoutingPresets.Where(p=>p!=null).ToList();
            foreach(var preset in RoutingPresets) { preset.Name??=""; preset.Applications??=new(); preset.Domains??=new(); preset.Networks??=new(); }
            DnsServers ??= "1.1.1.1\n1.0.0.1"; ZapretFolder ??= ""; ZapretStrategy ??= "";
        }
    }

    public sealed class RoutingPreset
    {
        public string Name { get; set; } = "";
        public string Mode { get; set; } = "Bypass";
        public bool Enabled { get; set; }
        public List<string> Applications { get; set; } = new();
        public List<string> Domains { get; set; } = new();
        public List<string> Networks { get; set; } = new();
        internal RoutingPreset Copy() => new() { Name=Name, Mode=Mode, Enabled=Enabled, Applications=new(Applications), Domains=new(Domains), Networks=new(Networks) };
        public override string ToString() => Name;
    }
}
