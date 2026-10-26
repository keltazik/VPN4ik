using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using WpfApplication = System.Windows.Application;
using WpfColor = System.Windows.Media.Color;
using WpfColorConverter = System.Windows.Media.ColorConverter;
using WpfMessageBox = System.Windows.MessageBox;
using WpfMessageBoxButton = System.Windows.MessageBoxButton;
using WpfMessageBoxImage = System.Windows.MessageBoxImage;
using WpfMouseButtonEventArgs = System.Windows.Input.MouseButtonEventArgs;
using WpfMouseEventArgs = System.Windows.Input.MouseEventArgs;
using MouseEventArgs = System.Windows.Input.MouseEventArgs;

namespace VPNyan
{
    // ============================================
    // КЛАСС СЕРВЕРА
    // ============================================
    public class ServerItem : INotifyPropertyChanged
    {
        public string ConfigPath { get; set; } = "";
        private string name = "", countryCode = "";
        public string Name
        {
            get => name;
            set
            {
                if (name == value) return;
                name = value ?? ""; countryCode = ServerCountry.Identify(name);
                OnPropertyChanged(nameof(Name)); OnPropertyChanged(nameof(DisplayName));
                OnPropertyChanged(nameof(CountryCode)); OnPropertyChanged(nameof(CountryFlag)); OnPropertyChanged(nameof(CountryLabel));
            }
        }
        public string DisplayName => ServerCountry.DisplayName(Name);
        public string CountryCode => countryCode;
        public ImageSource CountryFlag => ServerCountry.Flag(countryCode);
        public string CountryLabel => countryCode == "" ? "Страна не указана в названии сервера" : ServerCountry.Label(countryCode) + " · по названию сервера";
        public string Address { get; set; } = "";
        public int Port { get; set; }
        public string VpnEndpoint { get; set; } = "";
        public string TunnelName { get; set; } = "";
        public string Protocol { get; set; } = "WireGuard";
        public string SubscriptionUrl { get; set; } = "";
        public string ProfileId { get; set; } = "";
        public string Configuration { get; set; } = "";
        public string SelectionKey => string.IsNullOrEmpty(ProfileId) ? Name : "subscription:" +
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(SubscriptionUrl))) + ":" + ProfileId;
        public bool CanConnect => Protocol == "WireGuard" || XrayConfiguration.Supports(Protocol);
        public int Ping { get; set; } = -1;
        public string PingDisplay { get; set; } = "—";
        public string PingColor { get; set; } = "#A78762";
        public string PingDetail { get; private set; } = "TCP-пинг ещё не измерен.";
        public DateTime? LatencyMeasuredAt { get; private set; }
        public bool LatencyViaVpn { get; private set; }
        public bool PingPotentiallyInaccurate { get; private set; }
        public List<int> PingHistory { get; set; } = new List<int>();

        public void UpdatePingDisplay()
        {
            if (Ping < 0) { PingDisplay = "Нет замера"; PingColor = "#A78762"; }
            else if (Ping < 30) { PingDisplay = $"{Ping} ms"; PingColor = "#00D26A"; }
            else if (Ping < 60) { PingDisplay = $"{Ping} ms"; PingColor = "#4CAF50"; }
            else if (Ping < 100) { PingDisplay = $"{Ping} ms"; PingColor = "#FFD27A"; }
            else if (Ping < 200) { PingDisplay = $"{Ping} ms"; PingColor = "#FF9F43"; }
            else { PingDisplay = $"{Ping} ms"; PingColor = "#D4AA65"; }

            if (Ping >= 0 && PingPotentiallyInaccurate) PingDisplay = "≈ " + PingDisplay;

            PingHistory.Add(Ping);
            if (PingHistory.Count > 20) PingHistory.RemoveAt(0);
            OnPropertyChanged(nameof(PingDisplay));
            OnPropertyChanged(nameof(PingColor));
            OnPropertyChanged(nameof(Display));
        }

        internal void SetLatency(LatencyResult result)
        {
            Ping = result.Milliseconds;
            PingDetail = result.Detail;
            PingPotentiallyInaccurate = result.PotentiallyInaccurate;
            LatencyMeasuredAt = result.Measured ? DateTime.UtcNow : null;
            LatencyViaVpn = result.Measured && result.Kind == LatencyKind.Https;
            UpdatePingDisplay();
            OnPropertyChanged(nameof(PingDetail));
        }

        internal void SetLatencyPending()
        {
            Ping = -1;
            PingDisplay = "…";
            PingColor = "#A78762";
            LatencyMeasuredAt = null;
            LatencyViaVpn = false;
            PingPotentiallyInaccurate = false;
            PingDetail = "Проверяю TCP-пинг до порта сервера.";
            OnPropertyChanged(nameof(PingDisplay)); OnPropertyChanged(nameof(PingColor)); OnPropertyChanged(nameof(PingDetail));
        }

        public string Display => $"{Name} | {PingDisplay}";
        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    // ============================================
    // РЕСУРСЫ
    // ============================================
    public static class ResourceExtractor
    {
        public static void Extract(string resourceName, string outputPath)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) throw new Exception($"Resource not found: {resourceName}");
            using var file = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            stream.CopyTo(file);
        }
        public static bool ResourceExists(string resourceName) =>
            Assembly.GetExecutingAssembly().GetManifestResourceNames().Contains(resourceName);
    }

    // ============================================
    // ГЛАВНОЕ ОКНО
    // ============================================
    public partial class MainWindow : Window
    {
        string tempPath = "", wgPath = "";
        DispatcherTimer? pingTimer, dotsTimer, connectionTimer, trafficTimer;
        int dotsCount = 0;
        bool isConnected, isConnecting, isMouseOverOrnament, ornamentPressed;
        DateTime connectionStartTime;
        ServerItem? activeServer;
        bool isUpdatingPings, allowClose, isImporting;
        readonly System.Threading.CancellationTokenSource lifetime = new();
        List<Subscription> subscriptions = new();
        string SubscriptionPath => Path.Combine(tempPath, "subscriptions.dpapi");
        readonly TrafficMeter trafficMeter = new();
        bool readingTraffic;
        readonly ObservableCollection<ServerItem> servers = new();
        AppSettings settings = new();
        SystemTray? systemTray;
        ActivityStore activity = null!;
        IVpnSession? xraySession;
        readonly Func<IVpnSession> sessionFactory;
        readonly bool canCreateSession;
        ConnectionRecord? currentRecord;
        CancellationTokenSource? connectionCancellation;
        bool useBackground, closeRequested, isCheckingConnection, lastProbeFailed;
        DateTime lastConnectionCheck;
        AppSettings? draftSettings;
        CancellationTokenSource? latencyCancellation;
        bool latencyRefreshRequested;

        public MainWindow() : this(true) { }

        internal MainWindow(bool startMonitoring, string? dataDirectory = null, Func<IVpnSession>? connectionFactory = null)
        {
            sessionFactory = connectionFactory ?? (() => new XraySession());
            canCreateSession = startMonitoring || connectionFactory != null;
            InitializeComponent();
            UpdateOrnamentCache();
            Loaded += (_, _) => UpdateOrnamentCache();
            DpiChanged += (_, _) => UpdateOrnamentCache();
            useBackground = startMonitoring;
            // Keep the initial window inside the available desktop, including at high DPI.
            Height = Math.Min(Height, SystemParameters.WorkArea.Height);
            Width = Math.Min(Width, SystemParameters.WorkArea.Width);
            MinHeight = Math.Min(MinHeight, Height);
            MinWidth = Math.Min(MinWidth, Width);
            settings = AppSettings.LoadFromPath(dataDirectory == null ? null : Path.Combine(dataDirectory, "settings.json"));
            MenuToggleButton.IsChecked = settings.NavigationExpanded;
            ApplyNavigationLayout(false);
            if (startMonitoring) ApplySettings();
            if (startMonitoring) systemTray = new SystemTray(this);

            tempPath = dataDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPN4ik");
            Directory.CreateDirectory(tempPath);
            activity = new ActivityStore(tempPath);
            LogsList.ItemsSource = activity.Logs;
            HistoryList.ItemsSource = activity.History;
            activity.Add("Информация", "Приложение запущено.");
            wgPath = Path.Combine(tempPath, "wireguard.exe");

            if (startMonitoring) ExtractResources();
            SetupServers();
            try
            {
                subscriptions = SubscriptionStore.Load(SubscriptionPath);
                foreach (var subscription in subscriptions) AddSubscriptionServers(subscription);
            }
            catch { SubscriptionStatusText.Text = "Не удалось прочитать подписки. Импортируй ссылку повторно."; }

            ServerSelect.ItemsSource = servers;
            ServerSelect.SelectionChanged += ServerSelect_SelectionChanged;
            InitializeServerManagement();
            LoadSavedServer();
            if (servers.Count == 0) StatusText.Text = "Добавь подписку или конфигурацию сервера";
            UpdateServerControls();

            InitializeUpdates();
            if (startMonitoring)
            {
                StartPingLoop();
                StartConnectionTimer();
                StartTrafficMonitor();
                Loaded += async (_, _) => { if (settings.StartMinimized) WindowState = WindowState.Minimized; if (settings.AutoConnect) await Connect(); };
            }
        }

        void ExtractResources()
        {
            try
            {
                if (ResourceExtractor.ResourceExists("VPNyan.Resources.wireguard.exe"))
                {
                    ResourceExtractor.Extract("VPNyan.Resources.wireguard.exe", wgPath);
                }
                else
                {
                    var localWg = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wireguard.exe");
                    if (File.Exists(localWg)) File.Copy(localWg, wgPath, true);
                }



            }
            catch (Exception ex) { Debug.WriteLine($"❌ Resource error: {ex.Message}"); }
        }

        void SetupServers()
        {
            foreach (var configPath in Directory.EnumerateFiles(tempPath, "*.conf"))
            {
                try { servers.Add(ReadServer(configPath)); }
                catch (Exception ex) { Debug.WriteLine($"Config skipped: {ex.Message}"); }
            }
        }

        internal static ServerItem ReadServer(string configPath)
            => ReadServerText(File.ReadAllText(configPath), configPath);

        internal static ServerItem ReadServerText(string text, string configPath)
        {
            var endpoint = text.Split('\n')
                .Select(line => line.Split('#')[0].Trim())
                .Select(line => line.Split('=', 2))
                .FirstOrDefault(parts => parts.Length == 2 &&
                    parts[0].Trim().Equals("Endpoint", StringComparison.OrdinalIgnoreCase))?[1].Trim();
            if (string.IsNullOrWhiteSpace(endpoint) ||
                !Uri.TryCreate("udp://" + endpoint, UriKind.Absolute, out var address) ||
                address.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(address.Host))
                throw new InvalidDataException("В конфигурации нужен Endpoint с адресом и портом сервера.");
            var name = Path.GetFileNameWithoutExtension(configPath);
            if (!System.Text.RegularExpressions.Regex.IsMatch(name, @"^[a-zA-Z0-9_=+.-]{1,32}$"))
                throw new InvalidDataException("Имя файла: 1–32 латинские буквы, цифры или символы _ = + . -");
            return new ServerItem
            {
                Name = name, TunnelName = name, ConfigPath = configPath,
                VpnEndpoint = endpoint, Address = address.Host.Trim('[', ']'), Port = address.Port
            };
        }

        private void ImportConfig_Click(object sender, RoutedEventArgs e)
        {
            if (isConnecting || activeServer != null || isImporting) return;
            var dialog = new Microsoft.Win32.OpenFileDialog { Filter = "Конфигурации VPN (*.conf;*.json;*.txt)|*.conf;*.json;*.txt" };
            if (dialog.ShowDialog(this) != true) return;
            try
            {
                if (new FileInfo(dialog.FileName).Length > SubscriptionParser.MaxBytes) throw new InvalidDataException("Файл слишком большой (максимум 4 МБ).");
                if (Path.GetExtension(dialog.FileName).Equals(".conf", StringComparison.OrdinalIgnoreCase))
                {
                    var server = ReadServer(dialog.FileName);
                    var destination = Path.Combine(tempPath, Path.GetFileName(dialog.FileName));
                    if (!string.Equals(Path.GetFullPath(dialog.FileName), destination, StringComparison.OrdinalIgnoreCase))
                        File.Copy(dialog.FileName, destination, false);
                    server = ReadServer(destination);
                    var existing = servers.FirstOrDefault(item => item.ConfigPath.Equals(destination, StringComparison.OrdinalIgnoreCase));
                    if (existing == null) servers.Add(server);
                    ServerSelect.SelectedItem = existing ?? server;
                    SaveServer();
                    SubscriptionStatusText.Text = "Конфигурация WireGuard импортирована.";
                }
                else
                {
                    var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(dialog.FileName))));
                    var parsed = SubscriptionParser.ParseDocument(File.ReadAllText(dialog.FileName));
                    ApplySubscription(new Subscription { Url = "local:" + hash, DisplayName = Path.GetFileName(dialog.FileName), UpdatedAt = DateTime.UtcNow, Profiles = parsed.Profiles, IgnoredRoutingLines = parsed.IgnoredRoutingLines });
                }
                UpdateServerControls();
                activity.Add("Информация", "Конфигурация импортирована из файла.");
                RefreshImportedSources();
                ShowSection("home");
            }
            catch (Exception ex) { SubscriptionStatusText.Text = ex is InvalidDataException ? ex.Message : "Не удалось импортировать файл. Проверь формат и имя файла."; }
        }
        void AddSubscriptionServers(Subscription subscription)
        {
            foreach (var profile in subscription.Profiles)
            {
                var server = new ServerItem
                {
                    Name = profile.Name, Address = profile.Address, Port = profile.Port, Protocol = profile.Protocol,
                    SubscriptionUrl = subscription.Url, ProfileId = profile.Id,
                    Configuration = profile.Configuration,
                    VpnEndpoint = $"{profile.Address}:{profile.Port}"
                };
                if (!ServerLatency.SupportsTcpPing(profile.Protocol))
                {
                    server.SetLatency(new LatencyResult(server.SelectionKey, -1, "Hysteria2 использует UDP; TCP-пинг для него неприменим."));
                    server.PingDisplay = "UDP";
                }
                servers.Add(server);
            }
        }

        void UpdateServerControls()
        {
            var canManage = !isConnecting && !isImporting && !isSwitching && !isManagingData && !isResetting;
            var available = canManage && activeServer == null;
            ServerSelect.IsEnabled = canManage;
            ImportConfigButton.IsEnabled = available;
            SubscriptionUrlText.IsEnabled = ImportSubscriptionButton.IsEnabled = available;
            ServerSearchText.IsEnabled = canManage;
            ImportedSourcesList.IsEnabled = canManage;
            SortServersButton.IsEnabled = canManage;
            ResetAllButton.IsEnabled = canManage;
            RefreshSubscriptionButton.IsEnabled = available && subscriptions.Any(s => s.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
            EmptyServersText.Text = servers.Count == 0 ? "Добавь подписку или файл WireGuard .conf" : "Серверы не найдены";
            EmptyServersText.Visibility = CollectionViewSource.GetDefaultView(servers).IsEmpty ? Visibility.Visible : Visibility.Collapsed;
            ServerCountText.Text = servers.Count.ToString();
            CheckLatencyButton.IsEnabled = !isImporting && !isUpdatingPings && servers.Any(s => ServerLatency.SupportsTcpPing(s.Protocol));
            if (!isUpdatingPings) UpdateLatencySummary();
            BestServerButton.IsEnabled = canManage && !isUpdatingPings && servers.Any(s => s.Ping >= 0 && s.LatencyMeasuredAt >= DateTime.UtcNow.AddMinutes(-2));
        }

        internal async Task ImportSubscriptionAsync(string url)
        {
            if (isConnecting || activeServer != null || isImporting) return;
            isImporting = true;
            UpdateServerControls();
            SubscriptionStatusText.Text = "Загружаю подписку…";
            try
            {
                using var client = new SubscriptionClient();
                var subscription = await client.DownloadAsync(url, lifetime.Token);
                lifetime.Token.ThrowIfCancellationRequested();
                ApplySubscription(subscription);
                SubscriptionUrlText.Clear();
                activity.Add("Информация", $"Подписка обновлена: {subscription.Profiles.Count} серверов.");
                _ = UpdatePings();
            }
            catch (OperationCanceledException) when (!lifetime.IsCancellationRequested)
            { SubscriptionStatusText.Text = "Время ожидания истекло. Прежние серверы сохранены."; }
            catch (System.Net.Http.HttpRequestException)
            { SubscriptionStatusText.Text = "Не удалось загрузить подписку. Проверь интернет и ссылку."; }
            catch (InvalidDataException ex) { SubscriptionStatusText.Text = ex.Message; }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
            catch
            { SubscriptionStatusText.Text = "Не удалось сохранить подписку. Прежние серверы сохранены."; }
            finally { isImporting = false; UpdateServerControls(); }
        }

        internal void ApplySubscription(Subscription subscription)
        {
            if (isUpdatingPings) { latencyRefreshRequested = true; latencyCancellation?.Cancel(); }
            var selected = (ServerSelect.SelectedItem as ServerItem)?.SelectionKey;
            var previous = subscriptions.FirstOrDefault(s => s.Url == subscription.Url);
            subscription = CopySubscription(subscription);
            if (previous != null)
            {
                subscription.DeletedProfileIds = previous.DeletedProfileIds.Union(subscription.DeletedProfileIds).ToList();
                if (subscription.DisplayName == "") subscription.DisplayName = previous.DisplayName;
            }
            subscription.Profiles = subscription.Profiles.Where(p => !subscription.DeletedProfileIds.Contains(p.Id)).ToList();
            var next = subscriptions.Where(s => s.Url != subscription.Url).Append(subscription).ToList();
            // Persist atomically before replacing the visible list; a failed update leaves the old list intact.
            SubscriptionStore.Save(SubscriptionPath, next);
            ReplaceSubscriptionRows(next, selected);
            if (ServerSelect.SelectedItem != null) ServerSelect.ScrollIntoView(ServerSelect.SelectedItem);
            SubscriptionStatusText.Text = $"Серверов в подписке: {subscription.Profiles.Count} · обновлено {subscription.UpdatedAt.ToLocalTime():HH:mm}";
            if (subscription.IgnoredRoutingLines > 0)
            {
                const string routingNotice = "Серверы добавлены. Служебная маршрутизация провайдера пропущена; используются настройки VPN4ik.";
                SubscriptionStatusText.Text += "\n" + routingNotice;
                ShowNotice(routingNotice);
                activity.Add("Информация", routingNotice);
            }
            UpdateServerControls();
        }

        private async void ImportSubscription_Click(object sender, RoutedEventArgs e) =>
            await ImportSubscriptionAsync(SubscriptionUrlText.Text);

        private async void RefreshSubscription_Click(object sender, RoutedEventArgs e)
        {
            var url = (ServerSelect.SelectedItem as ServerItem)?.SubscriptionUrl;
            if (string.IsNullOrEmpty(url) || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) url = subscriptions.LastOrDefault(s => s.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))?.Url;
            if (!string.IsNullOrEmpty(url)) await ImportSubscriptionAsync(url);
        }
        void StartConnectionTimer()
        {
            connectionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            connectionTimer.Tick += (s, e) => TimeConnectedText.Text = isConnected
                ? (DateTime.Now - connectionStartTime).ToString(@"hh\:mm\:ss") : "00:00:00";
            connectionTimer.Start();
        }

        static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes; int order = 0;
            while (len >= 1024 && order < sizes.Length - 1) { order++; len /= 1024; }
            return $"{len:0.##} {sizes[order]}";
        }

        void StartPingLoop()
        {
            pingTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(settings.PingIntervalSeconds) };
            pingTimer.Tick += async (_, _) => { if (settings.AutoCheckPings) await UpdatePings(); };
            pingTimer.Start(); if (settings.AutoCheckPings) _ = UpdatePings();
        }

        private bool PingMayBeInaccurate => isConnecting || activeServer != null || isConnected || PingPolicy.IsTunActive();

        private void UpdateLatencySummary()
        {
            var count = servers.Count(s => ServerLatency.SupportsTcpPing(s.Protocol));
            LatencyStatusText.Text = $"TCP-пинг · {servers.Count(s => ServerLatency.SupportsTcpPing(s.Protocol) && s.Ping >= 0)} из {count}" +
                (PingMayBeInaccurate ? " · при VPN возможна погрешность" : "");
        }

        private DispatcherTimer? pingWarningTimer;

        private void ShowPingWarning()
        {
            PingWarningText.Text = PingPolicy.WarningMessage;
            PingWarning.Visibility = Visibility.Visible;
            pingWarningTimer ??= new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            pingWarningTimer.Stop();
            pingWarningTimer.Tick -= HidePingWarning;
            pingWarningTimer.Tick += HidePingWarning;
            pingWarningTimer.Start();
        }

        private void HidePingWarning(object? sender, EventArgs e)
        {
            pingWarningTimer?.Stop();
            PingWarning.Visibility = Visibility.Collapsed;
        }

        internal async Task UpdatePings(bool manual = false)
        {
            if (isResetting) return;
            if (!manual && !settings.AutoCheckPings) return;
            if (manual && PingMayBeInaccurate) ShowPingWarning();
            if (!useBackground || isUpdatingPings) return;
            var snapshot = servers.Where(s => ServerLatency.SupportsTcpPing(s.Protocol)).ToArray();
            if (snapshot.Length == 0) return;
            isUpdatingPings = true;
            pingsCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
            using var run = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            latencyCancellation = run;
            foreach (var server in snapshot) server.SetLatencyPending();
            LatencyStatusText.Text = "Проверяю TCP-пинг…" + (PingMayBeInaccurate ? " Возможна погрешность при VPN." : "");
            UpdateServerControls();
            try
            {
                foreach (var chunk in snapshot.Chunk(ServerLatency.BatchSize))
                {
                    var profiles = chunk.Select(server => (server.SelectionKey, new SubscriptionProfile
                    {
                        Id = server.ProfileId, Name = server.Name, Address = server.Address,
                        Protocol = server.Protocol, Configuration = server.Configuration, Port = server.Port
                    })).ToArray();
                    try
                    {
                        await ServerLatency.MeasureAsync(profiles, result =>
                        {
                            if (run.IsCancellationRequested || Dispatcher.HasShutdownStarted) return;
                            Dispatcher.Invoke(() => chunk.FirstOrDefault(s => s.SelectionKey == result.Key && servers.Contains(s))?.SetLatency(result));
                        }, run.Token, tunActive: () => PingMayBeInaccurate);
                    }
                    catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
                    { if (run.IsCancellationRequested) break; }
                    if (run.IsCancellationRequested) break;
                }
            }
            finally
            {
                foreach (var server in snapshot.Where(s => s.PingDisplay == "…"))
                    server.SetLatency(new LatencyResult(server.SelectionKey, -1, "Замер не завершён. Подключение можно попробовать независимо от результата проверки."));
                if (!lifetime.IsCancellationRequested)
                    UpdateLatencySummary();
                latencyCancellation = null;
                isUpdatingPings = false;
                pingsCompleted?.TrySetResult();
                ApplyServerSort(settings.ServerSort, false);
                if (!lifetime.IsCancellationRequested) UpdateServerControls();
                if (latencyRefreshRequested && !lifetime.IsCancellationRequested && !isResetting)
                {
                    latencyRefreshRequested = false;
                    _ = Dispatcher.BeginInvoke(new Action(() => _ = UpdatePings()));
                }
            }
        }

        private async void CheckLatency_Click(object sender, RoutedEventArgs e) => await UpdatePings(true);
        void UpdateStatusIndicator(bool connected)
        {
            var color = connected
                ? System.Windows.Media.Color.FromRgb(76, 175, 80)
                : System.Windows.Media.Color.FromRgb(255, 107, 107);
            StatusIndicator.Fill = new SolidColorBrush(color);
        }

        private void TopBar_MouseDown(object sender, WpfMouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.ButtonState == MouseButtonState.Pressed) DragMove();
        }
        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Maximize_Click(object sender, RoutedEventArgs e) =>
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void Ornament_MouseLeftButtonDown(object sender, WpfMouseButtonEventArgs e)
        {
            if (!OrnamentImage.ContainsVisiblePoint(e.GetPosition(OrnamentImage))) return;
            ornamentPressed = true;
            OrnamentImage.Focus();
            OrnamentImage.CaptureMouse();
            AnimateScale(0.97);
            e.Handled = true;
        }
        private async void Ornament_MouseLeftButtonUp(object sender, WpfMouseButtonEventArgs e)
        {
            var activate = ornamentPressed && OrnamentImage.ContainsVisiblePoint(e.GetPosition(OrnamentImage));
            ornamentPressed = false;
            OrnamentImage.ReleaseMouseCapture();
            AnimateScale(isMouseOverOrnament ? 1.04 : 1.0);
            e.Handled = true;
            if (!activate || isConnecting) return;
            if (activeServer == null) await Connect(); else await Disconnect();
        }

        private void Ornament_LostMouseCapture(object sender, MouseEventArgs e)
        {
            ornamentPressed = false;
            AnimateScale(isMouseOverOrnament ? 1.04 : 1.0);
        }

        private async void Ornament_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key is not (Key.Enter or Key.Space) || e.IsRepeat) return;
            e.Handled = true;
            if (isConnecting) return;
            if (activeServer == null) await Connect(); else await Disconnect();
        }

        void AnimateScale(double scale)
        {
            var anim = new DoubleAnimation { To = scale, Duration = TimeSpan.FromMilliseconds(200), EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } };
            OrnamentScale?.BeginAnimation(ScaleTransform.ScaleXProperty, anim);
            OrnamentScale?.BeginAnimation(ScaleTransform.ScaleYProperty, anim);
        }

        private void UpdateOrnamentCache()
        {
            // The vector stays the source. Render once with enough spare pixels
            // for the 1.04 hover scale, then animate outside the cached subtree.
            // Refresh resolution on monitor/DPI changes, never on animation frames.
            if (OrnamentImage.CacheMode is not BitmapCache cache) return;
            var dpi = VisualTreeHelper.GetDpi(this);
            var scale = Math.Max(1.5, Math.Max(dpi.DpiScaleX, dpi.DpiScaleY) * 1.25);
            if (Math.Abs(cache.RenderAtScale - scale) > 0.001) cache.RenderAtScale = scale;
        }

        void AnimateStatusColor(string toColor)
        {
            var brush = (StatusText.Foreground as SolidColorBrush)?.Clone() ?? new SolidColorBrush();
            StatusText.Foreground = brush;

            var colorAnim = new ColorAnimation
            {
                To = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(toColor),
                Duration = TimeSpan.FromMilliseconds(400)
            };
            brush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnim);
        }

        void StartConnectingAnimation()
        {
            dotsTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
            dotsTimer.Tick += (s, e) => { dotsCount = (dotsCount + 1) % 4; StatusText.Text = "Подключение" + new string('.', dotsCount); };
            dotsTimer.Start();
        }

        void StopConnectingAnimation() { dotsTimer?.Stop(); dotsTimer = null; dotsCount = 0; }

        ServerItem? GetBestServer() => servers.Where(s => s.Ping >= 0 && s.LatencyMeasuredAt >= DateTime.UtcNow.AddMinutes(-2)).OrderBy(s => s.Ping).FirstOrDefault();

        void SaveServer()
        {
            settings.LastServer = (ServerSelect.SelectedItem as ServerItem)?.SelectionKey ?? "";
            settings.Save();
        }

        void LoadSavedServer()
        {
            ServerSelect.SelectedItem = servers.FirstOrDefault(s => s.SelectionKey == settings.LastServer)
                ?? servers.FirstOrDefault();
        }
        private async void ServerSelect_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (suppressSelectionSwitch || isConnecting || isSwitching || isManagingData || isResetting) return;
            SaveServer();
            if (activeServer != null && ServerSelect.SelectedItem is ServerItem target && !ReferenceEquals(activeServer, target))
            { await SwitchToServerAsync(target); return; }
            if (activeServer != null || isConnecting) return;
            if (ServerSelect.SelectedItem is ServerItem server)
            {
                StatusText.Text = server.CanConnect ? "Отключено" : $"{server.Protocol} · протокол пока не поддерживается";
                IpText.Text = "";
                var subscription = subscriptions.FirstOrDefault(s => s.Url == server.SubscriptionUrl);
                if (subscription != null)
                    SubscriptionStatusText.Text = $"Серверов в подписке: {subscription.Profiles.Count} · обновлено {subscription.UpdatedAt.ToLocalTime():HH:mm}";
            }
            else
            {
                StatusText.Text = "Отключено";
                IpText.Text = "";
            }
        }

        private void BestServer_Click(object sender, RoutedEventArgs e)
        {
            var best = GetBestServer(); if (best != null) ServerSelect.SelectedItem = best;
        }

        private void ServerSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (ServerSelect?.ItemsSource == null) return;
            var search = ServerSearchText.Text.Trim();
            var view = CollectionViewSource.GetDefaultView(ServerSelect.ItemsSource);
            var wasSuppressed = suppressSelectionSwitch;
            suppressSelectionSwitch = true;
            try
            {
                view.Filter = item => item is ServerItem server &&
                    (server.Name.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
                     server.Protocol.Contains(search, StringComparison.OrdinalIgnoreCase));
                if (ServerSelect.SelectedItem == null && !view.IsEmpty)
                    ServerSelect.SelectedItem = activeServer != null ? (view.Contains(activeServer) ? activeServer : null) : view.Cast<ServerItem>().FirstOrDefault();
            }
            finally { suppressSelectionSwitch = wasSuppressed; }
            EmptyServersText.Text = servers.Count == 0 ? "Добавь подписку или файл WireGuard .conf" : "Серверы не найдены";
            EmptyServersText.Visibility = view.IsEmpty ? Visibility.Visible : Visibility.Collapsed;
        }

        private void MenuButton_Click(object sender, RoutedEventArgs e)
        {
            settings.NavigationExpanded = MenuToggleButton.IsChecked == true;
            ApplyNavigationLayout();
            settings.Save();
        }
        private static readonly DependencyProperty NavigationWidthProperty = DependencyProperty.Register(
            "NavigationWidth", typeof(double), typeof(MainWindow), new PropertyMetadata(64d, (owner, args) =>
            {
                var window = (MainWindow)owner;
                if (window.NavigationColumn != null) window.NavigationColumn.Width = new GridLength((double)args.NewValue);
            }));

        private void ApplyNavigationLayout(bool animate = true)
        {
            var from = (double)GetValue(NavigationWidthProperty);
            var target = MenuToggleButton.IsChecked == true ? 208d : 64d;
            BeginAnimation(NavigationWidthProperty, null);
            SetValue(NavigationWidthProperty, target);
            if (animate)
                BeginAnimation(NavigationWidthProperty, new DoubleAnimation(from, target, TimeSpan.FromMilliseconds(220))
                { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }, FillBehavior = FillBehavior.Stop });
            System.Windows.Automation.AutomationProperties.SetName(MenuToggleButton,
                MenuToggleButton.IsChecked == true ? "Свернуть названия разделов" : "Развернуть названия разделов");
        }
        // ✅ ИСПРАВЛЕНО: System.Windows.Input.MouseEventArgs вместо Forms
        private void Ornament_MouseEnter(object sender, System.Windows.Input.MouseEventArgs e)
        {
            isMouseOverOrnament = true;
            AnimateScale(1.04);
        }
        private void Ornament_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e)
        {
            isMouseOverOrnament = false;
            AnimateScale(1.0);
        }
        private void TestButton_Click(object sender, RoutedEventArgs e) => WpfMessageBox.Show("Кнопка работает!");

        private void ItemsHost_IsKeyboardFocusWithinChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (sender is StackPanel panel && !panel.IsKeyboardFocusWithin)
            {
                if (panel.TemplatedParent is System.Windows.Controls.ComboBox combo) combo.IsDropDownOpen = false;
            }
        }
    }
}
