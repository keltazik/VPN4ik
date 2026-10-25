using System.ComponentModel;
using System.IO;
using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;

namespace VPNyan;

public partial class MainWindow
{
    private void ApplySettings()
    {
        if (settings.StartWithWindows)
        {
            try { SetAutoStart(true); }
            catch { /* Changes in the settings page report persistence failures. */ }
        }
    }

    private static void SetAutoStart(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
        if (enabled)
        {
            var path = Environment.ProcessPath ?? throw new InvalidOperationException("Не найден путь приложения.");
            key.SetValue("VPNchik", $"\"{path}\"");
        }
        else key.DeleteValue("VPNchik", false);
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (useBackground && settings.MinimizeToTray && WindowState == WindowState.Minimized) Hide();
    }

    public async Task Connect()
    {
        if (isConnecting || activeServer != null || isImporting) return;
        if (ServerSelect.SelectedItem is not ServerItem server) { ShowSection("import"); return; }
        if (!useBackground) { StatusText.Text = "Подключение доступно при обычном запуске приложения"; return; }
        latencyCancellation?.Cancel();
        isConnecting = true;
        connectionCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        connectionCancellation.CancelAfter(TimeSpan.FromSeconds(100));
        currentRecord = activity.Begin(server.Name, server.Protocol);
        activity.Add("Информация", $"Подключение: {server.Name} · {server.Protocol}.");
        activeServer = server;
        UpdateServerControls();
        StartConnectingAnimation();
        AnimateStatusColor("#D4AA65");
        var status = "Ошибка";
        try
        {
            if (!server.CanConnect) throw new InvalidDataException("Подключение этого протокола пока не поддерживается.");
            if (server.Protocol == "WireGuard")
            {
                if (!File.Exists(wgPath) || !File.Exists(server.ConfigPath)) throw new FileNotFoundException("Не найдены WireGuard или конфигурация.");
                await TunnelService.RunAsync(wgPath, "/installtunnelservice", server.ConfigPath);
                await TunnelService.WaitForStateAsync(server.TunnelName, true);
                currentRecord.Result = "Туннель запущен";
                currentRecord.Refresh();
                StopConnectingAnimation();
                StatusText.Text = "Туннель WireGuard запущен";
                IpText.Text = "Служба работает; доступ через сервер ещё не подтверждён";
                activity.Add("Информация", "Служба WireGuard запущена. Handshake не проверен.");
            }
            else
            {
                var profile = subscriptions.SelectMany(s => s.Profiles).FirstOrDefault(p => p.Id == server.ProfileId)
                    ?? throw new InvalidDataException("Профиль не найден. Обнови подписку.");
                xraySession = new XraySession();
                var redactor = new SecretRedactor(profile.Configuration);
                xraySession.Log += line =>
                {
                    if (!Dispatcher.HasShutdownStarted)
                        Dispatcher.BeginInvoke(new Action(() => activity.Add(line.Contains("[Error]", StringComparison.OrdinalIgnoreCase) ? "Ошибка" : "Движок", redactor.Clean(line))));
                };
                var ip = await xraySession.StartAsync(profile, settings.TunMtu, connectionCancellation.Token, routing: settings);
                connectionCancellation.CancelAfter(Timeout.InfiniteTimeSpan);
                StopConnectingAnimation();
                StatusText.Text = "Подключено";
                IpText.Text = $"Внешний IP: {ip}";
                activity.Connected(currentRecord, ip);
                activity.Add("Информация", "TUN и доступ через VPN подтверждены HTTPS-проверкой.");
            }
            isConnected = true;
            lastProbeFailed = false;
            lastConnectionCheck = DateTime.UtcNow;
            connectionStartTime = DateTime.Now;
            trafficMeter.Reset();
            try
            {
                var baseline = await ReadTrafficCountersAsync();
                trafficMeter.Sample(baseline, TrafficMeter.MonotonicSeconds);
            }
            catch { /* Next successful sample establishes the baseline. */ }
            UpdateStatusIndicator(server.Protocol != "WireGuard");
            AnimateStatusColor(server.Protocol == "WireGuard" ? "#D4AA65" : "#8FCF9C");
            AnimateGlow(0.8, 22);
            SaveServer();
            if (settings.ShowNotifications) systemTray?.ShowNotification("VPN4ik", StatusText.Text + ": " + server.Name);
            return;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        { status = "Отменено"; StatusText.Text = "Подключение отменено"; }
        catch (OperationCanceledException)
        { status = "Отменено"; StatusText.Text = closeRequested ? "Подключение отменено" : "Не удалось подтвердить соединение. Попробуй другой сервер."; activity.Add("Информация", StatusText.Text); }
        catch (Exception ex)
        {
            var message = ex is InvalidDataException ? ex.Message : ex is System.Net.Sockets.SocketException
                ? "Не удалось определить адрес VPN-сервера. Проверь интернет и подписку." : "Не удалось подтвердить подключение. Подробности в журнале.";
            StatusText.Text = message;
            activity.Add("Ошибка", message);
        }
        finally
        {
            StopConnectingAnimation();
            if (!isConnected)
            {
                activity.End(currentRecord, status);
                try
                {
                    await StopOwnedTunnelAsync();
                    activeServer = null;
                    currentRecord = null;
                }
                catch { StatusText.Text = "Отключение не подтверждено. Нажми на орнамент ещё раз."; activity.Add("Ошибка", "Не удалось подтвердить остановку VPN после ошибки подключения."); }
                UpdateStatusIndicator(false);
                AnimateStatusColor("#FF8E8E");
                IpText.Text = "";
            }
            isConnecting = false;
            UpdateServerControls();
            if (closeRequested) _ = Dispatcher.BeginInvoke(new Action(Close));
        }
    }

    private async Task StopOwnedTunnelAsync()
    {
        if (xraySession != null)
        {
            await xraySession.DisposeAsync();
            xraySession = null;
        }
        else if (activeServer?.Protocol == "WireGuard")
        {
            await TunnelService.WaitForPendingOperationAsync();
            if (TunnelService.GetState(activeServer.TunnelName) != null)
                await TunnelService.RunAsync(wgPath, "/uninstalltunnelservice", activeServer.TunnelName);
            await TunnelService.WaitForStateAsync(activeServer.TunnelName, false);
        }
    }

    public Task Disconnect() => DisconnectCoreAsync("Отключено");

    private async Task DisconnectCoreAsync(string result)
    {
        if (isConnecting || activeServer == null) return;
        isConnecting = true;
        connectionCancellation?.Cancel();
        UpdateServerControls();
        try
        {
            await StopOwnedTunnelAsync();
            activity.End(currentRecord, result);
            activity.Add("Информация", result == "Отключено" ? "VPN отключён." : "VPN-соединение прервано: движок остановился.");
            currentRecord = null;
            activeServer = null;
            isConnected = false;
            StopConnectingAnimation();
            StatusText.Text = result == "Отключено" ? "Отключено" : "Соединение прервано";
            IpText.Text = "";
            UpdateStatusIndicator(false);
            AnimateStatusColor("#C9A15C");
            AnimateGlow(0, 0);
            AnimateScale(1);
            SpeedText.Text = "0 Mbps";
            trafficMeter.Reset();
            TimeConnectedText.Text = "00:00:00";
            TrafficText.Text = "↑ 0 MB | ↓ 0 MB";
            connectionCancellation?.Dispose();
            connectionCancellation = null;
        }
        catch
        { StatusText.Text = "Отключение не подтверждено"; activity.Add("Ошибка", "VPN-служба ещё не завершила отключение. Повтори отключение."); }
        finally { isConnecting = false; UpdateServerControls(); }
    }

    private void StartTrafficMonitor()
    {
        trafficTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        trafficTimer.Tick += async (_, _) =>
        {
            if (activeServer == null || isConnecting || readingTraffic) return;
            readingTraffic = true;
            var server = activeServer;
            try
            {
                if (activeServer.Protocol == "WireGuard" ? TunnelService.GetState(activeServer.TunnelName) != 4 : xraySession?.IsRunning != true)
                { await DisconnectCoreAsync("Разрыв"); return; }
                var counters = await ReadTrafficCountersAsync();
                if (activeServer != server || isConnecting) return;
                var sample = trafficMeter.Sample(counters, TrafficMeter.MonotonicSeconds);
                SpeedText.Text = $"↓ {TrafficMeter.Speed(sample.DownloadBytesPerSecond, settings.TrafficUnit)} · ↑ {TrafficMeter.Speed(sample.UploadBytesPerSecond, settings.TrafficUnit)}";
                TrafficText.Text = $"↑ {FormatBytes(sample.Upload)} | ↓ {FormatBytes(sample.Download)}";
                var now = DateTime.UtcNow;
                if (xraySession != null && !isCheckingConnection && now - lastConnectionCheck > TimeSpan.FromSeconds(30))
                    _ = RecheckConnectionAsync(xraySession);
            }
            catch { if (activeServer == server && !isConnecting) SpeedText.Text = "Нет данных"; }
            finally { readingTraffic = false; }
        };
        trafficTimer.Start();
    }

    private Task<TrafficCounters> ReadTrafficCountersAsync()
    {
        if (xraySession != null) return xraySession.ReadTrafficAsync(lifetime.Token);
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(a => a.Name == activeServer?.TunnelName && a.OperationalStatus == OperationalStatus.Up)
            ?? throw new IOException("Адаптер не найден.");
        var stats = adapter.GetIPStatistics();
        return Task.FromResult(new TrafficCounters(stats.BytesSent, stats.BytesReceived));
    }

    private async Task RecheckConnectionAsync(XraySession session)
    {
        isCheckingConnection = true;
        lastConnectionCheck = DateTime.UtcNow;
        try
        {
            var ip = await session.ProbeAsync(connectionCancellation?.Token ?? lifetime.Token);
            if (xraySession != session || isConnecting) return;
            if (!XraySession.HasTunRoute()) throw new IOException();
            StatusText.Text = "Подключено";
            IpText.Text = $"Внешний IP: {ip}";
            UpdateStatusIndicator(true);
            if (lastProbeFailed) activity.Add("Информация", "Доступ через VPN восстановлен.");
            lastProbeFailed = false;
        }
        catch
        {
            if (xraySession != session || isConnecting) return;
            StatusText.Text = "Нет подтверждённого доступа через VPN";
            UpdateStatusIndicator(false);
            if (!lastProbeFailed) activity.Add("Ошибка", "Периодическая проверка соединения не прошла.");
            lastProbeFailed = true;
        }
        finally { isCheckingConnection = false; }
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (allowClose) { base.OnClosing(e); return; }
        e.Cancel = true;
        base.OnClosing(e);
        if (isConnecting) { closeRequested = true; connectionCancellation?.Cancel(); return; }
        closeRequested = false;
        if (activeServer != null) await Disconnect();
        if (activeServer != null) return;
        lifetime.Cancel();
        pingTimer?.Stop(); pingWarningTimer?.Stop(); trafficTimer?.Stop(); connectionTimer?.Stop(); StopConnectingAnimation();
        settings.Save(); systemTray?.Dispose();
        allowClose = true;
        _ = Dispatcher.BeginInvoke(new Action(Close));
    }

    internal void ShowSection(string section)
    {
        ServersNavButton.IsChecked = section == "home";
        ImportMenuButton.IsChecked = section == "import";
        SettingsMenuButton.IsChecked = section == "settings";
        LogsMenuButton.IsChecked = section == "logs";
        HistoryMenuButton.IsChecked = section == "history";
        ContentGrid.Visibility = section == "home" ? Visibility.Visible : Visibility.Collapsed;
        SectionPanel.Visibility = section == "home" ? Visibility.Collapsed : Visibility.Visible;
        ImportPage.Visibility = section == "import" ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = section == "settings" ? Visibility.Visible : Visibility.Collapsed;
        LogsPage.Visibility = section == "logs" ? Visibility.Visible : Visibility.Collapsed;
        HistoryPage.Visibility = section == "history" ? Visibility.Visible : Visibility.Collapsed;
        SectionTitle.Text = section switch { "import" => "Импорт конфигурации", "settings" => "Настройки", "logs" => "Журнал событий", "history" => "История подключения", _ => "VPN4ik" };
        if (section == "settings")
        {
            loadingSettings = true;
            draftSettings = settings.Copy();
            SettingsPage.DataContext = draftSettings;
            MtuText.Text = draftSettings.TunMtu.ToString();
            LoadExtraSettings();
            SettingsStatusText.Text = "";
            loadingSettings = false;
        }
    }
    private void Home_Click(object sender, RoutedEventArgs e) => ShowSection("home");
    private void ImportMenu_Click(object sender, RoutedEventArgs e) => ShowSection("import");
    private void Settings_Click(object sender, RoutedEventArgs e) => ShowSection("settings");
    private void History_Click(object sender, RoutedEventArgs e) => ShowSection("history");
    private void Logs_Click(object sender, RoutedEventArgs e) => ShowSection("logs");
    private void ClearLogs_Click(object sender, RoutedEventArgs e) => activity.ClearLogs();
    private void ClearHistory_Click(object sender, RoutedEventArgs e) => activity.ClearHistory(currentRecord);

    private bool loadingSettings;

    private void SettingsCheckBox_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.CheckBox checkbox)
            checkbox.GetBindingExpression(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty)?.UpdateSource();
        SaveSettingsAutomatically();
    }

    private void MtuText_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (loadingSettings || draftSettings == null) return;
        if (!int.TryParse(MtuText.Text, out var mtu) || mtu is < 1280 or > 1500)
        { SettingsStatusText.Text = "MTU должен быть от 1280 до 1500. Последнее корректное значение сохранено."; return; }
        draftSettings.TunMtu = mtu;
        SaveSettingsAutomatically();
    }

    private void SaveSettingsAutomatically()
    {
        if (loadingSettings || draftSettings == null) return;
        var startupChanged = draftSettings.StartWithWindows != settings.StartWithWindows;
        var disableAutoPing = settings.AutoCheckPings && !draftSettings.AutoCheckPings;
        try
        {
            RoutingSettings.Validate(draftSettings, requireRules: false);
            draftSettings.LastServer = settings.LastServer;
            draftSettings.NavigationExpanded = MenuToggleButton.IsChecked == true;
            if (useBackground && startupChanged) SetAutoStart(draftSettings.StartWithWindows);
            draftSettings.SaveOrThrow();
            settings = draftSettings.Copy();
            if (activeServer == null) SpeedText.Text = "0 " + settings.TrafficUnit;
            if (pingTimer != null) pingTimer.Interval = TimeSpan.FromSeconds(settings.PingIntervalSeconds);
            if (disableAutoPing) latencyCancellation?.Cancel();
            SettingsStatusText.Text = int.TryParse(MtuText.Text, out var mtu) && mtu is >= 1280 and <= 1500
                ? "Сохранено. Параметры соединения применятся после переподключения."
                : "Настройки сохранены. Для MTU введи число от 1280 до 1500.";
            if (settings.SplitTunnelEnabled && settings.SplitTunnelMode == "Include" &&
                settings.SplitApplications.Count + settings.SplitDomains.Count + settings.SplitNetworks.Count == 0)
                SettingsStatusText.Text = "Сохранено. Для подключения добавь хотя бы одно правило маршрутизации.";
        }
        catch (InvalidDataException ex) { SettingsStatusText.Text = ex.Message; }
        catch
        {
            if (useBackground && startupChanged) { try { SetAutoStart(settings.StartWithWindows); } catch { } }
            SettingsStatusText.Text = "Не удалось сохранить настройки или автозапуск Windows.";
        }
    }
}
