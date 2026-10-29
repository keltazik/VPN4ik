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
        if (systemTray?.IsAvailable == true && settings.MinimizeToTray && WindowState == WindowState.Minimized) Hide();
    }

    public Task Connect() => isSwitching || isManagingData || isResetting || zapretBusy ? Task.CompletedTask : ConnectCoreAsync();

    private async Task ConnectCoreAsync()
    {
        if (isConnecting || activeServer != null || isImporting || zapretBusy) return;
        if (ServerSelect.SelectedItem is not ServerItem server) { ShowSection("import"); return; }
        if (!canCreateSession) { Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Подключение доступно при обычном запуске приложения"); return; }
        isConnecting = true;
        connectionCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        connectionCancellation.CancelAfter(TimeSpan.FromSeconds(100));
        currentRecord = activity.Begin(server.Name, server.Protocol);
        activity.Add("Информация", $"Подключение: {server.Name} · {server.Protocol}.");
        UpdateServerControls();
        StartConnectingAnimation();
        AnimateStatusColor("#D4AA65");
        var status = "Ошибка";
        try
        {
            if (!server.CanConnect) throw new InvalidDataException("Подключение этого протокола пока не поддерживается.");
            if (server.Protocol == "WireGuard" && settings.ConnectionMode == "proxy") throw new InvalidDataException("WireGuard работает в режиме TUN. Выбери TUN перед подключением.");
            await PrepareZapretForConnectionAsync(connectionCancellation.Token);
            connectionCancellation.Token.ThrowIfCancellationRequested();
            activeServer = server;
            if (server.Protocol == "WireGuard")
            {
                if (!File.Exists(wgPath) || !File.Exists(server.ConfigPath)) throw new FileNotFoundException("Не найдены WireGuard или конфигурация.");
                await TunnelService.RunAsync(wgPath, "/installtunnelservice", server.ConfigPath);
                await TunnelService.WaitForStateAsync(server.TunnelName, true);
                currentRecord.Result = "Туннель запущен";
                currentRecord.Refresh();
                StopConnectingAnimation();
                Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Туннель WireGuard запущен");
                Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, "Служба работает; доступ через сервер ещё не подтверждён");
                activity.Add("Информация", "Служба WireGuard запущена. Handshake не проверен.");
            }
            else
            {
                var profile = subscriptions.SelectMany(s => s.Profiles).FirstOrDefault(p => p.Id == server.ProfileId)
                    ?? throw new InvalidDataException("Профиль не найден. Обнови подписку.");
                xraySession = sessionFactory();
                var ownedSession = xraySession;
                var redactor = new SecretRedactor(profile.Configuration);
                xraySession.Log += line =>
                {
                    if (!Dispatcher.HasShutdownStarted)
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            if (ReferenceEquals(xraySession, ownedSession) && !isResetting && !lifetime.IsCancellationRequested)
                                activity.Add(line.Contains("[Error]", StringComparison.OrdinalIgnoreCase) ? "Ошибка" : "Движок", redactor.Clean(line));
                        }));
                };
                activeUsesTun = settings.ConnectionMode != "proxy";
                var ip = await xraySession.StartAsync(profile, settings.TunMtu, connectionCancellation.Token, enableTun: activeUsesTun, elevate: activeUsesTun, routing: settings);
                connectionCancellation.CancelAfter(Timeout.InfiniteTimeSpan);
                StopConnectingAnimation();
                Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Подключено");
                Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, ExternalIpLabel(ip));
                activity.Connected(currentRecord, ip);
                activity.Add("Информация", activeUsesTun ? "TUN и доступ через VPN подтверждены HTTPS-проверкой." : "Системный прокси и доступ через сервер подтверждены HTTPS-проверкой.");
            }
            isConnected = true;
            lastProbeFailed = false;
            failedConnectionChecks = 0;
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

            SaveServer();
            if (settings.ShowNotifications) systemTray?.ShowNotification("VPN4ik", StatusText.Text + ": " + server.DisplayName);
            return;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        { status = "Отменено"; Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Подключение отменено"); }
        catch (OperationCanceledException)
        { status = "Отменено"; Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, closeRequested ? "Подключение отменено" : "Не удалось подтвердить соединение. Попробуй другой сервер."); activity.Add("Информация", StatusText.Text); }
        catch (Exception ex)
        {
            var message = ex is InvalidDataException ? ex.Message : ex is System.Net.Sockets.SocketException
                ? "Не удалось определить адрес VPN-сервера. Проверь интернет и подписку." : "Не удалось подтвердить подключение. Подробности в журнале.";
            Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, message);
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
                catch { Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Отключение не подтверждено. Нажми на орнамент ещё раз."); activity.Add("Ошибка", "Не удалось подтвердить остановку VPN после ошибки подключения."); }
                if (activeServer == null) await RestorePausedZapretAsync();
                UpdateStatusIndicator(false);
                AnimateStatusColor("#FF8E8E");
                Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, "");
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

    public Task Disconnect() => isSwitching || isManagingData || isResetting ? Task.CompletedTask : DisconnectCoreAsync("Отключено");

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
            activity.Add("Информация", result == "Разрыв" ? "VPN-соединение прервано: движок остановился." : "VPN отключён: " + result + ".");
            currentRecord = null;
            activeServer = null;
            isConnected = false;
            if (!isSwitching && !isResetting) await RestorePausedZapretAsync();
            StopConnectingAnimation();
            Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, result == "Отключено" ? "Отключено" : "Соединение прервано");
            Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, "");
            UpdateStatusIndicator(false);
            AnimateStatusColor("#C9A15C");
            AnimateScale(1);
            Localization.Set(SpeedText, System.Windows.Controls.TextBlock.TextProperty, "0 " + settings.TrafficUnit);
            trafficMeter.Reset();
            Localization.Set(TimeConnectedText, System.Windows.Controls.TextBlock.TextProperty, "00:00:00");
            Localization.Set(TrafficText, System.Windows.Controls.TextBlock.TextProperty, "↑ 0 MB | ↓ 0 MB");
            connectionCancellation?.Dispose();
            connectionCancellation = null;
        }
        catch
        { Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Отключение не подтверждено"); activity.Add("Ошибка", "VPN-служба ещё не завершила отключение. Повтори отключение."); }
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
                Localization.Set(SpeedText, System.Windows.Controls.TextBlock.TextProperty, $"↓ {TrafficMeter.Speed(sample.DownloadBytesPerSecond, settings.TrafficUnit)} · ↑ {TrafficMeter.Speed(sample.UploadBytesPerSecond, settings.TrafficUnit)}");
                Localization.Set(TrafficText, System.Windows.Controls.TextBlock.TextProperty, $"↑ {FormatBytes(sample.Upload)} | ↓ {FormatBytes(sample.Download)}");
            }
            catch { if (activeServer == server && !isConnecting) Localization.Set(SpeedText, System.Windows.Controls.TextBlock.TextProperty, "Нет данных"); }
            finally
            {
                readingTraffic = false;
                if (activeServer == server && !isConnecting && xraySession != null && !isCheckingConnection && DateTime.UtcNow - lastConnectionCheck > TimeSpan.FromSeconds(30))
                    _ = RecheckConnectionAsync(xraySession);
            }
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

    private int failedConnectionChecks;
    private bool activeUsesTun = true;
    private static string ExternalIpLabel(string ip) => string.IsNullOrEmpty(ip) ? "Доступ через VPN подтверждён" : $"Внешний IP: {ip}";
    private async Task RecheckConnectionAsync(IVpnSession session)
    {
        isCheckingConnection = true;
        lastConnectionCheck = DateTime.UtcNow;
        try
        {
            var token = connectionCancellation?.Token ?? lifetime.Token;
            var proxyCheck = session.ProbeAsync(token);
            var checks = activeUsesTun && !settings.SplitTunnelEnabled
                ? await Task.WhenAll(proxyCheck, session.ProbeAsync(token, useProxy: false))
                : new[] { await proxyCheck };
            var ip = checks[0];
            if (xraySession != session || isConnecting) return;
            if (activeUsesTun && !XraySession.HasTunRoute()) throw new IOException();
            Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Подключено");
            Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, ExternalIpLabel(ip));
            UpdateStatusIndicator(true);
            AnimateStatusColor("#8FCF9C");
            if (failedConnectionChecks > 0) activity.Add("Информация", "Доступ через VPN повторно подтверждён.");
            lastProbeFailed = false;
            failedConnectionChecks = 0;
        }
        catch
        {
            if (xraySession != session || isConnecting || lifetime.IsCancellationRequested || connectionCancellation?.IsCancellationRequested == true) return;
            failedConnectionChecks++;
            if (failedConnectionChecks == 1)
            {
                Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Перепроверяю доступ через VPN…");
                lastConnectionCheck = DateTime.UtcNow.AddSeconds(-25);
                StatusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(212,170,101));
                AnimateStatusColor("#D4AA65");
                activity.Add("Информация", "HTTPS-проверка не прошла. Повторная проверка будет выполнена без отключения туннеля.");
                return;
            }
            Localization.Set(StatusText, System.Windows.Controls.TextBlock.TextProperty, "Нет подтверждённого доступа через VPN");
            lastConnectionCheck = DateTime.UtcNow.AddSeconds(-20);
            UpdateStatusIndicator(false);
            AnimateStatusColor("#FF8E8E");
            if (!lastProbeFailed) activity.Add("Ошибка", "Периодическая проверка соединения не прошла.");
            lastProbeFailed = true;
        }
        finally { isCheckingConnection = false; }
    }

    private bool exitRequested;
    internal void ExitApplication() { exitRequested = true; Close(); }
    protected override async void OnClosing(CancelEventArgs e)
    {
        if (allowClose) { base.OnClosing(e); return; }
        e.Cancel = true;
        base.OnClosing(e);
        if (!exitRequested && settings.CloseToTray && systemTray?.IsAvailable == true) { Hide(); return; }
        if (isConnecting || isSwitching || isManagingData || isResetting || isImporting || zapretBusy) { closeRequested = true; connectionCancellation?.Cancel(); zapretOperation?.Cancel(); if (installingUpdate) updateCancellation?.Cancel(); return; }
        closeRequested = false;
        if (pendingZapretLists.Count > 0) await SaveZapretListsAsync(false);
        var hadConnection = activeServer != null;
        if (activeServer != null) await Disconnect();
        if (activeServer != null) return;
        if (!hadConnection) await RestorePausedZapretAsync();
        lifetime.Cancel();
        pingTimer?.Stop(); subscriptionUpdateTimer?.Stop(); pingWarningTimer?.Stop(); trafficTimer?.Stop(); connectionTimer?.Stop(); updateTimer?.Stop(); zapretTimer?.Stop(); zapretSaveTimer?.Stop(); StopConnectingAnimation();
        settings.Save(); systemTray?.Dispose();
        allowClose = true;
        _ = Dispatcher.BeginInvoke(new Action(Close));
    }

    internal void ShowSection(string section)
    {
        SectionBackButton.Visibility=Visibility.Visible;
        RememberNavigation(section, section == "settings" ? settingsCategory : "overview");
        ServersNavButton.IsChecked = section == "home";
        ImportMenuButton.IsChecked = section == "import";
        SettingsMenuButton.IsChecked = section == "settings";
        LogsMenuButton.IsChecked = section == "logs";
        HistoryMenuButton.IsChecked = section == "history";
        ZapretMenuButton.IsChecked = section == "zapret";
        ContentGrid.Visibility = section == "home" ? Visibility.Visible : Visibility.Collapsed;
        SectionPanel.Visibility = section == "home" ? Visibility.Collapsed : Visibility.Visible;
        ImportPage.Visibility = section == "import" ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = section == "settings" ? Visibility.Visible : Visibility.Collapsed;
        LogsPage.Visibility = section == "logs" ? Visibility.Visible : Visibility.Collapsed;
        HistoryPage.Visibility = section == "history" ? Visibility.Visible : Visibility.Collapsed;
        ZapretPage.Visibility = section == "zapret" ? Visibility.Visible : Visibility.Collapsed;
        Localization.Set(SectionTitle, System.Windows.Controls.TextBlock.TextProperty, section switch { "import" => "Импорт конфигурации", "settings" => "Настройки", "logs" => "Журнал событий", "history" => "История подключения", "zapret" => "Управление zapret", _ => "VPN4ik" });
        if (section == "settings")
        {
            loadingSettings = true;
            draftSettings = settings.Copy();
            SettingsPage.DataContext = draftSettings;
            MtuText.Text = draftSettings.TunMtu.ToString();
            LoadExtraSettings();
            Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, "");
            loadingSettings = false;
            ShowSettingsCategory(settingsCategory);
        }
        if (section == "import") RefreshImportedSources();
        if (section == "zapret") { LoadZapretCompatibility(); _ = RefreshZapretAsync(); }
        UpdateOrnamentGlow();
    }
    private void Home_Click(object sender, RoutedEventArgs e) => ShowSection("home");
    private void Back_Click(object sender, RoutedEventArgs e) => NavigateBack();
    private void ImportMenu_Click(object sender, RoutedEventArgs e) => ShowSection("import");
    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        settingsCategory="overview";
        settingsHistory.Clear();
        ShowSection("settings");
    }
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
        { Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, "MTU должен быть от 1280 до 1500. Последнее корректное значение сохранено."); return; }
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
            draftSettings.ConnectionMode = settings.ConnectionMode;
            draftSettings.NavigationExpanded = MenuToggleButton.IsChecked == true;
            draftSettings.ZapretFolder = settings.ZapretFolder; draftSettings.ZapretStrategy = settings.ZapretStrategy;
            draftSettings.DisableZapretOnConnect = settings.DisableZapretOnConnect; draftSettings.RestoreZapretAfterVpn = settings.RestoreZapretAfterVpn;
            if (useBackground && startupChanged) SetAutoStart(draftSettings.StartWithWindows);
            draftSettings.SaveOrThrow();
            settings = draftSettings.Copy();
            // AppSettings is a snapshot, not INotifyPropertyChanged. Refresh sibling controls bound to the same option.
            loadingSettings=true;
            try { draftSettings=settings.Copy(); SettingsPage.DataContext=draftSettings; }
            finally { loadingSettings=false; }
            ApplyLanguage(); UpdateConnectionModeUi(); RefreshExtendedSettings();
            if (activeServer == null) Localization.Set(SpeedText, System.Windows.Controls.TextBlock.TextProperty, "0 " + settings.TrafficUnit);
            if (pingTimer != null) pingTimer.Interval = TimeSpan.FromSeconds(settings.PingIntervalSeconds);
            if (disableAutoPing) latencyCancellation?.Cancel();
            Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, int.TryParse(MtuText.Text, out var mtu) && mtu is >= 1280 and <= 1500
                ? "Сохранено. Параметры соединения применятся после переподключения."
                : "Настройки сохранены. Для MTU введи число от 1280 до 1500.");
            if (settings.SplitTunnelEnabled && settings.SplitTunnelMode == "Include" &&
                settings.SplitApplications.Count + settings.SplitDomains.Count + settings.SplitNetworks.Count == 0)
                Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, "Сохранено. Для подключения добавь хотя бы одно правило маршрутизации.");
        }
        catch (InvalidDataException ex) { RestoreSettingsSnapshot(); Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, ex.Message); }
        catch
        {
            if (useBackground && startupChanged) { try { SetAutoStart(settings.StartWithWindows); } catch { } }
            RestoreSettingsSnapshot();
            Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, "Не удалось сохранить настройки или автозапуск Windows.");
        }
    }

    private void RestoreSettingsSnapshot()
    {
        loadingSettings=true;
        try { draftSettings=settings.Copy(); SettingsPage.DataContext=draftSettings; RefreshExtendedSettings(); }
        finally { loadingSettings=false; }
    }
}
