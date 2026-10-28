using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Input;
using System.Windows.Media;
using ComboBox = System.Windows.Controls.ComboBox;
using TextBox = System.Windows.Controls.TextBox;

namespace VPNyan;

public partial class MainWindow
{
    private readonly IZapretController zapretController;
    private ZapretFolderInfo? zapretInfo;
    private ZapretState zapretState = new();
    private ZapretLease? pausedZapret;
    private bool zapretBusy, loadingZapret, refreshingZapret, zapretListsLoaded;
    private DispatcherTimer? zapretTimer, zapretSaveTimer;
    private CancellationTokenSource? zapretOperation;
    private Task? zapretInitialization;
    private readonly Dictionary<string, string> pendingZapretLists = new();
    private readonly Queue<string> zapretEvents = new();

    private void InitializeZapret()
    {
        LoadZapretCompatibility(); UpdateZapretControls();
        if (!useBackground) return;
        zapretInitialization = InitializeZapretFolderAsync();
        zapretTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        zapretTimer.Tick += async (_, _) => { if (ZapretPage.Visibility == Visibility.Visible) await RefreshZapretAsync(); };
        zapretTimer.Start();
    }
    private void LoadZapretCompatibility()
    {
        loadingZapret = true;
        try { DisableZapretOnConnectBox.IsChecked = settings.DisableZapretOnConnect; RestoreZapretAfterVpnBox.IsChecked = settings.RestoreZapretAfterVpn; }
        finally { loadingZapret = false; }
    }
    private void ZapretMenu_Click(object sender, RoutedEventArgs e) => ShowSection("zapret");
    private async void ZapretChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = Localization.T("Папка zapret: service.bat и bin/winws.exe"), Multiselect = false };
        if (Directory.Exists(settings.ZapretFolder)) dialog.InitialDirectory = settings.ZapretFolder;
        if (dialog.ShowDialog(this) == true)
        {
            await LoadZapretFolderAsync(dialog.FolderName, true);
            if (zapretInfo?.Folder.Equals(dialog.FolderName, StringComparison.OrdinalIgnoreCase) == true)
                Localization.Set(ZapretDiscoveryStatus, System.Windows.Controls.TextBlock.TextProperty, "");
        }
    }
    internal async Task LoadZapretFolderAsync(string folder, bool save)
    {
        if (zapretBusy || lifetime.IsCancellationRequested) return;
        zapretBusy = true; UpdateServerControls();
        try
        {
            var info = await Task.Run(() => ZapretProfiles.Read(folder), lifetime.Token);
            if (lifetime.IsCancellationRequested) return;
            var strategy = info.Profiles.FirstOrDefault(profile => profile.FileName == settings.ZapretStrategy) ?? info.Profiles.FirstOrDefault(profile => profile.FileName == "general.bat") ?? info.Profiles[0];
            if (save)
            {
                var next = settings.Copy(); next.ZapretFolder = info.Folder; next.ZapretStrategy = strategy.FileName; next.SaveOrThrow(); settings = next;
            }
            else settings.ZapretStrategy = strategy.FileName;
            zapretInfo = info; pendingZapretLists.Clear(); zapretListsLoaded = false;
            Localization.Set(ZapretDiscoveryStatus, System.Windows.Controls.TextBlock.TextProperty, "");
            loadingZapret = true;
            try
            {
                ZapretFolderText.Text = info.Folder; Localization.Set(ZapretVersionText, System.Windows.Controls.TextBlock.TextProperty, $"Flowseal · версия {info.Version} · стратегий: {info.Profiles.Count}");
                ZapretStrategySelect.ItemsSource = info.Profiles; ZapretStrategySelect.SelectedItem = strategy;
                SelectTag(ZapretGameSelect, info.GameMode); SelectTag(ZapretIpSetSelect, info.IpSetMode);
                LoadZapretAdvanced(info.Folder);
                ZapretDomainsText.Clear(); ZapretExcludeText.Clear(); ZapretIpsText.Clear();
            }
            finally { loadingZapret = false; }
            Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "");

        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { ZapretError(ex); }
        finally { zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
        await RefreshZapretAsync();
    }
    private static void SelectTag(ComboBox selector, string value) => selector.SelectedItem = selector.Items.OfType<ComboBoxItem>().FirstOrDefault(item => (string)item.Tag == value);
    private void ZapretStrategy_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is not ComboBox combo || combo.IsDropDownOpen) return;
        e.Handled = true;
        // Scroll the page without letting a focused closed ComboBox change its selection.
        for (DependencyObject? parent = VisualTreeHelper.GetParent(combo); parent != null; parent = VisualTreeHelper.GetParent(parent))
            if (parent is ScrollViewer scroll)
            {
                scroll.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta) { RoutedEvent = Mouse.MouseWheelEvent, Source = scroll });
                break;
            }
    }
    private void ZapretStrategy_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (loadingZapret || zapretInfo == null || ZapretStrategySelect.SelectedItem is not ZapretProfile profile) return;
        var next = settings.Copy(); next.ZapretStrategy = profile.FileName;
        try { next.SaveOrThrow(); settings = next; Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Выбран файл: " + profile.FileName); }
        catch (Exception ex) { ZapretError(ex); }
    }
    private void ZapretCompatibility_Click(object sender, RoutedEventArgs e)
    {
        if (loadingZapret) return;
        var next = settings.Copy(); next.DisableZapretOnConnect = DisableZapretOnConnectBox.IsChecked == true; next.RestoreZapretAfterVpn = RestoreZapretAfterVpnBox.IsChecked == true;
        try { next.SaveOrThrow(); settings = next; Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Сохранено. Правило действует со следующего подключения VPN."); }
        catch (Exception ex) { LoadZapretCompatibility(); ZapretError(ex); }
        UpdateZapretControls();
    }
    private void ZapretOpenFolder_Click(object sender, RoutedEventArgs e)
    {
        try { var folder = ZapretProfiles.ValidateFolder(settings.ZapretFolder); Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true }); }
        catch (Exception ex) { ZapretError(ex); }
    }
    private async void ZapretRefresh_Click(object sender, RoutedEventArgs e) => await RefreshZapretAsync();
    private async Task RefreshZapretAsync()
    {
        if (zapretBusy || refreshingZapret || isConnecting || isSwitching || settings.ZapretFolder == "" || lifetime.IsCancellationRequested) return;
        refreshingZapret = true;
        var folder = settings.ZapretFolder;
        try { var state = await zapretController.ReadAsync(folder, lifetime.Token); if (!lifetime.IsCancellationRequested && !zapretBusy && !isConnecting && !isSwitching && folder == settings.ZapretFolder) { zapretState = state; RenderZapretState(); } }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (!lifetime.IsCancellationRequested) { Localization.Set(ZapretStateText, System.Windows.Controls.TextBlock.TextProperty, "Статус не определён"); ZapretError(ex); } }
        finally { refreshingZapret = false; UpdateZapretControls(); }
    }
    private void RenderZapretState()
    {
        Localization.Set(ZapretStateText, System.Windows.Controls.TextBlock.TextProperty, zapretState.UnreadableProcesses > 0 ? "Не все процессы доступны для проверки" : zapretState.Services.Any(service => service.State is 2 or 3) ? "Служба zapret запускается или останавливается" : zapretState.Running
            ? zapretState.Services.Any(service => service.State == 4) ? "zapret работает как служба" : $"zapret работает · процессов: {zapretState.Processes.Count}"
            : zapretState.OtherProcesses > 0 ? "zapret работает из другой папки" : pausedZapret?.HasEntries == true ? "zapret выключен на время VPN" : "zapret выключен");
        ZapretStateText.Foreground = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(zapretState.Running ? "#8FCF9C" : "#F1D6A5"));
        Localization.Set(ZapretServiceText, System.Windows.Controls.TextBlock.TextProperty, zapretState.Services.Count == 0 ? "Служба zapret не установлена." : string.Join("\n", zapretState.Services.Select(service =>
            "Установлен: " + (service.Strategy == "" ? "BAT-файл не определён" : service.Strategy + (service.StrategyVerified ? "" : " · по данным службы")) +
            (service.State == 4 ? " · работает" : service.State == 1 ? " · остановлен" : " · меняет состояние"))));

    }
    private void UpdateZapretControls()
    {
        if (ZapretStartButton == null) return;
        var ready = !zapretBusy && !isConnecting && !isSwitching && !isManagingData && !isResetting && !isImporting;
        var configured = zapretInfo != null;
        ZapretChooseFolderButton.IsEnabled = ready && pausedZapret?.HasEntries != true && pendingZapretLists.Count == 0;
        ZapretFindFolderButton.IsEnabled = ZapretInstallationsSelect.IsEnabled = ZapretChooseFolderButton.IsEnabled;
        ZapretOpenFolderButton.IsEnabled = configured;
        ZapretStrategySelect.IsEnabled = ready && configured;
        ZapretStartButton.IsEnabled = ready && configured && !zapretState.Running;
        ZapretStopButton.IsEnabled = ready && configured && (zapretState.Running || zapretState.UnreadableProcesses > 0 || pausedZapret?.HasEntries == true);
        ZapretRestartButton.IsEnabled = ready && configured;
        ZapretRefreshButton.IsEnabled = ready && configured;
        ZapretGameSelect.IsEnabled = ZapretIpSetSelect.IsEnabled = ready && configured;
        DisableZapretOnConnectBox.IsEnabled = ready;
        RestoreZapretAfterVpnBox.IsEnabled = ready && settings.DisableZapretOnConnect;
        ZapretDomainsText.IsEnabled = ZapretExcludeText.IsEnabled = ZapretIpsText.IsEnabled = ready && configured;
        ZapretSaveListsAdminButton.IsEnabled = ready && pendingZapretLists.Count > 0;
        ZapretListsExpander.IsEnabled = ready && configured;
        ZapretFiltersExpander.IsEnabled = ready && configured;
        ZapretAdvancedPanel.IsEnabled = ready && configured;
        ZapretServiceExpander.IsEnabled = ready && configured;
        ZapretTestButton.IsEnabled = activeServer == null && pausedZapret?.HasEntries != true;
        ZapretInstallServiceButton.IsEnabled = !zapretState.Running && pausedZapret?.HasEntries != true;
        ZapretRemoveServiceButton.IsEnabled = zapretState.Services.Count > 0 && pausedZapret?.HasEntries != true;
    }
    private void ZapretError(Exception error)
    {
        Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, error is InvalidDataException ? error.Message : error is Win32Exception native && native.NativeErrorCode == 1223 ? "Запрос Windows отменён. zapret не изменён." : "Не удалось выполнить действие. Проверь папку и права доступа к zapret.");
    }
    private void LogZapret(string message)
    {
        zapretEvents.Enqueue(DateTime.Now.ToString("HH:mm:ss") + " · " + message); while (zapretEvents.Count > 8) zapretEvents.Dequeue();
        Localization.Set(ZapretLogText, System.Windows.Controls.TextBlock.TextProperty, string.Join('\n', zapretEvents)); activity.Add("zapret", message);
    }
    private async void ZapretStart_Click(object sender, RoutedEventArgs e) => await ManageZapretAsync("start");
    private async void ZapretStop_Click(object sender, RoutedEventArgs e) => await ManageZapretAsync("stop");
    private async void ZapretRestart_Click(object sender, RoutedEventArgs e) => await ManageZapretAsync("restart");
    internal async Task ManageZapretAsync(string action)
    {
        if (zapretBusy || isConnecting || isSwitching || isManagingData || isResetting || isImporting || settings.ZapretFolder == "") return;
        if (pendingZapretLists.Count > 0 && action != "stop")
        {
            await SaveZapretListsAsync(false);
            if (pendingZapretLists.Count > 0) { ShowNotice("Сначала исправь или примени изменения пользовательских списков."); return; }
        }
        zapretBusy = true; UpdateServerControls();
        try
        {
            zapretOperation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Выполняю действие zapret…");
            var result = await zapretController.RunAsync(new() { Action = action, Folder = settings.ZapretFolder, Strategy = settings.ZapretStrategy }, zapretOperation.Token);
            zapretState = result.State; RenderZapretState();
            if (!result.Success) throw new InvalidDataException(result.Message);
            // A cancelled/failed manual action must not discard a pending automatic restore.
            pausedZapret = null; RenderZapretState();
            Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, action == "stop" ? "zapret выключен." : "zapret запущен. Доступность ресурсов зависит от выбранной стратегии.");
            LogZapret(action == "stop" ? "zapret выключен вручную." : "Запущена стратегия: " + settings.ZapretStrategy);
            if (activeServer != null && action != "stop") ShowNotice("zapret включён вместе с VPN. При проблемах отключи zapret или включи автоотключение в его вкладке.");
        }
        catch (OperationCanceledException) { Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Действие отменено."); }
        catch (Exception ex) { ZapretError(ex); LogZapret(ZapretActionStatus.Text); }
        finally { zapretOperation?.Dispose(); zapretOperation = null; zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
    }

    private async void ZapretFilters_Changed(object sender, SelectionChangedEventArgs e) => await SaveZapretFiltersAsync();
    private async Task SaveZapretFiltersAsync()
    {
        if (loadingZapret || zapretBusy || zapretInfo == null || ZapretGameSelect.SelectedItem is not ComboBoxItem game || ZapretIpSetSelect.SelectedItem is not ComboBoxItem ipset) return;
        zapretBusy = true; UpdateServerControls();
        var gameMode = (string)game.Tag; var ipSetMode = (string)ipset.Tag;
        try
        {
            var tcp = ZapretProfiles.ValidatePorts(ZapretTcpPorts.Text); var udp = ZapretProfiles.ValidatePorts(ZapretUdpPorts.Text);
            try { await Task.Run(() => ZapretProfiles.Configure(settings.ZapretFolder, gameMode, ipSetMode, tcp, udp)); }
            catch (UnauthorizedAccessException)
            {
                var result = await zapretController.RunAsync(new() { Action = "configure", Folder = settings.ZapretFolder, GameMode = gameMode, IpSetMode = ipSetMode, TcpPorts = tcp, UdpPorts = udp }, lifetime.Token);
                if (!result.Success) throw new InvalidDataException(result.Message);
            }
            zapretInfo = ZapretProfiles.Read(settings.ZapretFolder);
            ZapretTcpPorts.Text = tcp; ZapretUdpPorts.Text = udp;
            Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Фильтры сохранены. Для применения к работающему zapret нажми «Перезапустить»."); LogZapret("Изменены фильтры zapret.");
        }
        catch (Exception ex)
        {
            ZapretError(ex); loadingZapret = true;
            try { SelectTag(ZapretGameSelect, zapretInfo.GameMode); SelectTag(ZapretIpSetSelect, zapretInfo.IpSetMode); } finally { loadingZapret = false; }
        }
        finally { zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
    }

    private async void ZapretLists_Expanded(object sender, RoutedEventArgs e)
    {
        if (zapretListsLoaded || zapretInfo == null || zapretBusy) return;
        zapretBusy = true; UpdateServerControls();
        try
        {
            var folder = settings.ZapretFolder;
            var texts = await Task.Run(() => new[] { ZapretProfiles.ReadList(folder, "domains"), ZapretProfiles.ReadList(folder, "exclude"), ZapretProfiles.ReadList(folder, "ips") });
            if (lifetime.IsCancellationRequested || folder != settings.ZapretFolder) return;
            loadingZapret = true;
            try { ZapretDomainsText.Text = texts[0]; ZapretExcludeText.Text = texts[1]; ZapretIpsText.Text = texts[2]; zapretListsLoaded = true; }
            finally { loadingZapret = false; }
        }
        catch (Exception ex) { ZapretError(ex); }
        finally { zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
    }
    private void ZapretList_Changed(object sender, TextChangedEventArgs e)
    {
        if (loadingZapret || zapretInfo == null || sender is not TextBox { Tag: string kind } editor) return;
        pendingZapretLists[kind] = editor.Text;
        zapretSaveTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
        zapretSaveTimer.Tick -= ZapretSave_Tick; zapretSaveTimer.Tick += ZapretSave_Tick; zapretSaveTimer.Stop(); zapretSaveTimer.Start();
    }
    private async void ZapretSave_Tick(object? sender, EventArgs e)
    {
        zapretSaveTimer?.Stop();
        if (zapretBusy || isConnecting || isSwitching || isManagingData || isResetting) { if (!lifetime.IsCancellationRequested) zapretSaveTimer?.Start(); return; }
        await SaveZapretListsAsync(false);
    }
    private async void ZapretSaveListsAdmin_Click(object sender, RoutedEventArgs e) => await SaveZapretListsAsync(true);
    internal async Task SaveZapretListsAsync(bool elevated)
    {
        if (zapretBusy || isConnecting || isSwitching || isManagingData || isResetting || pendingZapretLists.Count == 0 || zapretInfo == null) return;
        var pending = pendingZapretLists.ToDictionary(entry => entry.Key, entry => entry.Value);
        zapretBusy = true; UpdateServerControls();
        try
        {
            foreach (var (kind, text) in pending) ZapretProfiles.ValidateList(kind, text);
            if (elevated)
            {
                var result = await zapretController.RunAsync(new() { Action = "lists", Folder = settings.ZapretFolder, Lists = pending }, lifetime.Token);
                if (!result.Success) throw new InvalidDataException(result.Message);
            }
            else await Task.Run(() => { foreach (var (kind, text) in pending) ZapretProfiles.WriteList(settings.ZapretFolder, kind, text); });
            foreach (var (kind, text) in pending) if (pendingZapretLists.GetValueOrDefault(kind) == text) pendingZapretLists.Remove(kind);
            ZapretSaveListsAdminButton.Visibility = Visibility.Collapsed; Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Списки сохранены. Для применения к работающему zapret нажми «Перезапустить».");
        }
        catch (UnauthorizedAccessException) { ZapretSaveListsAdminButton.Visibility = Visibility.Visible; Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, "Для изменения этих списков нужны права администратора. Нажми кнопку под списками."); }
        catch (Exception ex) { ZapretError(ex); }
        finally { zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
    }

    private async Task PrepareZapretForConnectionAsync(CancellationToken token)
    {
        if (!settings.DisableZapretOnConnect)
        {
            const string warning = "Если zapret включён, он может конфликтовать с VPN. Лучше выключить его. Автоотключение можно включить во вкладке zapret.";
            ShowNotice(warning);
            if (useBackground && settings.ShowNotifications && (WindowState == WindowState.Minimized || !IsVisible)) systemTray?.ShowNotification("Возможен конфликт с zapret", Localization.T(warning));
            return;
        }
        if (pausedZapret?.HasEntries == true) return;
        if (settings.ZapretFolder == "") throw new InvalidDataException("Для автоотключения укажи папку во вкладке zapret или выключи эту настройку.");
        var state = await zapretController.ReadAsync(settings.ZapretFolder, token);
        if (state.OtherProcesses > 0) throw new InvalidDataException("Для автоотключения выбери папку работающего zapret. Другой экземпляр не был остановлен.");
        if (!state.Running && state.UnreadableProcesses == 0) return;
        var result = await zapretController.RunAsync(new() { Action = "pause", Folder = settings.ZapretFolder, CaptureRestore = settings.RestoreZapretAfterVpn }, token);
        if (result.Lease?.HasEntries == true) pausedZapret = result.Lease;
        zapretState = result.State; RenderZapretState();
        if (!result.Success || result.State.Running || result.State.UnreadableProcesses > 0) throw new InvalidDataException(result.Success ? "Не подтверждено отключение zapret. VPN не запущен." : result.Message);
        LogZapret("zapret выключен перед подключением VPN.");
    }
    private async Task RestorePausedZapretAsync()
    {
        if (pausedZapret is not { HasEntries: true } lease) return;
        if (!settings.RestoreZapretAfterVpn) { pausedZapret = null; RenderZapretState(); return; }
        try
        {
            var result = await zapretController.RunAsync(new() { Action = "resume", Folder = lease.Folder, Lease = lease }, CancellationToken.None);
            zapretState = result.State; RenderZapretState();
            if (!result.Success) throw new InvalidDataException(result.Message);
            pausedZapret = null; RenderZapretState(); LogZapret(result.Message != "" && result.Message != "Готово." ? result.Message : "Возвращено прежнее состояние zapret после VPN.");
        }
        catch (Exception ex) { ZapretError(ex); ShowNotice("Не удалось вернуть zapret после VPN. Открой его вкладку и включи вручную."); LogZapret(ZapretActionStatus.Text); }
    }
    private void ResetZapretUi()
    {
        zapretSaveTimer?.Stop(); pendingZapretLists.Clear(); zapretEvents.Clear(); zapretInfo = null; zapretState = new(); zapretListsLoaded = false;
        loadingZapret = true;
        try { ZapretFolderText.Clear(); ZapretStrategySelect.ItemsSource = null; ZapretGameSelect.SelectedItem = null; ZapretIpSetSelect.SelectedItem = null; ZapretDomainsText.Clear(); ZapretExcludeText.Clear(); ZapretIpsText.Clear(); ResetZapretAdvanced(); }
        finally { loadingZapret = false; }
        Localization.Set(ZapretStateText, System.Windows.Controls.TextBlock.TextProperty, "Папка zapret не выбрана"); Localization.Set(ZapretVersionText, System.Windows.Controls.TextBlock.TextProperty, "Подключи установленную сборку Flowseal");
        ZapretStateText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(241,214,165));
        Localization.Set(ZapretActionStatus, System.Windows.Controls.TextBlock.TextProperty, ""); Localization.Set(ZapretLogText, System.Windows.Controls.TextBlock.TextProperty, "События zapret появятся здесь и в общем журнале."); ZapretSaveListsAdminButton.Visibility = Visibility.Collapsed; LoadZapretCompatibility();
    }
}
