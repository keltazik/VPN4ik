using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace VPNyan;

public partial class MainWindow
{
    private readonly HashSet<string> checkedZapretFolders = new(StringComparer.OrdinalIgnoreCase);
    internal Task InitializeZapretFolderAsync(IEnumerable<string>? roots = null) => DiscoverZapretAsync(roots);
    private async void ZapretFindFolder_Click(object sender, RoutedEventArgs e) => await DiscoverZapretAsync();
    internal async Task DiscoverZapretAsync(IEnumerable<string>? roots = null)
    {
        if (zapretBusy || isConnecting || isSwitching || pausedZapret?.HasEntries == true || pendingZapretLists.Count != 0 || lifetime.IsCancellationRequested) return;
        zapretBusy = true; UpdateServerControls();
        ZapretDiscoveryStatus.Text = "Автоматически ищу zapret на компьютере…";
        if (zapretInfo == null) ZapretStateText.Text = "Ищу установленный zapret…";
        List<ZapretInstallation> found;
        try { found = await Task.Run(() => ZapretDiscovery.Find(settings.ZapretFolder, lifetime.Token, roots), lifetime.Token); }
        catch (OperationCanceledException) { return; }
        catch (Exception ex) { ZapretError(ex); if (zapretInfo == null) ZapretStateText.Text = "Не удалось найти zapret"; ZapretDiscoveryStatus.Text = "Автопоиск не завершён. Можно указать папку вручную ниже."; ZapretFolderExpander.IsExpanded = true; return; }
        finally { zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
        if (lifetime.IsCancellationRequested) return;
        loadingZapret = true;
        try
        {
            ZapretInstallationsSelect.ItemsSource = found; ZapretInstallationsSelect.SelectedItem = found.FirstOrDefault();
            ZapretInstallationsSelect.Visibility = found.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        }
        finally { loadingZapret = false; }
        if (found.Count > 0) await LoadZapretFolderAsync(found[0].Folder, true);
        else if (zapretInfo == null) { ZapretStateText.Text = "zapret не найден"; ZapretFolderExpander.IsExpanded = true; UpdateZapretStrategyHint(); }
        ZapretDiscoveryStatus.Text = found.Count == 0 ? "zapret не найден в обычных местах. Нажми «Указать папку вручную» и выбери распакованную папку с service.bat."
            : found.Count == 1 ? "zapret найден автоматически. Путь сохранён." : $"Найдено установок: {found.Count}. Выбери нужную из списка; сохранённый путь имеет приоритет.";
    }
    private async void ZapretInstallation_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!loadingZapret && ZapretInstallationsSelect.SelectedItem is ZapretInstallation selected && selected.Folder != settings.ZapretFolder)
            await LoadZapretFolderAsync(selected.Folder, true);
    }
    private void LoadZapretAdvanced(string folder)
    {
        var ports = ZapretProfiles.ReadGameRanges(folder); ZapretTcpPorts.Text = ports.Tcp; ZapretUdpPorts.Text = ports.Udp;
        ZapretUpdateCheckBox.IsChecked = ZapretProfiles.ReadUpdateCheck(folder);
        ZapretUpdatesStatus.Text = "";
        var files = ZapretProfiles.FakeFiles(folder);
        ZapretDiscordFake.ItemsSource = files; ZapretGameFake.ItemsSource = files;
        var discord = ZapretProfiles.CurrentFake(folder, "discord"); var game = ZapretProfiles.CurrentFake(folder, "game");
        ZapretDiscordFake.SelectedItem = files.FirstOrDefault(file => file == discord) ?? files.FirstOrDefault();
        ZapretGameFake.SelectedItem = files.FirstOrDefault(file => file == game) ?? files.FirstOrDefault();
        ZapretDiscordFakeCurrent.Text = "Discord UDP · сейчас: " + discord;
        ZapretGameFakeCurrent.Text = "Game Filter UDP · сейчас: " + game;
        ZapretHostsPanel.Visibility = ZapretReleaseButton.Visibility = Visibility.Collapsed; ZapretToolReport.Text = ""; ZapretHostsPreview.Clear();
        if (useBackground && ZapretUpdateCheckBox.IsChecked == true && checkedZapretFolders.Add(folder)) _ = CheckZapretVersionAsync(folder, true);
    }
    private async void ZapretPorts_LostFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (zapretInfo == null || loadingZapret || zapretBusy) return;
        try
        {
            var previous = ZapretProfiles.ReadGameRanges(zapretInfo.Folder);
            if (ZapretTcpPorts.Text != previous.Tcp || ZapretUdpPorts.Text != previous.Udp) await SaveZapretFiltersAsync();
        }
        catch (Exception ex) { ZapretError(ex); }
    }
    private async void ZapretPorts_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    { if (e.Key == Key.Enter) { e.Handled = true; await SaveZapretFiltersAsync(); } }

    // File settings normally save without UAC. Protected installations use the same scoped helper.
    private async Task ApplyZapretFileActionAsync(ZapretRequest request, Action local, string message)
    {
        if (zapretBusy || zapretInfo == null || isConnecting || isSwitching || isResetting || lifetime.IsCancellationRequested) return;
        zapretBusy = true; UpdateServerControls();
        try
        {
            request.Folder = settings.ZapretFolder;
            try { await Task.Run(local, lifetime.Token); }
            catch (UnauthorizedAccessException)
            {
                var result = await zapretController.RunAsync(request, lifetime.Token);
                if (!result.Success) throw new InvalidDataException(result.Message);
            }
            ZapretActionStatus.Text = message; LogZapret(message);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { ZapretError(ex); }
        finally { zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
    }
    private async void ZapretUpdateCheck_Click(object sender, RoutedEventArgs e)
    {
        var folder = settings.ZapretFolder; var enabled = ZapretUpdateCheckBox.IsChecked == true;
        await ApplyZapretFileActionAsync(new() { Action = "updates-setting", Enabled = enabled }, () => ZapretProfiles.WriteUpdateCheck(folder, enabled), enabled ? "Автопроверка обновлений zapret включена." : "Автопроверка обновлений zapret выключена.");
        try { ZapretUpdateCheckBox.IsChecked = ZapretProfiles.ReadUpdateCheck(folder); } catch { }
        if (ZapretUpdateCheckBox.IsChecked == true) await CheckZapretVersionAsync(folder, false);
    }
    private async void ZapretFake_Click(object sender, RoutedEventArgs e)
    {
        var kind = (string)((FrameworkElement)sender).Tag; var file = (kind == "discord" ? ZapretDiscordFake : ZapretGameFake).SelectedItem as string;
        if (file == null) { ZapretActionStatus.Text = "В папке bin нет доступных fake-файлов."; return; }
        var folder = settings.ZapretFolder;
        await ApplyZapretFileActionAsync(new() { Action = "fake", FakeKind = kind, FakeFile = file }, () => ZapretProfiles.ReplaceFake(folder, kind, file), "Active fake заменён. Для применения перезапусти zapret.");
        try { ZapretDiscordFakeCurrent.Text = "Discord UDP · сейчас: " + ZapretProfiles.CurrentFake(folder, "discord"); ZapretGameFakeCurrent.Text = "Game Filter UDP · сейчас: " + ZapretProfiles.CurrentFake(folder, "game"); } catch { }
    }
    private async void ZapretService_Click(object sender, RoutedEventArgs e) => await RunZapretToolAsync((string)((FrameworkElement)sender).Tag);
    private async void ZapretTool_Click(object sender, RoutedEventArgs e) => await RunZapretToolAsync((string)((FrameworkElement)sender).Tag);
    internal async Task RunZapretToolAsync(string action)
    {
        if (zapretBusy || zapretInfo == null || isConnecting || isSwitching || isResetting || isManagingData || isImporting || lifetime.IsCancellationRequested) return;
        if ((action is "test-strategies" or "install-service" or "remove-service") && pausedZapret?.HasEntries == true) { ShowNotice("Сначала отключи VPN, чтобы вернуть приостановленный zapret."); return; }
        if (action == "test-strategies" && activeServer != null) { ShowNotice("Выключи VPN перед тестом стратегий zapret."); return; }
        if (pendingZapretLists.Count > 0) { await SaveZapretListsAsync(false); if (pendingZapretLists.Count > 0) return; }
        if (action == "version") { await CheckZapretVersionAsync(settings.ZapretFolder, false); return; }
        zapretBusy = true; UpdateServerControls();
        try
        {
            zapretOperation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            ZapretToolReport.Text = action == "test-strategies" ? "Проверяю стратегии. Прежнее состояние zapret будет возвращено после теста…" : "Выполняю…";
            if (action == "diagnostics") ZapretToolReport.Text = await Task.Run(() => ZapretMaintenance.DiagnoseAsync(settings.ZapretFolder, zapretOperation.Token), zapretOperation.Token);
            else if (action == "hosts")
            {
                using var downloads = new ZapretMaintenance(); ZapretHostsPreview.Text = await downloads.DownloadAsync("hosts", zapretOperation.Token);
                ZapretHostsPanel.Visibility = Visibility.Visible; ZapretToolReport.Text = "Hosts скачан для просмотра. Системный файл не изменён.";
            }
            else
            {
                var request = new ZapretRequest { Folder = settings.ZapretFolder, Strategy = settings.ZapretStrategy, Action = action };
                if (action == "ipset")
                {
                    using var downloads = new ZapretMaintenance(); request.ListText = await downloads.DownloadAsync("ipset", zapretOperation.Token); request.Action = "ipset-update";
                    try { await Task.Run(() => ZapretProfiles.UpdateIpSet(request.Folder, request.ListText), zapretOperation.Token); request.Action = ""; }
                    catch (UnauthorizedAccessException) { }
                }
                if (request.Action != "")
                {
                    var result = await zapretController.RunAsync(request, zapretOperation.Token);
                    zapretState = result.State; RenderZapretState();
                    if (!result.Success) throw new InvalidDataException(result.Message);
                    ZapretToolReport.Text = action == "test-strategies" ? result.Message : action == "install-service" ? "Служба установлена и запущена. Автозапуск Windows включён." : action == "remove-service" ? "Службы выбранной папки удалены." : action == "timestamps" ? "TCP timestamps включены в Windows." : "IPSet обновлён. Текущий режим фильтра сохранён; перезапусти zapret для применения.";
                }
                else ZapretToolReport.Text = "IPSet обновлён. Текущий режим фильтра сохранён; перезапусти zapret для применения.";
            }
            ZapretActionStatus.Text = "Готово."; LogZapret("Инструмент zapret: " + (action switch { "test-strategies" => "тест стратегий завершён", "diagnostics" => "диагностика завершена", "hosts" => "загружен hosts для просмотра", "ipset" => "IPSet обновлён", "timestamps" => "TCP timestamps включены", "install-service" => "служба установлена", _ => "служба удалена" }));
        }
        catch (OperationCanceledException) { ZapretToolReport.Text = "Операция отменена или превышено время ожидания."; }
        catch (Exception ex) { ZapretError(ex); ZapretToolReport.Text = ZapretActionStatus.Text; }
        finally { zapretOperation?.Dispose(); zapretOperation = null; zapretBusy = false; UpdateServerControls(); FinishPendingClose(); }
    }
    private async Task CheckZapretVersionAsync(string folder, bool automatic)
    {
        try
        {
            using var downloads = new ZapretMaintenance(); var latest = (await downloads.DownloadAsync("version", lifetime.Token)).Trim();
            if (lifetime.IsCancellationRequested || folder != settings.ZapretFolder) return;
            if (automatic && !ZapretProfiles.ReadUpdateCheck(folder)) return;
            var current = ZapretProfiles.Read(folder).Version;
            var newer = Version.TryParse(latest, out var remote) && Version.TryParse(current, out var local) && remote > local;
            ZapretReleaseButton.Visibility = newer ? Visibility.Visible : Visibility.Collapsed;
            if (!automatic || newer) ZapretUpdatesStatus.Text = newer ? $"Доступно обновление zapret {latest}; установлено {current}." : $"Установлена актуальная версия zapret: {current}.";
            if (automatic && newer) ZapretActionStatus.Text = $"Доступно обновление zapret {latest}. Ссылка — в «Обновления и инструменты service.bat».";
        }
        catch (OperationCanceledException) { if (!automatic && !lifetime.IsCancellationRequested) ZapretUpdatesStatus.Text = "Проверка обновлений zapret не завершена: время ожидания истекло."; }
        catch { if (!automatic && !lifetime.IsCancellationRequested) ZapretUpdatesStatus.Text = "Не удалось проверить обновления zapret. Работа текущей версии не затронута."; }
    }
    private void ZapretRelease_Click(object sender, RoutedEventArgs e) { try { Process.Start(new ProcessStartInfo(ZapretMaintenance.Releases) { UseShellExecute = true }); } catch (Exception ex) { ZapretError(ex); } }
    private void ZapretCopyHosts_Click(object sender, RoutedEventArgs e) { try { System.Windows.Clipboard.SetText(ZapretHostsPreview.Text); ZapretActionStatus.Text = "Hosts скопирован."; } catch (Exception ex) { ZapretError(ex); } }
    private void ZapretOpenHosts_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe")) { UseShellExecute = true, Verb = "runas" };
            start.Arguments = ZapretProfiles.Quote(Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts")); Process.Start(start);
        }
        catch (Exception ex) { ZapretError(ex); }
    }
    private void ResetZapretAdvanced()
    {
        ZapretTcpPorts.Clear(); ZapretUdpPorts.Clear(); ZapretUpdateCheckBox.IsChecked = false;
        ZapretDiscordFake.ItemsSource = ZapretGameFake.ItemsSource = ZapretInstallationsSelect.ItemsSource = null;
        ZapretInstallationsSelect.Visibility = ZapretHostsPanel.Visibility = ZapretReleaseButton.Visibility = Visibility.Collapsed;
        ZapretHostsPreview.Clear(); ZapretToolReport.Text = ZapretDiscordFakeCurrent.Text = ZapretGameFakeCurrent.Text = "";
        ZapretServiceText.Text = ZapretUpdatesStatus.Text = "";
        ZapretDiscoveryStatus.Text = "Папка не выбрана. Нажми «Найти автоматически» или укажи путь вручную.";
        checkedZapretFolders.Clear();
        ZapretFolderExpander.IsExpanded = ZapretFiltersExpander.IsExpanded = false;
    }
}
