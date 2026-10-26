using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Data;
using Clipboard = System.Windows.Clipboard;
using Button = System.Windows.Controls.Button;

namespace VPNyan;

public partial class MainWindow
{
    private TaskCompletionSource<bool>? confirmation;
    private string dialogKind = "";
    private ServerItem? editingServer;
    private List<ProcessChoice> processChoices = new();
    private int processLoadGeneration;
    private bool dialogBusy;

    private void ShowNotice(string text)
    {
        PingWarningText.Text = text;
        PingWarning.Visibility = Visibility.Visible;
        pingWarningTimer ??= new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        pingWarningTimer.Stop(); pingWarningTimer.Tick -= HidePingWarning; pingWarningTimer.Tick += HidePingWarning; pingWarningTimer.Start();
    }

    private void OpenActionDialog(string kind, string title, string message, string primary)
    {
        dialogKind = kind; dialogBusy = false;
        DialogTitle.Text = title; DialogDescription.Text = message; DialogError.Text = "";
        DialogPrimary.Content = primary; DialogPrimary.IsEnabled = true; DialogCancel.IsEnabled = true;
        EditorPanel.Visibility = kind == "edit" ? Visibility.Visible : Visibility.Collapsed;
        ProcessPickerPanel.Visibility = kind == "process" ? Visibility.Visible : Visibility.Collapsed;
        ActionOverlay.Visibility = Visibility.Visible;
        DialogCancel.Focus();
    }

    private Task<bool> ConfirmAsync(string title, string message, string primary)
    {
        if (ActionOverlay.Visibility == Visibility.Visible) return Task.FromResult(false);
        confirmation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        OpenActionDialog("confirm", title, message, primary);
        return confirmation.Task;
    }

    private void CloseActionDialog(bool result = false)
    {
        ActionOverlay.Visibility = Visibility.Collapsed; dialogKind = ""; editingServer = null;
        ConfigurationEditor.Clear(); processChoices.Clear(); ProcessPickerList.ItemsSource = null;
        processLoadGeneration++;
        var pending = confirmation; confirmation = null; pending?.TrySetResult(result);
    }

    private void DialogCancel_Click(object sender, RoutedEventArgs e) { if (!dialogBusy) CloseActionDialog(); }
    private void ActionOverlay_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    { if (e.Key == Key.Escape && !dialogBusy) { CloseActionDialog(); e.Handled = true; } }

    private async void DialogPrimary_Click(object sender, RoutedEventArgs e)
    {
        if (dialogBusy) return;
        if (dialogKind == "confirm") { CloseActionDialog(true); return; }
        if (dialogKind == "process")
        {
            var selected = processChoices.Where(process => process.Selected).Select(process => process.Rule).ToArray();
            if (selected.Length == 0) { DialogError.Text = "Выбери хотя бы одно приложение."; return; }
            var entries = RoutingSettings.Lines(SplitApplicationsText.Text).Concat(selected).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            CloseActionDialog(); SplitApplicationsText.Text = string.Join('\n', entries); return;
        }
        if (dialogKind != "edit" || editingServer == null) return;
        dialogBusy = true; DialogPrimary.IsEnabled = DialogCancel.IsEnabled = false;
        try { await EditServerAsync(editingServer, ConfigurationEditor.Text); CloseActionDialog(); }
        catch (Exception ex) { DialogError.Text = ex is InvalidDataException ? ex.Message : "Не удалось сохранить конфигурацию. Прежняя версия сохранена, если отключение не подтверждено."; }
        finally { dialogBusy = false; DialogPrimary.IsEnabled = DialogCancel.IsEnabled = true; }
    }

    private async void AddRunningProcess_Click(object sender, RoutedEventArgs e)
    {
        OpenActionDialog("process", "Запущенные приложения", "Выбери программы для правила раздельного туннелирования. Если Windows скрывает путь, добавится имя .exe.", "Добавить выбранные");
        var generation = ++processLoadGeneration;
        ProcessSearchText.Clear(); DialogPrimary.IsEnabled = false; DialogError.Text = "Загружаю процессы…";
        try
        {
            var entries = await ProcessCatalog.ListAsync();
            if (generation != processLoadGeneration || dialogKind != "process") return;
            processChoices = entries; ProcessPickerList.ItemsSource = processChoices; FilterProcessChoices();
            DialogError.Text = entries.Count == 0 ? "Процессы не найдены. Можно выбрать .exe через файл." : "";
            DialogPrimary.IsEnabled = true;
        }
        catch { if (generation == processLoadGeneration) DialogError.Text = "Не удалось прочитать процессы. Используй выбор .exe."; }
    }
    private void ProcessSearch_TextChanged(object sender, TextChangedEventArgs e) { if (ProcessPickerList != null) FilterProcessChoices(); }
    private void FilterProcessChoices()
    {
        if (ProcessPickerList.ItemsSource == null) return;
        var search = ProcessSearchText.Text.Trim();
        CollectionViewSource.GetDefaultView(ProcessPickerList.ItemsSource).Filter = item => item is ProcessChoice process &&
            (search == "" || process.Name.Contains(search, StringComparison.CurrentCultureIgnoreCase) || process.Path.Contains(search, StringComparison.CurrentCultureIgnoreCase));
    }

    private void ServerRightClick(object sender, MouseButtonEventArgs e)
    {
        var row = ItemsControl.ContainerFromElement(ServerSelect, e.OriginalSource as DependencyObject) as ListBoxItem;
        contextServer = row?.DataContext as ServerItem;
        if (contextServer == null) { e.Handled = true; return; }
        PrepareServerMenu(); ServerContextMenu.PlacementTarget = row; ServerContextMenu.IsOpen = true; e.Handled = true;
    }

    private void ServerMenu_Opening(object sender, ContextMenuEventArgs e)
    {
        if (e.CursorLeft < 0) contextServer = ServerSelect.SelectedItem as ServerItem;
        if (contextServer == null) { e.Handled = true; return; }
        PrepareServerMenu();
    }

    private void PrepareServerMenu()
    {
        if (contextServer == null) return;
        ContextServerName.Text = contextServer.DisplayName; ContextServerFlag.Source = contextServer.CountryFlag;
        ContextConnect.Header = ReferenceEquals(contextServer, activeServer) ? "Отключиться" : activeServer != null ? "Переключиться на сервер" : "Подключиться";
        ContextCopy.Header = contextServer.Protocol == "WireGuard" ? "Копировать конфигурацию" : "Копировать JSON / ссылку";
        var available = !isConnecting && !isSwitching && !isManagingData && !isResetting && !isImporting;
        ContextConnect.IsEnabled = available; ContextEdit.IsEnabled = ContextDelete.IsEnabled = available;
        ContextPing.IsEnabled = !isUpdatingPings && !isResetting;
    }

    private async void ContextConnect_Click(object sender, RoutedEventArgs e)
    {
        if (contextServer is not { } target) return;
        if (ReferenceEquals(target, activeServer)) await Disconnect(); else await SwitchToServerAsync(target);
    }
    private async void ContextPing_Click(object sender, RoutedEventArgs e) { if (contextServer is { } server) await PingServerAsync(server); }
    private void ContextCopy_Click(object sender, RoutedEventArgs e)
    {
        if (contextServer == null) return;
        try { Clipboard.SetText(contextServer.Protocol == "WireGuard" ? File.ReadAllText(contextServer.ConfigPath) : contextServer.Configuration); ShowNotice("Конфигурация скопирована."); }
        catch { ShowNotice("Не удалось скопировать конфигурацию."); }
    }
    private void ContextEdit_Click(object sender, RoutedEventArgs e)
    {
        if (contextServer == null) return;
        try
        {
            var text = contextServer.Protocol == "WireGuard" ? File.ReadAllText(contextServer.ConfigPath) : contextServer.Configuration;
            OpenActionDialog("edit", "Конфигурация сервера", "Здесь находятся данные доступа. После изменения активного сервера приложение переподключится.", ReferenceEquals(contextServer, activeServer) ? "Применить и переподключить" : "Сохранить");
            editingServer = contextServer; ConfigurationEditor.Text = text;
        }
        catch { ShowNotice("Не удалось прочитать конфигурацию."); }
    }
    private async void ContextDelete_Click(object sender, RoutedEventArgs e)
    {
        if (contextServer is not { } server) return;
        if (!await ConfirmAsync("Удалить сервер?", "Остальная подписка сохранится. Если этот сервер подключён, VPN будет отключён.", "Удалить сервер")) return;
        try { await DeleteServerAsync(server); } catch (Exception ex) { ShowOperationError(ex); }
    }

    internal async Task PingServerAsync(ServerItem server)
    {
        if (isUpdatingPings || isResetting || !servers.Contains(server)) return;
        if (!ServerLatency.SupportsTcpPing(server.Protocol)) { ShowNotice("Сервер использует UDP; TCP-пинг к нему неприменим."); return; }
        if (PingMayBeInaccurate) ShowPingWarning();
        isUpdatingPings = true; pingsCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using var run = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); latencyCancellation = run;
        server.SetLatencyPending(); UpdateServerControls();
        try
        {
            await ServerLatency.MeasureAsync(new[] { (server.SelectionKey, new SubscriptionProfile { Protocol = server.Protocol, Address = server.Address, Port = server.Port }) }, result =>
            {
                if (!run.IsCancellationRequested) Dispatcher.Invoke(() => { if (servers.Contains(server)) server.SetLatency(result); });
            }, run.Token);
        }
        catch (OperationCanceledException) { }
        catch { ShowNotice("Замер не завершён. Подключение к серверу можно попробовать отдельно."); }
        finally
        {
            if (server.PingDisplay == "…") server.SetLatency(new(server.SelectionKey, -1, "Проверка отменена или не завершена."));
            isUpdatingPings = false; latencyCancellation = null; pingsCompleted?.TrySetResult();
            ApplyServerSort(settings.ServerSort, false); UpdateServerControls();
        }
    }

    internal async Task EditServerAsync(ServerItem server, string text)
    {
        if (!servers.Contains(server) || isConnecting || isSwitching || isManagingData || isResetting || isImporting) throw new InvalidDataException("Дождись завершения текущей операции.");
        SubscriptionProfile? profile = null;
        ServerItem? wireguard = null;
        if (server.Protocol == "WireGuard") wireguard = ReadServerText(text, server.ConfigPath);
        else
        {
            var profiles = SubscriptionParser.Parse(text);
            if (profiles.Count != 1) throw new InvalidDataException("Для редактирования одного сервера нужна одна конфигурация.");
            profile = profiles[0];
            _ = XrayConfiguration.Build(new EngineRequest { Profile = profile, ProbePort = 49152, EnableTun = false });
        }
        isManagingData = true; UpdateServerControls();
        var reconnect = ReferenceEquals(activeServer, server);
        try
        {
            if (reconnect) await DisconnectCoreAsync("Изменение конфигурации");
            if (ReferenceEquals(activeServer, server)) throw new IOException("Отключение не подтверждено.");
            if (wireguard != null)
            {
                if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(server.ConfigPath)), Path.GetFullPath(tempPath), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Файл не принадлежит хранилищу приложения.");
                File.WriteAllText(server.ConfigPath + ".tmp", text); File.Move(server.ConfigPath + ".tmp", server.ConfigPath, true);
                suppressSelectionSwitch = true;
                try { servers[servers.IndexOf(server)] = wireguard; ServerSelect.SelectedItem = wireguard; SaveServer(); }
                finally { suppressSelectionSwitch = false; }
            }
            else
            {
                var next = subscriptions.Select(source => source.Url == server.SubscriptionUrl
                    ? CopySubscription(source, source.Profiles.Select(old => old.Id == server.ProfileId ? profile! : old)) : source).ToList();
                SubscriptionStore.Save(SubscriptionPath, next);
                var key = new ServerItem { Name = profile!.Name, SubscriptionUrl = server.SubscriptionUrl, ProfileId = profile.Id }.SelectionKey;
                ReplaceSubscriptionRows(next, key);
            }
            if (reconnect && !closeRequested) await ConnectCoreAsync();
            RefreshImportedSources();
        }
        finally { isManagingData = false; UpdateServerControls(); FinishPendingClose(); }
    }

    private async void ResetAll_Click(object sender, RoutedEventArgs e)
    {
        if (!await ConfirmAsync("Полностью сбросить VPN4ik?", "Будут удалены все подписки, импортированные конфигурации, логи и история. Настройки вернутся к исходным, автозапуск отключится. Текущее VPN-подключение будет остановлено. Это действие нельзя отменить.", "Сбросить всё")) return;
        try { await ResetAllAsync(); ShowNotice("Данные удалены. VPN4ik сброшен к исходным настройкам."); }
        catch { ShowNotice("Сброс завершён не полностью. Проверь доступ к файлам и повтори его."); }
    }

    internal async Task ResetAllAsync()
    {
        if (isConnecting || isSwitching || isManagingData || isImporting || isResetting || zapretBusy) throw new InvalidOperationException("Дождись завершения операции.");
        isResetting = true; UpdateServerControls();
        try
        {
            if (activeServer != null) await DisconnectCoreAsync("Сброс данных");
            if (activeServer != null) throw new IOException("Туннель не остановлен.");
            await RestorePausedZapretAsync();
            if (pausedZapret?.HasEntries == true) throw new IOException("Сначала восстанови zapret или отключи возврат его состояния.");
            latencyRefreshRequested = false; latencyCancellation?.Cancel();
            if (isUpdatingPings && pingsCompleted != null) await pingsCompleted.Task;
            if (useBackground) SetAutoStart(false);
            var defaults = new AppSettings { StoragePath = settings.StoragePath };
            defaults.SaveOrThrow();
            SubscriptionStore.Save(SubscriptionPath, Array.Empty<Subscription>());
            foreach (var path in Directory.EnumerateFiles(tempPath, "*.conf", SearchOption.TopDirectoryOnly)) DeleteManagedConfig(path);
            foreach (var path in Directory.EnumerateFiles(tempPath, "*.conf.dpapi", SearchOption.TopDirectoryOnly)) File.Delete(path);
            activity.Reset();
            contextServer = null; CloseActionDialog();
            settings = defaults; draftSettings = null; subscriptions.Clear();
            ResetZapretUi();
            suppressSelectionSwitch = true;
            try { servers.Clear(); ServerSelect.SelectedItem = null; } finally { suppressSelectionSwitch = false; }
            MenuToggleButton.IsChecked = false; ApplyNavigationLayout();
            ServerSearchText.Clear(); SubscriptionUrlText.Clear(); ConfigurationEditor.Clear();
            ApplyServerSort("original", false); RefreshImportedSources();
            if (pingTimer != null) pingTimer.Interval = TimeSpan.FromSeconds(defaults.PingIntervalSeconds);
            ShowSection("settings"); ShowSettingsCategory("general");
            SubscriptionStatusText.Text = "Добавь подписку или конфигурацию."; StatusText.Text = "Отключено"; IpText.Text = "";
            SaveServer();
        }
        finally { isResetting = false; UpdateServerControls(); FinishPendingClose(); }
    }
}
