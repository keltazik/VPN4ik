using System.Collections;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace VPNyan;

public sealed record ImportedSourceItem(string Key, string Name, string Detail, bool CanRefresh, string ConfigPath = "");

public partial class MainWindow
{
    private readonly ObservableCollection<ImportedSourceItem> importedSources = new();
    private bool suppressSelectionSwitch, isSwitching, isManagingData, isResetting;
    private ServerItem? contextServer;
    private TaskCompletionSource? pingsCompleted;

    private void InitializeServerManagement()
    {
        ImportedSourcesList.ItemsSource = importedSources;
        ApplyServerSort(settings.ServerSort, false);
        RefreshImportedSources();
    }

    private static Subscription CopySubscription(Subscription source, IEnumerable<SubscriptionProfile>? profiles = null) => new()
    {
        Url = source.Url, DisplayName = source.DisplayName, UpdatedAt = source.UpdatedAt, IgnoredRoutingLines = source.IgnoredRoutingLines,
        DeletedProfileIds = new(source.DeletedProfileIds), Profiles = (profiles ?? source.Profiles).ToList()
    };

    private static string SourceName(Subscription source) => !string.IsNullOrWhiteSpace(source.DisplayName) ? source.DisplayName
        : Uri.TryCreate(source.Url, UriKind.Absolute, out var url) && url.Scheme == "https" ? url.Host : "Файл Xray";

    private void RefreshImportedSources()
    {
        importedSources.Clear();
        foreach (var source in subscriptions)
            importedSources.Add(new(source.Url, SourceName(source),
                (source.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? "Подписка" : "Файл конфигурации") +
                $" · {source.Profiles.Count} серверов" + (source.IgnoredRoutingLines > 0 ? " · маршрутизация VPN4ik" : ""), source.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)));
        foreach (var server in servers.Where(server => server.Protocol == "WireGuard"))
            importedSources.Add(new(server.SelectionKey, Path.GetFileName(server.ConfigPath), "Файл WireGuard", false, server.ConfigPath));
        ImportedSourcesEmpty.Visibility = importedSources.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ReplaceSubscriptionRows(List<Subscription> next, string? selectedKey = null)
    {
        suppressSelectionSwitch = true;
        try
        {
            var selected = selectedKey ?? (ServerSelect.SelectedItem as ServerItem)?.SelectionKey;
            var oldItems = servers.Where(s => s.Protocol != "WireGuard").ToDictionary(s => s.SelectionKey);
            subscriptions = next;
            foreach (var server in servers.Where(s => s.Protocol != "WireGuard").ToArray()) servers.Remove(server);
            foreach (var source in next)
            {
                foreach (var profile in source.Profiles)
                {
                    var key = new ServerItem { Name = profile.Name, ProfileId = profile.Id, SubscriptionUrl = source.Url }.SelectionKey;
                    if (oldItems.TryGetValue(key, out var old)) servers.Add(old);
                    else AddSubscriptionServers(CopySubscription(source, new[] { profile }));
                }
            }
            ServerSelect.SelectedItem = servers.FirstOrDefault(s => s.SelectionKey == selected) ??
                (activeServer != null && servers.Contains(activeServer) ? activeServer : servers.FirstOrDefault());
            SaveServer();
            ApplyServerSort(settings.ServerSort, false);
            RefreshImportedSources(); UpdateServerControls();
        }
        finally { suppressSelectionSwitch = false; }
    }

    internal async Task SwitchToServerAsync(ServerItem target)
    {
        if (!servers.Contains(target) || isConnecting || isSwitching || isManagingData || isResetting || isImporting) return;
        if (ReferenceEquals(activeServer, target)) return;
        isSwitching = true; UpdateServerControls();
        try
        {
            StatusText.Text = "Переключение сервера…";
            if (activeServer != null) await DisconnectCoreAsync("Переключение сервера");
            if (activeServer != null)
            {
                suppressSelectionSwitch = true;
                try { ServerSelect.SelectedItem = activeServer; SaveServer(); }
                finally { suppressSelectionSwitch = false; }
                return;
            }
            if (closeRequested) return;
            suppressSelectionSwitch = true;
            try { ServerSelect.SelectedItem = target; SaveServer(); }
            finally { suppressSelectionSwitch = false; }
            await ConnectCoreAsync();
        }
        finally
        {
            isSwitching = false; UpdateServerControls();
            if (closeRequested) _ = Dispatcher.BeginInvoke(new Action(Close));
        }
    }

    internal async Task DeleteSourceAsync(ImportedSourceItem source)
    {
        if (isConnecting || isSwitching || isManagingData || isResetting || isImporting) return;
        isManagingData = true; UpdateServerControls();
        try
        {
            if (activeServer != null && (source.ConfigPath != "" ? activeServer.ConfigPath == source.ConfigPath : activeServer.SubscriptionUrl == source.Key))
                await DisconnectCoreAsync("Удаление источника");
            if (activeServer != null && (activeServer.SubscriptionUrl == source.Key || activeServer.ConfigPath == source.ConfigPath && source.ConfigPath != ""))
                throw new IOException("Отключение не подтверждено — источник не удалён.");
            if (source.ConfigPath != "")
            {
                DeleteManagedConfig(source.ConfigPath);
                suppressSelectionSwitch = true;
                try
                {
                    foreach (var server in servers.Where(s => s.ConfigPath == source.ConfigPath).ToArray()) servers.Remove(server);
                    if (ServerSelect.SelectedItem == null) ServerSelect.SelectedItem = activeServer ?? servers.FirstOrDefault();
                    SaveServer();
                }
                finally { suppressSelectionSwitch = false; }
                RefreshImportedSources();
            }
            else
            {
                var next = subscriptions.Where(s => s.Url != source.Key).ToList();
                SubscriptionStore.Save(SubscriptionPath, next);
                ReplaceSubscriptionRows(next);
            }
            activity.Add("Информация", "Удалён источник конфигурации.");
            SubscriptionStatusText.Text = "Источник и его серверы удалены.";
        }
        finally { isManagingData = false; UpdateServerControls(); FinishPendingClose(); }
    }

    internal async Task DeleteServerAsync(ServerItem server)
    {
        if (!servers.Contains(server)) return;
        if (server.Protocol == "WireGuard")
        {
            await DeleteSourceAsync(new(server.SelectionKey, server.Name, "", false, server.ConfigPath)); return;
        }
        if (isConnecting || isSwitching || isManagingData || isResetting || isImporting) return;
        isManagingData = true; UpdateServerControls();
        try
        {
            if (ReferenceEquals(activeServer, server)) await DisconnectCoreAsync("Удаление сервера");
            if (ReferenceEquals(activeServer, server)) throw new IOException("Отключение не подтверждено — сервер не удалён.");
            var next = subscriptions.Select(source =>
            {
                if (source.Url != server.SubscriptionUrl) return source;
                var copy = CopySubscription(source, source.Profiles.Where(p => p.Id != server.ProfileId));
                if (!copy.DeletedProfileIds.Contains(server.ProfileId)) copy.DeletedProfileIds.Add(server.ProfileId);
                return copy;
            }).ToList();
            SubscriptionStore.Save(SubscriptionPath, next);
            ReplaceSubscriptionRows(next);
            SubscriptionStatusText.Text = "Сервер удалён. Остальная подписка сохранена.";
            activity.Add("Информация", "Сервер удалён из списка.");
        }
        finally { isManagingData = false; UpdateServerControls(); FinishPendingClose(); }
    }

    private void DeleteManagedConfig(string path)
    {
        var full = Path.GetFullPath(path);
        if (!string.Equals(Path.GetDirectoryName(full), Path.GetFullPath(tempPath), StringComparison.OrdinalIgnoreCase) ||
            !full.EndsWith(".conf", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Файл не принадлежит хранилищу VPN4ik.");
        File.Delete(full);
    }

    private async void DeleteSource_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: ImportedSourceItem source }) return;
        if (!await ConfirmAsync("Удалить источник?", "Его серверы исчезнут из приложения. Активное подключение этого источника будет остановлено.", "Удалить")) return;
        try { await DeleteSourceAsync(source); }
        catch (Exception ex) { ShowOperationError(ex); }
    }

    private async void RefreshSource_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ImportedSourceItem source } && source.CanRefresh) await ImportSubscriptionAsync(source.Key);
    }

    internal void ApplyServerSort(string mode, bool save = true)
    {
        if (mode is not ("original" or "name" or "country" or "ping" or "protocol")) mode = "original";
        var view = (ListCollectionView)CollectionViewSource.GetDefaultView(servers);
        var selected = ServerSelect.SelectedItem;
        var wasSuppressed = suppressSelectionSwitch;
        suppressSelectionSwitch = true;
        try
        {
            view.CustomSort = mode == "original" ? null : new ServerComparer(mode);
            if (selected != null && view.Contains(selected)) ServerSelect.SelectedItem = selected;
        }
        finally { suppressSelectionSwitch = wasSuppressed; }
        settings.ServerSort = mode;
        if (save) settings.Save();
        SortServersButton.ToolTip = "Сортировка: " + (mode switch
        { "name" => "по имени", "country" => "по стране", "ping" => "по пингу", "protocol" => "по протоколу", _ => "порядок подписки" });
        foreach (var item in SortServersMenu.Items.OfType<MenuItem>()) item.IsChecked = (string)item.Tag == mode;
    }

    private sealed class ServerComparer(string mode) : IComparer
    {
        public int Compare(object? x, object? y)
        {
            if (x is not ServerItem a || y is not ServerItem b) return 0;
            var comparison = mode switch
            {
                "ping" => (a.Ping < 0 ? int.MaxValue : a.Ping).CompareTo(b.Ping < 0 ? int.MaxValue : b.Ping),
                "country" => StringComparer.CurrentCultureIgnoreCase.Compare(a.CountryCode == "" ? "~~~" : a.CountryLabel, b.CountryCode == "" ? "~~~" : b.CountryLabel),
                "protocol" => StringComparer.OrdinalIgnoreCase.Compare(a.Protocol, b.Protocol),
                _ => StringComparer.CurrentCultureIgnoreCase.Compare(a.DisplayName, b.DisplayName)
            };
            return comparison != 0 ? comparison : StringComparer.CurrentCultureIgnoreCase.Compare(a.DisplayName, b.DisplayName);
        }
    }

    private void SortServers_Click(object sender, RoutedEventArgs e) { SortServersMenu.PlacementTarget = SortServersButton; SortServersMenu.IsOpen = true; }
    private void SortMode_Click(object sender, RoutedEventArgs e) { if (sender is MenuItem { Tag: string mode }) ApplyServerSort(mode); }
    private void FinishPendingClose() { if (closeRequested) _ = Dispatcher.BeginInvoke(new Action(Close)); }
    private void ShowOperationError(Exception error)
    {
        SubscriptionStatusText.Text = error is InvalidDataException ? error.Message : "Операция не завершена. Проверь доступ к хранилищу приложения.";
        ShowNotice(SubscriptionStatusText.Text);
    }
}
