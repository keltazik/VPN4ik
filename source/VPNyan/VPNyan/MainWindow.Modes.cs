using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace VPNyan;

public partial class MainWindow
{
    private void UpdateConnectionModeUi()
    {
        if (ConnectionModeLabel == null) return;
        Localization.Set(ConnectionModeLabel, System.Windows.Controls.TextBlock.TextProperty, settings.ConnectionMode == "proxy" ? "Прокси" : "Xray TUN");
        ProxyModeItem.IsChecked = settings.ConnectionMode == "proxy";
        XrayTunModeItem.IsChecked = settings.ConnectionMode != "proxy";
        LocalDnsMenuItem.IsChecked = settings.UseLocalDns;
        LocalDnsMenuItem.IsEnabled = settings.ConnectionMode == "tun";
        UpdateConnectedServerCard();
    }
    private void ConnectionMode_Opened(object sender, RoutedEventArgs e)
    {
        UpdateConnectionModeUi();
        ProxyModeItem.IsEnabled = XrayTunModeItem.IsEnabled = !isConnecting && activeServer == null && !isSwitching && !isManagingData;
    }
    internal bool SetConnectionMode(string mode)
    {
        if (mode is not ("tun" or "proxy") || isConnecting || activeServer != null || isSwitching || isManagingData) return false;
        var next = settings.Copy(); next.ConnectionMode = mode;
        try { next.SaveOrThrow(); settings = next; if (draftSettings != null) draftSettings.ConnectionMode = mode; UpdateConnectionModeUi(); return true; }
        catch { Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, "Не удалось сохранить режим подключения."); UpdateConnectionModeUi(); return false; }
    }
    private void ConnectionModeItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { Tag: string mode }) SetConnectionMode(mode);
        UpdateConnectionModeUi(); e.Handled = true;
    }
    private void LocalDns_Click(object sender, RoutedEventArgs e)
    {
        var next = settings.Copy(); next.UseLocalDns = LocalDnsMenuItem.IsChecked;
        try
        {
            next.SaveOrThrow(); settings = next; if (draftSettings != null) draftSettings.UseLocalDns = next.UseLocalDns;
            if (activeServer != null) Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, "DNS сохранён. Применится после переподключения.");
        }
        catch { Localization.Set(IpText, System.Windows.Controls.TextBlock.TextProperty, "Не удалось сохранить настройку DNS."); }
        UpdateConnectionModeUi();
    }
}
