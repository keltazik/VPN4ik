using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace VPNyan;

public partial class MainWindow
{
    private void UpdateConnectionModeUi()
    {
        if (ConnectionModeLabel == null) return;
        ConnectionModeLabel.Text = settings.ConnectionMode == "proxy" ? "Прокси" : "Xray TUN";
        ProxyModeItem.IsChecked = settings.ConnectionMode == "proxy";
        XrayTunModeItem.IsChecked = settings.ConnectionMode != "proxy";
        LocalDnsMenuItem.IsChecked = settings.UseLocalDns;
        LocalDnsMenuItem.IsEnabled = settings.ConnectionMode == "tun";
    }
    private void ConnectionMode_Click(object sender, RoutedEventArgs e)
    {
        UpdateConnectionModeUi();
        ProxyModeItem.IsEnabled = XrayTunModeItem.IsEnabled = !isConnecting && activeServer == null && !isSwitching && !isManagingData;
        ConnectionModeMenu.PlacementTarget = ConnectionModeButton;
        ConnectionModeMenu.Placement = PlacementMode.Top;
        ConnectionModeMenu.IsOpen = true;
    }
    internal bool SetConnectionMode(string mode)
    {
        if (mode is not ("tun" or "proxy") || isConnecting || activeServer != null || isSwitching || isManagingData) return false;
        var next = settings.Copy(); next.ConnectionMode = mode;
        try { next.SaveOrThrow(); settings = next; if (draftSettings != null) draftSettings.ConnectionMode = mode; UpdateConnectionModeUi(); return true; }
        catch { IpText.Text = "Не удалось сохранить режим подключения."; UpdateConnectionModeUi(); return false; }
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
            if (activeServer != null) IpText.Text = "DNS сохранён. Применится после переподключения.";
        }
        catch { IpText.Text = "Не удалось сохранить настройку DNS."; }
        UpdateConnectionModeUi();
    }
}