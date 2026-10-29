using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace VPNyan;

public partial class MainWindow
{
    private async void StandardConnect_Click(object sender,RoutedEventArgs args)
    {
        if(isConnecting || isSwitching || isManagingData || isResetting)return;
        if(activeServer==null)await Connect();else await Disconnect();
    }
    private void UpdateConnectedServerCard()
    {
        if(ConnectedServerCard==null)return;
        var server=activeServer??ServerSelect.SelectedItem as ServerItem;
        ConnectedServerFlag.Source=server?.CountryFlag;
        ConnectedServerFlag.Visibility=server==null?Visibility.Collapsed:Visibility.Visible;
        SelectedServerName.Text=server?.DisplayName??Localization.T("Сервер не выбран");
        ConnectedServerProtocol.Text=server==null?"":server.Protocol+" · "+(settings.ConnectionMode=="tun"?"TUN":Localization.T("Прокси"));
        ConnectedServerProtocol.Visibility=server==null?Visibility.Collapsed:Visibility.Visible;
        if(isConnected)
        {
            ConnectedServerCard.SetResourceReference(Border.BackgroundProperty,"AccentSoftBackground");
            ConnectedServerCard.SetResourceReference(Border.BorderBrushProperty,"Accent");
        }
        else { ConnectedServerCard.Background=System.Windows.Media.Brushes.Transparent;ConnectedServerCard.BorderBrush=System.Windows.Media.Brushes.Transparent; }
        StandardConnectButton.IsEnabled=canCreateSession && server?.CanConnect==true && !isConnecting && !isSwitching && !isManagingData && !isResetting;
        var action=isConnecting?"Подключение":activeServer==null?"Подключиться":"Отключиться";
        Localization.Set(StandardConnectButton,System.Windows.Automation.AutomationProperties.NameProperty,action);
        Localization.Set(StandardConnectButton,FrameworkElement.ToolTipProperty,action);
    }
}
