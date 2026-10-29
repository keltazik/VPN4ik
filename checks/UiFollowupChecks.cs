using System.Reflection;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Media.Imaging;
using VPNyan;
using Localization=VPNyan.Localization;

internal static class UiFollowupChecks
{
    internal static void Run(MainWindow window,Action<bool,string> check,string directory)
    {
        T Find<T>(string name)=>(T)window.FindName(name);
        void Click(string name)=>Find<Button>(name).RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        window.ShowSection("settings");window.ShowSettingsCategory("performance");
        window.NavigateBack();window.NavigateBack();
        check(Find<Grid>("SettingsPage").Visibility==Visibility.Visible && Find<TextBlock>("SectionTitle").Text=="Настройки","Settings back stops at its overview instead of opening servers");
        window.ShowSettingsCategory("performance");Click("OpenPerformanceTunnel");window.NavigateBack();
        check(Find<TextBlock>("SectionTitle").Text=="Производительность","Nested settings back restores exactly the preceding settings page");
        window.NavigateBack();
        check(Find<Button>("SectionBackButton").Visibility==Visibility.Collapsed,"Settings overview has no misleading server-list back arrow");
        var reset=Find<Button>("ResetAllButton");var scroller=Find<ScrollViewer>("SettingsScroller");
        check(IsAncestor(scroller,reset),"Reset is after settings content inside the scroll viewer");
        check(window.FindName("OpenTraySettings")==null && IsAncestor(Find<StackPanel>("GeneralSettings"),Find<Button>("OpenWindowsNetworkSettings")),"Windows network settings are in Windows behavior without a duplicate tray link in Connection");
        var bring=(RequestBringIntoViewEventArgs)Activator.CreateInstance(typeof(RequestBringIntoViewEventArgs),BindingFlags.Instance|BindingFlags.NonPublic,null,new object[]{Find<Expander>("TraySettingsExpander"),new Rect(0,0,20,20)},null)!;
        bring.RoutedEvent=FrameworkElement.RequestBringIntoViewEvent;
        Find<Expander>("TraySettingsExpander").RaiseEvent(bring);
        check(bring.Handled,"Expanding settings does not request automatic scrolling to its content");
        foreach(var name in new[]{"ConnectionModeMenu","SortServersMenu"})
        {
            var anchor=window.FindName(name) as MenuItem;
            check(anchor?.Parent is Menu,"Popup anchor belongs to the native menu capture subtree: "+name);
            anchor!.ApplyTemplate();
            var popup=anchor.Template.FindName("PART_Popup",anchor) as Popup;
            check(popup!=null && !popup.IsOpen,"Native menu template contains a closed submenu popup: "+name);
            var binding=System.Windows.Data.BindingOperations.GetBinding(popup!,Popup.IsOpenProperty);
            check(binding?.Path?.Path=="IsSubmenuOpen" && popup!.Placement==(name=="ConnectionModeMenu"?PlacementMode.Top:PlacementMode.Bottom),"Menu popup belongs to its native open state and preserves placement: "+name);
        }
        check(Find<MenuItem>("LocalDnsMenuItem").StaysOpenOnClick,"DNS retains independent checkbox behavior inside the native menu");
        var root=(FrameworkElement)window.Content;
        var snapshots=new List<string[]>();
        window.ShowSettingsCategory("appearance");
        foreach(var theme in new[]{"dark","wine","night","plum"})
        {
            Find<ComboBox>("AppearanceThemeSelect").SelectedValue=theme;
            root.Measure(new Size(1040,740));root.Arrange(new Rect(0,0,1040,740));root.UpdateLayout();
            snapshots.Add(new[]{Color(window.Background),Color(Find<Grid>("TitleBar").Background),Color(Find<TextBlock>("SectionTitle").Foreground),Color(Find<Button>("BestServerButton").Background),Color(Find<ComboBox>("AppearanceThemeSelect").Background),Color(Find<ComboBox>("AppearanceThemeSelect").Foreground),Color(Find<TextBox>("DnsServersText").CaretBrush)});
            var hoverKey=(DependencyPropertyKey)typeof(UIElement).GetField("IsMouseOverPropertyKey",BindingFlags.NonPublic|BindingFlags.Static)!.GetValue(null)!;
            var minimize=Find<Button>("MinimizeButton");minimize.ApplyTemplate();minimize.SetValue(hoverKey,true);
            check(Color(((Border)minimize.Template.FindName("Surface",minimize)).Background)==Color((Brush)window.FindResource("HoverBackground")),"Window controls use the theme hover state: "+theme);minimize.SetValue(hoverKey,false);
            var gradient=(RadialGradientBrush)Find<Grid>("ContentGrid").Background;
            check(gradient.GradientStops[0].Color!=Colors.Transparent,"Main backdrop has a themed gradient: "+theme);
            Save(window,directory,"appearance-"+theme);
        }
        for(var role=0;role<snapshots[0].Length;role++)check(snapshots.Select(p=>p[role]).Distinct().Count()==4,"All four themes change their actual surface/text role "+role);
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="button";
        check(Find<Button>("StandardConnectButton").Visibility==Visibility.Visible && Find<Viewbox>("OrnamentViewbox").Visibility==Visibility.Collapsed,"Standard connection button replaces the ornament");
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="ornament";
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="halo";
        check(Find<System.Windows.Controls.Image>("OrnamentGlow").Opacity>0,"The halo variant retains its soft idle glow");
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="ornament";
        var flags=BindingFlags.Instance|BindingFlags.NonPublic;
        void State(string field,object? value)=>typeof(MainWindow).GetField(field,flags)!.SetValue(window,value);
        void Refresh()=>typeof(MainWindow).GetMethod("UpdateOrnamentGlow",flags)!.Invoke(window,null);
        State("isConnecting",true);Refresh();
        var pulse=Find<ScaleTransform>("OrnamentPulseScale");
        check(!pulse.HasAnimatedProperties,"Connecting keeps the ornament still while the glow pulses");
        check(!Find<System.Windows.Controls.Image>("OrnamentGlow").HasAnimatedProperties,"Hidden home ornament does not animate behind settings");
        window.ShowSection("home");
        State("isConnecting",false);State("isConnected",true);State("activeServer",new ServerItem {Name="Латвия",Protocol="VLESS"});Refresh();
        check(!SystemParameters.ClientAreaAnimation || pulse.HasAnimatedProperties,"Connected ornament and glow have a slow pulse independent of hover");
        typeof(MainWindow).GetMethod("UpdateConnectedServerCard",flags)!.Invoke(window,null);
        check(Find<System.Windows.Controls.Image>("ConnectedServerFlag").Source!=null && Find<TextBlock>("ConnectedServerProtocol").Text.Contains("VLESS"),"Connected server card uses the actual server flag and protocol");
        check(!IsAncestor(Find<Border>("ConnectedServerCard"),Find<TextBlock>("StatusText")),"Compact server highlight excludes the independent connection status badge");
        window.ShowSection("home");
        Localization.Set(Find<TextBlock>("StatusText"),TextBlock.TextProperty,"Подключено");Find<TextBlock>("StatusText").Foreground=Brushes.LimeGreen;
        Find<System.Windows.Shapes.Ellipse>("StatusIndicator").Fill=Brushes.LimeGreen;
        Find<ComboBox>("AppearanceThemeSelect").SelectedValue="night";Save(window,directory,"home-connected-night");
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="button";Find<Button>("StandardConnectButton").IsEnabled=true;Save(window,directory,"home-standard-button");
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="ornament";
        State("isConnected",false);State("activeServer",null);Refresh();check(!pulse.HasAnimatedProperties,"Disconnect removes ornament pulse clocks");
        Localization.Set(Find<TextBlock>("StatusText"),TextBlock.TextProperty,"Отключено");
        var revealType=typeof(MainWindow).Assembly.GetType("VPNyan.AnimatedReveal");
        check(revealType!=null,"Subscription groups have an animated vertical reveal control");
        var reveal=(Decorator)Activator.CreateInstance(revealType!)!;reveal.Child=new Border {Width=180,Height=100};
        var progress=(DependencyProperty)revealType!.GetField("ProgressProperty")!.GetValue(null)!;
        reveal.SetValue(progress,.5d);reveal.Measure(new Size(200,double.PositiveInfinity));
        check(Math.Abs(reveal.DesiredSize.Height-50)<1 && reveal.ClipToBounds,"Reveal progress clips a half-open list to half its natural height");
        Find<ComboBox>("AppearanceThemeSelect").SelectedValue="dark";window.ShowSection("settings");window.ShowSettingsCategory("overview");
    }
    private static string Color(Brush brush)=>brush is SolidColorBrush solid?solid.Color.ToString():brush.ToString();
    private static bool IsAncestor(DependencyObject ancestor,DependencyObject? child)
    {while(child!=null){if(child==ancestor)return true;child=LogicalTreeHelper.GetParent(child)??(child is Visual?VisualTreeHelper.GetParent(child):null);}return false;}
    private static void Save(MainWindow window,string directory,string name)
    {
        var root=(FrameworkElement)window.Content;root.Measure(new Size(1040,740));root.Arrange(new Rect(0,0,1040,740));root.UpdateLayout();
        var image=new RenderTargetBitmap(1040,740,96,96,PixelFormats.Pbgra32);image.Render(root);
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(image));using var output=File.Create(Path.Combine(directory,name+".png"));encoder.Save(output);
    }
}
