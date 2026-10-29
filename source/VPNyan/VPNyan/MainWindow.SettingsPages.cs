using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using ComboBox = System.Windows.Controls.ComboBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using Binding = System.Windows.Data.Binding;
using Panel = System.Windows.Controls.Panel;
using RadioButton = System.Windows.Controls.RadioButton;
using FontFamily = System.Windows.Media.FontFamily;

namespace VPNyan;

public partial class MainWindow
{
    private readonly Dictionary<string, FrameworkElement> settingPages = new();
    private string settingsCategory = "overview";
    private Button settingsBack = null!;
    private TextBlock settingsHeading = null!, memoryDisplay = null!, diagnosticsOutput = null!;
    private ComboBox subscriptionInterval = null!, settingsSort = null!, settingsMode = null!, presetsSelect = null!;
    private CheckBox systemLanguageBox = null!, localDnsBox = null!;
    private TextBox presetName = null!;
    private readonly List<(string Key, Action Refresh)> settingsRefresh = new();

    private static SolidColorBrush SettingsBrush(string color) => new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(color));
    private TextBlock SettingsLabel(string text, double size = 12, string color = "#C4A285")
    {
        var label = new TextBlock { FontSize=size, Foreground=SettingsBrush(color), TextWrapping=TextWrapping.Wrap, Margin=new Thickness(0,0,0,9) };
        if(ThemeTokens.For(color) is { } role)label.SetResourceReference(TextBlock.ForegroundProperty,role);
        Localization.Set(label, TextBlock.TextProperty, text); return label;
    }
    private Button SettingsAction(string text, Action action, string? name = null)
    {
        var button = new Button { Style=(Style)FindResource("ActionButton"), Margin=new Thickness(0,0,8,8), HorizontalContentAlignment=System.Windows.HorizontalAlignment.Stretch };
        var label=SettingsLabel(text,12,"#F1D6A5"); label.Margin=new Thickness(0); button.Content=label;
        Localization.Set(button,System.Windows.Automation.AutomationProperties.NameProperty,text);
        button.Click += (_,_) => action();
        if (name != null) { button.Name=name; RegisterName(name,button); }
        return button;
    }
    private CheckBox SettingsToggle(string text, string property, string? name = null)
    {
        var box = new CheckBox { Margin=new Thickness(0,5,0,12) };
        Localization.Set(box, CheckBox.ContentProperty, text);
        box.SetBinding(CheckBox.IsCheckedProperty,new Binding(property) { Mode=BindingMode.TwoWay, UpdateSourceTrigger=UpdateSourceTrigger.PropertyChanged });
        box.Click += SettingsCheckBox_Click;
        if (name != null) { box.Name=name; RegisterName(name,box); }
        return box;
    }
    private Button SettingsNavigation(string text,string category,string name)
    {
        var button=SettingsAction(text,()=>ShowSettingsCategory(category),name);
        button.Style=(Style)FindResource("SettingsMenuRow"); button.Margin=new Thickness(0,0,0,2);
        var row=new Grid(); row.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(36) }); row.ColumnDefinitions.Add(new ColumnDefinition()); row.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(18) });
        var glyph=category switch { "appearance"=>"\uE790", "connect"=>"\uE701", "connection" or "routing"=>"\uE83D", "general"=>"\uE782", "subscriptions"=>"\uE8F1", "display"=>"\uE9D9", "updates"=>"\uE896", "about"=>"\uE946", "backup"=>"\uE74E", "performance"=>"\uE950", "presets"=>"\uE8B7", _=>"\uE9D9" };
        var icon=new TextBlock { Text=glyph,FontFamily=new FontFamily("Segoe MDL2 Assets"),FontSize=19,VerticalAlignment=VerticalAlignment.Center,Foreground=SettingsBrush("#D4AA65") };
        var label=SettingsLabel(text,13,"#F1D6A5"); label.Margin=new Thickness(0); label.VerticalAlignment=VerticalAlignment.Center; Grid.SetColumn(label,1);
        var arrow=SettingsLabel("›",18); arrow.Margin=new Thickness(4,0,0,0); arrow.VerticalAlignment=VerticalAlignment.Center; Grid.SetColumn(arrow,2);
        row.Children.Add(icon); row.Children.Add(label); row.Children.Add(arrow); button.Content=row; return button;
    }
    private Border SettingsCard(string title, params UIElement[] content)
    {
        var stack = new StackPanel(); if(title.Length>0) stack.Children.Add(SettingsLabel(title,15,"#F1D6A5"));
        foreach(var child in content) stack.Children.Add(child);
        var card=new Border { Background=SettingsBrush("#1C101A"), BorderBrush=SettingsBrush("#412332"), BorderThickness=new Thickness(1),
            CornerRadius=new CornerRadius(12), Padding=new Thickness(16), Margin=new Thickness(0,0,0,14), Child=stack };
        card.SetResourceReference(Border.BackgroundProperty,"CardBackground"); return card;
    }
    private StackPanel SettingsPageStack(string key)
    {
        var stack=new StackPanel { Visibility=Visibility.Collapsed, HorizontalAlignment=System.Windows.HorizontalAlignment.Stretch };
        settingPages[key]=stack; SettingsContentGrid.Children.Add(stack); return stack;
    }
    private ComboBox SettingsSelect(string[] labels, string[] values, Action<string> change, string name)
    {
        var select=new ComboBox { Style=(Style)FindResource("ZapretSelector"), SelectedValuePath="Tag", Margin=new Thickness(0,0,0,12), Name=name };
        for(int i=0;i<labels.Length;i++) { var item=new ComboBoxItem { Tag=values[i] }; Localization.Set(item,ComboBoxItem.ContentProperty,labels[i]); select.Items.Add(item); }
        RegisterName(name,select); select.PreviewMouseWheel += ZapretStrategy_MouseWheel;
        select.SelectionChanged += (_,_) => { if(!loadingSettings && draftSettings!=null && select.SelectedValue is string value) change(value); };
        return select;
    }

    private void InitializeSettingsPages()
    {
        InitializeSettingsScrollStability();
        System.ComponentModel.PropertyChangedEventHandler languageChanged=(_,args)=>{if(args.PropertyName==nameof(Localization.Language))UpdateConnectedServerCard();};
        Localization.Current.PropertyChanged+=languageChanged;
        Closed+=(_,_)=>Localization.Current.PropertyChanged-=languageChanged;
        foreach(var tab in SettingsTabsPanel.Children.OfType<RadioButton>()) tab.Visibility=Visibility.Collapsed;
        settingsBack=SettingsAction("←",()=>ShowSettingsCategory("overview"),"SettingsBackButton"); settingsBack.Width=36;
        settingsHeading=SettingsLabel("Настройки",16,"#F1D6A5"); settingsHeading.VerticalAlignment=VerticalAlignment.Center;
        SettingsTabsPanel.Children.Add(settingsBack); SettingsTabsPanel.Children.Add(settingsHeading);
        SettingsTabsPanel.Visibility=Visibility.Collapsed;
        Localization.Set(SectionBackButton,Button.ToolTipProperty,"Назад");
        Localization.Set(SectionBackButton,System.Windows.Automation.AutomationProperties.NameProperty,"Назад");
        settingPages["general"]=GeneralSettings; settingPages["connection"]=ConnectionSettings;
        settingPages["routing"]=RoutingSettingsPanel; settingPages["display"]=DisplaySettings;
        foreach(var panel in settingPages.Values) panel.MaxWidth=double.PositiveInfinity;
        var overview=SettingsPageStack("overview");
        overview.Children.Add(SettingsCard("",SettingsNavigation("Оформление и язык","appearance","OpenAppearanceSettings")));
        var columns=new Grid(); columns.ColumnDefinitions.Add(new ColumnDefinition()); columns.ColumnDefinitions.Add(new ColumnDefinition());
        var left=new StackPanel { Margin=new Thickness(0,10,8,0) }; var right=new StackPanel { Margin=new Thickness(8,10,0,0) }; Grid.SetColumn(right,1);
        columns.Children.Add(left); columns.Children.Add(right); overview.Children.Add(columns);
        Button Link(string text,string page,string name)=>SettingsNavigation(text,page,name);
        left.Children.Add(SettingsCard("Подключение",Link("Соединение","connect","OpenConnectionSettings"),Link("Туннель и маршруты","connection","OpenTunnelSettings"),Link("Поведение Windows","general","OpenWindowsSettings")));
        left.Children.Add(SettingsCard("Серверы",Link("Подписки и серверы","subscriptions","OpenSubscriptionSettings"),Link("Настройки пинга","display","OpenPingSettings")));
        right.Children.Add(SettingsCard("Приложение",Link("Версия и обновления","updates","OpenUpdateSettings"),Link("О приложении","about","OpenAboutSettings"),Link("Резервное копирование","backup","OpenBackupSettings")));
        right.Children.Add(SettingsCard("Дополнительно",Link("Производительность","performance","OpenPerformanceSettings"),Link("Логи и диагностика","diagnostics","OpenDiagnosticsSettings")));

        // Reuse the existing controls and handlers: no second copy of a setting can drift out of sync.
        var appearance=SettingsPageStack("appearance");
        // Select and heading are direct children of GeneralSettings.
        var languageIndex=GeneralSettings.Children.IndexOf(LanguageSelect);
        var heading=GeneralSettings.Children[languageIndex-1]; GeneralSettings.Children.Remove(heading); GeneralSettings.Children.Remove(LanguageSelect);
        systemLanguageBox=SettingsToggle("Как в Windows",nameof(AppSettings.UseSystemLanguage),"SystemLanguageBox");
        BuildAppearanceSettings(appearance, systemLanguageBox);
        var unitsTitle=DisplaySettings.Children[1]; var units=DisplaySettings.Children[2]; var unitsHelp=DisplaySettings.Children[3];
        DisplaySettings.Children.Remove(unitsTitle); DisplaySettings.Children.Remove(units); DisplaySettings.Children.Remove(unitsHelp);
        appearance.Children.Add(SettingsCard("Скорость и трафик",unitsTitle,units,unitsHelp));
        var updates=SettingsPageStack("updates");
        var updateCard=GeneralSettings.Children.OfType<Border>().Last(); GeneralSettings.Children.Remove(updateCard); updates.Children.Add(updateCard);

        var connect=SettingsPageStack("connect");
        connect.Children.Add(SettingsCard("Соединение",SettingsToggle("Разрешить доступ к локальной сети",nameof(AppSettings.BypassLocalNetwork)),Link("Правила исключений","routing","OpenConnectionRules")));
        var windowsControls=GeneralSettings.Children.Cast<UIElement>().ToArray();
        GeneralSettings.Children.Clear();
        GeneralSettings.Children.Add(SettingsCard("Основные настройки",windowsControls));
        GeneralSettings.Children.Add(SettingsCard("Работа в Windows",SettingsAction("Настройки сети Windows",()=>OpenSettingsLink("ms-settings:network-status"),"OpenWindowsNetworkSettings")));

        settingsMode=SettingsSelect(new[]{"VPN (TUN)","Прокси"},new[]{"tun","proxy"},mode=>
        { if(!SetConnectionMode(mode)) ShowNotice("Сначала отключи VPN для смены режима."); RefreshExtendedSettings(); },"SettingsConnectionMode");
        localDnsBox=SettingsToggle("Использовать DNS Windows",nameof(AppSettings.UseLocalDns),"SettingsLocalDnsBox");
        ConnectionSettings.Children.Insert(0,SettingsCard("Режим подключения",settingsMode,SettingsLabel("Hiddify Core + Xray"),localDnsBox));
        ConnectionSettings.Children.Add(SettingsCard("Маршрутизация",Link("Редактор правил","routing","OpenRoutingSettings"),Link("Профили маршрутизации","presets","OpenRoutingPresets")));

        var subscriptionPage=SettingsPageStack("subscriptions");
        subscriptionInterval=SettingsSelect(new[]{"1 час","2 часа","6 часов","12 часов","24 часа"},new[]{"1","2","6","12","24"},value=>
        { draftSettings!.SubscriptionUpdateHours=int.Parse(value,CultureInfo.InvariantCulture); SaveSettingsAutomatically(); },"SubscriptionIntervalSelect");
        subscriptionPage.Children.Add(SettingsCard("Обновление подписок",SettingsToggle("Автоматическое обновление подписок",nameof(AppSettings.AutoUpdateSubscriptions),"AutoUpdateSubscriptionsBox"),subscriptionInterval,
            SettingsToggle("Уведомлять об обновлении подписок",nameof(AppSettings.NotifySubscriptionUpdates)),SettingsToggle("Обновлять подписки при запуске",nameof(AppSettings.RefreshSubscriptionsOnStartup)),
            SettingsToggle("Проверять пинг после обновления",nameof(AppSettings.PingAfterSubscriptionUpdate)),SettingsAction("Обновить все подписки",()=>_ = RefreshAllSubscriptionsAsync(true),"RefreshAllSubscriptionsButton"),SettingsAction("Добавить или удалить подписки",()=>ShowSection("import"))));
        settingsSort=SettingsSelect(new[]{"Как в подписке","По задержке","По имени","По стране","По протоколу"},new[]{"original","ping","name","country","protocol"},value=>
        { draftSettings!.ServerSort=value; SaveSettingsAutomatically(); ApplyServerSort(settings.ServerSort,false); },"SettingsSortSelect");
        subscriptionPage.Children.Add(SettingsCard("Список серверов",settingsSort,Link("Настройки пинга","display","OpenSubscriptionPing")));

        var performance=SettingsPageStack("performance"); memoryDisplay=SettingsLabel("Память: —");
        performance.Children.Add(SettingsCard("Память",SettingsToggle("Показывать память на главном экране",nameof(AppSettings.ShowMemoryUsage),"ShowMemoryBox"),memoryDisplay,SettingsAction("Обновить показания",UpdateMemoryDisplay)));
        performance.Children.Add(SettingsCard("Определение доменов",SettingsToggle("Распознавать имя сайта",nameof(AppSettings.SniffDomains),"SniffDomainsBox"),SettingsLabel("Распознавание используется только для маршрутизации. Исходный адрес назначения сохраняется.")));
        performance.Children.Add(SettingsCard("Туннель",Link("MTU и DNS","connection","OpenPerformanceTunnel"),Link("Системная диагностика","diagnostics","OpenPerformanceDiagnostics")));
        BuildAboutSettings(); BuildBackupSettings(); BuildPresetSettings(); BuildDiagnosticsSettings();
        // Status remains visible on every detail page; reset stays on the overview and Windows page only.
        ShowSettingsCategory("overview");
    }

    private void RefreshExtendedSettings()
    {
        var wasLoading=loadingSettings; loadingSettings=true;
        try
        {
            settingsMode.SelectedValue=settings.ConnectionMode; localDnsBox.IsEnabled=settings.ConnectionMode=="tun";
            subscriptionInterval.SelectedValue=settings.SubscriptionUpdateHours.ToString(CultureInfo.InvariantCulture);
            subscriptionInterval.IsEnabled=settings.AutoUpdateSubscriptions; settingsSort.SelectedValue=settings.ServerSort;
            LanguageSelect.IsEnabled=!settings.UseSystemLanguage;
            LanguageSelect.SelectedValue=settings.Language;
            RefreshAppearanceSettings();
            presetsSelect.ItemsSource=settings.RoutingPresets.ToArray();
            foreach(var item in settingsRefresh) item.Refresh();
            UpdateMemoryDisplay();
        }
        finally { loadingSettings=wasLoading; }
    }

    private void BuildAboutSettings()
    {
        var page=SettingsPageStack("about"); var version=SettingsLabel("");
        settingsRefresh.Add(("version",()=>Localization.Set(version,TextBlock.TextProperty,"VPN4ik · "+ApplicationUpdates.CurrentVersion)));
        page.Children.Add(SettingsCard("VPN4ik",version,SettingsLabel("Hiddify Core 5.0.3 · Xray 26.10.21 · Windows x64"),SettingsAction("GitHub",()=>OpenSettingsLink("https://github.com/keltazik/VPN4ik")),SettingsAction("Поддержка в Telegram",()=>OpenSettingsLink("https://t.me/VPN4ikSupportBot")),SettingsAction("Лицензии компонентов",ShowComponentLicenses)));
        var card=(Border)page.Children[0];var text=card.Child;card.Child=null;
        var columns=new Grid();columns.ColumnDefinitions.Add(new ColumnDefinition());columns.ColumnDefinitions.Add(new ColumnDefinition {Width=new GridLength(128)});
        columns.Children.Add(text);
        var shoes=new System.Windows.Controls.Image {Name="AboutMoccasins",Source=BrandAssets.Moccasins(),Width=112,Height=76,Margin=new Thickness(16,0,0,0),HorizontalAlignment=System.Windows.HorizontalAlignment.Right,VerticalAlignment=VerticalAlignment.Top,IsHitTestVisible=false,Stretch=Stretch.Uniform};
        RegisterName(shoes.Name,shoes);Grid.SetColumn(shoes,1);columns.Children.Add(shoes);card.Child=columns;
    }

    private void OpenSettingsLink(string uri)
    { try { Process.Start(new ProcessStartInfo(uri) { UseShellExecute=true }); } catch { ShowNotice("Не удалось открыть ссылку."); } }

    private void BuildDiagnosticsSettings()
    {
        var page=SettingsPageStack("diagnostics"); diagnosticsOutput=SettingsLabel("");
        page.Children.Add(SettingsCard("Логи и диагностика",SettingsAction("Журнал событий",()=>ShowSection("logs")),SettingsAction("История подключения",()=>ShowSection("history")),SettingsAction("Информация о системе",()=>_ = ShowSystemDiagnosticsAsync(false)),SettingsAction("Таблица маршрутов",()=>_ = ShowSystemDiagnosticsAsync(true)),diagnosticsOutput));
    }

    private async Task ShowSystemDiagnosticsAsync(bool routes)
    {
        try
        {
            var text=await Task.Run(async ()=>
            {
                if(!routes) return System.Runtime.InteropServices.RuntimeInformation.OSDescription+"\n"+System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture+"\n"+
                    string.Join("\n",NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Name+" · "+n.OperationalStatus));
                using var process=new Process { StartInfo=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"route.exe"),"print")
                { UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true } };
                process.Start(); var output=process.StandardOutput.ReadToEndAsync(); var error=process.StandardError.ReadToEndAsync();
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); timeout.CancelAfter(TimeSpan.FromSeconds(5));
                try { await process.WaitForExitAsync(timeout.Token); } catch { try { process.Kill(); } catch { } throw; }
                await error; var result=await output; return result[..Math.Min(result.Length,16000)];
            });
            if(!lifetime.IsCancellationRequested) Localization.Set(diagnosticsOutput,TextBlock.TextProperty,text);
        }
        catch { Localization.Set(diagnosticsOutput,TextBlock.TextProperty,"Не удалось получить диагностику."); }
    }

    private void ShowComponentLicenses()
    {
        try
        {
            var paths=new[]{Path.Combine(AppContext.BaseDirectory,"licenses"),Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"..","..","licenses"))};
            var folder=paths.FirstOrDefault(Directory.Exists);
            if(folder!=null) OpenSettingsLink(folder); else OpenSettingsLink("https://github.com/keltazik/VPN4ik/blob/main/THIRD_PARTY.md");
        }
        catch { ShowNotice("Не удалось открыть лицензии."); }
    }

    private void UpdateMemoryDisplay()
    {
        var bytes=SettingsMemoryBytes(); var text=$"Память приложения и ядер: {bytes/1048576d:0} MB";
        Localization.Set(memoryDisplay,TextBlock.TextProperty,text);
        memoryIndicator.Visibility=settings.ShowMemoryUsage?Visibility.Visible:Visibility.Collapsed;
        Localization.Set(memoryIndicator,TextBlock.TextProperty,$"Память: {bytes/1048576d:0} MB");
    }
    private long SettingsMemoryBytes()
    {
        long bytes=0;
        var ids=new[]{Environment.ProcessId}.Concat(xraySession is XraySession x?x.OwnedProcessIds.Concat(x.HelperProcessId is int helperId?new[]{helperId}:Array.Empty<int>()):Array.Empty<int>()).Distinct();
        foreach(var id in ids) try { using var process=Process.GetProcessById(id); bytes+=process.WorkingSet64; } catch { }
        return bytes;
    }
    private TextBlock memoryIndicator=null!;
    private void InitializeSettingsBackground()
    {
        memoryIndicator=SettingsLabel(""); memoryIndicator.FontSize=10; memoryIndicator.Margin=new Thickness(0,6,0,0); memoryIndicator.Visibility=Visibility.Collapsed;
        if(TrafficText.Parent is Grid grid)
        {
            Grid.SetRow(memoryIndicator,grid.RowDefinitions.Count); Grid.SetColumnSpan(memoryIndicator,2);
            grid.RowDefinitions.Add(new RowDefinition { Height=GridLength.Auto }); grid.Children.Add(memoryIndicator);
        }
        var timer=new System.Windows.Threading.DispatcherTimer { Interval=TimeSpan.FromSeconds(3) };
        timer.Tick+=(_,_)=>{ if(settings.ShowMemoryUsage || settingsCategory=="performance" && SettingsPage.IsVisible) UpdateMemoryDisplay(); };
        if(useBackground) timer.Start(); Closed+=(_,_)=>timer.Stop();
        InitializeSubscriptionUpdates();
    }
}
