using System.IO;
using System.Windows;
using RadioButton = System.Windows.Controls.RadioButton;
using TextBox = System.Windows.Controls.TextBox;

namespace VPNyan;

public partial class MainWindow
{
    private void ApplyLanguage()
    {
        Localization.Current.Apply(settings.EffectiveLanguage);
        ApplyAppearance();
        Language = System.Windows.Markup.XmlLanguage.GetLanguage(settings.EffectiveLanguage);
        if (ServerSelect.ItemsSource != null)
        {
            ApplyServerSort(settings.ServerSort, false);
            UpdateServerFilter();
        }
    }

    internal void ShowSettingsCategory(string category)
    {
        if (!settingPages.ContainsKey(category)) category = "overview";
        if(!restoringNavigation && SettingsPage.Visibility==Visibility.Visible && settingsCategory!=category) settingsHistory.Push(settingsCategory);
        if (SettingsPage.Visibility==Visibility.Visible) RememberNavigation("settings", category);
        settingsCategory=category;
        foreach(var page in settingPages) page.Value.Visibility=page.Key==category?Visibility.Visible:Visibility.Collapsed;
        GeneralSettingsTab.IsChecked = category == "general";
        ConnectionSettingsTab.IsChecked = category == "connection";
        RoutingSettingsTab.IsChecked = category == "routing";
        DisplaySettingsTab.IsChecked = category == "display";
        SettingsFooter.Visibility = Visibility.Visible;
        ResetAllButton.Visibility = category=="overview"?Visibility.Visible:Visibility.Collapsed;
        SectionBackButton.Visibility=category=="overview"?Visibility.Collapsed:Visibility.Visible;
        settingsBack.Visibility=Visibility.Collapsed;
        settingsHeading.Visibility=Visibility.Collapsed;
        var categoryTitle=category switch {
            "general"=>"Поведение Windows", "appearance"=>"Оформление и язык", "connect"=>"Соединение", "connection"=>"Туннель и маршруты",
            "routing"=>"Редактор правил", "display"=>"Настройки пинга", "subscriptions"=>"Подписки и серверы", "performance"=>"Производительность",
            "updates"=>"Версия и обновления", "about"=>"О приложении", "backup"=>"Резервное копирование", "presets"=>"Профили маршрутизации", "diagnostics"=>"Логи и диагностика", _=>"Настройки" };
        Localization.Set(settingsHeading,System.Windows.Controls.TextBlock.TextProperty,categoryTitle);
        if(draftSettings!=null) RefreshExtendedSettings();
        if (SettingsPage.Visibility==Visibility.Visible) Localization.Set(SectionTitle,System.Windows.Controls.TextBlock.TextProperty,categoryTitle);
        SettingsScroller.ScrollToTop();
    }

    private void SettingsTab_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton button && button.Tag is string category) ShowSettingsCategory(category);
    }

    private void LoadExtraSettings()
    {
        if (draftSettings == null) return;
        LanguageSelect.SelectedValue = draftSettings.Language;
        DnsServersText.Text = draftSettings.DnsServers;
        SplitApplicationsText.Text = string.Join('\n', draftSettings.SplitApplications);
        SplitDomainsText.Text = string.Join('\n', draftSettings.SplitDomains);
        SplitNetworksText.Text = string.Join('\n', draftSettings.SplitNetworks);
        BypassModeButton.IsChecked = draftSettings.SplitTunnelMode == "Bypass";
        IncludeModeButton.IsChecked = draftSettings.SplitTunnelMode == "Include";
        MbpsUnitButton.IsChecked = draftSettings.TrafficUnit != "MB/s";
        MegabytesUnitButton.IsChecked = draftSettings.TrafficUnit == "MB/s";
        Ping30Button.IsChecked = draftSettings.PingIntervalSeconds == 30;
        Ping60Button.IsChecked = draftSettings.PingIntervalSeconds == 60;
        Ping120Button.IsChecked = draftSettings.PingIntervalSeconds == 120;
        UpdateRoutingDescription();
        RefreshExtendedSettings();
    }

    private void UpdateRoutingDescription() => Localization.Set(RoutingModeDescription, System.Windows.Controls.TextBlock.TextProperty, draftSettings?.SplitTunnelMode == "Include"
        ? "Только совпавшие приложения, домены и IP идут через VPN. Остальное — напрямую. Для приложения с несколькими процессами добавь каждый нужный .exe."
        : "Совпавшие приложения, домены и IP идут напрямую. Остальной трафик — через VPN.");

    private void SplitMode_Click(object sender, RoutedEventArgs e)
    {
        if (loadingSettings || draftSettings == null || sender is not RadioButton button) return;
        draftSettings.SplitTunnelMode = (string)button.Tag;
        UpdateRoutingDescription();
        SaveSettingsAutomatically();
    }

    private void RoutingText_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (loadingSettings || draftSettings == null || sender is not TextBox editor) return;
        try
        {
            var kind = (string)editor.Tag;
            if (kind == "dns")
            {
                _ = RoutingSettings.Dns(editor.Text);
                draftSettings.DnsServers = editor.Text;
            }
            else
            {
                var values = RoutingSettings.Parse(editor.Text, kind);
                if (kind == "process") draftSettings.SplitApplications = values;
                else if (kind == "domain") draftSettings.SplitDomains = values;
                else draftSettings.SplitNetworks = values;
            }
            SaveSettingsAutomatically();
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
        { Localization.Set(SettingsStatusText, System.Windows.Controls.TextBlock.TextProperty, ex.Message + " Последние корректные правила сохранены."); }
    }

    private void AddSplitApplication_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = Localization.T("Выбери приложение"), Filter = Localization.T("Приложения Windows (*.exe)|*.exe"), Multiselect = true };
        if (dialog.ShowDialog(this) != true) return;
        var entries = RoutingSettings.Lines(SplitApplicationsText.Text).Concat(dialog.FileNames.Select(path => path.Replace('\\', '/'))).Distinct();
        SplitApplicationsText.Text = string.Join('\n', entries);
    }

    private void TrafficUnit_Click(object sender, RoutedEventArgs e)
    {
        if (draftSettings == null || sender is not RadioButton button) return;
        draftSettings.TrafficUnit = (string)button.Tag;
        SaveSettingsAutomatically();
    }

    private void PingInterval_Click(object sender, RoutedEventArgs e)
    {
        if (draftSettings == null || sender is not RadioButton button) return;
        draftSettings.PingIntervalSeconds = int.Parse((string)button.Tag);
        SaveSettingsAutomatically();
    }

    private void Language_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (loadingSettings || draftSettings == null || LanguageSelect.SelectedValue is not string language) return;
        draftSettings.Language = language;
        draftSettings.UseSystemLanguage=false;
        SaveSettingsAutomatically();
        if (settings.Language == language) ApplyLanguage();
        else
        {
            loadingSettings = true;
            try { draftSettings.Language = settings.Language; LanguageSelect.SelectedValue = settings.Language; }
            finally { loadingSettings = false; }
        }
    }
}
