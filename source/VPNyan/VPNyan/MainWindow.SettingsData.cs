using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using ComboBox = System.Windows.Controls.ComboBox;
using TextBox = System.Windows.Controls.TextBox;

namespace VPNyan;

public partial class MainWindow
{
    private PasswordBox backupPassword=null!;
    private CheckBox backupSettingsBox=null!,backupServersBox=null!,backupRoutingBox=null!;
    private TextBlock backupPreview=null!;
    private Button backupRestore=null!,backupCreate=null!,backupChoose=null!;
    private SettingsBackupData? pendingBackup;

    private void BuildBackupSettings()
    {
        var page=SettingsPageStack("backup");
        CheckBox Choice(string text,string name) { var box=new CheckBox { IsChecked=true,Name=name }; Localization.Set(box,CheckBox.ContentProperty,text); RegisterName(name,box); return box; }
        backupSettingsBox=Choice("Настройки приложения","BackupSettingsBox"); backupServersBox=Choice("Подписки и серверы","BackupServersBox"); backupRoutingBox=Choice("Правила маршрутизации","BackupRoutingBox");
        backupPassword=new PasswordBox { MinHeight=34,Margin=new Thickness(0,0,0,14),MaxLength=1024,Name="BackupPassword" }; RegisterName(backupPassword.Name,backupPassword);
        Localization.Set(backupPassword,System.Windows.Automation.AutomationProperties.NameProperty,"Пароль копии");
        page.Children.Add(SettingsCard("Состав копии",backupSettingsBox,backupServersBox,backupRoutingBox));
        backupCreate=SettingsAction("Создать копию",()=>_ = ExportSettingsBackupAsync(),"CreateBackupButton");
        backupChoose=SettingsAction("Выбрать файл",()=>_ = ChooseSettingsBackupAsync(),"ChooseBackupButton");
        backupPreview=SettingsLabel("Файл не выбран");
        backupRestore=SettingsAction("Восстановить",()=>_ = ConfirmRestoreBackupAsync(),"RestoreBackupButton"); backupRestore.IsEnabled=false;
        page.Children.Add(SettingsCard("Резервная копия с паролем",SettingsLabel("Пароль копии"),backupPassword,SettingsLabel("Минимум 8 символов. Пароль не сохраняется. Копия содержит данные доступа — храни её в надёжном месте."),backupCreate,backupChoose,backupPreview,backupRestore));
        page.Children.Add(SettingsLabel("Восстановление заменяет выбранные данные. VPN должен быть отключён. Автозапуск Windows и путь zapret на этом ПК сохраняются."));
        backupPassword.PasswordChanged+=(_,_)=> { pendingBackup=null; backupRestore.IsEnabled=false; };
    }

    internal SettingsBackupData CaptureSettingsBackup(bool includeSettings,bool includeServers,bool includeRouting)
    {
        if(!includeSettings && !includeServers && !includeRouting) throw new InvalidDataException("Выбери хотя бы один раздел копии.");
        var copy=includeSettings?settings.Copy():null;
        if(copy!=null)
        {
            copy.LastServer=""; copy.ZapretFolder=""; copy.ZapretStrategy="";
            // Routing is an independent selection in the backup interface.
            copy.SplitApplications.Clear(); copy.SplitDomains.Clear(); copy.SplitNetworks.Clear(); copy.SplitTunnelEnabled=false; copy.RoutingPresets.Clear();
        }
        return new SettingsBackupData { Settings=copy,
            Subscriptions=includeServers?JsonSerializer.Deserialize<List<Subscription>>(JsonSerializer.Serialize(subscriptions)):null,
            WireGuardFiles=includeServers?servers.Where(s=>s.Protocol=="WireGuard").ToDictionary(s=>Path.GetFileName(s.ConfigPath),s=>File.ReadAllText(s.ConfigPath),StringComparer.OrdinalIgnoreCase):null,
            Routing=includeRouting?SettingsBackup.CaptureRouting(settings):null,
            RoutingProfiles=includeRouting?settings.RoutingPresets.Select(p=>p.Copy()).ToList():null };
    }

    private async Task ExportSettingsBackupAsync()
    {
        if(dialogBusy || isManagingData || isResetting || isImporting) return;
        try
        {
            var password=backupPassword.Password; var data=CaptureSettingsBackup(backupSettingsBox.IsChecked==true,backupServersBox.IsChecked==true,backupRoutingBox.IsChecked==true);
            if(password.Length<8) throw new InvalidDataException("Пароль должен содержать от 8 до 1024 символов.");
            var dialog=new Microsoft.Win32.SaveFileDialog { Filter="VPN4ik (*.vpn4ik)|*.vpn4ik",FileName="VPN4ik-"+DateTime.Now.ToString("yyyy-MM-dd")+".vpn4ik",AddExtension=true,DefaultExt=".vpn4ik" };
            if(dialog.ShowDialog(this)!=true) return;
            SetBackupBusy(true);
            await Task.Run(()=> { var encrypted=SettingsBackup.Encrypt(data,password); SettingsBackup.ApplyFiles(new Dictionary<string,byte[]?> { [dialog.FileName]=encrypted }); });
            backupPassword.Clear(); ShowNotice("Резервная копия сохранена.");
        }
        catch(Exception ex) { ShowNotice(ex is InvalidDataException?ex.Message:"Не удалось сохранить резервную копию."); }
        finally { SetBackupBusy(false); }
    }

    private async Task ChooseSettingsBackupAsync()
    {
        if(dialogBusy || isManagingData || isResetting || isImporting) return;
        pendingBackup=null; backupRestore.IsEnabled=false;
        var dialog=new Microsoft.Win32.OpenFileDialog { Filter="VPN4ik (*.vpn4ik)|*.vpn4ik",CheckFileExists=true };
        if(dialog.ShowDialog(this)!=true) return;
        SetBackupBusy(true);
        try
        {
            var password=backupPassword.Password;
            var data=await Task.Run(()=>
            {
                if(new FileInfo(dialog.FileName).Length>SettingsBackup.MaxBytes+100) throw new InvalidDataException("Резервная копия слишком большая.");
                return SettingsBackup.Decrypt(File.ReadAllBytes(dialog.FileName),password);
            });
            backupPassword.Clear(); pendingBackup=data;
            Localization.Set(backupPreview,TextBlock.TextProperty,BackupDescription(data));
        }
        catch(Exception ex) { Localization.Set(backupPreview,TextBlock.TextProperty,ex is InvalidDataException?ex.Message:"Не удалось прочитать резервную копию."); }
        finally { SetBackupBusy(false); }
    }
    private static string BackupDescription(SettingsBackupData data) =>
        $"Дата копии: {data.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm}\nПодписок: {data.Subscriptions?.Count ?? 0} · серверов: {data.Subscriptions?.Sum(s=>s.Profiles.Count) ?? 0} · WireGuard: {data.WireGuardFiles?.Count ?? 0}\n"+
        (data.Settings!=null?"Настройки приложения\n":"")+(data.Routing!=null?"Правила маршрутизации\n":"");
    private void SetBackupBusy(bool busy)
    {
        backupCreate.IsEnabled=backupChoose.IsEnabled=backupPassword.IsEnabled=!busy;
        backupRestore.IsEnabled=!busy && pendingBackup!=null;
    }
    private async Task ConfirmRestoreBackupAsync()
    {
        if(pendingBackup is not {} data) return;
        if(activeServer!=null || isConnecting || isImporting || isManagingData || isResetting || isSwitching || zapretBusy) { ShowNotice("Сначала отключи VPN и дождись завершения операций."); return; }
        if(!await ConfirmAsync("Восстановить резервную копию?",BackupDescription(data)+"Выбранные данные будут заменены. Логи и история сохранятся.","Восстановить")) return;
        try { await RestoreSettingsBackupAsync(data); pendingBackup=null; backupRestore.IsEnabled=false; ShowNotice("Резервная копия восстановлена."); }
        catch(Exception ex) { ShowNotice(ex is InvalidDataException?ex.Message:"Не удалось восстановить копию. Проверь журнал и состояние файлов."); activity.Add("Ошибка","Не удалось восстановить резервную копию."); }
    }

    internal async Task RestoreSettingsBackupAsync(SettingsBackupData data)
    {
        if(activeServer!=null || isConnecting || isImporting || isManagingData || isResetting || isSwitching || zapretBusy) throw new InvalidOperationException("Сначала отключи VPN и дождись завершения операций.");
        SettingsBackup.Validate(data);
        isManagingData=true; UpdateServerControls();
        try
        {
            latencyRefreshRequested=false; latencyCancellation?.Cancel();
            if(isUpdatingPings && pingsCompleted!=null) await pingsCompleted.Task;
            var next=data.Settings?.Copy()??settings.Copy(); next.StoragePath=settings.StoragePath;
            next.StartWithWindows=settings.StartWithWindows; next.AutoConnect=settings.AutoConnect; next.StartMinimized=settings.StartMinimized;
            next.ZapretFolder=settings.ZapretFolder; next.ZapretStrategy=settings.ZapretStrategy; next.LastServer=data.Subscriptions!=null || data.WireGuardFiles!=null?"":settings.LastServer;
            var routing=data.Routing??SettingsBackup.CaptureRouting(settings);
            next.SplitTunnelEnabled=routing.Enabled; next.SplitTunnelMode=routing.Mode; next.SplitApplications=new(routing.Applications); next.SplitDomains=new(routing.Domains); next.SplitNetworks=new(routing.Networks);
            next.RoutingPresets=(data.RoutingProfiles??settings.RoutingPresets).Select(p=>p.Copy()).ToList();
            var changes=new Dictionary<string,byte[]?>(StringComparer.OrdinalIgnoreCase);
            var settingsPath=settings.StoragePath??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"VPNyan","settings.json");
            changes[settingsPath]=JsonSerializer.SerializeToUtf8Bytes(next,new JsonSerializerOptions { WriteIndented=true });
            if(data.Subscriptions!=null) changes[SubscriptionPath]=SubscriptionStore.Encode(data.Subscriptions);
            if(data.WireGuardFiles!=null)
            {
                foreach(var path in Directory.EnumerateFiles(tempPath,"*.conf",SearchOption.TopDirectoryOnly)) changes[path]=null;
                foreach(var path in Directory.EnumerateFiles(tempPath,"*.conf.dpapi",SearchOption.TopDirectoryOnly)) changes[path]=null;
                foreach(var item in data.WireGuardFiles) changes[Path.Combine(tempPath,item.Key)]=Encoding.UTF8.GetBytes(item.Value);
            }
            SettingsBackup.ApplyFiles(changes);
            settings=next; draftSettings=null;
            suppressSelectionSwitch=true;
            try { servers.Clear(); SetupServers(); subscriptions=SubscriptionStore.Load(SubscriptionPath); foreach(var source in subscriptions) AddSubscriptionServers(source); ServerSelect.SelectedItem=servers.FirstOrDefault(s=>s.SelectionKey==next.LastServer)??servers.FirstOrDefault(); }
            finally { suppressSelectionSwitch=false; }
            ApplyLanguage(); UpdateConnectionModeUi(); ApplyServerSort(settings.ServerSort,false); RefreshImportedSources();
            if(pingTimer!=null) pingTimer.Interval=TimeSpan.FromSeconds(settings.PingIntervalSeconds);
            MenuToggleButton.IsChecked=settings.NavigationExpanded; ApplyNavigationLayout();
            ShowSection("settings"); ShowSettingsCategory("backup"); SaveServer();
        }
        finally { isManagingData=false; UpdateServerControls(); FinishPendingClose(); }
    }

    private void BuildPresetSettings()
    {
        var page=SettingsPageStack("presets"); presetName=new TextBox { MaxLength=80,Margin=new Thickness(0,0,0,10),MinHeight=34,Name="RoutingPresetName" }; RegisterName(presetName.Name,presetName);
        presetsSelect=new ComboBox { Style=(Style)FindResource("ZapretSelector"),Margin=new Thickness(0,0,0,12),Name="RoutingPresetSelect" }; RegisterName(presetsSelect.Name,presetsSelect);
        presetsSelect.PreviewMouseWheel+=ZapretStrategy_MouseWheel;
        page.Children.Add(SettingsCard("Профили маршрутизации",SettingsLabel("Название профиля"),presetName,SettingsAction("Сохранить текущие правила",SaveRoutingPreset,"SaveRoutingPresetButton"),presetsSelect,
            SettingsAction("Применить профиль",ApplyRoutingPreset,"ApplyRoutingPresetButton"),SettingsAction("Удалить профиль",DeleteRoutingPreset,"DeleteRoutingPresetButton"),SettingsAction("Редактор правил",()=>ShowSettingsCategory("routing"))));
    }
    private void SaveRoutingPreset()
    {
        if(draftSettings==null) return; var name=presetName.Text.Trim();
        if(name.Length==0) { ShowNotice("Введи название профиля."); return; }
        if(draftSettings.RoutingPresets.Count>=100 && !draftSettings.RoutingPresets.Any(p=>p.Name==name)) { ShowNotice("Слишком много профилей маршрутизации."); return; }
        var preset=SettingsBackup.CaptureRouting(draftSettings,name); draftSettings.RoutingPresets.RemoveAll(p=>p.Name==name); draftSettings.RoutingPresets.Add(preset); SaveSettingsAutomatically();
        presetsSelect.SelectedItem=settings.RoutingPresets.FirstOrDefault(p=>p.Name==name);
    }
    private void ApplyRoutingPreset()
    {
        if(draftSettings==null || presetsSelect.SelectedItem is not RoutingPreset preset) { ShowNotice("Выбери профиль маршрутизации."); return; }
        draftSettings.SplitTunnelEnabled=preset.Enabled; draftSettings.SplitTunnelMode=preset.Mode; draftSettings.SplitApplications=new(preset.Applications); draftSettings.SplitDomains=new(preset.Domains); draftSettings.SplitNetworks=new(preset.Networks);
        SaveSettingsAutomatically(); ShowSection("settings"); ShowSettingsCategory("routing");
    }
    private void DeleteRoutingPreset()
    {
        if(draftSettings==null || presetsSelect.SelectedItem is not RoutingPreset preset) return;
        draftSettings.RoutingPresets.RemoveAll(p=>p.Name==preset.Name); SaveSettingsAutomatically();
    }
}
