using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using VPNyan;
using Localization = VPNyan.Localization;

internal static class SettingsFeatureChecks
{
    private const string Link="vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#Latvia";
    internal static void Run(string fixtures,Action<bool,string> check)
    {
        var context=SynchronizationContext.Current; SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        var directory=Path.Combine(fixtures,"settings-features-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        var path=Path.Combine(directory,"settings.json");
        var options=new AppSettings { StoragePath=path,AutoCheckPings=false,AutoUpdateSubscriptions=true,SplitDomains=new(){"example.org"} }; options.SaveOrThrow();
        var window=new MainWindow(false,directory);
        try
        {
            BrandAssetsChecks.Run(window,directory,check);
            UiFollowupChecks.Run(window,check,directory);
            window.ShowSection("settings");
            Pump();
            T Find<T>(string name)=>(T)window.FindName(name);
            void Click(string name)=>Find<Button>(name).RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            void Toggle(string name,bool value) { var box=Find<CheckBox>(name); box.IsChecked=value; box.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); }
            Click("OpenAppearanceSettings");
            Find<ComboBox>("AppearanceThemeSelect").SelectedValue="night";
            Find<ComboBox>("AppearanceVisualSelect").SelectedValue="compact";
            var appearanceSaved=AppSettings.LoadFromPath(path);
            check(appearanceSaved.Theme=="night" && appearanceSaved.ConnectionVisual=="compact" && appearanceSaved.Copy().ConnectionVisual=="compact","Appearance selections persist and survive settings snapshots");
            Click("OpenPerformanceDiagnostics");
            window.ShowSection("logs"); window.NavigateBack();
            check(Find<Grid>("SettingsPage").Visibility==Visibility.Visible && Find<TextBlock>("SectionTitle").Text=="Логи и диагностика","Back from logs restores its settings category");
            window.NavigateBack();
            check(Find<TextBlock>("SectionTitle").Text=="Оформление и язык","Nested settings back returns to the previous settings page");
            check(Find<RadioButton>("LogsMenuButton").Visibility==Visibility.Collapsed && Find<RadioButton>("HistoryMenuButton").Visibility==Visibility.Collapsed,"Logs and history are accessible through settings only");
            using(var metadata=new System.Net.Http.HttpResponseMessage())
            {
                metadata.Headers.TryAddWithoutValidation("profile-title","base64:"+Convert.ToBase64String(Encoding.UTF8.GetBytes("Ultima VPN")));
                metadata.Headers.TryAddWithoutValidation("subscription-userinfo","upload=1; download=2; total=3; expire=1795000000");
                check(SubscriptionPresentation.Title(metadata.Headers)=="Ultima VPN" && SubscriptionPresentation.Expiry(metadata.Headers)==DateTimeOffset.FromUnixTimeSeconds(1795000000),"Provider title and expiry are read from metadata without exposing access URLs");
                check(SubscriptionPresentation.Name(new Subscription { Url="https://sub.ultima.test/private-token" })=="Ultima VPN","A subscription without metadata uses a human readable provider name without URL tokens");
                check(SubscriptionPresentation.Name(new Subscription { Url="https://g.ultm.in/private-token" })=="Ultima VPN","Ultima short host resolves to the full provider name");
            }
            Toggle("SystemLanguageBox",true); check(AppSettings.LoadFromPath(path).UseSystemLanguage && !Find<ComboBox>("LanguageSelect").IsEnabled,"System language persists and disables manual selection: "+Find<TextBlock>("SettingsStatusText").Text);
            Toggle("SystemLanguageBox",false); Find<ComboBox>("LanguageSelect").SelectedValue="ru";
            Click("SettingsBackButton"); Click("OpenSubscriptionSettings");
            Find<ComboBox>("SubscriptionIntervalSelect").SelectedValue="6";
            Find<ComboBox>("SettingsSortSelect").SelectedValue="country";
            check(AppSettings.LoadFromPath(path).SubscriptionUpdateHours==6 && AppSettings.LoadFromPath(path).ServerSort=="country","Subscription interval and sorting save immediately");
            Toggle("AutoUpdateSubscriptionsBox",false); check(!Find<ComboBox>("SubscriptionIntervalSelect").IsEnabled,"Disabled automatic updates disable the interval selector");
            Toggle("AutoUpdateSubscriptionsBox",true);
            window.ShowSettingsCategory("connection"); Find<ComboBox>("SettingsConnectionMode").SelectedValue="proxy"; Toggle("SettingsLocalDnsBox",true);
            check(AppSettings.LoadFromPath(path).ConnectionMode=="proxy" && AppSettings.LoadFromPath(path).UseLocalDns,"Mode and local DNS controls update the same persisted settings as the home menu");
            window.ShowSettingsCategory("performance"); Toggle("ShowMemoryBox",true); Toggle("SniffDomainsBox",false);
            check(AppSettings.LoadFromPath(path).ShowMemoryUsage && !AppSettings.LoadFromPath(path).SniffDomains,"Memory display and domain detection settings persist");
            using(var locked=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
            {
                Toggle("ShowMemoryBox",false); Pump();
                check(Find<CheckBox>("ShowMemoryBox").IsChecked==true && AppSettings.LoadFromPath(path).ShowMemoryUsage && !File.Exists(path+".tmp"),"A failed settings write restores the visible toggle and removes the staging file");
            }
            window.ShowSettingsCategory("presets"); Find<TextBox>("RoutingPresetName").Text="Family"; Click("SaveRoutingPresetButton");
            var saved=AppSettings.LoadFromPath(path); check(saved.RoutingPresets.Single().Domains.SequenceEqual(new[]{"example.org"}),"Routing preset stores a separate copy of the current rules");
            window.ShowSettingsCategory("routing"); Find<TextBox>("SplitDomainsText").Text="changed.example";
            window.ShowSettingsCategory("presets"); Find<ComboBox>("RoutingPresetSelect").SelectedIndex=0; Click("ApplyRoutingPresetButton");
            check(AppSettings.LoadFromPath(path).SplitDomains.SequenceEqual(new[]{"example.org"}) && Find<TextBox>("SplitDomainsText").Text=="example.org","Applying a routing preset restores the editors and persistent rules");

            var source=new Subscription { Url="https://example.test/subscription",UpdatedAt=DateTime.UtcNow.AddDays(-1),Profiles=SubscriptionParser.Parse(Link) };
            var now=DateTime.UtcNow;
            check(MainWindow.SubscriptionUpdateDue(source,saved,now) && !MainWindow.SubscriptionUpdateDue(new Subscription { Url="local:one",UpdatedAt=source.UpdatedAt },saved,now),"Update scheduling includes only due HTTPS sources");
            source.UpdatedAt=now; check(!MainWindow.SubscriptionUpdateDue(source,saved,now),"A recent subscription is not downloaded again before the selected interval");
            window.ApplySubscription(source); var called=0;
            Await(window.RefreshAllSubscriptionsAsync(true,(_,_)=> { called++; throw new IOException("Synthetic failure"); }));
            check(called==1 && SubscriptionStore.Load(Path.Combine(directory,"subscriptions.dpapi")).Single().Profiles.Count==1,"A failed update preserves the existing protected subscription");
            Await(window.RefreshAllSubscriptionsAsync(true,async(url,token)=> { await Task.Yield(); return new Subscription { Url=url,UpdatedAt=DateTime.UtcNow,Profiles=SubscriptionParser.Parse(Link+"2") }; }));
            check(SubscriptionStore.Load(Path.Combine(directory,"subscriptions.dpapi")).Single().Profiles.Single().Name=="Latvia2","A successful asynchronous update replaces the protected source without network fixtures");

            var backup=window.CaptureSettingsBackup(true,true,true); var encrypted=SettingsBackup.Encrypt(backup,"test-password");
            check(!Encoding.UTF8.GetString(encrypted).Contains("subscription") && !Encoding.UTF8.GetString(encrypted).Contains("example.org"),"Portable backup does not store settings or access links in plaintext");
            var restored=SettingsBackup.Decrypt(encrypted,"test-password");
            check(restored.Subscriptions!.Single().Profiles.Single().Name=="Latvia2" && restored.Routing!.Domains.Single()=="example.org","Encrypted backup round trips server data and selected routing rules");
            foreach(var scenario in new[]{"password","cipher","header"})
            {
                var tampered=(byte[])encrypted.Clone(); if(scenario=="cipher") tampered[^1]^=1; if(scenario=="header") tampered[0]^=1;
                var rejected=false; try { SettingsBackup.Decrypt(tampered,scenario=="password"?"wrong-password":"test-password"); } catch(InvalidDataException) { rejected=true; }
                check(rejected,"Backup rejects invalid authentication: "+scenario);
            }
            var traversal=new SettingsBackupData { WireGuardFiles=new() { ["../escape.conf"]="Endpoint=192.0.2.1:443" } };
            var blocked=false; try { SettingsBackup.Validate(traversal); } catch(InvalidDataException) { blocked=true; }
            check(blocked,"Backup validation rejects configuration path traversal");
            var malformed=new SettingsBackupData { Subscriptions=new(){ new Subscription { Url=source.Url,Profiles=new(){new SubscriptionProfile { Id="one",Name="Bad",Configuration="invalid" }} } } };
            blocked=false; try { SettingsBackup.Validate(malformed); } catch(InvalidDataException) { blocked=true; } check(blocked,"Backup validation rejects malformed server configuration before touching storage");
            var a=Path.Combine(directory,"rollback-a" ); var b=Path.Combine(directory,"rollback-b"); File.WriteAllText(a,"before");
            try { SettingsBackup.ApplyFiles(new Dictionary<string,byte[]?> { [a]=Encoding.UTF8.GetBytes("after"),[b]=new byte[]{1} },count=> { if(count==2) throw new IOException("fixture"); }); } catch(IOException) { }
            check(File.ReadAllText(a)=="before" && !File.Exists(b),"A failed restore rolls back changed and newly created files");
            var wireguardCopy=new SettingsBackupData { WireGuardFiles=new() { ["family.conf"]="[Peer]\nEndpoint=192.0.2.1:51820" } };
            Await(window.RestoreSettingsBackupAsync(SettingsBackup.Decrypt(SettingsBackup.Encrypt(wireguardCopy,"test-password"),"test-password")));
            check(File.Exists(Path.Combine(directory,"family.conf")) && ((ListBox)window.FindName("ServerSelect")).Items.Cast<ServerItem>().Any(s=>s.Protocol=="WireGuard"),"Portable restore adds validated WireGuard files to the visible server list");
            window.ShowSettingsCategory("routing"); Find<TextBox>("SplitDomainsText").Text="changed.example";
            Await(window.RestoreSettingsBackupAsync(restored));
            check(AppSettings.LoadFromPath(path).SplitDomains.Single()=="example.org" && SubscriptionStore.Load(Path.Combine(directory,"subscriptions.dpapi")).Single().Profiles.Count==1,"Restoring the validated snapshot updates settings and DPAPI storage together");
            var settingsOnly=window.CaptureSettingsBackup(true,false,false); check(settingsOnly.Subscriptions==null && settingsOnly.Routing==null && settingsOnly.Settings!.SplitDomains.Count==0,"Backup component selections do not accidentally export routing or credentials");
            window.ApplySubscription(new Subscription {Url="https://another.example.test/subscription",DisplayName="Same name",Profiles=SubscriptionParser.Parse(Link+"other")});
            var grouped=System.Windows.Data.CollectionViewSource.GetDefaultView(Find<ListBox>("ServerSelect").ItemsSource);
            check(grouped.Groups!.Count>=2 && grouped.Groups.Cast<System.Windows.Data.CollectionViewGroup>().Select(g=>g.Name).Distinct().Count()==grouped.Groups.Count,"Servers remain separate subscription groups independent of their displayed titles");
            CheckSniffing(check);
            CheckLayout(window,directory,check);
        }
        finally { window.Close(); Localization.Current.Apply("ru"); SynchronizationContext.SetSynchronizationContext(context); }
    }
    private static void CheckSniffing(Action<bool,string> check)
    {
        var request=new EngineRequest { Profile=SubscriptionParser.Parse(Link).Single(),ProbePort=49151,ProbeUser="test",ProbePassword="fixture",HttpProxyPort=49152,EnableTun=false,EnableSystemProxy=true,Routing=new AppSettings { SniffDomains=false } };
        var native=JsonNode.Parse(HiddifyCore.Build(request))!; var xray=JsonNode.Parse(XrayConfiguration.Build(request))!;
        check(!native["route"]!["rules"]!.AsArray().Any(r=>r?["action"]?.ToString()=="sniff") && !xray["inbounds"]!.AsArray().Any(i=>i?["sniffing"]?["enabled"]?.GetValue<bool>()==true),"Disabling domain detection reaches both engine configurations");
        request.Routing.SniffDomains=true; native=JsonNode.Parse(HiddifyCore.Build(request))!;
        check(native["route"]!["rules"]!.AsArray().Any(r=>r?["action"]?.ToString()=="sniff"),"Default domain detection remains enabled in the native tunnel");
    }
    private static void CheckLayout(MainWindow window,string directory,Action<bool,string> check)
    {
        var root=(FrameworkElement)window.Content; var scroller=(ScrollViewer)window.FindName("SettingsScroller");
        ((FrameworkElement)window.FindName("PingWarning")).Visibility=Visibility.Collapsed;
        foreach(var language in new[]{"ru","en","hy"})
        {
            ((ComboBox)window.FindName("LanguageSelect")).SelectedValue=language;
            foreach(var category in new[]{"overview","appearance","connect","connection","general","subscriptions","display","performance","diagnostics","about","updates","backup","presets"})
            {
                window.ShowSettingsCategory(category);
                foreach(var size in new[]{new Size(760,540),new Size(1040,740)})
                {
                    root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout(); Pump();
                    scroller.ScrollToBottom(); root.UpdateLayout(); Pump();
                    var reset=(Button)window.FindName("ResetAllButton"); var before=reset.TransformToAncestor(root).TransformBounds(new Rect(reset.RenderSize));
                    check(scroller.ExtentWidth<=scroller.ViewportWidth+1,"Settings have no horizontal overflow: "+category+"/"+language+"/"+size.Width);
                    if(category=="overview")
                    {
                        scroller.ScrollToTop();root.UpdateLayout();Pump();
                        var after=reset.TransformToAncestor(root).TransformBounds(new Rect(reset.RenderSize));
                        var viewport=scroller.TransformToAncestor(root).TransformBounds(new Rect(scroller.RenderSize));
                        check(before.Bottom<=viewport.Bottom+1 && (scroller.ScrollableHeight<1 || after.Y>before.Y+1),"Reset flows with content and is reachable at the bottom: "+category+"/"+language+"/"+size.Width);
                    }
                    if(size.Width==1040 && language=="ru")
                    {
                        scroller.ScrollToTop(); root.UpdateLayout(); Pump();
                        var image=new RenderTargetBitmap((int)size.Width,(int)size.Height,96,96,PixelFormats.Pbgra32); image.Render(root);
                        var encoder=new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image)); using var file=File.Create(Path.Combine(directory,"settings-"+category+".png")); encoder.Save(file);
                    }
                }
            }
        }
    }
    private static void Pump()=>Dispatcher.CurrentDispatcher.Invoke(()=>{},DispatcherPriority.Background);
    private static void Await(Task task)
    { var until=DateTime.UtcNow.AddSeconds(20); while(!task.IsCompleted && DateTime.UtcNow<until) { Pump(); Thread.Sleep(10); } if(!task.IsCompleted) throw new TimeoutException(); task.GetAwaiter().GetResult(); }
}
