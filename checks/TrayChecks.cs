using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using VPNyan;

internal static class TrayChecks
{
    internal static void Run(string fixtures, Action<bool,string> check)
    {
        var previous=SynchronizationContext.Current; SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        try
        {
            var legacy=Path.Combine(fixtures,"tray-legacy-"+Guid.NewGuid().ToString("N")+".json");File.WriteAllText(legacy,"{\"MinimizeToTray\":false}");
            var migrated=AppSettings.LoadFromPath(legacy);
            check(!migrated.MinimizeToTray&&!migrated.CloseToTray,"Existing tray preferences retain their minimize setting and default to real exit on close");
            foreach(var available in new[] {true,false})
            {
                var directory=Path.Combine(fixtures,"tray-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
                new AppSettings { StoragePath=Path.Combine(directory,"settings.json"),CloseToTray=true,ShowNotifications=false }.SaveOrThrow();
                var tray=new FakeTray {IsAvailable=available};var session=new Session();
                var window=new MainWindow(false,directory,()=>session,tray:tray);var closed=false;window.Closed+=(_,_)=>closed=true;
                window.ApplySubscription(new Subscription {Url="local:tray",Profiles=SubscriptionParser.Parse("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:443?security=tls#Tray")});
                Await(window.Connect());
                if(available)
                {
                    window.ShowSection("settings");
                    var minimize=(CheckBox)window.FindName("MinimizeToTrayBox");minimize.IsChecked=false;minimize.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
                    var stored=AppSettings.LoadFromPath(Path.Combine(directory,"settings.json"));
                    check(!stored.MinimizeToTray&&stored.CloseToTray&&stored.Copy().CloseToTray,"Minimize and close-to-tray options are independent and save immediately");
                    var expander=(Expander)window.FindName("TraySettingsExpander");Render(window,Path.Combine(fixtures,"tray-options-closed.png"));
                    expander.IsExpanded=true;Wait(260);Render(window,Path.Combine(fixtures,"tray-options-open.png"));
                    var drawer=(Border)expander.Template.FindName("TrayDrawer",expander);
                    check(drawer.ActualHeight>70&&drawer.Opacity>0.9,"Hide-to-tray drawer expands to reveal both options");
                    expander.IsExpanded=false;Wait(260);Render(window,Path.Combine(fixtures,"tray-options-closed.png"));
                    check(drawer.ActualHeight==0&&drawer.Opacity==0,"Hide-to-tray drawer smoothly closes without taking page space");
                }
                window.Close();Pump();
                if(available)
                {
                    check(!closed&&session.IsRunning&&!tray.Disposed,"Closing to tray keeps the application and VPN running without disposing the tray");
                    window.ExitApplication();Until(()=>closed);
                    check(closed&&!session.IsRunning&&tray.Disposed,"Explicit Exit bypasses close-to-tray and stops the owned VPN before disposing the tray");
                }
                else {Until(()=>closed);check(closed&&!session.IsRunning,"When no tray icon is available closing exits instead of hiding an unreachable application");}
            }
        }
        finally{SynchronizationContext.SetSynchronizationContext(previous);}
    }
    private sealed class FakeTray:ITrayHost
    {
        public bool IsAvailable{get;set;}public bool Disposed;
        public void ShowNotification(string title,string message){}public void Dispose()=>Disposed=true;
    }
    private sealed class Session:IVpnSession
    {
        public bool IsRunning{get;private set;}public event Action<string>? Log{add{}remove{}}
        public Task<string> StartAsync(SubscriptionProfile profile,int mtu,CancellationToken token,bool enableTun=true,bool elevate=true,bool diagnostics=false,AppSettings? routing=null){IsRunning=true;return Task.FromResult("192.0.2.1");}
        public Task<string> ProbeAsync(CancellationToken token,bool useProxy=true)=>Task.FromResult("192.0.2.1");
        public Task<TrafficCounters> ReadTrafficAsync(CancellationToken token)=>Task.FromResult(new TrafficCounters(0,0));
        public ValueTask DisposeAsync(){IsRunning=false;return ValueTask.CompletedTask;}
    }
    private static void Await(Task task){Until(()=>task.IsCompleted);task.GetAwaiter().GetResult();}
    private static void Until(Func<bool> condition){var deadline=DateTime.UtcNow.AddSeconds(10);while(!condition()){if(DateTime.UtcNow>deadline)throw new TimeoutException("Tray test timed out");Pump();Thread.Sleep(5);}Pump();}
    private static void Wait(int milliseconds){var until=DateTime.UtcNow.AddMilliseconds(milliseconds);while(DateTime.UtcNow<until){Pump();Thread.Sleep(5);}}
    private static void Pump(){var frame=new DispatcherFrame();Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background,new Action(()=>frame.Continue=false));Dispatcher.PushFrame(frame);}
    private static void Render(MainWindow window,string path){var root=(FrameworkElement)window.Content;root.Measure(new Size(1040,740));root.Arrange(new Rect(0,0,1040,740));root.UpdateLayout();var bitmap=new RenderTargetBitmap(1040,740,96,96,PixelFormats.Pbgra32);bitmap.Render(root);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using var output=File.Create(path);encoder.Save(output);}
}
