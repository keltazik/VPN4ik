using System.IO;
using System.Windows.Threading;

namespace VPNyan;

public partial class MainWindow
{
    private DispatcherTimer? subscriptionUpdateTimer;
    private DateTime nextSubscriptionCheck=DateTime.UtcNow;

    private void InitializeSubscriptionUpdates()
    {
        if(!useBackground) return;
        subscriptionUpdateTimer=new DispatcherTimer { Interval=TimeSpan.FromMinutes(1) };
        subscriptionUpdateTimer.Tick+=async (_,_)=>
        {
            if(!settings.AutoUpdateSubscriptions || DateTime.UtcNow<nextSubscriptionCheck) return;
            await RefreshAllSubscriptionsAsync(false);
        };
        subscriptionUpdateTimer.Start();
    }

    internal static bool SubscriptionUpdateDue(Subscription source,AppSettings options,DateTime utcNow) =>
        options.AutoUpdateSubscriptions && source.Url.StartsWith("https://",StringComparison.OrdinalIgnoreCase) &&
        source.UpdatedAt.ToUniversalTime().AddHours(Math.Clamp(options.SubscriptionUpdateHours,1,24))<=utcNow;

    internal async Task RefreshAllSubscriptionsAsync(bool manual,Func<string,CancellationToken,Task<Subscription>>? fetch=null)
    {
        if(isImporting || isManagingData || isResetting || isSwitching || isConnecting || closeRequested || lifetime.IsCancellationRequested)
        { if(manual) ShowNotice("Дождись завершения операции."); return; }
        var sources=subscriptions.Where(s=>s.Url.StartsWith("https://",StringComparison.OrdinalIgnoreCase) &&
            (manual || SubscriptionUpdateDue(s,settings,DateTime.UtcNow))).ToArray();
        // Startup can be enabled independently of periodic updating.
        if(startupSubscriptionRefresh) sources=subscriptions.Where(s=>s.Url.StartsWith("https://",StringComparison.OrdinalIgnoreCase)).ToArray();
        if(sources.Length==0) { if(manual) ShowNotice("Нет подписок для обновления."); return; }
        isImporting=true; UpdateServerControls(); var completed=0; var failed=0;
        try
        {
            using var client=new SubscriptionClient();
            foreach(var source in sources)
            {
                if(closeRequested || lifetime.IsCancellationRequested) break;
                try
                {
                    using var timeout=CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); timeout.CancelAfter(TimeSpan.FromSeconds(25));
                    var updated=await (fetch!=null?fetch(source.Url,timeout.Token):client.DownloadAsync(source.Url,timeout.Token));
                    if(closeRequested || lifetime.IsCancellationRequested) break;
                    // A source must not change its identity as a result of a redirect or a remote response.
                    updated.Url=source.Url; ApplySubscription(updated); completed++;
                }
                catch(OperationCanceledException) when(lifetime.IsCancellationRequested) { break; }
                catch { failed++; activity.Add("Ошибка","Не удалось обновить подписку. Прежние серверы сохранены."); }
            }
            var message=$"Обновление подписок: {completed} · ошибок: {failed}";
            activity.Add("Информация",message);
            if(manual || settings.NotifySubscriptionUpdates) ShowNotice(message);
            if(!manual && settings.NotifySubscriptionUpdates && settings.ShowNotifications)
                systemTray?.ShowNotification("VPN4ik",Localization.T(message));
        }
        finally
        {
            nextSubscriptionCheck=DateTime.UtcNow.AddMinutes(failed>0?5:1);
            isImporting=false; UpdateServerControls(); FinishPendingClose();
        }
        if(completed>0 && settings.PingAfterSubscriptionUpdate && !closeRequested && !lifetime.IsCancellationRequested) await UpdatePings();
    }
    private bool startupSubscriptionRefresh;
    private async Task RefreshSubscriptionsAtStartupAsync()
    {
        startupSubscriptionRefresh=true;
        try { await RefreshAllSubscriptionsAsync(false); } finally { startupSubscriptionRefresh=false; }
    }
}
