using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace VPNyan;

public partial class MainWindow
{
    private ApplicationRelease? availableUpdate;
    private DispatcherTimer? updateTimer;
    private bool checkingUpdates, installingUpdate, updateFallback;
    private string dismissedUpdate = "";
    private CancellationTokenSource? updateCancellation;

    private void InitializeUpdates()
    {
        Localization.Set(AppVersionText, System.Windows.Controls.TextBlock.TextProperty, "VPN4ik " + ApplicationUpdates.CurrentVersion);
        if (!useBackground) return;
        updateTimer = new DispatcherTimer { Interval = TimeSpan.FromHours(4) };
        updateTimer.Tick += async (_, _) => { if (settings.CheckForUpdates) await CheckForUpdatesAsync(false); };
        updateTimer.Start();
        Loaded += async (_, _) =>
        {
            if (Environment.GetCommandLineArgs().Contains("--updated")) ShowNotice("VPN4ik обновлён до " + ApplicationUpdates.CurrentVersion + ".");
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(4), lifetime.Token);
                _ = Task.Run(UpdateInstaller.CleanCache);
                if (settings.CheckForUpdates) await CheckForUpdatesAsync(false);
            }
            catch (OperationCanceledException) { }
        };
    }

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e) => await CheckForUpdatesAsync(true);
    private async Task CheckForUpdatesAsync(bool manual)
    {
        if (checkingUpdates || installingUpdate || lifetime.IsCancellationRequested || !useBackground) return;
        checkingUpdates = true; CheckUpdatesButton.IsEnabled = false;
        if (manual) Localization.Set(UpdateCheckStatus, System.Windows.Controls.TextBlock.TextProperty, "Проверяю GitHub…");
        try
        {
            using var service = new ApplicationUpdates();
            var release = await service.CheckAsync(lifetime.Token);
            if (lifetime.IsCancellationRequested || installingUpdate || (!manual && !settings.CheckForUpdates)) return;
            if (manual) dismissedUpdate = "";
            PresentUpdate(release);
            Localization.Set(UpdateCheckStatus, System.Windows.Controls.TextBlock.TextProperty, release == null ? "Установлена актуальная версия." : "Доступна версия " + release.Version + ".");
        }
        catch (OperationCanceledException) { if (manual && !lifetime.IsCancellationRequested) Localization.Set(UpdateCheckStatus, System.Windows.Controls.TextBlock.TextProperty, "GitHub не ответил. Попробуй позже."); }
        catch { if (manual && !lifetime.IsCancellationRequested) Localization.Set(UpdateCheckStatus, System.Windows.Controls.TextBlock.TextProperty, "Не удалось проверить GitHub. Интернет и VPN можно продолжать использовать."); }
        finally { checkingUpdates = false; CheckUpdatesButton.IsEnabled = !installingUpdate; }
    }

    internal void PresentUpdate(ApplicationRelease? release)
    {
        availableUpdate = release; updateFallback = release?.CanInstall != true;
        UpdateBanner.Visibility = release == null || dismissedUpdate == release.Version ? Visibility.Collapsed : Visibility.Visible;
        if (release == null) return;
        Localization.Set(UpdateBannerTitle, System.Windows.Controls.TextBlock.TextProperty, "Доступно обновление · " + release.Version);
        Localization.Set(UpdateBannerDetail, System.Windows.Controls.TextBlock.TextProperty, release.CanInstall ? "Скачать, установить и перезапустить VPN4ik." : "Новый выпуск доступен на GitHub.");
        Localization.Set(InstallUpdateButton, System.Windows.Controls.Button.ContentProperty, release.CanInstall ? "Обновить" : "Открыть релиз");
        InstallUpdateButton.IsEnabled = true;
    }

    private void DismissUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (installingUpdate) return;
        dismissedUpdate = availableUpdate?.Version ?? ""; UpdateBanner.Visibility = Visibility.Collapsed;
    }

    private void OpenUpdateRelease()
    {
        var page = availableUpdate?.Page ?? new Uri(ApplicationUpdates.ReleasesPage);
        // Page URLs are constructed locally; never launch arbitrary release metadata as a shell URL.
        if (page.Scheme != "https" || page.Host != "github.com" || !page.AbsolutePath.StartsWith("/keltazik/VPN4ik/releases", StringComparison.Ordinal)) return;
        try { Process.Start(new ProcessStartInfo(page.AbsoluteUri) { UseShellExecute = true }); }
        catch { ShowNotice("Не удалось открыть браузер. Релизы: github.com/keltazik/VPN4ik/releases"); }
    }

    private async void InstallUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (availableUpdate is not { } release || installingUpdate || !useBackground) return;
        if (updateFallback) { OpenUpdateRelease(); return; }
        if (isConnecting || isSwitching || isManagingData || isResetting || isImporting)
        { ShowNotice("Дождись завершения текущей операции."); return; }
        installingUpdate = true;
        try
        {
            if (activeServer != null && !await ConfirmAsync("Обновить VPN4ik?", "После загрузки и проверки приложение отключит свой VPN и перезапустится. Подписки и настройки сохранятся.", "Обновить")) return;
            isManagingData = true; UpdateServerControls();
            updateCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            InstallUpdateButton.IsEnabled = DismissUpdateButton.IsEnabled = CheckUpdatesButton.IsEnabled = false;
            var executable = Environment.ProcessPath ?? throw new IOException();
            if (!Path.GetFileName(executable).Equals("VPNyan.exe", StringComparison.OrdinalIgnoreCase) || File.Exists(Path.Combine(AppContext.BaseDirectory, "VPNyan.runtimeconfig.json")))
                throw new InvalidDataException("Обновление этой сборки доступно через GitHub.");
            UpdateInstaller.CheckWritable(Path.GetDirectoryName(executable)!);
            using var service = new ApplicationUpdates();
            var progress = new Progress<string>(text => { if (installingUpdate && !lifetime.IsCancellationRequested) Localization.Set(UpdateBannerDetail, System.Windows.Controls.TextBlock.TextProperty, text); });
            var work = await service.PrepareAsync(release, progress, updateCancellation.Token);
            updateCancellation.Token.ThrowIfCancellationRequested();
            if (activeServer != null) await DisconnectCoreAsync("Обновление приложения");
            if (activeServer != null) throw new IOException("Не удалось подтвердить отключение VPN.");
            Localization.Set(UpdateBannerDetail, System.Windows.Controls.TextBlock.TextProperty, "Перезапускаю VPN4ik…");
            UpdateInstaller.Launch(work, executable);
            ExitApplication(); // Updating must exit even when the close button normally hides to tray.
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested || updateCancellation?.IsCancellationRequested == true) { }
        catch
        {
            updateFallback = true;
            Localization.Set(UpdateBannerDetail, System.Windows.Controls.TextBlock.TextProperty, "Автоустановка недоступна. Скачай новую версию со страницы релиза.");
            Localization.Set(InstallUpdateButton, System.Windows.Controls.Button.ContentProperty, "Открыть релиз");
        }
        finally
        {
            installingUpdate = false; isManagingData = false;
            updateCancellation?.Dispose(); updateCancellation = null;
            InstallUpdateButton.IsEnabled = DismissUpdateButton.IsEnabled = CheckUpdatesButton.IsEnabled = true;
            UpdateServerControls(); FinishPendingClose();
        }
    }
}
