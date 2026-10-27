using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using VPNyan;
using Localization = VPNyan.Localization;

internal static class LocalizationChecks
{
    internal static void Run(string fixtures, Action<bool, string> require)
    {
        var locale = Localization.Current;
        var originalCulture = CultureInfo.CurrentCulture.Name;
        var fields = new Regex(@"\{\d+(?:,[^}:]+)?(?::[^}]+)?\}");
        require(locale.Catalog.Count >= 714 && locale.Catalog.Select(e => e.Id).Distinct().Count() == locale.Catalog.Count,
            "Three-language catalog has unique resource identifiers");
        require(locale.Catalog.All(e => !string.IsNullOrWhiteSpace(e.En) && !string.IsNullOrWhiteSpace(e.Hy) &&
            fields.Matches(e.Ru).Select(m => m.Value).Order().SequenceEqual(fields.Matches(e.En).Select(m => m.Value).Order()) &&
            fields.Matches(e.Ru).Select(m => m.Value).Order().SequenceEqual(fields.Matches(e.Hy).Select(m => m.Value).Order())),
            "Every translation preserves all format placeholders");
        var directory = Path.Combine(fixtures, "localization"); Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "settings.json");
        var settings = new AppSettings { StoragePath = path, Language = "hy", AutoCheckPings = false };
        settings.SaveOrThrow();
        require(AppSettings.LoadFromPath(path).Language == "hy" && settings.Copy().Language == "hy",
            "Language is persisted and copied with settings");
        settings.Language = "invalid"; settings.SaveOrThrow();
        require(AppSettings.LoadFromPath(path).Language == "ru", "Unknown saved locale falls back to Russian");
        settings.Language = "ru"; settings.SaveOrThrow();
        var window = new MainWindow(false, directory);
        try
        {
            window.ShowSection("settings"); window.ShowSettingsCategory("general");
            var root = (FrameworkElement)window.Content;
            T Find<T>(string name) => (T)window.FindName(name);
            var selector = Find<ComboBox>("LanguageSelect");
            var scroller = Find<ScrollViewer>("SettingsScroller");
            var reset = Find<Button>("ResetAllButton");
            var footer = Find<StackPanel>("SettingsFooter");
            var general = Find<StackPanel>("GeneralSettings");
            var tray = Find<Expander>("TraySettingsExpander");
            var notify = general.Children.OfType<CheckBox>().Single(c => (string)c.Content == "Показывать уведомления о подключении");
            var selectedName = "Настройки"; // Deliberately identical to a translatable UI label.
            var list = Find<ListBox>("ServerSelect");
            list.ItemsSource = new[] { new ServerItem { Name=selectedName } }; list.SelectedIndex=0;
            require(general.Children.IndexOf(tray) == general.Children.IndexOf(notify) + 1,
                "Tray settings follow connection notifications");
            require(!IsAncestor(scroller, footer), "Reset footer is outside the settings scroll viewer");
            foreach (var language in new[] { "en", "hy", "ru" })
            {
                selector.SelectedValue = language; Pump();
                require(AppSettings.LoadFromPath(path).Language == language && locale.Language == language,
                    "Language changes and saves immediately: " + language);
                require(Find<TextBlock>("SectionTitle").Text == Localization.T("Настройки") &&
                    (string)reset.Content == Localization.T("Сбросить все данные VPN4ik") &&
                    (string)tray.Header == Localization.T("Скрывать в трей"), "Live titles and controls translated: " + language);
                require((string)Find<MenuItem>("ContextPing").Header == Localization.T("Тест пинга"),
                    "Detached context menu localized: " + language);
                require(Find<TextBlock>("SelectedServerName").Text == selectedName,
                    "Provider server names are not translated: " + language);
                Localization.Set(Find<TextBlock>("StatusText"), TextBlock.TextProperty, "Нет подтверждённого доступа через VPN");
                require(Find<TextBlock>("StatusText").Text == Localization.T("Нет подтверждённого доступа через VPN"),
                    "Dynamic status text localized: " + language);
                require(Localization.T("Подписка обновлена: 12 серверов.").Contains("12") &&
                    (language == "ru" || !Regex.IsMatch(Localization.T("Подписка обновлена: 12 серверов."), "[А-Яа-я]")),
                    "Formatted messages retain values: " + language);
                foreach (var size in new[] { new Size(1040,740), new Size(760,540) })
                {
                    Layout(root, size); scroller.ScrollToTop(); Pump(); Layout(root,size);
                    var before = reset.TransformToAncestor(root).TransformBounds(new Rect(reset.RenderSize));
                    scroller.ScrollToBottom(); Pump(); Layout(root,size);
                    var after = reset.TransformToAncestor(root).TransformBounds(new Rect(reset.RenderSize));
                    require(Math.Abs(before.Y-after.Y) < 1 && after.Bottom <= size.Height && after.Height >= 30,
                        "Reset stays pinned and reachable: " + language + " " + size);
                    scroller.ScrollToTop(); Pump(); Layout(root,size);
                    var bitmap = new RenderTargetBitmap((int)size.Width,(int)size.Height,96,96,PixelFormats.Pbgra32);
                    bitmap.Render(root);
                    var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                    using var output = File.Create(Path.Combine(fixtures, $"settings-{language}-{size.Width}.png")); encoder.Save(output);
                }
                window.ShowSettingsCategory("connection");
                require(footer.Visibility == Visibility.Collapsed, "Reset is only shown on General: " + language);
                window.ShowSettingsCategory("general");
            }
            locale.Apply("en"); Pump();
            require(Find<TextBlock>("StatusText").Text == "VPN access not confirmed", "Existing dynamic status updates when language changes");
            require(Localization.T("Выбран файл: example.bat") == "Selected file: example.bat", "Joined captions retain BAT file names");
            require(Localization.T("12:34:56 · Подписка обновлена: 3 серверов.\n12:34:57 · Не удалось загрузить подписку.") ==
                "12:34:56 · Subscription updated: 3 servers.\n12:34:57 · Could not download subscription.", "Timestamped multiline event feed is localized");
            require(Localization.T(@"C:\Настройки\Конфигурация сервера.conf") == @"C:\Настройки\Конфигурация сервера.conf", "Absolute paths remain unchanged");
            require(CultureInfo.CurrentCulture.Name == originalCulture, "Language does not change numeric/configuration culture");
            var entry = new LogEntry(DateTimeOffset.UtcNow,"Ошибка","Не удалось загрузить подписку.");
            require(entry.Level == "Ошибка" && entry.Message == "Не удалось загрузить подписку." && Localization.T(entry.Message) == "Could not download subscription.",
                "Stored events remain canonical while presentation is localized");
        }
        finally { window.Close(); Pump(); locale.Apply("ru"); }
    }
    private static bool IsAncestor(DependencyObject ancestor, DependencyObject node)
    {
        for (var parent=VisualTreeHelper.GetParent(node); parent!=null; parent=VisualTreeHelper.GetParent(parent)) if(parent==ancestor) return true;
        return false;
    }
    private static void Layout(FrameworkElement root, Size size) { root.Measure(size); root.Arrange(new Rect(size)); root.UpdateLayout(); }
    private static void Pump()
    {
        var frame=new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ContextIdle,new Action(()=>frame.Continue=false));
        Dispatcher.PushFrame(frame);
    }
}
