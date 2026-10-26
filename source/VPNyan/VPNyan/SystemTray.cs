using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Forms;

namespace VPNyan
{
    public class SystemTray : IDisposable
    {
        private readonly NotifyIcon? trayIcon;
        private readonly MainWindow mainWindow;
        private readonly System.Drawing.Icon? applicationIcon;

        public SystemTray(MainWindow window)
        {
            mainWindow = window;
            try
            {
                using var iconStream = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/VPNyan;component/Assets/VPN4ik.ico"))!.Stream;
                using var resourceIcon = new System.Drawing.Icon(iconStream);
                applicationIcon = (System.Drawing.Icon)resourceIcon.Clone();
                trayIcon = new NotifyIcon
                {
                    Icon = applicationIcon,
                    Text = "VPN4ik",
                    Visible = true
                };
                trayIcon.MouseClick += (s, e) =>
                {
                    if (e.Button == MouseButtons.Left)
                    {
                        mainWindow.Show();
                        mainWindow.WindowState = WindowState.Normal;
                        mainWindow.Activate();
                    }
                };
                var ctx = new ContextMenuStrip
                {
                    ShowImageMargin = false,
                    BackColor = System.Drawing.Color.FromArgb(24, 12, 22),
                    ForeColor = System.Drawing.Color.FromArgb(255, 210, 122),
                    Renderer = new ToolStripProfessionalRenderer(new TrayColors())
                };
                ctx.Items.Add("Подключиться", null, (s, e) => _ = mainWindow.Connect());
                ctx.Items.Add("Отключиться", null, async (s, e) => await mainWindow.Disconnect());
                ctx.Items.Add("Открыть приложение", null, (s, e) => { mainWindow.Show(); mainWindow.WindowState = WindowState.Normal; mainWindow.Activate(); });
                ctx.Items.Add("Выход", null, (s, e) => mainWindow.Close());
                trayIcon.ContextMenuStrip = ctx;
            }
            catch
            {
                trayIcon = null;
            }
        }

        public void ShowNotification(string title, string message)
        {
            try { trayIcon?.ShowBalloonTip(3000, title, message, ToolTipIcon.Info); }
            catch { }
        }

        public void Hide()
        {
            if (trayIcon != null)
                trayIcon.Visible = false;
        }

        public void Dispose()
        {
            try { trayIcon?.ContextMenuStrip?.Dispose(); trayIcon?.Dispose(); applicationIcon?.Dispose(); }
            catch { }
        }

        private sealed class TrayColors : ProfessionalColorTable
        {
            private static System.Drawing.Color BackgroundColor => System.Drawing.Color.FromArgb(24, 12, 22);
            private static System.Drawing.Color SelectionColor => System.Drawing.Color.FromArgb(58, 35, 50);
            public override System.Drawing.Color ToolStripDropDownBackground => BackgroundColor;
            public override System.Drawing.Color MenuItemSelected => SelectionColor;
            public override System.Drawing.Color MenuItemBorder => System.Drawing.Color.FromArgb(201, 161, 92);
            public override System.Drawing.Color MenuBorder => System.Drawing.Color.FromArgb(118, 82, 57);
            public override System.Drawing.Color MenuItemSelectedGradientBegin => SelectionColor;
            public override System.Drawing.Color MenuItemSelectedGradientEnd => SelectionColor;
            public override System.Drawing.Color ImageMarginGradientBegin => BackgroundColor;
            public override System.Drawing.Color ImageMarginGradientMiddle => BackgroundColor;
            public override System.Drawing.Color ImageMarginGradientEnd => BackgroundColor;
        }
    }
}
