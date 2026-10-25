using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace VPNyan
{
    public class SettingsWindow : Window
    {
        public SettingsWindow(AppSettings settings, MainWindow main)
        {
            Title = "Settings";
            Width = 500;
            Height = 400;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Owner = main;
            Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(11, 18, 48));

            var grid = new Grid();
            var text = new TextBlock
            {
                Text = "Settings",
                Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 210, 122)),
                FontSize = 24,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = System.Windows.VerticalAlignment.Center
            };
            grid.Children.Add(text);
            Content = grid;
        }
        private void Maximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }
    }
}