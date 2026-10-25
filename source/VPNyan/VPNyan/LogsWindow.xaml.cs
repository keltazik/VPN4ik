using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace VPNyan
{
    public class WpfLogsWindow : Window
    {
        public WpfLogsWindow()
        {
            Title = "Logs";
            Width = 600;
            Height = 400;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(11, 18, 48));

            var grid = new Grid();
            var text = new TextBlock
            {
                Text = "Logs",
                Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 210, 122)),
                FontSize = 24,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = System.Windows.VerticalAlignment.Center
            };
            grid.Children.Add(text);
            Content = grid;
        }
    }
}