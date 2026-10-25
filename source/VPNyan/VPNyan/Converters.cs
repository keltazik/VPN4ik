using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;  // ✅ Только WPF

namespace VPNyan
{
    public class PingColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int ping)
            {
                if (ping < 0) return new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 107, 107));
                if (ping < 30) return new SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 210, 106));
                if (ping < 60) return new SolidColorBrush(System.Windows.Media.Color.FromRgb(76, 175, 80));
                if (ping < 100) return new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 210, 122));
                if (ping < 200) return new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 159, 67));
                return new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 107, 107));
            }
            return new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 107, 107));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class BytesConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                string[] sizes = { "B", "KB", "MB", "GB" };
                double len = bytes;
                int order = 0;
                while (len >= 1024 && order < sizes.Length - 1)
                {
                    order++;
                    len = len / 1024;
                }
                return $"{len:0.##} {sizes[order]}";
            }
            return "0 B";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class BoolToIconConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool success)
            {
                return success ? "✓" : "✗";
            }
            return "?";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
