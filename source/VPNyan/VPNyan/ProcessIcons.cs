using System.IO;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Color = System.Windows.Media.Color;
using Pen = System.Windows.Media.Pen;
using Point = System.Windows.Point;
using Size = System.Windows.Size;

namespace VPNyan;

internal static class ProcessIcons
{
    internal static ImageSource Fallback { get; } = CreateFallback();
    internal static ImageSource Load(string path)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal) || !File.Exists(path)) return Fallback;
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon == null) return Fallback;
            var bitmap = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromWidthAndHeight(32,32));
            bitmap.Freeze(); return bitmap;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Runtime.InteropServices.ExternalException) { return Fallback; }
    }
    private static ImageSource CreateFallback()
    {
        var drawing = new DrawingGroup();
        using (var context = drawing.Open())
        {
            var background = new SolidColorBrush(Color.FromRgb(53,32,44)); var gold = new SolidColorBrush(Color.FromRgb(201,161,92));
            context.DrawRoundedRectangle(background,new Pen(gold,1),new Rect(1,1,30,30),6,6);
            context.DrawLine(new Pen(gold,1),new Point(2,9),new Point(30,9));
            foreach(var point in new[] {new Point(8,15),new Point(18,15),new Point(8,23),new Point(18,23)}) context.DrawRoundedRectangle(gold,null,new Rect(point,new Size(6,4)),1,1);
        }
        drawing.Freeze(); var image = new DrawingImage(drawing); image.Freeze(); return image;
    }
}
