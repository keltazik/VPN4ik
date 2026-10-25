using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Image = System.Windows.Controls.Image;
using Point = System.Windows.Point;

namespace VPNyan;

// Image normally hit-tests its entire rectangle, including transparent PNG pixels.
public sealed class AlphaHitImage : Image
{
    private BitmapSource? cachedSource;
    private byte[]? pixels;
    private int pixelWidth, pixelHeight;

    internal bool ContainsVisiblePoint(Point point)
    {
        if (Source is not BitmapSource bitmap || RenderSize.Width <= 0 || RenderSize.Height <= 0)
            return false;
        if (!ReferenceEquals(bitmap, cachedSource))
        {
            var converted = new FormatConvertedBitmap(bitmap, PixelFormats.Bgra32, null, 0);
            pixelWidth = converted.PixelWidth;
            pixelHeight = converted.PixelHeight;
            pixels = new byte[pixelWidth * pixelHeight * 4];
            converted.CopyPixels(pixels, pixelWidth * 4, 0);
            cachedSource = bitmap;
        }
        var scaleX = RenderSize.Width / bitmap.Width;
        var scaleY = RenderSize.Height / bitmap.Height;
        if (Stretch == Stretch.Uniform) scaleX = scaleY = Math.Min(scaleX, scaleY);
        else if (Stretch == Stretch.UniformToFill) scaleX = scaleY = Math.Max(scaleX, scaleY);
        else if (Stretch == Stretch.None) scaleX = scaleY = 1;
        if (StretchDirection == StretchDirection.DownOnly) { scaleX = Math.Min(1, scaleX); scaleY = Math.Min(1, scaleY); }
        if (StretchDirection == StretchDirection.UpOnly) { scaleX = Math.Max(1, scaleX); scaleY = Math.Max(1, scaleY); }
        var width = bitmap.Width * scaleX;
        var height = bitmap.Height * scaleY;
        var x = (point.X - (RenderSize.Width - width) / 2) / width * pixelWidth;
        var y = (point.Y - (RenderSize.Height - height) / 2) / height * pixelHeight;
        if (x < 0 || y < 0 || x >= pixelWidth || y >= pixelHeight) return false;
        return pixels![((int)y * pixelWidth + (int)x) * 4 + 3] >= 16;
    }

    protected override HitTestResult? HitTestCore(PointHitTestParameters hitTestParameters) =>
        ContainsVisiblePoint(hitTestParameters.HitPoint) ? new PointHitTestResult(this, hitTestParameters.HitPoint) : null;
}
