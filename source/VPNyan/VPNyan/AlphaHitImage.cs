using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Image = System.Windows.Controls.Image;
using Point = System.Windows.Point;
using Brush = System.Windows.Media.Brush;

namespace VPNyan;

// Only painted pixels or vector shapes activate the ornament, not its rectangle.
public sealed class AlphaHitImage : Image
{
    public static readonly DependencyProperty HitGeometryProperty = DependencyProperty.Register(
        nameof(HitGeometry), typeof(Geometry), typeof(AlphaHitImage));

    public Geometry? HitGeometry
    {
        get => (Geometry?)GetValue(HitGeometryProperty);
        set => SetValue(HitGeometryProperty, value);
    }

    private BitmapSource? cachedSource;
    private ImageSource? measuredSource;
    private Rect sourceBounds;
    private byte[]? pixels;
    private int pixelWidth, pixelHeight;

    internal bool ContainsVisiblePoint(Point point)
    {
        var source = Source;
        if (source == null || RenderSize.Width <= 0 || RenderSize.Height <= 0)
            return false;
        // DrawingImage.Width/Height recompute the bounds of every child drawing.
        // A frozen source cannot change: measure it once instead of on mouse moves.
        if (!ReferenceEquals(source, measuredSource) || !source.IsFrozen)
        {
            sourceBounds = source is DrawingImage drawing ? drawing.Drawing.Bounds : new Rect(0, 0, source.Width, source.Height);
            measuredSource = source;
        }
        if (sourceBounds.IsEmpty || sourceBounds.Width <= 0 || sourceBounds.Height <= 0) return false;
        var scaleX = RenderSize.Width / sourceBounds.Width;
        var scaleY = RenderSize.Height / sourceBounds.Height;
        if (Stretch == Stretch.Uniform) scaleX = scaleY = Math.Min(scaleX, scaleY);
        else if (Stretch == Stretch.UniformToFill) scaleX = scaleY = Math.Max(scaleX, scaleY);
        else if (Stretch == Stretch.None) scaleX = scaleY = 1;
        if (StretchDirection == StretchDirection.DownOnly) { scaleX = Math.Min(1, scaleX); scaleY = Math.Min(1, scaleY); }
        if (StretchDirection == StretchDirection.UpOnly) { scaleX = Math.Max(1, scaleX); scaleY = Math.Max(1, scaleY); }
        var width = sourceBounds.Width * scaleX;
        var height = sourceBounds.Height * scaleY;
        var x = (point.X - (RenderSize.Width - width) / 2) / width;
        var y = (point.Y - (RenderSize.Height - height) / 2) / height;
        if (x < 0 || y < 0 || x >= 1 || y >= 1) return false;
        if (source is DrawingImage vector)
        {
            var sourcePoint = new Point(sourceBounds.X + x * sourceBounds.Width, sourceBounds.Y + y * sourceBounds.Height);
            return HitGeometry is { } silhouette ? silhouette.FillContains(sourcePoint) : ContainsDrawing(vector.Drawing, sourcePoint);
        }
        if (source is not BitmapSource bitmap) return false;
        if (!ReferenceEquals(bitmap, cachedSource))
        {
            var converted = new FormatConvertedBitmap(bitmap, PixelFormats.Bgra32, null, 0);
            pixelWidth = converted.PixelWidth;
            pixelHeight = converted.PixelHeight;
            pixels = new byte[pixelWidth * pixelHeight * 4];
            converted.CopyPixels(pixels, pixelWidth * 4, 0);
            cachedSource = bitmap;
        }
        return pixels![((int)(y * pixelHeight) * pixelWidth + (int)(x * pixelWidth)) * 4 + 3] >= 16;
    }

    private static bool ContainsDrawing(Drawing drawing, Point point)
    {
        // Reject distant paths before the expensive curve hit test.
        if (!drawing.Bounds.Contains(point)) return false;
        if (drawing is DrawingGroup group)
        {
            if (group.Opacity <= 0) return false;
            var transform = group.Transform?.Value ?? Matrix.Identity;
            if (!transform.HasInverse) return false;
            transform.Invert();
            point = transform.Transform(point);
            if (group.ClipGeometry is { } clip && !clip.FillContains(point)) return false;
            foreach (var child in group.Children)
                if (ContainsDrawing(child, point)) return true;
            return false;
        }
        if (drawing is not GeometryDrawing shape) return false;
        return (VisibleBrush(shape.Brush) && shape.Geometry.FillContains(point)) ||
               (shape.Pen is { } pen && VisibleBrush(pen.Brush) && shape.Geometry.StrokeContains(pen, point));
    }

    private static bool VisibleBrush(Brush? brush) => brush != null && brush.Opacity > 0 &&
        (brush is not SolidColorBrush solid || solid.Color.A >= 16);

    protected override HitTestResult? HitTestCore(PointHitTestParameters hitTestParameters) =>
        ContainsVisiblePoint(hitTestParameters.HitPoint) ? new PointHitTestResult(this, hitTestParameters.HitPoint) : null;
}
