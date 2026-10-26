using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

internal static class IconGenerator
{
    internal static void Generate(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var sizes = new[] { 16, 20, 24, 32, 40, 48, 64, 128, 256 };
        var images = sizes.Select(Render).ToArray();
        using var output = new BinaryWriter(File.Create(path));
        output.Write((ushort)0); output.Write((ushort)1); output.Write((ushort)sizes.Length);
        var offset = 6 + sizes.Length * 16;
        for (var i = 0; i < sizes.Length; i++)
        {
            output.Write((byte)(sizes[i] == 256 ? 0 : sizes[i])); output.Write((byte)(sizes[i] == 256 ? 0 : sizes[i]));
            output.Write((byte)0); output.Write((byte)0); output.Write((ushort)1); output.Write((ushort)32);
            output.Write(images[i].Length); output.Write(offset); offset += images[i].Length;
        }
        foreach (var image in images) output.Write(image);
        File.WriteAllBytes(Path.ChangeExtension(path, ".png"), images[^1]);
        Console.WriteLine("Generated multi-resolution VPN4ik icon (16–256 px).");
    }

    private static byte[] Render(int size)
    {
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.PushTransform(new ScaleTransform(size / 64d, size / 64d));
            dc.DrawRoundedRectangle(new LinearGradientBrush(Color.FromRgb(57, 17, 37), Color.FromRgb(22, 9, 23), 90), null, new Rect(2, 2, 60, 60), 15, 15);
            var gold = new SolidColorBrush(Color.FromRgb(237, 191, 107));
            var outline = new Pen(gold, size <= 24 ? 3.3 : 2.5) { LineJoin = PenLineJoin.Round };
            dc.DrawGeometry(null, outline, Geometry.Parse("M32,7 C37,18 47,21 55,32 C47,43 37,46 32,57 C27,46 17,43 9,32 C17,21 27,18 32,7Z"));
            var power = new Pen(gold, 3.5) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            dc.DrawGeometry(null, power, Geometry.Parse("M25,25 A11,11 0 1 0 39,25 M32,21 L32,32"));
            dc.Pop();
        }
        var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var buffer = new MemoryStream(); encoder.Save(buffer); return buffer.ToArray();
    }
}
