using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Color=System.Windows.Media.Color;
using ColorConverter=System.Windows.Media.ColorConverter;
using Brush=System.Windows.Media.Brush;

namespace VPNyan;

internal static class BrandAssets
{
    private static readonly Dictionary<string,ImageSource> Cache=new();
    private static readonly Dictionary<string,string> Names=new() { ["classic"]="01-classic",["editorial"]="02-editorial",["palatial"]="03-palatial",["modern"]="04-modern",["signature"]="05-signature",["four"]="06-four" };
    private static Dictionary<string,Dictionary<string,string>>? palettes;
    internal static string Palette(string theme)=>theme=="dark"?"gold":theme;
    internal static ImageSource Wordmark(string style,string palette)=>Bitmap("Assets/Wordmarks/"+palette+"/"+Names.GetValueOrDefault(style,"01-classic")+".png",600);
    internal static ImageSource Moccasins()=>Bitmap("Assets/AboutMoccasins.png",256);
    private static ImageSource Bitmap(string path,int width)
    {
        if(Cache.TryGetValue(path,out var cached))return cached;
        var bitmap=new BitmapImage();bitmap.BeginInit();bitmap.CacheOption=BitmapCacheOption.OnLoad;bitmap.DecodePixelWidth=width;
        bitmap.UriSource=new Uri("pack://application:,,,/VPNyan;component/"+path,UriKind.Absolute);bitmap.EndInit();bitmap.Freeze();Cache[path]=bitmap;return bitmap;
    }
    internal static DrawingImage Ornament(string palette)
    {
        var original=(DrawingImage)System.Windows.Application.Current.FindResource("OrnamentVector");
        if(palette=="gold") {if(!original.IsFrozen && original.CanFreeze)original.Freeze();return original;}
        if(Cache.TryGetValue("ornament/"+palette,out var cached))return (DrawingImage)cached;
        if(palettes==null)
        {
            using var stream=typeof(BrandAssets).Assembly.GetManifestResourceStream("VPNyan.OrnamentPalettes.json")!;
            palettes=JsonSerializer.Deserialize<Dictionary<string,Dictionary<string,string>>>(stream)!;
        }
        if(!palettes.TryGetValue(palette,out var colors))return original;
        var brushes=new Dictionary<string,SolidColorBrush>();
        Brush? Recolor(Brush? brush)
        {
            if(brush is not SolidColorBrush solid)return brush;
            var key="#"+solid.Color.R.ToString("X2")+solid.Color.G.ToString("X2")+solid.Color.B.ToString("X2");
            if(solid.Color.A!=255 || !colors.TryGetValue(key,out var replacement))return brush;
            if(!brushes.TryGetValue(replacement,out var result)){result=new SolidColorBrush((Color)ColorConverter.ConvertFromString(replacement));result.Freeze();brushes.Add(replacement,result);}return result;
        }
        Drawing Clone(Drawing drawing)
        {
            if(drawing is GeometryDrawing path)return new GeometryDrawing(Recolor(path.Brush),path.Pen,path.Geometry);
            if(drawing is not DrawingGroup group)return drawing;
            var copy=new DrawingGroup { Transform=group.Transform,ClipGeometry=group.ClipGeometry,Opacity=group.Opacity,OpacityMask=group.OpacityMask,GuidelineSet=group.GuidelineSet };
            foreach(var child in group.Children)copy.Children.Add(Clone(child));return copy;
        }
        var image=new DrawingImage(Clone(original.Drawing));image.Freeze();Cache.Add("ornament/"+palette,image);return image;
    }
}
