using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using VPNyan;

internal static class BrandAssetsChecks
{
    internal static void Run(MainWindow window,string directory,Action<bool,string> check)
    {
        T Find<T>(string name)=>(T)window.FindName(name);
        window.ShowSection("settings");window.ShowSettingsCategory("appearance");
        check(window.FindName("WordmarkStyleSelect") is ComboBox,"Appearance has a separate wordmark style selector from the approved design");
        var styles=Find<ComboBox>("WordmarkStyleSelect");var themes=Find<ComboBox>("AppearanceThemeSelect");
        check(styles.Items.Count==6 && window.FindName("WordmarkThemeSelect")==null && window.FindName("OrnamentThemeSelect")==null,"Six design wordmarks use the application palette without separate color settings");
        check(Find<TextBlock>("AppearancePreviewServer").TextAlignment==TextAlignment.Center && Find<TextBlock>("AppearancePreviewStatus").TextAlignment==TextAlignment.Center,"Preview captions below the ornament are centered");
        var variants=new HashSet<ImageSource>(ReferenceEqualityComparer.Instance);
        foreach(var palette in new[]{"dark","wine","night","plum"})
        foreach(var style in new[]{"classic","editorial","palatial","modern","signature","four"})
        {
            themes.SelectedValue=palette;styles.SelectedValue=style;
            var main=Find<System.Windows.Controls.Image>("MainWordmarkImage");var preview=Find<System.Windows.Controls.Image>("AppearancePreviewWordmark");
            check(main.Source is BitmapSource {IsFrozen:true} && ReferenceEquals(main.Source,preview.Source),"Actual and preview wordmarks share the immutable approved asset: "+palette+"/"+style);
            variants.Add(main.Source);
        }
        check(variants.Count==24,"All 24 wordmark designs are distinct assets");
        var pinned=Find<System.Windows.Controls.Image>("MainWordmarkImage").Source;
        themes.SelectedValue="wine";
        check(!ReferenceEquals(pinned,Find<System.Windows.Controls.Image>("MainWordmarkImage").Source),"Wordmark palette always follows the application theme");
        var ornamentSources=new HashSet<ImageSource>(ReferenceEqualityComparer.Instance);
        Geometry[]? gold=null;
        foreach(var palette in new[]{"dark","wine","night","plum"})
        {
            themes.SelectedValue=palette;var image=(DrawingImage)Find<System.Windows.Controls.Image>("OrnamentImage").Source;
            var paths=Paths(image.Drawing).ToArray();gold??=paths.Select(p=>p.Geometry).ToArray();
            check(image.IsFrozen && paths.Length==6954 && paths.Select((p,i)=>ReferenceEquals(p.Geometry,gold[i])).All(s=>s),"Ornament palette preserves and shares every original vector geometry: "+palette);
            ornamentSources.Add(image);
        }
        check(ornamentSources.Count==4,"Four original design ornament palettes are selectable");
        var saved=AppSettings.LoadFromPath(Path.Combine(directory,"settings.json"));
        check(saved.WordmarkStyle=="four" && saved.Theme=="plum" && saved.Copy().WordmarkStyle=="four","Wordmark style persists alongside the shared application theme");
        var accent=window.Resources["Accent"];window.ShowSettingsCategory("general");window.ShowSettingsCategory("appearance");
        check(ReferenceEquals(accent,window.Resources["Accent"]),"Ordinary settings navigation does not rebuild palette brushes and invalidate hover surfaces");
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="button";
        check(Find<Button>("StandardConnectButton").Content is TextBlock {Text:"⏻"} && window.FindName("StandardConnectLabel")==null,"Standard connection button contains only the power symbol");
        var shoes=Find<System.Windows.Controls.Image>("AboutMoccasins");
        check(shoes.Source is BitmapSource && shoes.Width<=128 && shoes.Height<=90 && shoes.HorizontalAlignment==HorizontalAlignment.Right && !shoes.IsHitTestVisible,"Approved moccasins are a small decorative image in the right corner of About");
        foreach(var category in new[]{"appearance","connect","general","about","connection","diagnostics"})
        {window.ShowSettingsCategory(category);check(Find<Button>("ResetAllButton").Visibility==Visibility.Collapsed,"Reset is absent from subsection: "+category);}
        window.ShowSettingsCategory("overview");check(Find<Button>("ResetAllButton").Visibility==Visibility.Visible,"Reset exists only in the settings overview");
        var fakes=Find<Expander>("ZapretFakesExpander");var updates=Find<Expander>("ZapretToolsExpander");
        check(fakes.Parent is Border && updates.Parent is Border && !ReferenceEquals(fakes.Parent,updates.Parent),"Zapret packet substitution and update tools have separate cards");
        Find<ComboBox>("AppearanceVisualSelect").SelectedValue="ornament";styles.SelectedValue="classic";themes.SelectedValue="dark";
    }
    private static IEnumerable<GeometryDrawing> Paths(Drawing drawing)
    {if(drawing is GeometryDrawing path && path.Brush is SolidColorBrush {Color.A:>0})yield return path;else if(drawing is DrawingGroup group)foreach(var child in group.Children)foreach(var item in Paths(child))yield return item;}
}
