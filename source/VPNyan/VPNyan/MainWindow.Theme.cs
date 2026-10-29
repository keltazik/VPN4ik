using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Control=System.Windows.Controls.Control;
using Color=System.Windows.Media.Color;
using ColorConverter=System.Windows.Media.ColorConverter;
using Panel=System.Windows.Controls.Panel;

namespace VPNyan;

public partial class MainWindow
{
    private string? appliedTheme;
    private void ApplyThemePalette()
    {
        if(appliedTheme==settings.Theme)return;
        var values=ThemePalette.For(settings.Theme);
        void Populate(ResourceDictionary resources)
        {
            foreach(var entry in values)
            {
                var color=(Color)ColorConverter.ConvertFromString(entry.Value);
                resources[entry.Key]=new SolidColorBrush(color);resources[entry.Key+"Color"]=color;
            }
        }
        Populate(Resources);
        var accent=(Color)Resources["AccentColor"];
        Resources["AccentTransparentColor"]=Color.FromArgb(0,accent.R,accent.G,accent.B);
        SetResourceReference(BackgroundProperty,"AppBackground");SetResourceReference(ForegroundProperty,"TextPrimary");
        var seen=new HashSet<DependencyObject>();
        void Walk(DependencyObject element)
        {
            if(!seen.Add(element))return;
            if(element is FrameworkElement view)
            {
                var properties=new List<DependencyProperty>();
                if(view is Control)properties.AddRange(new[]{Control.ForegroundProperty,Control.BackgroundProperty,Control.BorderBrushProperty});
                if(view is TextBlock)properties.Add(TextBlock.ForegroundProperty);
                if(view is Border)properties.AddRange(new[]{Border.BackgroundProperty,Border.BorderBrushProperty});
                if(view is Panel)properties.Add(Panel.BackgroundProperty);
                if(view is Shape)properties.AddRange(new[]{Shape.FillProperty,Shape.StrokeProperty});
                foreach(var property in properties)
                    if(view.GetValue(property) is SolidColorBrush brush && ThemeTokens.For(brush.Color.ToString()) is { } key)view.SetResourceReference(property,key);
                if(view.ContextMenu is { } menu){Populate(menu.Resources);Walk(menu);}
            }
            foreach(var child in LogicalTreeHelper.GetChildren(element).OfType<DependencyObject>())Walk(child);
        }
        Walk(MainGrid);
        if(OrnamentGlow.Effect is System.Windows.Media.Effects.DropShadowEffect glow)
        {var changed=glow.CloneCurrentValue();changed.Color=(Color)Resources["AccentColor"];OrnamentGlow.Effect=changed;}
        appliedTheme=settings.Theme;
    }
}
