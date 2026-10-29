using System.Windows;
using System.Windows.Controls.Primitives;

namespace VPNyan;

public static class MenuPlacement
{
    public static readonly DependencyProperty ValueProperty=DependencyProperty.RegisterAttached("Value",typeof(PlacementMode),typeof(MenuPlacement),new PropertyMetadata(PlacementMode.Bottom));
    public static PlacementMode GetValue(DependencyObject target)=>(PlacementMode)target.GetValue(ValueProperty);
    public static void SetValue(DependencyObject target,PlacementMode value)=>target.SetValue(ValueProperty,value);
}
