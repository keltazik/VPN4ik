using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using Size=System.Windows.Size;

namespace VPNyan;

public sealed class AnimatedReveal : Decorator
{
    public static readonly DependencyProperty ProgressProperty=DependencyProperty.Register(nameof(Progress),typeof(double),typeof(AnimatedReveal),new FrameworkPropertyMetadata(0d,FrameworkPropertyMetadataOptions.AffectsMeasure));
    public static readonly DependencyProperty IsExpandedProperty=DependencyProperty.Register(nameof(IsExpanded),typeof(bool),typeof(AnimatedReveal),new PropertyMetadata(false,ExpandedChanged));
    public double Progress {get=>(double)GetValue(ProgressProperty);set=>SetValue(ProgressProperty,value);}
    public bool IsExpanded {get=>(bool)GetValue(IsExpandedProperty);set=>SetValue(IsExpandedProperty,value);}
    public AnimatedReveal(){ClipToBounds=true;}
    private static void ExpandedChanged(DependencyObject target,DependencyPropertyChangedEventArgs args)
    {
        var reveal=(AnimatedReveal)target;var expanded=(bool)args.NewValue;
        if(reveal.Child!=null)reveal.Child.IsEnabled=expanded;
        if(!reveal.IsLoaded || !SystemParameters.ClientAreaAnimation){reveal.BeginAnimation(ProgressProperty,null);reveal.Progress=expanded?1:0;return;}
        reveal.BeginAnimation(ProgressProperty,new DoubleAnimation {To=expanded?1:0,Duration=TimeSpan.FromMilliseconds(210),EasingFunction=new CubicEase {EasingMode=EasingMode.EaseInOut}});
    }
    protected override Size MeasureOverride(Size constraint)
    {
        if(Child==null)return default;
        Child.IsEnabled=IsExpanded;
        Child.Measure(new Size(constraint.Width,double.PositiveInfinity));
        return new Size(Child.DesiredSize.Width,Child.DesiredSize.Height*Math.Clamp(Progress,0,1));
    }
    protected override Size ArrangeOverride(Size size)
    {
        Child?.Arrange(new Rect(0,0,size.Width,Child.DesiredSize.Height));return size;
    }
}
