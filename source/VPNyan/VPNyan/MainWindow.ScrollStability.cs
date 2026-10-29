using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace VPNyan;

public partial class MainWindow
{
    private void InitializeSettingsScrollStability()
    {
        MainGrid.AddHandler(FrameworkElement.RequestBringIntoViewEvent,new RequestBringIntoViewEventHandler((_,args)=>
        {
            // Keep a mouse-expanded header in place. Keyboard Tab navigation may
            // still reveal the focused input for accessibility.
            if(Keyboard.IsKeyDown(Key.Tab))return;
            DependencyObject? element=args.TargetObject;
            while(element!=null)
            {
                if(element is Expander){args.Handled=true;return;}
                element=LogicalTreeHelper.GetParent(element)??(element is Visual?VisualTreeHelper.GetParent(element):null);
            }
        }),true);
        if(ZapretPage.Content is not StackPanel stack)return;
        Border Card(UIElement child)
        {
            if(child is FrameworkElement view)view.Margin=new Thickness(0);
            var card=new Border {Padding=new Thickness(16),Margin=new Thickness(0,0,0,14),CornerRadius=new CornerRadius(12),BorderThickness=new Thickness(1),Child=child};
            card.SetResourceReference(Border.BackgroundProperty,"CardBackground");card.SetResourceReference(Border.BorderBrushProperty,"BorderSubtle");return card;
        }
        foreach(var child in stack.Children.Cast<UIElement>().ToArray())
        {
            if(child is Border border)
            {
                border.Padding=new Thickness(16);border.Margin=new Thickness(0,0,0,14);border.CornerRadius=new CornerRadius(12);border.BorderThickness=new Thickness(1);
                border.SetResourceReference(Border.BackgroundProperty,"CardBackground");border.SetResourceReference(Border.BorderBrushProperty,"BorderSubtle");
            }
            else if(child is StackPanel {Name:"ZapretAdvancedPanel"} advanced)
            {
                advanced.Margin=new Thickness(0);
                foreach(var section in advanced.Children.OfType<Expander>().ToArray())
                {var index=advanced.Children.IndexOf(section);advanced.Children.Remove(section);advanced.Children.Insert(index,Card(section));}
            }
            else if(child is Expander)
            {
                var index=stack.Children.IndexOf(child);stack.Children.Remove(child);
                stack.Children.Insert(index,Card(child));
            }
        }
        var logHeading=stack.Children.OfType<TextBlock>().FirstOrDefault();
        if(logHeading!=null)
        {
            stack.Children.Remove(logHeading);stack.Children.Remove(ZapretLogText);
            stack.Children.Add(SettingsCard("",logHeading,ZapretLogText));
        }
    }
}
