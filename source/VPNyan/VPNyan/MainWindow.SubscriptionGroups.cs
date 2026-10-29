using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Binding = System.Windows.Data.Binding;

namespace VPNyan;

public partial class MainWindow
{
    private bool subscriptionGroupsInitialized;
    private readonly HashSet<string> collapsedSubscriptions=new();
    private void InitializeSubscriptionGroups()
    {
        if(subscriptionGroupsInitialized)return;
        subscriptionGroupsInitialized=true;
        var expander=new FrameworkElementFactory(typeof(Expander));
        expander.SetValue(Expander.IsExpandedProperty,true);
        expander.SetResourceReference(Expander.ForegroundProperty,"Accent");
        expander.SetValue(Expander.MarginProperty,new Thickness(0,3,0,8));
        expander.SetBinding(Expander.HeaderProperty,new Binding("Name") { Converter=new SubscriptionGroupLabel(this) });
        expander.AddHandler(FrameworkElement.LoadedEvent,new RoutedEventHandler((sender,_)=>{if(sender is Expander {DataContext:CollectionViewGroup group} item)item.IsExpanded=!collapsedSubscriptions.Contains(group.Name as string??"");}));
        expander.AddHandler(Expander.CollapsedEvent,new RoutedEventHandler((sender,_)=>{if(sender is Expander {IsLoaded:true,DataContext:CollectionViewGroup group})collapsedSubscriptions.Add(group.Name as string??"");}));
        expander.AddHandler(Expander.ExpandedEvent,new RoutedEventHandler((sender,_)=>{if(sender is Expander {IsLoaded:true,DataContext:CollectionViewGroup group})collapsedSubscriptions.Remove(group.Name as string??"");}));
        var items=new FrameworkElementFactory(typeof(ItemsPresenter));expander.AppendChild(items);
        var template=new ControlTemplate(typeof(GroupItem)) { VisualTree=expander };
        var container=new Style(typeof(GroupItem));container.Setters.Add(new Setter(GroupItem.TemplateProperty,template));
        container.Setters.Add(new Setter(System.Windows.Automation.AutomationProperties.NameProperty,new Binding("Name") {Converter=new SubscriptionGroupLabel(this)}));
        ServerSelect.GroupStyle.Add(new GroupStyle {ContainerStyle=container});
        VirtualizingPanel.SetIsVirtualizingWhenGrouping(ServerSelect,true);
    }
    private sealed class SubscriptionGroupLabel(MainWindow owner):IValueConverter
    {
        public object Convert(object value,Type targetType,object parameter,CultureInfo culture)
        {
            var source=owner.subscriptions.FirstOrDefault(s=>s.Url==value as string);
            return source==null?"WireGuard":SubscriptionPresentation.Label(source)+" · "+source.Profiles.Count;
        }
        public object ConvertBack(object value,Type targetType,object parameter,CultureInfo culture)=>Binding.DoNothing;
    }
}
