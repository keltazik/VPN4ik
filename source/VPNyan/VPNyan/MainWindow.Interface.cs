using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Button = System.Windows.Controls.Button;
using ComboBox = System.Windows.Controls.ComboBox;
using Orientation = System.Windows.Controls.Orientation;
using RadioButton = System.Windows.Controls.RadioButton;
using ContextMenu = System.Windows.Controls.ContextMenu;

namespace VPNyan;

public partial class MainWindow
{
    private readonly Stack<(string Section,string Category)> navigationHistory = new();
    private (string Section,string Category) navigationLocation = ("home","overview");
    private bool restoringNavigation;
    private readonly Stack<string> settingsHistory=new();
    private void RememberNavigation(string section,string category)
    {
        var next=(section,category);
        if (restoringNavigation || navigationLocation==next) return;
        navigationHistory.Push(navigationLocation); navigationLocation=next;
    }
    internal void NavigateBack()
    {
        if(navigationLocation.Section=="settings" || SettingsPage.Visibility==Visibility.Visible)
        {
            if(settingsCategory=="overview")return;
            var category=settingsHistory.TryPop(out var parent)?parent:"overview";
            restoringNavigation=true;
            try { ShowSettingsCategory(category);navigationLocation=("settings",category); }
            finally { restoringNavigation=false; }
            return;
        }
        if (!navigationHistory.TryPop(out var previous)) previous=("home","overview");
        restoringNavigation=true;
        try { ShowSection(previous.Section); if(previous.Section=="settings") ShowSettingsCategory(previous.Category); navigationLocation=previous; }
        finally { restoringNavigation=false; }
    }

    private ComboBox appearanceTheme=null!, appearanceVisual=null!;
    private ComboBox wordmarkStyle=null!;
    private System.Windows.Controls.Image previewWordmark=null!, previewOrnament=null!;
    private Border appearancePreview=null!;
    private Viewbox appearanceOrnament=null!;
    private Button appearanceButton=null!;
    private TextBlock appearanceServer=null!, appearanceStatus=null!;
    private readonly Dictionary<string,RadioButton> appearanceLanguages=new();
    private Grid appearanceLayout=null!;
    private void BuildAppearanceSettings(StackPanel page,System.Windows.Controls.CheckBox systemLanguage)
    {
        appearanceLayout=new Grid(); appearanceLayout.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(3,GridUnitType.Star) });
        appearanceLayout.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(2,GridUnitType.Star) });
        var choices=new StackPanel { Margin=new Thickness(0,0,14,0) }; appearanceLayout.Children.Add(choices);
        appearanceTheme=SettingsSelect(new[]{"Бордово-золотая","Винный бархат","Ночной сапфир","Тёмная слива"},new[]{"dark","wine","night","plum"},value=>{draftSettings!.Theme=value;SaveSettingsAutomatically();},"AppearanceThemeSelect");
        appearanceVisual=SettingsSelect(new[]{"Орнамент VPN4ik","Орнамент с сиянием","Компактный орнамент","Обычная кнопка"},new[]{"ornament","halo","compact","button"},value=>{draftSettings!.ConnectionVisual=value;SaveSettingsAutomatically();},"AppearanceVisualSelect");
        choices.Children.Add(SettingsCard("Оформление",SettingsLabel("Тема"),appearanceTheme,SettingsLabel("Вид подключения"),appearanceVisual,SettingsLabel("Иконка приложения · Фирменная")));
        wordmarkStyle=SettingsSelect(new[]{"Классика","Книжный","Медальон","Современный","Росчерк","Акцент на 4"},new[]{"classic","editorial","palatial","modern","signature","four"},value=>{draftSettings!.WordmarkStyle=value;SaveSettingsAutomatically();},"WordmarkStyleSelect");
        choices.Children.Add(SettingsCard("Главная надпись",wordmarkStyle,SettingsLabel("Цвет надписи и орнамента соответствует теме приложения.")));
        var languages=new WrapPanel();
        foreach(var (code,title) in new[]{("ru","Русский"),("en","English"),("hy","Հայերեն")})
        {
            var row=new StackPanel { Orientation=Orientation.Horizontal };
            row.Children.Add(new System.Windows.Controls.Image { Source=LanguageFlag(code),Width=24,Height=16,Margin=new Thickness(0,0,7,0) });
            row.Children.Add(new TextBlock { Text=title,VerticalAlignment=VerticalAlignment.Center });
            var radio=new RadioButton { Content=row,Tag=code,GroupName="AppearanceLanguage",Style=(Style)FindResource("SettingsTab"),Margin=new Thickness(0,0,6,8) };
            System.Windows.Automation.AutomationProperties.SetName(radio,title);
            radio.Click+=(_,_)=>{if(loadingSettings || draftSettings==null)return;draftSettings.Language=code;draftSettings.UseSystemLanguage=false;SaveSettingsAutomatically();};
            appearanceLanguages.Add(code,radio);languages.Children.Add(radio);
        }
        LanguageSelect.Visibility=Visibility.Collapsed;
        choices.Children.Add(SettingsCard("Язык приложения",languages,LanguageSelect,SettingsLabel("Язык интерфейса можно менять без перезапуска."),systemLanguage));
        var preview=new StackPanel { HorizontalAlignment=System.Windows.HorizontalAlignment.Stretch };
        previewWordmark=new System.Windows.Controls.Image {Name="AppearancePreviewWordmark",Height=64,MaxWidth=270,Stretch=Stretch.Uniform,HorizontalAlignment=System.Windows.HorizontalAlignment.Center};RegisterName(previewWordmark.Name,previewWordmark);preview.Children.Add(previewWordmark);
        previewOrnament=new System.Windows.Controls.Image { Source=(ImageSource)FindResource("OrnamentVector"),Width=220,Height=270 };
        appearanceOrnament=new Viewbox { Height=210,Margin=new Thickness(12,18,12,20),Child=previewOrnament };
        appearanceButton=new Button { Style=(Style)FindResource("StandardConnectionButton"),Width=150,Height=150,Content="⏻",FontSize=52,HorizontalAlignment=System.Windows.HorizontalAlignment.Center,Margin=new Thickness(0,20,0,20),IsHitTestVisible=false }; preview.Children.Add(appearanceButton);
        preview.Children.Add(appearanceOrnament); appearanceServer=SettingsLabel("Сервер не выбран",16,"#FFD27A"); appearanceStatus=SettingsLabel("Отключено");
        appearanceServer.Name="AppearancePreviewServer";appearanceStatus.Name="AppearancePreviewStatus";RegisterName(appearanceServer.Name,appearanceServer);RegisterName(appearanceStatus.Name,appearanceStatus);
        appearanceServer.TextAlignment=appearanceStatus.TextAlignment=TextAlignment.Center;
        preview.Children.Add(appearanceServer);preview.Children.Add(appearanceStatus);
        appearancePreview=new Border { CornerRadius=new CornerRadius(12),Padding=new Thickness(22),BorderBrush=SettingsBrush("#503441"),BorderThickness=new Thickness(1),Child=preview,VerticalAlignment=VerticalAlignment.Top };
        var right=new StackPanel();right.Children.Add(SettingsLabel("Вид главного экрана"));right.Children.Add(appearancePreview);Grid.SetColumn(right,1);appearanceLayout.Children.Add(right);page.Children.Add(appearanceLayout);
        appearanceLayout.RowDefinitions.Add(new RowDefinition {Height=GridLength.Auto});appearanceLayout.RowDefinitions.Add(new RowDefinition {Height=GridLength.Auto});
        page.SizeChanged+=(_,_)=>
        {
            var narrow=page.ActualWidth<690;
            appearanceLayout.ColumnDefinitions[0].Width=new GridLength(narrow?1:3,GridUnitType.Star);
            appearanceLayout.ColumnDefinitions[1].Width=new GridLength(narrow?0:2,GridUnitType.Star);
            Grid.SetRow(right,narrow?1:0);Grid.SetColumn(right,narrow?0:1);
            choices.Margin=new Thickness(0,0,narrow?0:14,0);
        };
    }
    private static ImageSource LanguageFlag(string code)
    {
        var colors=code switch {"ru"=>new[]{"#FFFFFF","#0039A6","#D52B1E"},"hy"=>new[]{"#D90012","#0033A0","#F2A800"},_=>new[]{"#B22234","#FFFFFF","#B22234","#FFFFFF","#B22234","#FFFFFF","#B22234"}};
        var group=new DrawingGroup();for(var i=0;i<colors.Length;i++)group.Children.Add(new GeometryDrawing(SettingsBrush(colors[i]),null,new RectangleGeometry(new Rect(0,i*16d/colors.Length,24,16d/colors.Length))));
        if(code=="en")group.Children.Add(new GeometryDrawing(SettingsBrush("#3C3B6E"),null,new RectangleGeometry(new Rect(0,0,11,9))));
        group.Freeze();return new DrawingImage(group);
    }
    private void RefreshAppearanceSettings()
    {
        if(appearanceTheme==null)return;
        appearanceTheme.SelectedValue=settings.Theme;appearanceVisual.SelectedValue=settings.ConnectionVisual;
        wordmarkStyle.SelectedValue=settings.WordmarkStyle;
        foreach(var item in appearanceLanguages){item.Value.IsChecked=item.Key==settings.EffectiveLanguage;}
        ApplyAppearance();
        var english=settings.EffectiveLanguage=="en";var armenian=settings.EffectiveLanguage=="hy";
        appearanceServer.Text=(ServerSelect.SelectedItem as ServerItem)?.DisplayName ?? (english?"No server selected":armenian?"Սերվեր ընտրված չէ":"Сервер не выбран");
        appearanceStatus.Text=activeServer==null?(english?"● Disconnected":armenian?"● Անջատված":"● Отключено"):(english?"● Connected":armenian?"● Միացված":"● Подключено");
    }
    private void ApplyAppearance()
    {
        ApplyThemePalette();
        var palette=BrandAssets.Palette(settings.Theme);
        MainWordmarkImage.Source=BrandAssets.Wordmark(settings.WordmarkStyle,palette);
        var ornament=BrandAssets.Ornament(palette);OrnamentImage.Source=ornament;OrnamentGlow.Source=ornament;
        if(previewWordmark!=null){previewWordmark.Source=MainWordmarkImage.Source;previewOrnament.Source=ornament;}
        var button=settings.ConnectionVisual=="button";
        OrnamentViewbox.Visibility=button?Visibility.Collapsed:Visibility.Visible;
        StandardConnectButton.Visibility=button?Visibility.Visible:Visibility.Collapsed;
        OrnamentViewbox.MaxHeight=settings.ConnectionVisual=="compact"?240:double.PositiveInfinity;
        if(appearancePreview!=null)
        {
            appearancePreview.SetResourceReference(Border.BackgroundProperty,"PanelBackground");
            appearanceOrnament.Visibility=button?Visibility.Collapsed:Visibility.Visible;
            appearanceButton.Visibility=button?Visibility.Visible:Visibility.Collapsed;
            appearanceOrnament.Height=settings.ConnectionVisual=="compact"?150:210;
            appearanceOrnament.Effect=settings.ConnectionVisual=="halo"?new System.Windows.Media.Effects.DropShadowEffect {Color=(System.Windows.Media.Color)Resources["AccentColor"],BlurRadius=30,ShadowDepth=0,Opacity=.65}:null;
        }
        ornamentGlowState=-1;
        UpdateOrnamentGlow();
    }
}
