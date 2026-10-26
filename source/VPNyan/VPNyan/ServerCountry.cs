using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Media;
using Point = System.Windows.Point;
using Rect = System.Windows.Rect;
using Brush = System.Windows.Media.Brush;
using Pen = System.Windows.Media.Pen;
using ColorConverter = System.Windows.Media.ColorConverter;

namespace VPNyan;

// Flags are frozen vector drawings: Windows does not need an emoji flag font.
// Country comes only from the provider's name/emoji, never from an IP lookup.
internal static class ServerCountry
{
    private sealed record Country(string Code, string Label, string Aliases);
    private static readonly Country[] Countries =
    {
        new("SE", "Швеция", "sweden|швеция|se"), new("EE", "Эстония", "estonia|эстония|ee"),
        new("NL", "Нидерланды", "netherlands|holland|нидерланды|голландия|nl"),
        new("US", "США", "united states|usa|сша|us"), new("DE", "Германия", "germany|deutschland|германия|de"),
        new("LV", "Латвия", "latvia|латвия|lv"), new("LT", "Литва", "lithuania|литва|lt"),
        new("FI", "Финляндия", "finland|финляндия|fi"), new("NO", "Норвегия", "norway|норвегия|no"),
        new("DK", "Дания", "denmark|дания|dk"), new("IS", "Исландия", "iceland|исландия|is"),
        new("GB", "Великобритания", "united kingdom|great britain|britain|england|великобритания|англия|uk|gb"),
        new("FR", "Франция", "france|франция|fr"), new("IT", "Италия", "italy|италия|it"),
        new("IE", "Ирландия", "ireland|ирландия|ie"), new("BE", "Бельгия", "belgium|бельгия|be"),
        new("AT", "Австрия", "austria|австрия|at"), new("CH", "Швейцария", "switzerland|швейцария|ch"),
        new("PL", "Польша", "poland|польша|pl"), new("CZ", "Чехия", "czechia|czech republic|чехия|cz"),
        new("ES", "Испания", "spain|испания|es"), new("RO", "Румыния", "romania|румыния|ro"),
        new("HU", "Венгрия", "hungary|венгрия|hu"), new("BG", "Болгария", "bulgaria|болгария|bg"),
        new("RU", "Россия", "russia|россия|ru"), new("UA", "Украина", "ukraine|украина|ua"),
        new("AM", "Армения", "armenia|армения|am"), new("TR", "Турция", "turkey|turkiye|турция|tr"),
        new("CA", "Канада", "canada|канада|ca"), new("JP", "Япония", "japan|япония|jp"),
        new("SG", "Сингапур", "singapore|сингапур|sg"), new("IN", "Индия", "india|индия|in"),
        new("AE", "ОАЭ", "united arab emirates|uae|оаэ|дубай|dubai|ae"),
        new("IL", "Израиль", "israel|израиль|il"), new("BR", "Бразилия", "brazil|бразилия|br"),
        new("ID", "Индонезия", "indonesia|индонезия|id"), new("EU", "Европа", "europe|европа|евросоюз|eu"),
    };
    private static readonly Regex FlagEmoji = new(@"(?:\uD83C[\uDDE6-\uDDFF]){2}", RegexOptions.Compiled);
    private static readonly (Country Country, Regex Pattern)[] Patterns = Countries.Select(country =>
        (country, new Regex(@"(?<![\p{L}\p{N}])(?:(?i:" + string.Join('|', country.Aliases.Split('|').Where(alias => alias.Length > 2)) +
            ")|" + country.Code + (country.Code == "GB" ? "|UK" : "") + @")(?![\p{L}\p{N}])",
            RegexOptions.CultureInvariant | RegexOptions.Compiled))).ToArray();
    private static readonly ConcurrentDictionary<string, ImageSource> Flags = new();

    internal static string Identify(string name)
    {
        var emoji = FlagEmoji.Match(name);
        if (emoji.Success)
        {
            var code = string.Concat(emoji.Value.EnumerateRunes().Select(rune => (char)('A' + rune.Value - 0x1F1E6)));
            return Countries.Any(country => country.Code == code) ? code : "";
        }
        return Patterns.FirstOrDefault(item => item.Pattern.IsMatch(name)).Country?.Code ?? "";
    }

    internal static string DisplayName(string name) => FlagEmoji.Replace(name, "").Trim(' ', '|', '-', '·');
    internal static string Label(string code) => Countries.FirstOrDefault(country => country.Code == code)?.Label ?? "Страна не указана";
    internal static ImageSource Flag(string code) => Flags.GetOrAdd(code, CreateFlag);

    private static ImageSource CreateFlag(string code)
    {
        var group = new DrawingGroup { ClipGeometry = new EllipseGeometry(new Point(15, 10), 10, 10) };
        using (var dc = group.Open())
        {
            Brush Color(string hex)
            {
                var brush = new SolidColorBrush((System.Windows.Media.Color)ColorConverter.ConvertFromString(hex));
                brush.Freeze(); return brush;
            }
            void Rect(string color, double x, double y, double width, double height) => dc.DrawRectangle(Color(color), null, new Rect(x,y,width,height));
            void Circle(string color, double x, double y, double radius) => dc.DrawEllipse(Color(color),null,new Point(x,y),radius,radius);
            void Shape(string color, string data) => dc.DrawGeometry(Color(color),null,Geometry.Parse(data));
            void Stripes(bool vertical, params string[] colors)
            {
                for (var i=0; i<colors.Length; i++)
                    Rect(colors[i], vertical?i*30d/colors.Length:0, vertical?0:i*20d/colors.Length,
                        vertical?30d/colors.Length:30, vertical?20:20d/colors.Length);
            }
            void Cross(string background, string cross, string? inner = null)
            {
                Rect(background,0,0,30,20); Rect(cross,9,0,4,20); Rect(cross,0,8,30,4);
                if (inner != null) { Rect(inner,10,0,2,20); Rect(inner,0,9,30,2); }
            }
            void Star(string color, double x, double y, double radius)
            {
                var geometry = new StreamGeometry();
                using (var context=geometry.Open())
                {
                    var points=Enumerable.Range(0,10).Select(i=> {
                        var angle=i*Math.PI/5-Math.PI/2; var r=i%2==0?radius:radius*.4;
                        return new Point(x+Math.Cos(angle)*r,y+Math.Sin(angle)*r);
                    }).ToArray();
                    context.BeginFigure(points[0],true,true); context.PolyLineTo(points.Skip(1).ToArray(),true,false);
                }
                geometry.Freeze(); dc.DrawGeometry(Color(color),null,geometry);
            }
            switch (code)
            {
                case "SE": Cross("#006AA7","#FECC00"); break;
                case "FI": Cross("#FFFFFF","#003580"); break;
                case "DK": Cross("#C8102E","#FFFFFF"); break;
                case "NO": Cross("#BA0C2F","#FFFFFF","#00205B"); break;
                case "IS": Cross("#02529C","#FFFFFF","#DC1E35"); break;
                case "EE": Stripes(false,"#4891D9","#171717","#FFFFFF"); break;
                case "NL": Stripes(false,"#AE1C28","#FFFFFF","#21468B"); break;
                case "DE": Stripes(false,"#171717","#DD0000","#FFCE00"); break;
                case "LV": Rect("#9E1B34",0,0,30,20); Rect("#FFFFFF",0,8,30,4); break;
                case "LT": Stripes(false,"#FDB913","#006A44","#C1272D"); break;
                case "RU": Stripes(false,"#FFFFFF","#0039A6","#D52B1E"); break;
                case "AM": Stripes(false,"#D90012","#0033A0","#F2A800"); break;
                case "AT": Stripes(false,"#ED2939","#FFFFFF","#ED2939"); break;
                case "HU": Stripes(false,"#CE2939","#FFFFFF","#477050"); break;
                case "BG": Stripes(false,"#FFFFFF","#00966E","#D62612"); break;
                case "UA": Stripes(false,"#0057B7","#FFDD00"); break;
                case "PL": Stripes(false,"#FFFFFF","#DC143C"); break;
                case "ID": Stripes(false,"#CE1126","#FFFFFF"); break;
                case "FR": Stripes(true,"#002654","#FFFFFF","#ED2939"); break;
                case "IT": Stripes(true,"#009246","#FFFFFF","#CE2B37"); break;
                case "IE": Stripes(true,"#169B62","#FFFFFF","#FF883E"); break;
                case "BE": Stripes(true,"#171717","#FDDA24","#EF3340"); break;
                case "RO": Stripes(true,"#002B7F","#FCD116","#CE1126"); break;
                case "CZ": Stripes(false,"#FFFFFF","#D7141A"); Shape("#11457E","M0,0 L15,10 L0,20 Z"); break;
                case "CH": Rect("#DA291C",0,0,30,20); Rect("#FFFFFF",12,4,6,12); Rect("#FFFFFF",9,7,12,6); break;
                case "JP": Rect("#FFFFFF",0,0,30,20); Circle("#BC002D",15,10,6); break;
                case "ES": Rect("#AA151B",0,0,30,20); Rect("#F1BF00",0,5,30,10); break;
                case "US":
                    for(var i=0;i<13;i++)Rect(i%2==0?"#B22234":"#FFFFFF",0,i*20d/13,30,20d/13);
                    Rect("#3C3B6E",0,0,13,20d*7/13);
                    for(var row=0;row<9;row++) for(var col=0;col<(row%2==0?6:5);col++)
                        Star("#FFFFFF",1.1+col*2.15+(row%2)*1.05,.65+row*1.18,.48);
                    break;
                case "GB":
                    Rect("#012169",0,0,30,20); Shape("#FFFFFF","M0,0 L4,0 L30,17 L30,20 L26,20 L0,3 Z M30,0 L26,0 L0,17 L0,20 L4,20 L30,3 Z");
                    Shape("#C8102E","M0,0 L1.8,0 L30,18.2 L30,20 L28.2,20 L0,1.8 Z M30,0 L28.2,0 L0,18.2 L0,20 L1.8,20 L30,1.8 Z");
                    Rect("#FFFFFF",11,0,8,20); Rect("#FFFFFF",0,6,30,8); Rect("#C8102E",12.5,0,5,20); Rect("#C8102E",0,7.5,30,5); break;
                case "TR":
                    Rect("#E30A17",0,0,30,20); Circle("#FFFFFF",13,10,5.4); Circle("#E30A17",14.5,10,4.3); Star("#FFFFFF",20,10,2.8); break;
                case "CA":
                    Stripes(true,"#D80621","#FFFFFF","#D80621"); Rect("#FFFFFF",7.5,0,15,20);
                    Shape("#D80621","M15,3 L16.4,6.4 L18,5.6 L17.5,9 L20,8.1 L19.2,10.3 L21,11.1 L17.2,14 L15.6,13.7 L15.6,17 L14.4,17 L14.4,13.7 L12.8,14 L9,11.1 L10.8,10.3 L10,8.1 L12.5,9 L12,5.6 L13.6,6.4 Z"); break;
                case "SG":
                    Stripes(false,"#EF3340","#FFFFFF"); Circle("#FFFFFF",11,5,3.5); Circle("#EF3340",12.3,4.6,2.9);
                    for(var i=0;i<5;i++)Star("#FFFFFF",16+Math.Cos(i*Math.PI*2/5-Math.PI/2)*2,5+Math.Sin(i*Math.PI*2/5-Math.PI/2)*2,.65); break;
                case "IN": Stripes(false,"#FF9933","#FFFFFF","#138808"); Circle("#000080",15,10,2.4); Circle("#FFFFFF",15,10,1.6); break;
                case "AE": Stripes(false,"#00732F","#FFFFFF","#000000"); Rect("#FF0000",0,0,7.5,20); break;
                case "IL":
                    Rect("#FFFFFF",0,0,30,20); Rect("#0038B8",0,3,30,2.5); Rect("#0038B8",0,14.5,30,2.5);
                    dc.DrawGeometry(null,new Pen(Color("#0038B8"),.8),Geometry.Parse("M15,6 L18.5,12 L11.5,12 Z M15,14 L11.5,8 L18.5,8 Z")); break;
                case "BR": Rect("#009B3A",0,0,30,20); Shape("#FFDF00","M15,2 L27,10 L15,18 L3,10 Z"); Circle("#002776",15,10,4.8); break;
                case "EU":
                    Rect("#003399",0,0,30,20); for(var i=0;i<12;i++)Star("#FFCC00",15+Math.Cos(i*Math.PI/6)*6,10+Math.Sin(i*Math.PI/6)*6,.8); break;
                default:
                    Rect("#39313C",0,0,30,20); var pen=new Pen(Color("#BCA98C"),.8);
                    dc.DrawEllipse(null,pen,new Point(15,10),8,8); dc.DrawEllipse(null,pen,new Point(15,10),3.5,8);
                    dc.DrawLine(pen,new Point(7,10),new Point(23,10)); break;
            }
        }
        group.Freeze(); var image = new DrawingImage(group); image.Freeze(); return image;
    }
}
