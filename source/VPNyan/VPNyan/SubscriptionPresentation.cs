using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;

namespace VPNyan;

internal static class SubscriptionPresentation
{
    internal static string Title(HttpResponseHeaders headers)
    {
        if(!headers.TryGetValues("profile-title",out var values))return "";
        var text=values.FirstOrDefault()??"";
        if(text.StartsWith("base64:",StringComparison.OrdinalIgnoreCase))
            try{text=Encoding.UTF8.GetString(Convert.FromBase64String(text[7..]));}catch(FormatException){return "";}
        return Clean(text);
    }
    private static string Clean(string text)=>new(text.Where(c=>!char.IsControl(c)).Take(100).ToArray());
    internal static DateTimeOffset? Expiry(HttpResponseHeaders headers)
    {
        if(!headers.TryGetValues("subscription-userinfo",out var values))return null;
        var match=Regex.Match(string.Join(";",values),@"(?:^|;)\s*expire\s*=\s*(\d+)\s*(?:;|$)",RegexOptions.IgnoreCase);
        if(!match.Success || !long.TryParse(match.Groups[1].Value,NumberStyles.None,CultureInfo.InvariantCulture,out var seconds) || seconds<=0)return null;
        try{return DateTimeOffset.FromUnixTimeSeconds(seconds);}catch(ArgumentOutOfRangeException){return null;}
    }
    internal static string Name(Subscription source)
    {
        if(!string.IsNullOrWhiteSpace(source.DisplayName) && !source.DisplayName.Contains("://"))
        {
            var name=Regex.Replace(Clean(source.DisplayName),@"^https?\s*[/ :]+","",RegexOptions.IgnoreCase).Trim();
            if(name.Length>0)return name.Equals("ultima",StringComparison.OrdinalIgnoreCase)?"Ultima VPN":name;
        }
        if(!Uri.TryCreate(source.Url,UriKind.Absolute,out var uri) || uri.Scheme!="https")return "Файл Xray";
        var host=uri.IdnHost.Split('.');var brand=host.Length>1?host[^2]:host[0];
        if((brand is "co" or "com" or "net") && host.Length>2)brand=host[^3];
        brand=Regex.Replace(brand,@"[^\p{L}\p{N}]+"," ").Trim();
        if(brand.Equals("ultm",StringComparison.OrdinalIgnoreCase) || brand.Equals("ultima",StringComparison.OrdinalIgnoreCase))return "Ultima VPN";
        return brand.Length==0?"Подписка":CultureInfo.InvariantCulture.TextInfo.ToTitleCase(brand)+" VPN";
    }
    internal static string Label(Subscription source)=>Name(source)+(source.ExpiresAt is { } expiry?" · "+Localization.T("до")+" "+expiry.ToLocalTime().ToString("dd.MM.yyyy",CultureInfo.InvariantCulture):"");
}
