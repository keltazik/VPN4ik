using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;
using Binding = System.Windows.Data.Binding;

namespace VPNyan;

/// <summary>Localizes presentation only. Stored events, configuration and routing values stay canonical.</summary>
public sealed class Localization : INotifyPropertyChanged
{
    internal sealed record Entry(string Id, string Ru, string En, string Hy);
    private sealed record Template(Entry Entry, Regex Pattern);
    private static readonly Regex Placeholder = new(@"\{(?<index>\d+)(?:,[^}:]+)?(?::[^}]+)?\}", RegexOptions.CultureInvariant);
    public static Localization Current { get; } = new();
    private readonly Entry[] entries;
    private readonly Dictionary<string, Entry> exact;
    private readonly Dictionary<string, Entry> byId;
    private readonly Template[] templates;
    private readonly Regex fragments;
    public string Language { get; private set; } = "ru";
    public string this[string id] => byId.TryGetValue(id, out var entry) ? Select(entry) : id;
    public event PropertyChangedEventHandler? PropertyChanged;
    internal IReadOnlyList<Entry> Catalog => entries;

    private Localization()
    {
        using var stream = typeof(Localization).Assembly.GetManifestResourceStream("VPNyan.Localization.json")
            ?? throw new InvalidDataException("Missing localization catalog.");
        entries = JsonSerializer.Deserialize<Entry[]>(stream)!;
        exact = entries.ToDictionary(e => e.Ru, StringComparer.Ordinal);
        byId = entries.ToDictionary(e => e.Id, StringComparer.Ordinal);
        templates = entries.Where(e => Placeholder.IsMatch(e.Ru)).OrderByDescending(e => e.Ru.Length)
            .Select(e => new Template(e, CompileTemplate(e.Ru))).ToArray();
        // One pass, longest phrases first. No translated output is fed back into the matcher.
        fragments = new Regex(string.Join("|", entries.Where(e => !Placeholder.IsMatch(e.Ru))
            .OrderByDescending(e => e.Ru.Length).Select(e => Regex.Escape(e.Ru))), RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(150));
    }

    public void Apply(string language)
    {
        Language = language is "en" or "hy" ? language : "ru";
        // Do not change CurrentCulture: protocol numbers and configuration must remain unaffected.
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(Language);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
    }

    private string Select(Entry entry) => Language switch { "en" => entry.En, "hy" => entry.Hy, _ => entry.Ru };
    public static string T(string? text) => Current.Translate(text ?? "");
    private string Translate(string text)
    {
        if (Language == "ru" || text.Length == 0) return text;
        if (text.Length > 32768 || System.IO.Path.IsPathFullyQualified(text)) return text;
        if (exact.TryGetValue(text, out var entry)) return Select(entry);
        if (text.Contains('\n')) return string.Join('\n', text.Split('\n').Select(Translate));
        // zapret's compact event feed prefixes canonical messages with a local timestamp.
        if (text.Length > 11 && Regex.IsMatch(text, @"^\d{2}:\d{2}:\d{2} · ")) return text[..11] + Translate(text[11..]);
        foreach (var template in templates)
        {
            Match match;
            try { match = template.Pattern.Match(text); }
            catch (RegexMatchTimeoutException) { continue; }
            if (!match.Success) continue;
            // Keep inserted values (server names, paths, identifiers) intact.
            return TranslateFragments(Placeholder.Replace(Select(template.Entry), p => match.Groups["v" + p.Groups["index"].Value].Value));
        }
        return TranslateFragments(text);
    }

    private string TranslateFragments(string text)
    {
        try { return fragments.Replace(text, match => Select(exact[match.Value])); }
        catch (RegexMatchTimeoutException) { return text; }
    }

    private static Regex CompileTemplate(string text)
    {
        var pattern = new StringBuilder("\\A");
        var last = 0;
        var seen = new HashSet<string>();
        foreach (Match match in Placeholder.Matches(text))
        {
            pattern.Append(Regex.Escape(text[last..match.Index]));
            var name = "v" + match.Groups["index"].Value;
            pattern.Append(seen.Add(name) ? "(?<" + name + ">.*?)" : "\\k<" + name + ">");
            last = match.Index + match.Length;
        }
        pattern.Append(Regex.Escape(text[last..])).Append("\\z");
        return new Regex(pattern.ToString(), RegexOptions.Singleline | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(100));
    }

    internal static void Set(DependencyObject target, DependencyProperty property, string? text) =>
        BindingOperations.SetBinding(target, property, new Binding(nameof(Language))
        {
            Source = Current, Mode = BindingMode.OneWay,
            Converter = PresentationConverter.Instance, ConverterParameter = text ?? ""
        });

    private sealed class PresentationConverter : IValueConverter
    {
        internal static PresentationConverter Instance { get; } = new();
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => T(parameter as string);
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
    }
}

/// <summary>A data binding refreshed both by model changes and by the selected language.</summary>
public sealed class TranslateExtension : MarkupExtension
{
    public string Path { get; set; } = ".";
    public string? ElementName { get; set; }
    public string Fallback { get; set; } = "";
    public bool PreserveValue { get; set; }
    public bool IsServerName { get; set; }
    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var value = new Binding(Path) { Mode = BindingMode.OneWay };
        if (ElementName != null) value.ElementName = ElementName;
        var binding = new MultiBinding { Mode = BindingMode.OneWay, Converter = new Converter(Fallback, PreserveValue, IsServerName) };
        binding.Bindings.Add(value);
        binding.Bindings.Add(new Binding(nameof(Localization.Language)) { Source = Localization.Current });
        return binding.ProvideValue(serviceProvider);
    }
    private sealed class Converter(string fallback, bool preserveValue, bool serverName) : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) =>
            values[0] is string text && text.Length > 0 ? (serverName ? ServerCountry.LocalizedDisplayName(text) : preserveValue ? text : Localization.T(text)) : Localization.T(fallback);
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) =>
            targetTypes.Select(_ => Binding.DoNothing).ToArray();
    }
}
