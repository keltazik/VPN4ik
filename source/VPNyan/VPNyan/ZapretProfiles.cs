using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace VPNyan;

internal sealed record ZapretProfile(string FileName, string Name) { public override string ToString() => Name; }
internal sealed record ZapretFolderInfo(string Folder, string Version, List<ZapretProfile> Profiles, string GameMode, string IpSetMode);

internal static class ZapretProfiles
{
    internal static string ValidateFolder(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Path.IsPathFullyQualified(folder)) throw new InvalidDataException("Выбери распакованную папку zapret.");
        var root = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar);
        foreach (var relative in new[] { "service.bat", "bin/winws.exe", "bin/WinDivert.dll" })
            if (!File.Exists(SafePath(root, relative))) throw new InvalidDataException("Нужна папка сборки Flowseal: service.bat, bin/winws.exe и списки.");
        if (!Directory.Exists(SafePath(root, "lists"))) throw new InvalidDataException("В папке zapret отсутствуют списки.");
        return root;
    }

    internal static string SafePath(string folder, string relative)
    {
        var root = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar);
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Путь вне папки zapret.");
        var current = path;
        while (true)
        {
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            if (info.LinkTarget != null) throw new InvalidDataException("Ссылки на другие папки в установке zapret не поддерживаются.");
            if (current.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
            current = Path.GetDirectoryName(current) ?? throw new InvalidDataException();
        }
        return path;
    }

    internal static ZapretFolderInfo Read(string folder)
    {
        folder = ValidateFolder(folder);
        var service = ReadSmall(SafePath(folder, "service.bat"));
        var version = Regex.Match(service, @"(?im)^\s*set\s+""?LOCAL_VERSION=([0-9.]+)").Groups[1].Value;
        var profiles = Directory.EnumerateFiles(folder, "*.bat").Where(path => !Path.GetFileName(path).StartsWith("service", StringComparison.OrdinalIgnoreCase))
            .Select(path => new ZapretProfile(Path.GetFileName(path), Path.GetFileNameWithoutExtension(path)))
            .OrderBy(profile => Natural(profile.Name), StringComparer.OrdinalIgnoreCase).ToList();
        if (profiles.Count == 0) throw new InvalidDataException("В папке нет стратегий zapret (*.bat).");
        return new(folder, version == "" ? "не определена" : version, profiles, ReadGameMode(folder), ReadIpSetMode(folder));
    }

    private static string Natural(string name) => Regex.Replace(name, @"\d+", match => match.Value.PadLeft(8, '0'));
    internal static string ReadSmall(string path)
    {
        if (new FileInfo(path).Length > 4 * 1024 * 1024) throw new InvalidDataException("Файл zapret слишком большой.");
        return File.ReadAllText(path, Encoding.UTF8);
    }

    internal static string[] BuildArguments(string folder, string strategy)
    {
        folder = ValidateFolder(folder);
        if (Path.GetFileName(strategy) != strategy || !strategy.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) || strategy.StartsWith("service", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Выбери стратегию zapret.");
        var source = ReadSmall(SafePath(folder, strategy)).Replace("^\r\n", " ").Replace("^\n", " ");
        var match = Regex.Match(source, "(?im)^\\s*start\\s+[^\\r\\n]*?\"%BIN%winws\\.exe\"\\s+(?<args>[^\\r\\n]+)\\r?$");
        if (!match.Success) throw new InvalidDataException("Эта стратегия не поддерживается: не найден запуск winws.exe. Исходный BAT не выполнялся.");
        var (tcp, udp) = GameRanges(folder);
        var variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["BIN"] = SafePath(folder, "bin") + "\\", ["LISTS"] = SafePath(folder, "lists") + "\\", ["GameFilterTCP"] = tcp, ["GameFilterUDP"] = udp, ["GameFilter"] = tcp
        };
        var expanded = Regex.Replace(match.Groups["args"].Value, "%([A-Za-z0-9_]+)%", variable => variables.TryGetValue(variable.Groups[1].Value, out var value)
            ? value : throw new InvalidDataException("Неизвестная переменная в стратегии zapret."));
        expanded = expanded.Replace("^!", "!");
        if (expanded.Contains('%') || Regex.IsMatch(expanded, @"![A-Za-z0-9_]+!")) throw new InvalidDataException("Стратегия содержит неподдерживаемые подстановки.");
        var args = SplitCommandLine("winws.exe " + expanded).Skip(1).ToArray();
        ValidateArguments(args);
        return args;
    }

    internal static void ValidateArguments(string[] args)
    {
        if (args.Length is < 1 or > 512 || args.Sum(arg => arg.Length + 1) > 30000 || args.Any(arg => !arg.StartsWith("--", StringComparison.Ordinal) || arg.Contains('\0') || arg.Contains('\r') || arg.Contains('\n')))
            throw new InvalidDataException("Некорректные параметры стратегии zapret.");
        foreach (var arg in args)
        {
            var key = arg.Split('=', 2)[0];
            if (key is "--wf-save" or "--debug" or "--pidfile" or "--daemon" or "--help" or "--version")
                throw new InvalidDataException("Стратегия запрашивает неподдерживаемую служебную операцию.");
        }
    }

    internal static string[] SplitCommandLine(string command)
    {
        var argv = CommandLineToArgvW(command, out var count);
        if (argv == IntPtr.Zero) throw new InvalidDataException("Не удалось разобрать параметры zapret.");
        try { return Enumerable.Range(0, count).Select(index => Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, index * IntPtr.Size)) ?? "").ToArray(); }
        finally { LocalFree(argv); }
    }

    internal static string Quote(string value) => "\"" + Regex.Replace(Regex.Replace(value, "(\\\\*)\"", "$1$1\\\""), "(\\\\+)$", "$1$1") + "\"";

    private static Dictionary<string, string> GameSettings(string folder, bool useBackup = false)
    {
        var path = SafePath(folder, "utils/game_filter.enabled");
        if (useBackup && !File.Exists(path)) path = SafePath(folder, "utils/game_filter.enabled.vpn4ik-backup");
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(path)) foreach (var line in ReadSmall(path).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = line.Split('=', 2); if (pair.Length == 2) values[pair[0]] = pair[1];
            else if (line is "all" or "tcp" or "udp") values["mode"] = line;
        }
        return values;
    }
    internal static string ReadGameMode(string folder) => GameSettings(folder).TryGetValue("mode", out var mode) && mode is "all" or "tcp" or "udp" ? mode : "disabled";
    private static (string Tcp, string Udp) GameRanges(string folder)
    {
        var values = GameSettings(folder); var mode = ReadGameMode(folder);
        string Range(string key) => values.TryGetValue(key, out var value) && Regex.IsMatch(value, @"^\d{1,5}-\d{1,5}$") && value.Split('-').Select(int.Parse).ToArray() is var ports && ports[0] >= 1 && ports[0] <= ports[1] && ports[1] <= 65535 ? value : "1024-65535";
        return (mode is "all" or "tcp" ? Range("tcp") : "12", mode is "all" or "udp" ? Range("udp") : "12");
    }
    internal static string ReadIpSetMode(string folder)
    {
        var path = SafePath(folder, "lists/ipset-all.txt");
        if (!File.Exists(path)) return "none";
        var text = ReadSmall(path).Trim();
        return text == "" ? "any" : text.Contains("203.0.113.113/32", StringComparison.Ordinal) ? "none" : "loaded";
    }

    internal static void Configure(string folder, string game, string ipset)
    {
        folder = ValidateFolder(folder);
        if (game is not ("disabled" or "all" or "tcp" or "udp") || ipset is not ("none" or "loaded" or "any")) throw new InvalidDataException("Некорректный режим фильтра.");
        var ipPath = SafePath(folder, "lists/ipset-all.txt"); var backup = SafePath(folder, "lists/ipset-all.txt.vpn4ik-backup");
        var current = ReadIpSetMode(folder);
        if (current != ipset)
        {
            if (current == "loaded") AtomicWrite(backup, ReadSmall(ipPath));
            var restored = File.Exists(backup) ? backup : SafePath(folder, "lists/ipset-all.txt.backup");
            if (ipset == "loaded" && !File.Exists(restored)) throw new InvalidDataException("Нет сохранённого IPSet. Добавь список в папке zapret.");
            AtomicWrite(ipPath, ipset == "any" ? "" : ipset == "none" ? "203.0.113.113/32\n" : ReadSmall(restored));
        }
        var flag = SafePath(folder, "utils/game_filter.enabled");
        if (ReadGameMode(folder) == game) return;
        if (game == "disabled") { if (File.Exists(flag)) { AtomicWrite(flag + ".vpn4ik-backup", ReadSmall(flag)); File.Delete(flag); } }
        else
        {
            var values = GameSettings(folder, true); var tcp = values.GetValueOrDefault("tcp", "1024-65535"); var udp = values.GetValueOrDefault("udp", "1024-65535");
            AtomicWrite(flag, $"mode={game}\ntcp={tcp}\nudp={udp}\n");
        }
    }

    internal static string ReadList(string folder, string kind)
    {
        var path = ListPath(folder, kind); var text = File.Exists(path) ? ReadSmall(path) : "";
        return text.StartsWith("# VPN4ik empty user list", StringComparison.Ordinal) ? "" : text;
    }
    private static string ListPath(string folder, string kind) => SafePath(ValidateFolder(folder), kind switch
    { "domains" => "lists/list-general-user.txt", "exclude" => "lists/list-exclude-user.txt", "ips" => "lists/ipset-exclude-user.txt", _ => throw new InvalidDataException("Неизвестный список.") });
    internal static void WriteList(string folder, string kind, string text)
    {
        ValidateList(kind, text);
        var lines = text.Split('\n').Select(line => line.Trim()).ToArray();
        var path = ListPath(folder, kind);
        if (File.Exists(path)) AtomicWrite(path + ".vpn4ik-backup", ReadSmall(path));
        var output = lines.Any(line => line != "" && !line.StartsWith('#')) ? string.Join('\n', lines) + "\n"
            : "# VPN4ik empty user list\n" + (kind == "ips" ? "203.0.113.113/32" : "vpn4ik-empty.invalid") + "\n";
        AtomicWrite(path, output);
    }
    internal static void EnsureUserLists(string folder)
    {
        foreach (var kind in new[] { "domains", "exclude", "ips" }) if (!File.Exists(ListPath(folder, kind))) WriteList(folder, kind, "");
    }
    internal static void ValidateList(string kind, string text)
    {
        if (kind is not ("domains" or "exclude" or "ips")) throw new InvalidDataException("Неизвестный список.");
        if (Encoding.UTF8.GetByteCount(text) > 1024 * 1024 || text.Contains('\0')) throw new InvalidDataException("Список слишком большой или содержит недопустимый символ.");
        var lines = text.Split('\n').Select(line => line.Trim()).ToArray();
        foreach (var line in lines.Where(line => line != "" && !line.StartsWith('#')))
        {
            if (kind == "ips") { _ = RoutingSettings.Parse(line, "ip"); continue; }
            var domain = line.StartsWith("*.") ? line[2..] : line.TrimStart('.');
            if (Uri.CheckHostName(domain) == UriHostNameType.Unknown || line.Contains(' ') || line.Contains('/')) throw new InvalidDataException("Введи домены по одному на строку, без https:// и путей.");
        }
    }

    private static void AtomicWrite(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); var pending = path + ".vpn4ik-" + Guid.NewGuid().ToString("N");
        try { File.WriteAllText(pending, text, new UTF8Encoding(false)); File.Move(pending, path, true); }
        finally { if (File.Exists(pending)) File.Delete(pending); }
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CommandLineToArgvW(string command, out int argc);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
