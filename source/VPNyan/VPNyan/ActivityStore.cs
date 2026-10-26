using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace VPNyan;

public sealed record LogEntry(DateTimeOffset Time, string Level, string Message)
{
    public string TimeDisplay => Time.ToLocalTime().ToString("dd.MM HH:mm:ss");
    public string LevelColor => Level == "Ошибка" ? "#FF8E8E" : "#C9A15C";
}

public sealed class ConnectionRecord : INotifyPropertyChanged
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ServerName { get; set; } = "";
    public string Protocol { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ConnectedAt { get; set; }
    public DateTimeOffset? EndedAt { get; set; }
    public string Result { get; set; } = "Подключение";
    public string ExternalIp { get; set; } = "";
    public string StartedDisplay => StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    public string DurationDisplay => ConnectedAt == null ? "—" : EndedAt is DateTimeOffset end
        ? (end - ConnectedAt.Value).ToString(@"hh\:mm\:ss") : Result == "Подключено" ? "Сеанс активен" : "Завершение неизвестно";
    public string ResultColor => Result == "Ошибка" ? "#FF8E8E" : "#C9A15C";
    public event PropertyChangedEventHandler? PropertyChanged;
    internal void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
}

internal sealed class ActivityStore
{
    private readonly string path;
    internal ObservableCollection<LogEntry> Logs { get; } = new();
    internal ObservableCollection<ConnectionRecord> History { get; } = new();
    internal ActivityStore(string dataDirectory)
    {
        path = Path.Combine(dataDirectory, "activity.dpapi");
        if (!File.Exists(path)) return;
        try
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
            var data = JsonSerializer.Deserialize<ActivityData>(bytes);
            foreach (var item in data?.Logs.Take(1000) ?? Enumerable.Empty<LogEntry>()) Logs.Add(item);
            foreach (var item in data?.History.Take(200) ?? Enumerable.Empty<ConnectionRecord>())
            {
                if (item.EndedAt == null && item.Result is "Подключение" or "Подключено") item.Result = "Прервано";
                History.Add(item);
            }
        }
        catch { Logs.Add(new LogEntry(DateTimeOffset.UtcNow, "Ошибка", "Не удалось прочитать предыдущий журнал.")); }
    }
    internal void Add(string level, string message)
    {
        Logs.Insert(0, new LogEntry(DateTimeOffset.UtcNow, level, SecretRedactor.Generic(message)));
        while (Logs.Count > 1000) Logs.RemoveAt(Logs.Count - 1);
        Save();
    }
    internal ConnectionRecord Begin(string name, string protocol)
    {
        var record = new ConnectionRecord { ServerName = SecretRedactor.Generic(name), Protocol = protocol };
        History.Insert(0, record);
        while (History.Count > 200) History.RemoveAt(History.Count - 1);
        Save();
        return record;
    }
    internal void Connected(ConnectionRecord record, string ip)
    { record.ConnectedAt = DateTimeOffset.UtcNow; record.Result = "Подключено"; record.ExternalIp = ip; record.Refresh(); Save(); }
    internal void End(ConnectionRecord? record, string result)
    { if (record == null) return; record.EndedAt = DateTimeOffset.UtcNow; record.Result = result; record.Refresh(); Save(); }
    internal void ClearLogs() { Logs.Clear(); Save(); }
    internal void ClearHistory(ConnectionRecord? active)
    { foreach (var item in History.Where(item => item != active).ToArray()) History.Remove(item); Save(); }
    private void Save()
    {
        try
        {
            var bytes = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(new ActivityData { Logs = Logs.ToList(), History = History.ToList() }), null, DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path + ".tmp", bytes);
            File.Move(path + ".tmp", path, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        { System.Diagnostics.Debug.WriteLine("Could not persist VPN activity."); }
    }
    private sealed class ActivityData
    {
        public List<LogEntry> Logs { get; set; } = new();
        public List<ConnectionRecord> History { get; set; } = new();
    }
}

internal sealed class SecretRedactor
{
    private readonly List<string> secrets = new();
    internal SecretRedactor(string config)
    {
        try
        {
            void Read(JsonNode? node)
            {
                if (node is JsonObject obj)
                    foreach (var pair in obj)
                    {
                        if (pair.Key.ToLowerInvariant() is "id" or "password" or "pass" or "auth" or "publickey" or "privatekey" or "shortid" or "servicename" or "path" or "spiderx" or "authorization" or "token" && pair.Value is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 3)
                            secrets.Add(text);
                        Read(pair.Value);
                    }
                else if (node is JsonArray array) foreach (var item in array) Read(item);
            }
            Read(JsonNode.Parse(config));
        }
        catch (JsonException)
        {
            if (Uri.TryCreate(config, UriKind.Absolute, out var uri))
            {
                var credentials = Uri.UnescapeDataString(uri.UserInfo);
                if (!credentials.Contains(':') && uri.Scheme == "ss")
                {
                    try
                    {
                        var base64 = credentials.Replace('-', '+').Replace('_', '/');
                        credentials = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=')));
                    }
                    catch (FormatException) { }
                }
                if (credentials.Length > 3) secrets.Add(credentials);
                foreach (var part in credentials.Split(':')) if (part.Length > 3) secrets.Add(part);
            }
        }
    }
    internal string Clean(string text)
    {
        foreach (var secret in secrets.OrderByDescending(s => s.Length)) text = text.Replace(secret, "[скрыто]", StringComparison.Ordinal);
        return Generic(text);
    }
    internal static string Generic(string text)
    {
        text = Regex.Replace(text, @"\x1B\[[0-?]*[ -/]*[@-~]", "");
        text = Regex.Replace(text, @"(?i)\b(?:https?|vless|vmess|ss|trojan|socks|hy2|hysteria2|hysteria)://\S+", "[ссылка скрыта]");
        text = Regex.Replace(text, @"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[ключ скрыт]");
        return text.Length > 600 ? text[..600] + "…" : text;
    }
}
