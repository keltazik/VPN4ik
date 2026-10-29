using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VPNyan;

internal sealed class SettingsBackupData
{
    public int Version { get; set; }=1;
    public DateTime CreatedUtc { get; set; }=DateTime.UtcNow;
    public AppSettings? Settings { get; set; }
    public List<Subscription>? Subscriptions { get; set; }
    public Dictionary<string,string>? WireGuardFiles { get; set; }
    public RoutingPreset? Routing { get; set; }
    public List<RoutingPreset>? RoutingProfiles { get; set; }
}

/// <summary>Portable authenticated encryption. Does not export Windows DPAPI or device-specific paths.</summary>
internal static class SettingsBackup
{
    private static readonly byte[] Magic=Encoding.ASCII.GetBytes("VPN4IK-BACKUP-1\n");
    internal const int MaxBytes=24*1024*1024;
    private const int Iterations=600_000;
    internal static byte[] Encrypt(SettingsBackupData data,string password)
    {
        if(password.Length<8 || password.Length>1024) throw new InvalidDataException("Пароль должен содержать от 8 до 1024 символов.");
        var plain=JsonSerializer.SerializeToUtf8Bytes(data);
        if(plain.Length>MaxBytes) throw new InvalidDataException("Резервная копия слишком большая.");
        var salt=RandomNumberGenerator.GetBytes(16); var nonce=RandomNumberGenerator.GetBytes(12);
        var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,Iterations,HashAlgorithmName.SHA256,32);
        var result=new byte[Magic.Length+16+12+16+plain.Length];
        Magic.CopyTo(result,0); salt.CopyTo(result,Magic.Length); nonce.CopyTo(result,Magic.Length+16);
        try
        {
            using var aes=new AesGcm(key,16);
            aes.Encrypt(nonce,plain,result.AsSpan(Magic.Length+44),result.AsSpan(Magic.Length+28,16),result.AsSpan(0,Magic.Length+28));
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plain); }
    }
    internal static SettingsBackupData Decrypt(byte[] file,string password)
    {
        if(file.Length<Magic.Length+44 || file.Length>MaxBytes+Magic.Length+44 || !file.AsSpan(0,Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("Это не поддерживаемая резервная копия VPN4ik.");
        if(password.Length is < 8 or > 1024) throw new InvalidDataException("Неверный пароль или повреждённая копия.");
        var key=Rfc2898DeriveBytes.Pbkdf2(password,file.AsSpan(Magic.Length,16),Iterations,HashAlgorithmName.SHA256,32);
        var plain=new byte[file.Length-Magic.Length-44];
        try
        {
            using var aes=new AesGcm(key,16);
            aes.Decrypt(file.AsSpan(Magic.Length+16,12),file.AsSpan(Magic.Length+44),file.AsSpan(Magic.Length+28,16),plain,file.AsSpan(0,Magic.Length+28));
            var result=JsonSerializer.Deserialize<SettingsBackupData>(plain)??throw new InvalidDataException("Копия пуста.");
            Validate(result); return result;
        }
        catch(CryptographicException) { throw new InvalidDataException("Неверный пароль или повреждённая копия."); }
        catch(JsonException) { throw new InvalidDataException("Повреждена структура резервной копии."); }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plain); }
    }
    internal static void Validate(SettingsBackupData data)
    {
        if(data.Version!=1 || data.Settings==null && data.Subscriptions==null && data.WireGuardFiles==null && data.Routing==null)
            throw new InvalidDataException("В копии нет поддерживаемых данных.");
        if(data.Settings is {} settings)
        {
            settings.Normalize(); RoutingSettings.Validate(settings,false);
            if(settings.RoutingPresets.Count>100) throw new InvalidDataException("Слишком много профилей маршрутизации.");
            foreach(var preset in settings.RoutingPresets) ValidatePreset(preset);
        }
        if(data.Routing is {} routing) ValidatePreset(routing);
        if(data.RoutingProfiles is {} presets) { if(presets.Count>100) throw new InvalidDataException("Слишком много профилей маршрутизации."); foreach(var preset in presets) ValidatePreset(preset); }
        if(data.Subscriptions is {} sources)
        {
            if(sources.Count>1000 || sources.Any(s=>s==null || s.Profiles==null || s.Profiles.Count>10000)) throw new InvalidDataException("Слишком много серверов в копии.");
            var urls=new HashSet<string>(StringComparer.Ordinal);
            foreach(var source in sources)
            {
                if(string.IsNullOrEmpty(source.Url) || !urls.Add(source.Url) || source.DeletedProfileIds==null || source.DisplayName==null || source.DisplayName.Length>512)
                    throw new InvalidDataException("Повреждены данные подписок.");
                if(!source.Url.StartsWith("local:",StringComparison.Ordinal)) _=SubscriptionParser.ParseUrl(source.Url);
                var ids=new HashSet<string>(StringComparer.Ordinal);
                foreach(var profile in source.Profiles)
                {
                    if(profile==null || string.IsNullOrEmpty(profile.Id) || !ids.Add(profile.Id) || profile.Name==null || profile.Name.Length>512 || string.IsNullOrEmpty(profile.Configuration) || profile.Configuration.Length>SubscriptionParser.MaxBytes)
                        throw new InvalidDataException("Повреждены данные сервера.");
                    var parsed=SubscriptionParser.ParseDocument(profile.Configuration).Profiles;
                    if(!parsed.Any(p=>p.Protocol.Equals(profile.Protocol,StringComparison.OrdinalIgnoreCase) && p.Address==profile.Address && p.Port==profile.Port))
                        throw new InvalidDataException("Конфигурация сервера не совпадает с данными копии.");
                }
            }
        }
        if(data.WireGuardFiles is {} configs)
        {
            if(configs.Count>1000) throw new InvalidDataException("Слишком много конфигураций.");
            foreach(var item in configs)
            {
                if(item.Key!=Path.GetFileName(item.Key) || item.Key.IndexOfAny(Path.GetInvalidFileNameChars())>=0 || !item.Key.EndsWith(".conf",StringComparison.OrdinalIgnoreCase) || item.Value==null || item.Value.Length>SubscriptionParser.MaxBytes)
                    throw new InvalidDataException("Недопустимое имя конфигурации в копии.");
                _=MainWindow.ReadServerText(item.Value,item.Key);
            }
        }
    }
    internal static void ValidatePreset(RoutingPreset preset)
    {
        if(preset.Name==null || preset.Name.Length>80 || preset.Applications==null || preset.Domains==null || preset.Networks==null) throw new InvalidDataException("Повреждён профиль маршрутизации.");
        RoutingSettings.Validate(new AppSettings { SplitTunnelEnabled=preset.Enabled,SplitTunnelMode=preset.Mode,SplitApplications=preset.Applications,SplitDomains=preset.Domains,SplitNetworks=preset.Networks },false);
    }
    internal static RoutingPreset CaptureRouting(AppSettings settings,string name="") => new()
    { Name=name,Mode=settings.SplitTunnelMode,Enabled=settings.SplitTunnelEnabled,Applications=new(settings.SplitApplications),Domains=new(settings.SplitDomains),Networks=new(settings.SplitNetworks) };

    // Roll back all managed files on a failed write, including files that did not exist before.
    internal static void ApplyFiles(IReadOnlyDictionary<string,byte[]?> changes,Action<int>? afterWrite=null)
    {
        var before=changes.Keys.ToDictionary(path=>path,path=>File.Exists(path)?File.ReadAllBytes(path):null,StringComparer.OrdinalIgnoreCase);
        var written=new List<string>();
        try
        {
            foreach(var item in changes) { written.Add(item.Key); Write(item.Key,item.Value); afterWrite?.Invoke(written.Count); }
        }
        catch(Exception original)
        {
            var failures=new List<Exception>();
            foreach(var path in written.AsEnumerable().Reverse()) try { Write(path,before[path]); } catch(Exception ex) { failures.Add(ex); }
            if(failures.Count>0) throw new AggregateException("Не удалось полностью восстановить прежние файлы.",failures.Prepend(original));
            throw;
        }
    }
    private static void Write(string path,byte[]? bytes)
    {
        if(bytes==null) { if(File.Exists(path)) File.Delete(path); return; }
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var stage=path+".restore-"+Guid.NewGuid().ToString("N");
        try { File.WriteAllBytes(stage,bytes); File.Move(stage,path,true); } finally { if(File.Exists(stage)) File.Delete(stage); }
    }
}
