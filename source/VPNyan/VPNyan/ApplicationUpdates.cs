using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace VPNyan;

internal sealed record ReleaseVersion(int Major, int Minor, int Patch, string[] Preview) : IComparable<ReleaseVersion>
{
    internal static ReleaseVersion? Parse(string text)
    {
        var match = Regex.Match(text, @"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$");
        if (!match.Success || !int.TryParse(match.Groups[1].Value, out var major) || !int.TryParse(match.Groups[2].Value, out var minor) || !int.TryParse(match.Groups[3].Value, out var patch)) return null;
        var preview = match.Groups[4].Success ? match.Groups[4].Value.Split('.') : Array.Empty<string>();
        if (preview.Any(part => part.All(char.IsAsciiDigit) && part.Length > 1 && part[0] == '0')) return null;
        return new(major, minor, patch, preview);
    }

    public int CompareTo(ReleaseVersion? other)
    {
        if (other == null) return 1;
        foreach (var pair in new[] { (Major, other.Major), (Minor, other.Minor), (Patch, other.Patch) })
        { var comparison = pair.Item1.CompareTo(pair.Item2); if (comparison != 0) return comparison; }
        if (Preview.Length == 0 || other.Preview.Length == 0) return (Preview.Length == 0 ? 1 : 0).CompareTo(other.Preview.Length == 0 ? 1 : 0);
        for (var index = 0; index < Math.Min(Preview.Length, other.Preview.Length); index++)
        {
            var a = Preview[index]; var b = other.Preview[index];
            var aNumeric = a.All(char.IsAsciiDigit); var bNumeric = b.All(char.IsAsciiDigit);
            var comparison = aNumeric && bNumeric ? (a.Length != b.Length ? a.Length.CompareTo(b.Length) : string.CompareOrdinal(a, b))
                : aNumeric != bNumeric ? (aNumeric ? -1 : 1) : string.CompareOrdinal(a, b);
            if (comparison != 0) return comparison;
        }
        return Preview.Length.CompareTo(other.Preview.Length);
    }
}

internal sealed record ApplicationRelease(string Version, Uri Page, Uri? Download, string Sha256, long Size)
{
    internal bool CanInstall => Download != null && Regex.IsMatch(Sha256, "^[a-fA-F0-9]{64}$") && Size is > 0 and <= ApplicationUpdates.MaxDownload;
}

internal sealed class ApplicationUpdates : IDisposable
{
    internal const long MaxDownload = 256L * 1024 * 1024;
    internal const string RepositoryPage = "https://github.com/keltazik/VPN4ik";
    internal const string ReleasesPage = RepositoryPage + "/releases";
    internal static string CurrentVersion => typeof(App).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";
    internal static string CacheRoot => Path.Combine(Path.GetTempPath(), "VPN4ik-updates");
    private readonly HttpClient client;

    internal ApplicationUpdates(HttpMessageHandler? handler = null)
    {
        client = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("VPN4ik/" + CurrentVersion);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2026-03-10");
    }

    internal async Task<ApplicationRelease?> CheckAsync(CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var response = await client.GetAsync("https://api.github.com/repos/keltazik/VPN4ik/releases?per_page=30", HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        response.EnsureSuccessStatusCode();
        using var data = new MemoryStream();
        await CopyLimitedAsync(await response.Content.ReadAsStreamAsync(timeout.Token), data, 2 * 1024 * 1024, timeout.Token);
        return SelectRelease(data.ToArray(), CurrentVersion);
    }

    internal static ApplicationRelease? SelectRelease(byte[] json, string installed)
    {
        var current = ReleaseVersion.Parse(installed) ?? throw new InvalidDataException("Не удалось определить версию приложения.");
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Некорректный ответ GitHub.");
        var candidates = new List<(ReleaseVersion Version, ApplicationRelease Release)>();
        foreach (var release in document.RootElement.EnumerateArray())
        {
            if (release.ValueKind != JsonValueKind.Object || !release.TryGetProperty("draft", out var draft) || draft.ValueKind != JsonValueKind.False ||
                !release.TryGetProperty("published_at", out var date) || date.ValueKind != JsonValueKind.String) continue;
            var tag = Text(release, "tag_name"); var version = ReleaseVersion.Parse(tag);
            if (version == null || version.CompareTo(current) <= 0) continue;
            var name = tag.StartsWith('v') ? tag[1..] : tag;
            var page = new Uri(ReleasesPage + "/tag/" + Uri.EscapeDataString(tag));
            ApplicationRelease candidate = new(name, page, null, "", 0);
            if (release.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                foreach (var asset in assets.EnumerateArray())
                {
                    if (Text(asset, "name") != $"VPN4ik-v{name}-windows-x64.zip" || Text(asset, "state") != "uploaded") continue;
                    var expected = $"https://github.com/keltazik/VPN4ik/releases/download/{Uri.EscapeDataString(tag)}/VPN4ik-v{name}-windows-x64.zip";
                    var digest = Text(asset, "digest");
                    if (Text(asset, "browser_download_url") == expected && asset.TryGetProperty("size", out var size) && size.ValueKind == JsonValueKind.Number && size.TryGetInt64(out var bytes))
                        candidate = candidate with { Download = new Uri(expected), Sha256 = digest.StartsWith("sha256:", StringComparison.Ordinal) ? digest[7..] : "", Size = bytes };
                }
            candidates.Add((version, candidate));
        }
        return candidates.OrderByDescending(item => item.Version).Select(item => item.Release).FirstOrDefault();
    }

    internal async Task<string> PrepareAsync(ApplicationRelease release, IProgress<string>? progress, CancellationToken token)
    {
        if (!release.CanInstall) throw new InvalidDataException("Для этого выпуска доступна загрузка через GitHub.");
        var work = Path.Combine(CacheRoot, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
        var archive = Path.Combine(work, "update.zip");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromMinutes(10));
        progress?.Report("Скачиваю обновление…");
        using (var response = await DownloadResponseAsync(release.Download!, timeout.Token))
        {
            if (response.Content.Headers.ContentLength is long length && length != release.Size) throw new InvalidDataException("Размер архива обновления не совпадает.");
            using var output = File.Create(archive);
            using var input = await response.Content.ReadAsStreamAsync(timeout.Token);
            await CopyLimitedAsync(input, output, release.Size, timeout.Token, (size) => progress?.Report($"Скачиваю обновление… {size * 100 / release.Size}%"));
            if (output.Length != release.Size) throw new InvalidDataException("Обновление скачано не полностью.");
        }
        progress?.Report("Проверяю архив…");
        await Task.Run(() => ExtractVerified(archive, Path.Combine(work, "payload"), release.Version, release.Sha256, timeout.Token), timeout.Token);
        var binaryVersion = FileVersionInfo.GetVersionInfo(Path.Combine(work, "payload", "VPNyan.exe")).ProductVersion?.Split('+')[0];
        if (binaryVersion != release.Version) throw new InvalidDataException("Версия программы в архиве не совпадает с выпуском.");
        await UpdateInstaller.VerifyStartupAsync(Path.Combine(work, "payload"), timeout.Token);
        return work;
    }

    private async Task<HttpResponseMessage> DownloadResponseAsync(Uri url, CancellationToken token)
    {
        for (var count = 0; count < 6; count++)
        {
            if (!TrustedDownloadHost(url)) throw new InvalidDataException("Неизвестный адрес загрузки обновления.");
            var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
            if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            {
                var location = response.Headers.Location; response.Dispose();
                if (location == null) throw new InvalidDataException("Некорректное перенаправление GitHub.");
                url = new Uri(url, location); continue;
            }
            if (!response.IsSuccessStatusCode) { response.Dispose(); throw new HttpRequestException("Не удалось скачать обновление."); }
            return response;
        }
        throw new InvalidDataException("Слишком много перенаправлений GitHub.");
    }

    internal static bool TrustedDownloadHost(Uri uri) => uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo == "" && uri.Host is "github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com";
    private static string Text(JsonElement item, string name) => item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
    private static async Task CopyLimitedAsync(Stream input, Stream output, long limit, CancellationToken token, Action<long>? progress = null)
    {
        using (input)
        {
            var buffer = new byte[81920]; long total = 0; var lastPercent = -1L;
            int read;
            while ((read = await input.ReadAsync(buffer, token)) > 0)
            {
                total += read; if (total > limit) throw new InvalidDataException("Превышен размер ответа обновления.");
                await output.WriteAsync(buffer.AsMemory(0, read), token);
                var percent = total * 100 / limit;
                if (percent != lastPercent) { progress?.Invoke(total); lastPercent = percent; }
            }
        }
    }

    internal static void ExtractVerified(string archive, string payload, string expectedVersion, string expectedHash, CancellationToken token = default)
    {
        using (var input = File.OpenRead(archive))
            if (!Convert.ToHexString(SHA256.HashData(input)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Контрольная сумма обновления не совпадает.");
        if (Directory.Exists(payload)) throw new InvalidDataException("Папка подготовки уже существует.");
        using var zip = ZipFile.OpenRead(archive);
        if (zip.Entries.Count > 256) throw new InvalidDataException("Слишком много файлов обновления.");
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase); long total = 0;
        foreach (var entry in zip.Entries)
        {
            token.ThrowIfCancellationRequested();
            var path = entry.FullName.Replace('\\', '/');
            var parts = path.TrimEnd('/').Split('/');
            if (parts.Length < 1 || parts[0] != "VPN4ik" || parts.Any(p => p is "" or "." or ".." || p.IndexOfAny(new[] { ':', '<', '>', '|', '?', '*', '\0' }) >= 0) ||
                ((entry.ExternalAttributes >> 16) & 0xf000) == 0xa000) throw new InvalidDataException("Недопустимый путь в обновлении.");
            if (path.EndsWith('/')) continue;
            var relative = string.Join('/', parts.Skip(1));
            if (!UpdateInstaller.AllowedFile(relative) || !files.Add(relative)) throw new InvalidDataException("Неизвестный или повторяющийся файл в обновлении.");
            total += entry.Length; if (entry.Length > MaxDownload || total > 800L * 1024 * 1024) throw new InvalidDataException("Архив обновления слишком большой.");
            var destination = Path.Combine(payload, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            using var source = entry.Open(); using var output = File.Create(destination);
            var buffer = new byte[81920]; long copied = 0; int read;
            while ((read = source.Read(buffer)) > 0)
            {
                token.ThrowIfCancellationRequested(); copied += read;
                if (copied > entry.Length) throw new InvalidDataException("Некорректный размер файла обновления.");
                output.Write(buffer, 0, read);
            }
        }
        foreach (var required in new[] { "VPNyan.exe", "BUILD-INFO.json", "Engine/xray.exe", "Engine/wintun.dll", "Engine/geoip.dat", "Engine/geosite.dat" })
            if (!files.Contains(required)) throw new InvalidDataException("В обновлении отсутствуют файлы приложения.");
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(payload, "BUILD-INFO.json")));
        var root = manifest.RootElement;
        if (Text(root, "Version") != expectedVersion || !root.TryGetProperty("DotNetBundled", out var bundled) || bundled.ValueKind != JsonValueKind.True ||
            !HashFile(Path.Combine(payload, "VPNyan.exe")).Equals(Text(root, "ExecutableSHA256"), StringComparison.OrdinalIgnoreCase) ||
            !HashFile(Path.Combine(payload, "Engine", "xray.exe")).Equals(Text(root, "XraySHA256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Данные сборки обновления не совпадают.");
    }

    internal static string HashFile(string path) { using var input = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(input)); }
    public void Dispose() => client.Dispose();
}
