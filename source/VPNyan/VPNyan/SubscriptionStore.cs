using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace VPNyan;

internal static class SubscriptionStore
{
    internal static void Save(string path, IReadOnlyList<Subscription> subscriptions)
    {
        var protectedData = Encode(subscriptions);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var pending = path + ".tmp";
        try
        {
            File.WriteAllBytes(pending, protectedData);
            File.Move(pending, path, true);
        }
        finally { if (File.Exists(pending)) File.Delete(pending); }
    }

    internal static byte[] Encode(IReadOnlyList<Subscription> subscriptions) =>
        ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(subscriptions),null,DataProtectionScope.CurrentUser);

    internal static List<Subscription> Load(string path)
    {
        if (!File.Exists(path)) return new();
        var data = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
        return JsonSerializer.Deserialize<List<Subscription>>(data) ?? new();
    }
}
