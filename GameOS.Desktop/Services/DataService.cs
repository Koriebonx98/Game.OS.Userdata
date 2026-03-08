using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace GameOS.Desktop.Services;

public class DataService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static readonly string BaseDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".gameos");

    public static string GetUserDataPath(string username) =>
        Path.Combine(BaseDir, "accounts", username.ToLowerInvariant());

    public static async Task<T?> ReadJsonAsync<T>(string path)
    {
        try
        {
            if (!File.Exists(path)) return default;
            var json = await File.ReadAllTextAsync(path);
            return JsonSerializer.Deserialize<T>(json, JsonOptions);
        }
        catch (Exception ex)
        {
#if DEBUG
            System.Diagnostics.Debug.WriteLine($"[DataService] ReadJsonAsync failed for '{path}': {ex.Message}");
#else
            _ = ex; // suppress unused variable warning in Release
#endif
            return default;
        }
    }

    public static async Task WriteJsonAsync<T>(string path, T data)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(data, JsonOptions);
        await File.WriteAllTextAsync(path, json);
    }

    public static int GetUserCount()
    {
        var accountsDir = Path.Combine(BaseDir, "accounts");
        if (!Directory.Exists(accountsDir)) return 0;
        try
        {
            return Directory.GetDirectories(accountsDir).Length;
        }
        catch
        {
            return 0;
        }
    }
}
