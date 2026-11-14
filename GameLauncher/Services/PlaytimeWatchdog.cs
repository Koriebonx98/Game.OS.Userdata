using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace GameLauncher.Services;

/// <summary>Out-of-process fallback for sessions whose launcher exits before the game.</summary>
internal static class PlaytimeWatchdog
{
    internal sealed class Request
    {
        public int ParentId { get; set; }
        public long ParentStartTicks { get; set; }
        public int GameId { get; set; }
        public long GameStartTicks { get; set; }
        public string StartedAt { get; set; } = "";
        public string Platform { get; set; } = "";
        public string Title { get; set; } = "";
        public string JournalPath { get; set; } = "";
        public string SessionsPath { get; set; } = "";
        public string GameFolder { get; set; } = "";
        public bool Snapshot { get; set; }
        public string LaunchTarget { get; set; } = "";
        public int[] BaselinePids { get; set; } = Array.Empty<int>();
        public int BaseMinutes { get; set; }
        public string BackendUrl { get; set; } = "";
        public string Token { get; set; } = "";
    }

    internal sealed class Recovery
    {
        public string StartedAt { get; set; } = "";
        public string EndedAt { get; set; } = "";
        public string Platform { get; set; } = "";
        public string Title { get; set; } = "";
        public int Minutes { get; set; }
        public int TotalMinutes { get; set; }
    }

    internal static void Start(Process game, DateTime startedAt, string platform, string title,
        string dataDir, int baseMinutes, string? backendUrl, string? token, string? gameFolder = null)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var request = new Request
            {
                GameId = game.Id, GameStartTicks = game.StartTime.ToUniversalTime().Ticks,
                GameFolder = gameFolder ?? ""
            };
            StartWorker(request, startedAt, platform, title, dataDir, baseMinutes, backendUrl, token);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Playtime] Could not start watchdog: {ex.Message}");
            DevLogService.Log($"[Playtime] Could not start watchdog: {ex.Message}");
        }
    }

    internal static void StartSnapshot(DateTime startedAt, string platform, string title,
        string dataDir, int baseMinutes, string? backendUrl, string? token, string launchTarget,
        IReadOnlyCollection<int> baselinePids)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            StartWorker(new Request { Snapshot = true, LaunchTarget = launchTarget, BaselinePids = baselinePids.ToArray() },
                startedAt, platform, title, dataDir, baseMinutes, backendUrl, token);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Playtime] Could not start watchdog: {ex.Message}");
            DevLogService.Log($"[Playtime] Could not start watchdog: {ex.Message}");
        }
    }

    private static void StartWorker(Request request, DateTime startedAt, string platform, string title,
        string dataDir, int baseMinutes, string? backendUrl, string? token)
    {
        using var parent = Process.GetCurrentProcess();
        request.ParentId = parent.Id;
        request.ParentStartTicks = parent.StartTime.ToUniversalTime().Ticks;
        request.StartedAt = startedAt.ToString("o");
        request.Platform = platform;
        request.Title = title;
        request.JournalPath = Path.Combine(dataDir, "watchdog", Guid.NewGuid().ToString("N") + ".json");
        request.SessionsPath = Path.Combine(dataDir, "sessions.json");
        request.BaseMinutes = baseMinutes;
        request.BackendUrl = backendUrl ?? "";
        request.Token = token ?? "";
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Launcher executable is unavailable.");
        var info = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(exe), "dotnet", StringComparison.OrdinalIgnoreCase))
            info.ArgumentList.Add(Assembly.GetEntryAssembly()!.Location);
        info.ArgumentList.Add("--playtime-watchdog");
        using var worker = Process.Start(info) ?? throw new InvalidOperationException("Could not start playtime watchdog.");
        worker.StandardInput.WriteLine(JsonSerializer.Serialize(request));
        worker.StandardInput.Close();
    }

    internal static async Task RunAsync()
    {
        Request? request = null;
        try
        {
            request = JsonSerializer.Deserialize<Request>(await Console.In.ReadLineAsync() ?? "");
            if (request == null || (!request.Snapshot && request.GameId <= 0) || request.ParentId <= 0
                || !DateTime.TryParse(request.StartedAt, out var started))
                throw new InvalidDataException("Invalid watchdog request.");

            await WaitForGameAsync(request);
            var ended = DateTime.UtcNow;

            // The launcher normally saves and syncs the session itself. If it is still
            // running, allow its exit handler to finish rather than writing a duplicate.
            for (int i = 0; i < 10 && IsAlive(request.ParentId, request.ParentStartTicks); i++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
                if (SessionAlreadySaved(request)) return;
            }
            var minutes = Math.Max(1, (int)(ended - started.ToUniversalTime()).TotalMinutes);
            var recovery = new Recovery
            {
                StartedAt = request.StartedAt, EndedAt = ended.ToString("o"),
                Platform = request.Platform, Title = request.Title, Minutes = minutes,
                TotalMinutes = request.BaseMinutes + minutes
            };
            Directory.CreateDirectory(Path.GetDirectoryName(request.JournalPath)!);
            var temp = request.JournalPath + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(recovery));
            File.Move(temp, request.JournalPath);

            if (!string.IsNullOrEmpty(request.BackendUrl) && !string.IsNullOrEmpty(request.Token))
            {
                for (int attempt = 0; ; attempt++)
                {
                    try
                    {
                        await SyncAsync(request.BackendUrl, request.Token, recovery);
                        break;
                    }
                    catch (HttpRequestException ex) when (attempt < 2 &&
                        (ex.StatusCode == null || (int)ex.StatusCode >= 500 || (int)ex.StatusCode == 429))
                    {
                        await Task.Delay(TimeSpan.FromSeconds(attempt == 0 ? 5 : 15));
                    }
                    catch (TaskCanceledException) when (attempt < 2)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(attempt == 0 ? 5 : 15));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Playtime watchdog] {ex.Message}");
            DevLogService.Log($"[Playtime watchdog] {ex.Message}");
            if (!string.IsNullOrEmpty(request?.JournalPath))
            {
                try
                {
                    var directory = Path.GetDirectoryName(request.JournalPath)!;
                    Directory.CreateDirectory(directory);
                    await File.AppendAllTextAsync(Path.Combine(directory, "errors.log"),
                        $"{DateTime.UtcNow:o} {ex.Message}{Environment.NewLine}");
                }
                catch (Exception logError) when (logError is IOException or UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"[Playtime watchdog] Could not write error log: {logError.Message}");
                }
            }
        }
    }

    internal static async Task SyncAsync(string backendUrl, string token, Recovery recovery)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.PatchAsJsonAsync(
            backendUrl.TrimEnd('/') + "/api/me/games/playtime",
            new { platform = recovery.Platform, title = recovery.Title,
                playtimeMinutes = recovery.TotalMinutes, lastPlayedAt = recovery.EndedAt });
        response.EnsureSuccessStatusCode();
    }

    private static async Task WaitForGameAsync(Request request)
    {
        if (request.Snapshot)
        {
            await WaitForSnapshotAsync(request);
            return;
        }
        if (string.IsNullOrEmpty(request.GameFolder))
        {
            while (IsAlive(request.GameId, request.GameStartTicks))
                await Task.Delay(TimeSpan.FromSeconds(2));
            return;
        }

        var folder = Path.GetFullPath(request.GameFolder).TrimEnd(Path.DirectorySeparatorChar)
                     + Path.DirectorySeparatorChar;
        var found = false;
        DateTime? launcherExited = null;
        while (true)
        {
            bool launcherAlive = IsAlive(request.GameId, request.GameStartTicks);
            if (!launcherAlive) launcherExited ??= DateTime.UtcNow;
            bool folderAlive = false;
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        if (process.Id == Environment.ProcessId || process.Id == request.ParentId) continue;
                        var path = process.MainModule?.FileName;
                        if (path != null && path.StartsWith(folder, StringComparison.OrdinalIgnoreCase))
                            folderAlive = true;
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch (NotSupportedException) { }
                }
            }
            found |= folderAlive;
            if (!launcherAlive && !folderAlive &&
                (found || DateTime.UtcNow - launcherExited >= TimeSpan.FromSeconds(30))) return;
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }

    private static async Task WaitForSnapshotAsync(Request request)
    {
        var baseline = new HashSet<int>(request.BaselinePids);
        var hints = BuildLaunchHints(request.LaunchTarget, request.Title);
        var tracked = new Dictionary<int, long>();
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (true)
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        if (process.Id == Environment.ProcessId || process.Id == request.ParentId
                            || baseline.Contains(process.Id) || tracked.ContainsKey(process.Id)
                            || process.HasExited || !IsCandidateProcess(process, hints)) continue;
                        tracked.Add(process.Id, process.StartTime.ToUniversalTime().Ticks);
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch (NotSupportedException) { }
                }
            }
            if (tracked.Count > 0 && !tracked.Any(p => IsAlive(p.Key, p.Value))) return;
            if (tracked.Count == 0 && DateTime.UtcNow >= deadline) return;
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }

    internal static string[] BuildLaunchHints(string launchTarget, string title)
    {
        var hints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in (launchTarget ?? "").Split(new[] { '\\', '/', ':', '!', '.', '-', '_', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            if (token.Length >= 3) hints.Add(token.ToLowerInvariant());
        foreach (var token in (title ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            if (token.Length >= 3) hints.Add(token.ToLowerInvariant());
        return hints.ToArray();
    }

    internal static bool IsCandidateProcess(Process process, string[] hints)
    {
        string name = process.ProcessName ?? "";
        if (string.IsNullOrWhiteSpace(name) ||
            name.Equals("GameLauncher", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("explorer", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("cmd", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("pwsh", StringComparison.OrdinalIgnoreCase)) return false;
        return hints.Any(h => name.Contains(h, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsAlive(int id, long startTicks)
    {
        try
        {
            using var process = Process.GetProcessById(id);
            return !process.HasExited && process.StartTime.ToUniversalTime().Ticks == startTicks;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private static bool SessionAlreadySaved(Request request)
    {
        try
        {
            if (!File.Exists(request.SessionsPath)) return false;
            using var document = JsonDocument.Parse(File.ReadAllText(request.SessionsPath));
            return document.RootElement.EnumerateArray().Any(s =>
                s.TryGetProperty("startedAt", out var start) && start.GetString() == request.StartedAt
                && s.TryGetProperty("title", out var title) && title.GetString() == request.Title
                && s.TryGetProperty("platform", out var platform) && platform.GetString() == request.Platform
                && (!s.TryGetProperty("isCheckpoint", out var checkpoint) || !checkpoint.GetBoolean()));
        }
        catch (IOException) { return false; }
        catch (JsonException) { return false; }
    }
}
