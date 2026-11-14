using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using GameLauncher.Services;

if (args.Length == 1 && args[0] == "--wait")
{
    await Task.Delay(TimeSpan.FromSeconds(30));
    return;
}
if (args.Length == 1 && args[0] == "--worker")
{
    await PlaytimeWatchdog.RunAsync();
    return;
}

var dir = Path.Combine(Path.GetTempPath(), "gameos-watchdog-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dir);
try
{
    await TestTakeover(dir, HttpStatusCode.OK);
    await TestTakeover(dir, HttpStatusCode.InternalServerError);
    await TestNormalCompletion(dir);
    await TestDetection(dir, snapshot: false);
    await TestDetection(dir, snapshot: true);
    Console.WriteLine("Watchdog tests passed.");
}
finally
{
    Directory.Delete(dir, true);
}

static Process Child(string mode = "--wait")
{
    var exe = Environment.ProcessPath!;
    var info = new ProcessStartInfo(exe)
    {
        UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = mode == "--worker"
    };
    if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        info.ArgumentList.Add(Assembly.GetEntryAssembly()!.Location);
    info.ArgumentList.Add(mode);
    return Process.Start(info)!;
}

static async Task TestTakeover(string dir, HttpStatusCode responseCode)
{
    using var parent = Child();
    using var game = Child();
    using var port = new TcpListener(IPAddress.Loopback, 0);
    port.Start();
    int number = ((IPEndPoint)port.LocalEndpoint).Port;
    port.Stop();
    using var listener = new HttpListener();
    listener.Prefixes.Add($"http://127.0.0.1:{number}/");
    listener.Start();
    var journal = Path.Combine(dir, Guid.NewGuid() + ".json");
    var request = new PlaytimeWatchdog.Request
    {
        ParentId = parent.Id, ParentStartTicks = parent.StartTime.ToUniversalTime().Ticks,
        GameId = game.Id, GameStartTicks = game.StartTime.ToUniversalTime().Ticks,
        StartedAt = DateTime.UtcNow.AddMinutes(-5).ToString("o"),
        Platform = "PC", Title = "Test game", BaseMinutes = 42,
        JournalPath = journal, SessionsPath = Path.Combine(dir, "sessions.json"),
        BackendUrl = $"http://127.0.0.1:{number}", Token = "test-token"
    };
    using var worker = Child("--worker");
    await worker.StandardInput.WriteLineAsync(JsonSerializer.Serialize(request));
    worker.StandardInput.Close();
    parent.Kill();
    await parent.WaitForExitAsync();
    game.Kill();
    await game.WaitForExitAsync();
    for (int i = 0; i < (responseCode == HttpStatusCode.OK ? 1 : 3); i++)
    {
        var context = await listener.GetContextAsync().WaitAsync(TimeSpan.FromSeconds(25));
        using var reader = new StreamReader(context.Request.InputStream);
        using var payload = JsonDocument.Parse(await reader.ReadToEndAsync());
        Check(context.Request.Headers["Authorization"] == "Bearer test-token", "missing authentication");
        Check(payload.RootElement.GetProperty("playtimeMinutes").GetInt32() >= 47, "incorrect total");
        context.Response.StatusCode = (int)responseCode;
        context.Response.Close();
    }
    await worker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
    Check(worker.ExitCode == 0, "worker failed");
    Check(File.Exists(journal), "journal lost after sync attempt");
    Check(!File.ReadAllText(journal).Contains("test-token", StringComparison.Ordinal), "token persisted");
}

static async Task TestNormalCompletion(string dir)
{
    using var parent = Process.GetCurrentProcess();
    using var game = Child();
    var started = DateTime.UtcNow.ToString("o");
    var sessions = Path.Combine(dir, "sessions.json");
    await File.WriteAllTextAsync(sessions, JsonSerializer.Serialize(new[]
    {
        new { startedAt = started, title = "Test game", platform = "PC", isCheckpoint = false }
    }));
    var journal = Path.Combine(dir, Guid.NewGuid() + ".json");
    var request = new PlaytimeWatchdog.Request
    {
        ParentId = parent.Id, ParentStartTicks = parent.StartTime.ToUniversalTime().Ticks,
        GameId = game.Id, GameStartTicks = game.StartTime.ToUniversalTime().Ticks,
        StartedAt = started, Platform = "PC", Title = "Test game",
        JournalPath = journal, SessionsPath = sessions
    };
    Console.SetIn(new StringReader(JsonSerializer.Serialize(request)));
    var worker = PlaytimeWatchdog.RunAsync();
    game.Kill();
    await game.WaitForExitAsync();
    await worker.WaitAsync(TimeSpan.FromSeconds(15));
    Check(!File.Exists(journal), "normal completion produced a duplicate journal");
}

static async Task TestDetection(string dir, bool snapshot)
{
    using var parent = Child();
    using var game = Child();
    var journal = Path.Combine(dir, Guid.NewGuid() + ".json");
    var request = new PlaytimeWatchdog.Request
    {
        ParentId = parent.Id, ParentStartTicks = parent.StartTime.ToUniversalTime().Ticks,
        GameId = game.Id, GameStartTicks = game.StartTime.ToUniversalTime().Ticks,
        StartedAt = DateTime.UtcNow.AddMinutes(-2).ToString("o"),
        Platform = "PC", Title = game.ProcessName,
        Snapshot = snapshot, LaunchTarget = game.ProcessName,
        BaselinePids = Array.ConvertAll(Process.GetProcesses(), p =>
        {
            using (p) return p.Id == game.Id ? -1 : p.Id;
        }),
        GameFolder = snapshot ? "" : Path.GetDirectoryName(game.MainModule!.FileName)!,
        JournalPath = journal, SessionsPath = Path.Combine(dir, "no-sessions.json")
    };
    Console.SetIn(new StringReader(JsonSerializer.Serialize(request)));
    var worker = PlaytimeWatchdog.RunAsync();
    parent.Kill();
    await parent.WaitForExitAsync();
    await Task.Delay(TimeSpan.FromSeconds(3));
    game.Kill();
    await game.WaitForExitAsync();
    await worker.WaitAsync(TimeSpan.FromSeconds(15));
    Check(File.Exists(journal), snapshot ? "snapshot game was not recovered" : "folder game was not recovered");
}

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

namespace GameLauncher.Services
{
    public static class DevLogService
    {
        public static void Log(string message) => Console.Error.WriteLine(message);
    }
}
