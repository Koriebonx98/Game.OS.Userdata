using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services;

/// <summary>Converts PS1/PS2 disc images between CHD and ISO (PS1: BIN/CUE) using chdman.</summary>
public static class RomConvertService
{
    public static bool IsChd(string path) => path.EndsWith(".chd", StringComparison.OrdinalIgnoreCase);
    public static bool IsIso(string path) => path.EndsWith(".iso", StringComparison.OrdinalIgnoreCase);

    /// <summary>Finds chdman next to the launcher, in a Tools folder, or on the PATH.</summary>
    public static string? FindChdman()
    {
        string exe = OperatingSystem.IsWindows() ? "chdman.exe" : "chdman";
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, exe),
            Path.Combine(AppContext.BaseDirectory, "Tools", exe),
            Path.Combine(AppContext.BaseDirectory, "tools", exe),
        };
        foreach (var c in candidates) if (File.Exists(c)) return c;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            try { var p = Path.Combine(dir.Trim('"'), exe); if (File.Exists(p)) return p; } catch { }
        }
        return null;
    }

    /// <summary>CHD → ISO (PS2) or BIN/CUE (PS1). Returns the produced image path.</summary>
    public static async Task<(string? Output, string? Error)> ChdToIsoAsync(
        string chdPath, string outputFolder, bool isPs1, Action<string> log, CancellationToken ct)
    {
        var chdman = FindChdman();
        if (chdman == null) return (null, "chdman not found — put chdman.exe next to the launcher (or on PATH).");
        Directory.CreateDirectory(outputFolder);
        string name = Path.GetFileNameWithoutExtension(chdPath);
        string output;
        string[] args;
        if (isPs1)
        {
            output = Path.Combine(outputFolder, name + ".cue");
            args = new[] { "extractcd", "-i", chdPath, "-o", output, "-ob", Path.Combine(outputFolder, name + ".bin"), "-f" };
        }
        else
        {
            output = Path.Combine(outputFolder, name + ".iso");
            args = new[] { "extractdvd", "-i", chdPath, "-o", output, "-f" };
        }
        int rc = await RunAsync(chdman, args, log, ct);
        return rc == 0 && File.Exists(output) ? (output, null) : (null, "chdman failed to extract the CHD (see log).");
    }

    /// <summary>ISO (or PS1 CUE) → CHD next to the source. Returns the produced CHD path.</summary>
    public static async Task<(string? Output, string? Error)> ToChdAsync(
        string sourcePath, bool isPs1, Action<string> log, CancellationToken ct)
    {
        var chdman = FindChdman();
        if (chdman == null) return (null, "chdman not found — put chdman.exe next to the launcher (or on PATH).");
        string output = Path.ChangeExtension(sourcePath, ".chd");
        string verb = isPs1 || sourcePath.EndsWith(".cue", StringComparison.OrdinalIgnoreCase) ? "createcd" : "createdvd";
        int rc = await RunAsync(chdman, new[] { verb, "-i", sourcePath, "-o", output, "-f" }, log, ct);
        return rc == 0 && File.Exists(output) ? (output, null) : (null, "chdman failed to create the CHD (see log).");
    }

    private static async Task<int> RunAsync(string exe, string[] args, Action<string> log, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = new Process { StartInfo = psi };
        // chdman reports progress with carriage returns, so split on both
        void Pump(StreamReader r) => _ = Task.Run(async () =>
        {
            var sb = new StringBuilder();
            var buf = new char[256];
            int n;
            while ((n = await r.ReadAsync(buf, 0, buf.Length)) > 0)
                for (int i = 0; i < n; i++)
                {
                    if (buf[i] is '\r' or '\n')
                    {
                        if (sb.Length > 0) { log(sb.ToString().Trim()); sb.Clear(); }
                    }
                    else sb.Append(buf[i]);
                }
        });
        p.Start();
        Pump(p.StandardOutput);
        Pump(p.StandardError);
        using var reg = ct.Register(() => { try { p.Kill(true); } catch { } });
        await p.WaitForExitAsync(CancellationToken.None);
        ct.ThrowIfCancellationRequested();
        return p.ExitCode;
    }
}
