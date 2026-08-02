using System;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace GameOS.Updater;

/// <summary>
/// Full-screen update window.
/// Extracts the downloaded launcher zip over the target directory, updates
/// Version.json, relaunches Game.OS (optionally with --username for auto-login),
/// then closes itself.
/// </summary>
public partial class UpdaterWindow : Window
{
    private readonly string? _zipPath;
    private readonly string? _targetDir;
    private readonly string? _launcherPath;
    private readonly string? _username;

    private TextBlock? _statusText;
    private ProgressBar? _progressBar;
    private TextBlock? _progressLabel;
    private TextBlock? _versionLabel;

    public UpdaterWindow() : this(null, null, null, null) { }

    public UpdaterWindow(string? zipPath, string? targetDir, string? launcherPath, string? username)
    {
        _zipPath      = zipPath;
        _targetDir    = targetDir;
        _launcherPath = launcherPath;
        _username     = username;

        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);

        _statusText    = this.FindControl<TextBlock>("StatusText");
        _progressBar   = this.FindControl<ProgressBar>("ProgressBar");
        _progressLabel = this.FindControl<TextBlock>("ProgressLabel");
        _versionLabel  = this.FindControl<TextBlock>("VersionLabel");

        Opened += OnOpened;
    }

    private void OnOpened(object? sender, EventArgs e)
    {
        _ = RunUpdateAsync();
    }

    private async Task RunUpdateAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_zipPath) || !File.Exists(_zipPath))
            {
                SetStatus("No update file found. Nothing to do.", 0);
                await Task.Delay(3000);
                Close();
                return;
            }

            if (string.IsNullOrEmpty(_targetDir) || !Directory.Exists(_targetDir))
            {
                SetStatus("Target directory not found.", 0);
                await Task.Delay(3000);
                Close();
                return;
            }

            // ── Step 1: Extract zip ────────────────────────────────────────
            SetStatus("Extracting update…", 0);
            SetVersion($"Installing from: {Path.GetFileName(_zipPath)}");

            await Task.Run(() => ExtractZip(_zipPath, _targetDir)).ConfigureAwait(true);

            // ── Step 2: Write Version.json ─────────────────────────────────
            SetStatus("Updating version file…", 90);
            await Task.Run(() => WriteVersionJson(_targetDir)).ConfigureAwait(true);

            // ── Step 3: Relaunch Game.OS ───────────────────────────────────
            SetStatus("Relaunching Game.OS…", 95);
            await Task.Delay(600);

            if (!string.IsNullOrEmpty(_launcherPath) && File.Exists(_launcherPath))
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = _launcherPath,
                    UseShellExecute = true,
                };
                if (!string.IsNullOrWhiteSpace(_username))
                    psi.Arguments = $"--auto-login \"{_username}\"";

                System.Diagnostics.Process.Start(psi);
            }

            SetStatus("Done!", 100);
            await Task.Delay(1000);
        }
        catch (Exception ex)
        {
            SetStatus($"Error: {ex.Message}", 0);
            await Task.Delay(5000);
        }

        Close();
    }

    private void ExtractZip(string zipPath, string targetDir)
    {
        using var archive = ZipFile.OpenRead(zipPath);
        int total   = archive.Entries.Count;
        int current = 0;

        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
            {
                current++;
                continue;
            }

            string destPath = Path.Combine(targetDir, entry.FullName);
            string? destFolder = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(destFolder))
                Directory.CreateDirectory(destFolder);

            // Skip overwriting the updater itself (it is currently running).
            if (string.Equals(Path.GetFileName(destPath), "GameOS.Updater.exe",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(destPath), "GameOS.Updater",
                    StringComparison.OrdinalIgnoreCase))
            {
                current++;
                continue;
            }

            try { entry.ExtractToFile(destPath, overwrite: true); }
            catch { /* best-effort — skip locked files */ }

            current++;
            int pct = total > 0 ? (int)(current / (double)total * 88) : 0;
            Dispatcher.UIThread.Post(() => SetProgress(pct));
        }
    }

    private static void WriteVersionJson(string targetDir)
    {
        try
        {
            // Try to read the version from the launcher assembly after extraction.
            string launcherExe = Path.Combine(targetDir, "GameLauncher.exe");
            if (!File.Exists(launcherExe))
                launcherExe = Path.Combine(targetDir, "GameLauncher");

            string version = "v0.0.0.0";
            if (File.Exists(launcherExe))
            {
                var fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(launcherExe);
                if (!string.IsNullOrWhiteSpace(fvi.ProductVersion))
                    version = fvi.ProductVersion.StartsWith("v", StringComparison.OrdinalIgnoreCase)
                        ? fvi.ProductVersion : $"v{fvi.ProductVersion}";
            }

            string jsonPath = Path.Combine(targetDir, "Version.json");
            var obj = new { version, channel = "stable", updatedAt = DateTime.UtcNow.ToString("O") };
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(obj,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* best-effort */ }
    }

    private void SetStatus(string text, int progress)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (_statusText   != null) _statusText.Text   = text;
            SetProgress(progress);
        });
    }

    private void SetProgress(int pct)
    {
        if (_progressBar   != null) _progressBar.Value   = pct;
        if (_progressLabel != null) _progressLabel.Text  = $"{pct}%";
    }

    private void SetVersion(string text)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (_versionLabel != null) _versionLabel.Text = text;
        });
    }
}
