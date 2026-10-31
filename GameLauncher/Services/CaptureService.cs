using System;
using System.Diagnostics;
using System.IO;

namespace GameLauncher.Services
{
    /// <summary>
    /// Screenshots and screen recordings of the running game, saved to
    /// <c>{MediaLocation}/Games/{Platform}/{Game}/</c> (MediaLocation defaults to <c>Data/Media</c>).
    /// Screenshots use System.Drawing; recordings use ffmpeg (gdigrab), downloaded on demand.
    /// </summary>
    public static class CaptureService
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);

        private static Process? _recorder;
        private static readonly object Gate = new();

        public static bool IsRecording { get { lock (Gate) return _recorder is { HasExited: false }; } }

        public static string GameFolder(string platform, string game)
        {
            string root = AppSettingsService.Load().MediaLocation;
            if (string.IsNullOrWhiteSpace(root)) root = Path.Combine(UserDataService.DataRoot, "Media");
            return Path.Combine(root, "Games",
                UserDataService.SanitiseFolderName(string.IsNullOrWhiteSpace(platform) ? "PC" : platform.Trim()),
                UserDataService.SanitiseFolderName(game.Trim()));
        }

        private static string NewFile(string platform, string game, string ext)
        {
            string dir = GameFolder(platform, game);
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, $"{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.{ext}");
        }

        /// <summary>Captures the primary screen. Returns the saved path, or null on failure / unsupported OS.</summary>
        public static string? TakeScreenshot(string platform, string game)
        {
            if (!OperatingSystem.IsWindows()) return null;
            try
            {
                string path = NewFile(platform, game, "png");
                int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
                using var bmp = new System.Drawing.Bitmap(w, h);
                using (var g = System.Drawing.Graphics.FromImage(bmp))
                    g.CopyFromScreen(0, 0, 0, 0, new System.Drawing.Size(w, h));
                bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
                return path;
            }
            catch (Exception ex) { DevLogService.Log($"[Capture] screenshot failed: {ex.Message}"); return null; }
        }

        /// <summary>Starts recording the desktop. Returns false if already recording or ffmpeg is unavailable.</summary>
        public static bool StartRecording(string platform, string game)
        {
            if (!OperatingSystem.IsWindows()) return false;
            lock (Gate)
            {
                if (_recorder is { HasExited: false }) return false;
                string? ffmpeg = StreamHostService.FindFfmpeg();
                if (ffmpeg == null) { StreamHostService.EnsureFfmpegAsync(); return false; }
                try
                {
                    string path = NewFile(platform, game, "mp4");
                    _recorder = Process.Start(new ProcessStartInfo
                    {
                        FileName = ffmpeg,
                        Arguments = $"-y -f gdigrab -framerate 30 -i desktop -c:v libx264 -preset ultrafast -pix_fmt yuv420p \"{path}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardInput = true,
                    });
                    return _recorder != null;
                }
                catch (Exception ex) { DevLogService.Log($"[Capture] record failed: {ex.Message}"); return false; }
            }
        }

        public static void StopRecording()
        {
            lock (Gate)
            {
                try
                {
                    if (_recorder is { HasExited: false })
                    {
                        _recorder.StandardInput.Write("q"); // lets ffmpeg finalise the mp4
                        _recorder.StandardInput.Flush();
                        if (!_recorder.WaitForExit(5000)) _recorder.Kill();
                    }
                }
                catch (Exception ex) { DevLogService.Log($"[Capture] stop failed: {ex.Message}"); }
                finally { _recorder = null; }
            }
        }
    }
}
