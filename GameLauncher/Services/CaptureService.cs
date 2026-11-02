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

        public static bool IsRecording { get { lock (Gate) return _starting || _recorder is { HasExited: false }; } }

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

        private static bool _starting;

        /// <summary>Starts recording the desktop to the game's media folder (same place as screenshots).
        /// Downloads ffmpeg first when missing. Returns false if already recording/starting or unsupported.</summary>
        public static bool StartRecording(string platform, string game)
        {
            if (!OperatingSystem.IsWindows()) return false;
            lock (Gate)
            {
                if (_starting || _recorder is { HasExited: false }) return false;
                _starting = true;
            }
            _ = System.Threading.Tasks.Task.Run(async () =>
            {
                try
                {
                    string? ffmpeg = StreamHostService.FindFfmpeg();
                    if (ffmpeg == null)
                    {
                        await StreamHostService.EnsureFfmpegAsync();
                        ffmpeg = StreamHostService.FindFfmpeg();
                    }
                    if (ffmpeg == null) { DevLogService.Log("[Capture] record failed: ffmpeg unavailable"); return; }

                    string path = NewFile(platform, game, "mp4");
                    // libx264 + yuv420p need even dimensions, otherwise ffmpeg exits immediately.
                    var p = Process.Start(new ProcessStartInfo
                    {
                        FileName = ffmpeg,
                        Arguments = $"-y -f gdigrab -framerate 30 -i desktop -vf \"scale=trunc(iw/2)*2:trunc(ih/2)*2\" -c:v libx264 -preset ultrafast -pix_fmt yuv420p -movflags +faststart \"{path}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardInput = true,
                        RedirectStandardError = true,
                    });
                    if (p == null) return;
                    // Drain stderr so ffmpeg never blocks on a full pipe.
                    p.ErrorDataReceived += (_, e) => { if (e.Data != null && e.Data.Contains("rror")) DevLogService.Log("[Capture] ffmpeg: " + e.Data); };
                    p.BeginErrorReadLine();
                    lock (Gate) _recorder = p;
                }
                catch (Exception ex) { DevLogService.Log($"[Capture] record failed: {ex.Message}"); }
                finally { lock (Gate) _starting = false; }
            });
            return true;
        }

        /// <summary>Types a key token from the Game OS on-screen keyboard into the foreground window (Windows only).</summary>
        public static void TypeIntoForeground(string token)
        {
            if (!OperatingSystem.IsWindows()) return;
            switch (token)
            {
                case "{BACKSPACE}": NativeMethods.SendSingleKey(0x08); break;
                case "{ENTER}": NativeMethods.SendSingleKey(NativeMethods.VK_RETURN); break;
                default: NativeMethods.SendText(token); break;
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
