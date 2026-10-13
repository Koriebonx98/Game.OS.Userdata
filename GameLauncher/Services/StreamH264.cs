using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    public static partial class StreamHostService
    {
        private static string? _ffmpegPath;
        private static string? _encoder;
        private static readonly object EncoderLock = new();

        /// <summary>Codec string the viewer passes to Media Source Extensions (constrained baseline, level 4.2).</summary>
        private const string H264Codec = "avc1.42E02A";

        private static readonly string FfmpegDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "ffmpeg");
        private static int _ffmpegDownloadStarted;

        /// <summary>Downloads ffmpeg via the Xabe.FFmpeg.Downloader NuGet package (once, in the background) if none is found.</summary>
        public static void EnsureFfmpegAsync()
        {
            if (!OperatingSystem.IsWindows() || FindFfmpeg() != null) return;
            if (Interlocked.Exchange(ref _ffmpegDownloadStarted, 1) == 1) return;
            _ = Task.Run(async () =>
            {
                try
                {
                    Directory.CreateDirectory(FfmpegDir);
                    DevLogService.Log("[Stream] Downloading ffmpeg for H.264 streaming…");
                    await Xabe.FFmpeg.Downloader.FFmpegDownloader.GetLatestVersion(Xabe.FFmpeg.Downloader.FFmpegVersion.Official, FfmpegDir);
                    _ffmpegPath = null;
                    DevLogService.Log(FindFfmpeg() != null ? "[Stream] ffmpeg ready." : "[Stream] ffmpeg download finished but ffmpeg.exe not found.");
                }
                catch (Exception ex)
                {
                    DevLogService.Log("[Stream] ffmpeg download failed: " + ex.Message);
                    Interlocked.Exchange(ref _ffmpegDownloadStarted, 0);
                }
            });
        }

        private static string? FindFfmpeg()
        {
            if (_ffmpegPath != null) return _ffmpegPath.Length == 0 ? null : _ffmpegPath;
            string exe = OperatingSystem.IsWindows() ? "ffmpeg.exe" : "ffmpeg";
            var candidates = new List<string>
            {
                Path.Combine(AppContext.BaseDirectory, exe),
                Path.Combine(AppContext.BaseDirectory, "ffmpeg", exe),
                Path.Combine(FfmpegDir, exe),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", exe)
            };
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                candidates.Add(Path.Combine(dir.Trim('"'), exe));
            _ffmpegPath = "";
            foreach (var c in candidates)
            {
                try { if (File.Exists(c)) { _ffmpegPath = c; break; } } catch { }
            }
            return _ffmpegPath.Length == 0 ? null : _ffmpegPath;
        }

        private static string EncoderArgs(string enc, int bitrateKbps, int fps) => enc switch
        {
            "h264_nvenc" => $"-c:v h264_nvenc -preset p1 -tune ll -rc cbr -zerolatency 1 -profile:v baseline -bf 0 -b:v {bitrateKbps}k -maxrate {bitrateKbps}k -bufsize {Math.Max(bitrateKbps / fps, 1)}k -g {fps * 2}",
            "h264_qsv" => $"-c:v h264_qsv -preset veryfast -profile:v baseline -look_ahead 0 -bf 0 -b:v {bitrateKbps}k -maxrate {bitrateKbps}k -g {fps * 2}",
            "h264_amf" => $"-c:v h264_amf -usage ultralowlatency -profile:v constrained_baseline -bf 0 -rc cbr -b:v {bitrateKbps}k -g {fps * 2}",
            _ => $"-c:v libx264 -preset ultrafast -tune zerolatency -profile:v baseline -x264-params slices=1 -b:v {bitrateKbps}k -maxrate {bitrateKbps}k -bufsize {Math.Max(bitrateKbps / fps, 1)}k -g {fps * 2}"
        };

        /// <summary>Picks the first hardware H.264 encoder that works on this PC, else libx264.</summary>
        private static string PickEncoder(string ffmpeg)
        {
            lock (EncoderLock)
            {
                if (_encoder != null) return _encoder;
                foreach (var enc in new[] { "h264_nvenc", "h264_qsv", "h264_amf" })
                {
                    try
                    {
                        using var p = Process.Start(new ProcessStartInfo(ffmpeg,
                            $"-hide_banner -loglevel error -f lavfi -i color=s=256x256:d=0.2 -frames:v 1 -c:v {enc} -f null -")
                        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardError = true })!;
                        if (p.WaitForExit(6000) && p.ExitCode == 0) return _encoder = enc;
                        if (!p.HasExited) p.Kill();
                    }
                    catch { }
                }
                return _encoder = "libx264";
            }
        }

        public static bool IsH264Available => OperatingSystem.IsWindows() && FindFfmpeg() != null;

        private static int BitrateKbps(int w, int h, int fps, int quality)
        {
            double bpp = quality switch { <= 35 => 0.06, <= 50 => 0.08, <= 60 => 0.10, <= 75 => 0.14, _ => 0.20 };
            return (int)Math.Clamp(w * (double)h * fps * bpp / 1000, 1500, 60000);
        }

        /// <summary>
        /// Hardware-accelerated H.264 (fragmented MP4 over WebSocket) for Media Source Extensions in the viewer.
        /// Sends a JSON text message first ({codec} or {error}), then binary fMP4 chunks (one per frame).
        /// </summary>
        private static async Task StreamH264(TcpClient client, string request, CancellationToken ct, int fps, int maxWidth, int quality)
        {
            var net = client.GetStream();
            string? key = request.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Split(':', 2))
                .Where(p => p.Length == 2 && p[0].Trim().Equals("Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase))
                .Select(p => p[1].Trim()).FirstOrDefault();
            if (string.IsNullOrEmpty(key)) { await Respond(net, 400, "text/plain", "WebSocket upgrade required."); return; }

            string accept = Convert.ToBase64String(System.Security.Cryptography.SHA1.HashData(
                Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            await net.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                $"Sec-WebSocket-Accept: {accept}\r\n\r\n"), ct);

            string? ffmpeg = OperatingSystem.IsWindows() ? FindFfmpeg() : null;
            if (ffmpeg == null) EnsureFfmpegAsync();
            if (ffmpeg == null)
            {
                await SendWebSocketFrame(net, 0x1, Encoding.UTF8.GetBytes("{\"error\":\"H.264 is preparing (ffmpeg is downloading); using MJPEG for now.\"}"), ct);
                return;
            }

            int sw = GetSystemMetrics(0), sh = GetSystemMetrics(1);
            int w = Math.Min(sw, maxWidth) & ~1, h = ((int)((long)sh * w / sw)) & ~1;
            string enc = PickEncoder(ffmpeg);
            string args = $"-hide_banner -loglevel error -fflags nobuffer -f gdigrab -framerate {fps} -draw_mouse 1 -i desktop " +
                          $"-vf scale={w}:{h},format=yuv420p {EncoderArgs(enc, BitrateKbps(w, h, fps, quality), fps)} " +
                          "-an -flush_packets 1 -f mp4 -movflags frag_every_frame+empty_moov+default_base_moof+omit_tfhd_offset pipe:1";

            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo(ffmpeg, args)
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true }
            };
            try
            {
                proc.Start();
                _ = proc.StandardError.ReadToEndAsync();
                DevLogService.Log($"[Stream] H.264 via {enc} {w}x{h}@{fps}");
                await SendWebSocketFrame(net, 0x1, JsonSerializer.SerializeToUtf8Bytes(new { codec = H264Codec, encoder = enc, width = w, height = h }), ct);

                var chunks = Channel.CreateUnbounded<byte[]>();
                var reader = Task.Run(async () =>
                {
                    var buf = new byte[65536];
                    var o = proc.StandardOutput.BaseStream;
                    try
                    {
                        int n;
                        while ((n = await o.ReadAsync(buf, ct)) > 0) chunks.Writer.TryWrite(buf.AsSpan(0, n).ToArray());
                    }
                    catch { }
                    finally { chunks.Writer.TryComplete(); }
                }, ct);

                // Coalesce reads into one WebSocket message per encoded frame: ffmpeg writes each frame
                // atomically, so a short idle gap marks the frame boundary.
                var cr = chunks.Reader;
                using var pending = new MemoryStream();
                while (await cr.WaitToReadAsync(ct))
                {
                    while (cr.TryRead(out var c)) pending.Write(c);
                    while (true)
                    {
                        var more = cr.WaitToReadAsync(ct).AsTask();
                        if (await Task.WhenAny(more, Task.Delay(3, ct)) != more) break;
                        if (!await more) break;
                        while (cr.TryRead(out var c)) pending.Write(c);
                    }
                    await SendWebSocketFrame(net, 0x2, pending.ToArray(), ct);
                    pending.SetLength(0);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (Exception ex)
            {
                try { await SendWebSocketFrame(net, 0x1, JsonSerializer.SerializeToUtf8Bytes(new { error = "H.264 failed: " + ex.Message }), CancellationToken.None); } catch { }
            }
            finally
            {
                try { if (!proc.HasExited) proc.Kill(true); } catch { }
            }
        }
    }
}
