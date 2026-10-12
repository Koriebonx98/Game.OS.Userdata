using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Streams this PC's primary screen to a phone/tablet browser on the local network
    /// as MJPEG over HTTP. The launcher serves its own viewer page (so the browser never
    /// hits mixed-content blocking) and every request must carry the pairing PIN.
    /// Uses a raw <see cref="TcpListener"/> so no Windows URL-ACL/admin rights are needed.
    /// Capture is currently Windows-only (GDI).
    /// </summary>
    public static class StreamHostService
    {
        public const int DefaultPort = 47632;

        private static readonly string ConfigPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "GameOS", "stream.json");

        private static TcpListener? _listener;
        private static CancellationTokenSource? _cts;
        private static string _pin = "";
        private static int _port = DefaultPort;
        private static string _status = "Stream host not started.";

        public static string Pin => _pin;
        public static int Port => _port;
        public static bool IsRunning => _listener != null;
        public static string AddressText => _listener == null
            ? "Unavailable"
            : string.Join("  •  ", GetLanAddresses().Select(a => $"{a}:{_port}"));
        public static string StatusText => _listener != null
            ? "Ready — connect your iPhone or iPad to the same Wi-Fi network."
            : _status;

        /// <summary>Human-readable status for the settings page.</summary>
        public static string InfoText => _listener == null
            ? _status
            : $"Open the Game OS web app → Profile → Settings → PC game streaming, then enter: " +
              $"{string.Join(" or ", GetLanAddresses().Select(a => $"{a}:{_port}"))}  PIN {_pin}";

        public static void Start()
        {
            if (_listener != null) return;
            try
            {
                LoadOrCreateConfig();
                _cts = new CancellationTokenSource();
                _listener = new TcpListener(IPAddress.Any, _port);
                _listener.Start();
                _ = Task.Run(() => AcceptLoop(_cts.Token));
                DevLogService.Log($"[Stream] Listening on port {_port}. PIN {_pin}");
            }
            catch (Exception ex)
            {
                _listener = null;
                _status = "Stream host failed to start: " + ex.Message;
                DevLogService.Log("[Stream] " + _status);
            }
        }

        public static void Stop()
        {
            try { _cts?.Cancel(); _listener?.Stop(); } catch { }
            _listener = null;
        }

        private static void LoadOrCreateConfig()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(ConfigPath));
                    if (doc.RootElement.TryGetProperty("pin", out var p) && p.GetString() is { Length: >= 6 } pin)
                        _pin = pin;
                    if (doc.RootElement.TryGetProperty("port", out var pt) && pt.TryGetInt32(out var port) && port is > 1024 and < 65536)
                        _port = port;
                }
            }
            catch { }
            if (_pin.Length == 0)
            {
                _pin = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
                    File.WriteAllText(ConfigPath, JsonSerializer.Serialize(new { pin = _pin, port = _port }));
                }
                catch { }
            }
        }

        private static IEnumerable<string> GetLanAddresses()
        {
            var list = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                            list.Add(ua.Address.ToString());
                }
            }
            catch { }
            if (list.Count == 0) list.Add("<PC-IP>");
            return list;
        }

        private static async Task AcceptLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener!.AcceptTcpClientAsync(ct);
                    _ = Task.Run(() => HandleClient(client, ct));
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch { await Task.Delay(200, CancellationToken.None); }
            }
        }

        private static async Task HandleClient(TcpClient client, CancellationToken ct)
        {
            using (client)
            {
                try
                {
                    client.NoDelay = true;
                    var stream = client.GetStream();
                    stream.ReadTimeout = 5000;
                    var buf = new byte[4096];
                    int n = await stream.ReadAsync(buf, 0, buf.Length, ct);
                    if (n <= 0) return;
                    var first = Encoding.ASCII.GetString(buf, 0, n).Split('\n')[0].Trim();
                    var parts = first.Split(' ');
                    if (parts.Length < 2 || parts[0] != "GET") { await Respond(stream, 405, "text/plain", "Method not allowed"); return; }

                    var target = parts[1];
                    int q = target.IndexOf('?');
                    string path = q < 0 ? target : target[..q];
                    string query = q < 0 ? "" : target[(q + 1)..];
                    string pin = "";
                    foreach (var kv in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var s = kv.Split('=', 2);
                        if (s[0] == "pin" && s.Length == 2) pin = Uri.UnescapeDataString(s[1]);
                    }

                    if (path == "/ping")
                    {
                        await Respond(stream, 200, "text/plain", "gameos-stream");
                        return;
                    }
                    if (!PinMatches(pin))
                    {
                        await Respond(stream, 401, "text/html", "<h3>Wrong or missing PIN</h3>");
                        return;
                    }
                    if (path == "/" || path == "/index.html")
                        await Respond(stream, 200, "text/html; charset=utf-8", ViewerHtml(pin));
                    else if (path == "/stream")
                        await StreamMjpeg(stream, ct);
                    else
                        await Respond(stream, 404, "text/plain", "Not found");
                }
                catch { /* client disconnected */ }
            }
        }

        private static bool PinMatches(string pin) =>
            pin.Length == _pin.Length &&
            CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(pin), Encoding.UTF8.GetBytes(_pin));

        private static async Task Respond(NetworkStream s, int code, string type, string body)
        {
            var b = Encoding.UTF8.GetBytes(body);
            var h = Encoding.ASCII.GetBytes($"HTTP/1.1 {code} {(code == 200 ? "OK" : "Error")}\r\nContent-Type: {type}\r\nContent-Length: {b.Length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
            await s.WriteAsync(h);
            await s.WriteAsync(b);
        }

        private static async Task StreamMjpeg(NetworkStream s, CancellationToken ct)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                await Respond(s, 501, "text/plain", "Screen capture is only supported on Windows.");
                return;
            }
            await s.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"), ct);
            while (!ct.IsCancellationRequested)
            {
                var started = Environment.TickCount64;
                byte[] jpg = CaptureJpeg();
                await s.WriteAsync(Encoding.ASCII.GetBytes($"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {jpg.Length}\r\n\r\n"), ct);
                await s.WriteAsync(jpg, ct);
                await s.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
                int wait = 50 - (int)(Environment.TickCount64 - started); // ~20 fps cap
                if (wait > 0) await Task.Delay(wait, ct);
            }
        }

        [SupportedOSPlatform("windows")]
        private static byte[] CaptureJpegWin()
        {
            int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
            using var full = new Bitmap(w, h, PixelFormat.Format24bppRgb);
            using (var g = Graphics.FromImage(full))
                g.CopyFromScreen(0, 0, 0, 0, new Size(w, h));
            // Downscale to max 1280 wide to keep Wi-Fi bandwidth reasonable.
            int tw = Math.Min(w, 1280), th = (int)((long)h * tw / w);
            using var small = new Bitmap(tw, th, PixelFormat.Format24bppRgb);
            using (var g = Graphics.FromImage(small))
                g.DrawImage(full, 0, 0, tw, th);
            var codec = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
            using var ep = new EncoderParameters(1);
            ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 60L);
            using var ms = new MemoryStream();
            small.Save(ms, codec, ep);
            return ms.ToArray();
        }

        private static byte[] CaptureJpeg() =>
            OperatingSystem.IsWindows() ? CaptureJpegWin() : throw new PlatformNotSupportedException();

        [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);

        private static string ViewerHtml(string pin) => @"<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'>
<meta name='apple-mobile-web-app-capable' content='yes'><title>Game OS Stream</title>
<style>html,body{margin:0;height:100%;background:#000;color:#fff;font-family:-apple-system,sans-serif}
img{width:100%;height:100%;object-fit:contain;display:block}
a{position:fixed;top:max(8px,env(safe-area-inset-top));left:8px;color:#fff;background:rgba(0,0,0,.6);padding:6px 12px;border-radius:14px;text-decoration:none;font-size:14px}</style></head>
<body><a href='javascript:history.back()'>‹ Back</a><img id='s' alt='Connecting…'>
<script>var s=document.getElementById('s');function go(){s.src='/stream?pin=" + Uri.EscapeDataString(pin) + @"&t='+Date.now();}
s.onerror=function(){setTimeout(go,1500)};go();</script></body></html>";
    }
}
