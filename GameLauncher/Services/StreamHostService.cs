using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
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
using System.Threading.Channels;
using NAudio.Wave;

namespace GameLauncher.Services
{
    /// <summary>
    /// Streams this PC's primary screen to a phone/tablet browser on the local network
    /// as MJPEG over HTTP. The launcher serves its own viewer page (so the browser never
    /// hits mixed-content blocking) and every request must carry the pairing PIN.
    /// Uses a raw <see cref="TcpListener"/> so no Windows URL-ACL/admin rights are needed.
    /// Capture is currently Windows-only (GDI).
    /// </summary>
    public static partial class StreamHostService
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
        private static readonly ConcurrentDictionary<Guid, AudioClient> AudioClients = new();
        private static readonly object AudioLock = new();
        private static WasapiLoopbackCapture? _audioCapture;
        private static int _frameRate = 20;
        private static int _maxWidth = 1280;
        private static int _jpegQuality = 60;
        private static bool _audioEnabled = true;

        public static string Pin => _pin;
        public static int Port => _port;
        public static bool IsRunning => _listener != null;
        public static string AddressText => _listener == null
            ? "Unavailable"
            : string.Join("  •  ", GetLanAddresses().Select(a => $"{a}:{_port}"));
        public static string StatusText => _listener != null
            ? "Ready — connect your iPhone or iPad to the same Wi-Fi network."
            : _status;
        public static int ClampFrameRate(int value) => value is 10 or 15 or 20 or 30 or 60 ? value : 20;
        public static int ClampMaxWidth(int value) => value is 640 or 854 or 1280 or 1920 ? value : 1280;
        public static int ClampJpegQuality(int value) => value is 35 or 50 or 60 or 75 or 90 ? value : 60;

        public static void Configure(int frameRate, int maxWidth, int jpegQuality, bool audioEnabled)
        {
            _frameRate = ClampFrameRate(frameRate);
            _maxWidth = ClampMaxWidth(maxWidth);
            _jpegQuality = ClampJpegQuality(jpegQuality);
            _audioEnabled = audioEnabled;
        }

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
                var settings = AppSettingsService.Load();
                Configure(settings.StreamFrameRate, settings.StreamMaxWidth, settings.StreamJpegQuality, settings.StreamAudioEnabled);
                _cts = new CancellationTokenSource();
                _listener = new TcpListener(IPAddress.Any, _port);
                _listener.Start();
                _ = Task.Run(() => AcceptLoop(_cts.Token));
                EnsureFfmpegAsync();
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
            if (_pin.Length == 0) RegeneratePin();
        }

        /// <summary>Creates a new random 6-digit PIN and persists it; existing viewers must re-enter it.</summary>
        public static string RegeneratePin()
        {
            _pin = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
                File.WriteAllText(ConfigPath, JsonSerializer.Serialize(new { pin = _pin, port = _port }));
            }
            catch { }
            return _pin;
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
                    var request = Encoding.ASCII.GetString(buf, 0, n);
                    var first = request.Split('\n')[0].Trim();
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
                    var qp = ParseQuery(query);
                    if (!PinMatches(pin))
                    {
                        await Respond(stream, 401, "text/html", "<h3>Wrong or missing PIN</h3>");
                        return;
                    }
                    if (path == "/" || path == "/index.html")
                        await Respond(stream, 200, "text/html; charset=utf-8", ViewerHtml(pin));
                    else if (path == "/speedtest")
                    {
                        int kb = qp.TryGetValue("kb", out var kbs) && int.TryParse(kbs, out var k) ? Math.Clamp(k, 1, 8192) : 1024;
                        await Respond(stream, 200, "application/octet-stream", new string('0', kb * 1024));
                    }
                    else if (path == "/stream")
                    {
                        int fps = qp.TryGetValue("fps", out var f) && int.TryParse(f, out var fv) ? ClampFrameRate(fv) : _frameRate;
                        int w = qp.TryGetValue("w", out var ws) && int.TryParse(ws, out var wv) ? ClampMaxWidth(wv) : _maxWidth;
                        int jq = qp.TryGetValue("q", out var qs) && int.TryParse(qs, out var qv) ? ClampJpegQuality(qv) : _jpegQuality;
                        await StreamMjpeg(stream, ct, fps, w, jq);
                    }
                    else if (path == "/video")
                    {
                        int fps = qp.TryGetValue("fps", out var f2) && int.TryParse(f2, out var fv2) ? ClampFrameRate(fv2) : _frameRate;
                        int w = qp.TryGetValue("w", out var ws2) && int.TryParse(ws2, out var wv2) ? ClampMaxWidth(wv2) : _maxWidth;
                        int jq = qp.TryGetValue("q", out var qs2) && int.TryParse(qs2, out var qv2) ? ClampJpegQuality(qv2) : _jpegQuality;
                        await StreamH264(client, request, ct, fps, w, jq);
                    }
                    else if (path == "/audio")
                        await StreamAudio(client, request, ct);
                    else
                        await Respond(stream, 404, "text/plain", "Not found");
                }
                catch { /* client disconnected */ }
            }
        }

        private static Dictionary<string, string> ParseQuery(string query)
        {
            var d = new Dictionary<string, string>();
            foreach (var kv in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var p = kv.Split('=', 2);
                if (p.Length == 2) d[p[0]] = Uri.UnescapeDataString(p[1]);
            }
            return d;
        }

        /// <summary>Rates a connection from measured throughput (Mbps) and latency (ms).</summary>
        public static string RateConnection(double mbps, double latencyMs) =>
            mbps >= 20 && latencyMs <= 40 ? "Good" :
            mbps >= 8 && latencyMs <= 100 ? "OK" : "Bad";

        /// <summary>Measures capture+encode speed with the current settings and rates whether this PC can sustain them.</summary>
        public static async Task<string> RunLocalTestAsync()
        {
            if (!OperatingSystem.IsWindows()) return "Connection test needs Windows screen capture.";
            return await Task.Run(() =>
            {
                const int frames = 10;
                long bytes = 0; var sw = System.Diagnostics.Stopwatch.StartNew();
                for (int i = 0; i < frames; i++) bytes += CaptureJpeg(_maxWidth, _jpegQuality).Length;
                double perFrameMs = sw.Elapsed.TotalMilliseconds / frames;
                double achievableFps = 1000 / Math.Max(1, perFrameMs);
                double neededMbps = bytes / (double)frames * 8 * _frameRate / 1_000_000;
                string rating = achievableFps >= _frameRate ? (neededMbps <= 20 ? "Good" : "OK") : "Bad";
                return $"{rating}: encode {perFrameMs:F0} ms/frame (~{achievableFps:F0} fps possible, target {_frameRate}). " +
                       $"Needs ~{neededMbps:F1} Mbps Wi-Fi. Test on iPhone/iPad from the stream page for real network speed.";
            });
        }

        private static bool PinMatches(string pin) =>
            pin.Length == _pin.Length &&
            CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(pin), Encoding.UTF8.GetBytes(_pin));

        private static async Task Respond(NetworkStream s, int code, string type, string body)
        {
            var b = Encoding.UTF8.GetBytes(body);
            var h = Encoding.ASCII.GetBytes($"HTTP/1.1 {code} {(code == 200 ? "OK" : "Error")}\r\nContent-Type: {type}\r\nContent-Length: {b.Length}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
            await s.WriteAsync(h);
            await s.WriteAsync(b);
        }

        private static async Task StreamMjpeg(NetworkStream s, CancellationToken ct, int frameRate, int maxWidth, int jpegQuality)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                await Respond(s, 501, "text/plain", "Screen capture is only supported on Windows.");
                return;
            }
            await s.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"), ct);
            while (!ct.IsCancellationRequested)
            {
                var started = Environment.TickCount64;
                byte[] jpg = CaptureJpeg(maxWidth, jpegQuality);
                await s.WriteAsync(Encoding.ASCII.GetBytes($"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {jpg.Length}\r\n\r\n"), ct);
                await s.WriteAsync(jpg, ct);
                await s.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
                int wait = 1000 / frameRate - (int)(Environment.TickCount64 - started);
                if (wait > 0) await Task.Delay(wait, ct);
            }
        }

        private static async Task StreamAudio(TcpClient client, string request, CancellationToken ct)
        {
            if (!_audioEnabled)
            {
                await Respond(client.GetStream(), 403, "text/plain", "Audio streaming is disabled in launcher settings.");
                return;
            }
            if (!OperatingSystem.IsWindows())
            {
                await Respond(client.GetStream(), 501, "text/plain", "Desktop audio capture is only supported on Windows.");
                return;
            }

            string? key = request.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split(':', 2))
                .Where(parts => parts.Length == 2 && parts[0].Trim().Equals("Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase))
                .Select(parts => parts[1].Trim())
                .FirstOrDefault();
            if (string.IsNullOrEmpty(key))
            {
                await Respond(client.GetStream(), 400, "text/plain", "WebSocket upgrade required.");
                return;
            }

            WasapiLoopbackCapture capture;
            try
            {
                lock (AudioLock)
                {
                    if (_audioCapture == null)
                    {
                        _audioCapture = new WasapiLoopbackCapture();
                        _audioCapture.DataAvailable += OnAudioDataAvailable;
                        _audioCapture.StartRecording();
                    }
                    capture = _audioCapture;
                }
            }
            catch (Exception ex)
            {
                await Respond(client.GetStream(), 503, "text/plain", "Could not capture desktop audio: " + ex.Message);
                return;
            }

            string accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(
                key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            byte[] response = Encoding.ASCII.GetBytes(
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
                $"Sec-WebSocket-Accept: {accept}\r\n\r\n");
            var stream = client.GetStream();
            await stream.WriteAsync(response, ct);

            var format = capture.WaveFormat;
            var standardFormat = format is WaveFormatExtensible extensible
                ? extensible.ToStandardWaveFormat()
                : format;
            bool isFloat = standardFormat.Encoding == WaveFormatEncoding.IeeeFloat && format.BitsPerSample == 32;
            bool isPcm16 = standardFormat.Encoding == WaveFormatEncoding.Pcm && format.BitsPerSample == 16;
            if (!isFloat && !isPcm16)
            {
                await SendWebSocketFrame(stream, 0x1, Encoding.UTF8.GetBytes("{\"error\":\"Unsupported desktop audio format.\"}"), ct);
                lock (AudioLock)
                {
                    if (AudioClients.IsEmpty && _audioCapture == capture)
                    {
                        capture.DataAvailable -= OnAudioDataAvailable;
                        capture.StopRecording();
                        capture.Dispose();
                        _audioCapture = null;
                    }
                }
                return;
            }

            string formatName = isFloat ? "float32" : "int16";
            var id = Guid.NewGuid();
            var audioClient = new AudioClient();
            AudioClients[id] = audioClient;
            try
            {
                var metadata = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    sampleRate = format.SampleRate,
                    channels = format.Channels,
                    format = formatName
                });
                await SendWebSocketFrame(stream, 0x1, metadata, ct);
                await foreach (var data in audioClient.Queue.Reader.ReadAllAsync(ct))
                    await SendWebSocketFrame(stream, 0x2, data, ct);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            finally
            {
                AudioClients.TryRemove(id, out _);
                audioClient.Queue.Writer.TryComplete();
                if (AudioClients.IsEmpty)
                {
                    lock (AudioLock)
                    {
                        if (AudioClients.IsEmpty && _audioCapture != null)
                        {
                            _audioCapture.DataAvailable -= OnAudioDataAvailable;
                            _audioCapture.StopRecording();
                            _audioCapture.Dispose();
                            _audioCapture = null;
                        }
                    }
                }
                await SendWebSocketFrame(stream, 0x8, Array.Empty<byte>(), CancellationToken.None);
            }
        }

        private static void OnAudioDataAvailable(object? sender, WaveInEventArgs e)
        {
            if (AudioClients.IsEmpty || e.BytesRecorded <= 0) return;
            var format = (sender as WasapiLoopbackCapture)?.WaveFormat;
            if (format == null) return;
            int bytesPerSample = format.BitsPerSample / 8;
            int frameSize = bytesPerSample * format.Channels;
            int size = e.BytesRecorded - e.BytesRecorded % frameSize;
            if (size <= 0) return;
            var chunk = new byte[size];
            Buffer.BlockCopy(e.Buffer, 0, chunk, 0, size);
            foreach (var client in AudioClients.Values)
                client.Queue.Writer.TryWrite(chunk);
        }

        private static async Task SendWebSocketFrame(NetworkStream stream, byte opcode, byte[] payload, CancellationToken ct)
        {
            byte[] header = payload.Length < 126
                ? new byte[] { (byte)(0x80 | opcode), (byte)payload.Length }
                : payload.Length <= ushort.MaxValue
                    ? new byte[] { (byte)(0x80 | opcode), 126, (byte)(payload.Length >> 8), (byte)payload.Length }
                    : new byte[] { (byte)(0x80 | opcode), 127, 0, 0, 0, 0, (byte)(payload.Length >> 24), (byte)(payload.Length >> 16), (byte)(payload.Length >> 8), (byte)payload.Length };
            await stream.WriteAsync(header, ct);
            if (payload.Length > 0)
                await stream.WriteAsync(payload, ct);
        }

        private sealed class AudioClient
        {
            public AudioClient()
            {
                Queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(32)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false
                });
            }

            public Channel<byte[]> Queue { get; }
        }

        [SupportedOSPlatform("windows")]
        private static byte[] CaptureJpegWin(int maxWidth, int quality)
        {
            int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
            using var full = new Bitmap(w, h, PixelFormat.Format24bppRgb);
            using (var g = Graphics.FromImage(full))
                g.CopyFromScreen(0, 0, 0, 0, new Size(w, h));
            int tw = Math.Min(w, maxWidth), th = (int)((long)h * tw / w);
            using var small = new Bitmap(tw, th, PixelFormat.Format24bppRgb);
            using (var g = Graphics.FromImage(small))
                g.DrawImage(full, 0, 0, tw, th);
            var codec = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
            using var ep = new EncoderParameters(1);
            ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)quality);
            using var ms = new MemoryStream();
            small.Save(ms, codec, ep);
            return ms.ToArray();
        }

        private static byte[] CaptureJpeg(int maxWidth, int quality) =>
            OperatingSystem.IsWindows() ? CaptureJpegWin(maxWidth, quality) : throw new PlatformNotSupportedException();

        [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);

        private static string ViewerHtml(string pin) => @"<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'>
<meta name='apple-mobile-web-app-capable' content='yes'><title>Game OS Stream</title>
<style>html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#000;color:#fff;font-family:-apple-system,sans-serif}
body{position:fixed;inset:0}img{width:100%;height:100%;object-fit:contain;display:block}
#controls{position:fixed;z-index:2;top:max(8px,env(safe-area-inset-top));left:8px;right:8px;display:flex;gap:8px}
button,a{color:#fff;background:rgba(0,0,0,.72);border:1px solid #777;padding:8px 12px;border-radius:16px;text-decoration:none;font-size:14px}
#audioStatus{align-self:center;font-size:12px;text-shadow:0 1px 3px #000}
body.immersive #controls{opacity:.25;transition:opacity .2s}body.immersive #controls:active{opacity:1}
</style></head>
<body><div id='controls'><a href='javascript:history.back()'>‹ Back</a><button id='audio'>Enable audio</button><button id='full'>Fullscreen</button><button id='cfg'>Settings</button><span id='audioStatus' role='status'></span></div>
<div id='panel' hidden style='position:fixed;z-index:3;inset:auto 8px 8px 8px;background:rgba(20,20,24,.95);border:1px solid #555;border-radius:16px;padding:12px;font-size:14px'>
<label>FPS <select id='sFps'><option>10</option><option>15</option><option>20</option><option>30</option><option>60</option></select></label>
<label>Width <select id='sW'><option>640</option><option>854</option><option>1280</option><option>1920</option></select></label>
<label>Quality <select id='sQ'><option>35</option><option>50</option><option>60</option><option>75</option><option>90</option></select></label>
<div style='margin-top:8px'><button id='sApply'>Apply</button> <button id='sTest'>Test connection</button></div><div id='sRes' style='margin-top:6px'></div></div>
<img id='s' alt='Connecting…'><video id='v' muted playsinline autoplay disablepictureinpicture style='display:none;width:100%;height:100%;object-fit:contain;background:#000'></video>
<script>
var s=document.getElementById('s'), audioButton=document.getElementById('audio'), status=document.getElementById('audioStatus');
var pinQ='" + Uri.EscapeDataString(pin) + @"';
var cfg=JSON.parse(localStorage.getItem('gameOS_stream_cfg')||'{}');
function go(){var a='';if(cfg.fps)a+='&fps='+cfg.fps;if(cfg.w)a+='&w='+cfg.w;if(cfg.q)a+='&q='+cfg.q;s.src='/stream?pin='+pinQ+a+'&t='+Date.now();}
var wl=null;async function keepAwake(){try{if(navigator.wakeLock&&document.visibilityState==='visible')wl=await navigator.wakeLock.request('screen')}catch(e){}}
keepAwake();document.addEventListener('visibilitychange',keepAwake);document.addEventListener('click',keepAwake);
['sFps','sW','sQ'].forEach(function(id,i){var k=['fps','w','q'][i];if(cfg[k])document.getElementById(id).value=cfg[k]});
document.getElementById('cfg').onclick=function(){var p=document.getElementById('panel');p.hidden=!p.hidden};
document.getElementById('sApply').onclick=function(){cfg={fps:sFps.value,w:sW.value,q:sQ.value};localStorage.setItem('gameOS_stream_cfg',JSON.stringify(cfg));go();document.getElementById('panel').hidden=true};
document.getElementById('sTest').onclick=async function(){var r=document.getElementById('sRes');r.textContent='Testing…';try{
 var lat=[];for(var i=0;i<5;i++){var t=performance.now();await fetch('/ping?t='+Date.now(),{cache:'no-store'});lat.push(performance.now()-t)}
 var l=Math.min.apply(null,lat),t0=performance.now(),b=await (await fetch('/speedtest?pin='+pinQ+'&kb=2048&t='+Date.now(),{cache:'no-store'})).arrayBuffer();
 var mbps=b.byteLength*8/1e6/((performance.now()-t0)/1000);var q=mbps>=20&&l<=40?'Good':mbps>=8&&l<=100?'OK':'Bad';
 r.textContent=q+' connection — '+mbps.toFixed(1)+' Mbps, '+l.toFixed(0)+' ms latency'}catch(e){r.textContent='Test failed'}};
var vid=document.getElementById('v'),vws=null,vgen=0;
function startMjpeg(){vid.style.display='none';s.style.display='block';go()}
function startVideo(){
 var gen=++vgen;if(vws){try{vws.close()}catch(e){}vws=null}
 var MS=window.ManagedMediaSource||window.MediaSource;
 if(!MS){startMjpeg();return}
 var a='';if(cfg.fps)a+='&fps='+cfg.fps;if(cfg.w)a+='&w='+cfg.w;if(cfg.q)a+='&q='+cfg.q;
 var ms=new MS(),sb=null,queue=[],got=false,ws=new WebSocket('ws://'+location.host+'/video?pin='+pinQ+a);vws=ws;ws.binaryType='arraybuffer';
 var fb=setTimeout(function(){if(!got&&gen===vgen){try{ws.close()}catch(e){}startMjpeg()}},6000);
 function pump(){if(!sb||sb.updating||!queue.length)return;try{
  if(queue.length>60){queue.length=0;return}
  sb.appendBuffer(queue.shift())}catch(e){queue.length=0}}
 function live(){try{var b=vid.buffered;if(b.length){var e=b.end(b.length-1);if(e-vid.currentTime>.3)vid.currentTime=e-.05;if(vid.paused)vid.play().catch(function(){});
  if(b.start(0)<vid.currentTime-4&&!sb.updating)sb.remove(0,vid.currentTime-2)}}catch(e){}}
 vid.disableRemotePlayback=true;vid.src=URL.createObjectURL(ms);
 ws.onmessage=function(e){
  if(gen!==vgen)return;
  if(typeof e.data==='string'){var m=JSON.parse(e.data);if(m.error){clearTimeout(fb);startMjpeg();return}
   var open=function(){sb=ms.addSourceBuffer('video/mp4; codecs=""'+m.codec+'""');sb.mode='sequence';sb.onupdateend=function(){live();pump()};pump()};
   if(ms.readyState==='open')open();else ms.addEventListener('sourceopen',open,{once:true});return}
  if(!got){got=true;clearTimeout(fb);s.style.display='none';vid.style.display='block'}
  queue.push(e.data);pump()};
 ws.onclose=function(){if(gen===vgen&&got)setTimeout(startVideo,1000)};
 ws.onerror=function(){if(!got&&gen===vgen){clearTimeout(fb);startMjpeg()}};
}
s.onerror=function(){setTimeout(go,1500)};
document.getElementById('sApply').addEventListener('click',function(){startVideo()});
startVideo();
var ctx=null,socket=null,nextAt=0;
audioButton.onclick=async function(){
 if(socket){socket.close();socket=null;if(ctx){await ctx.close();ctx=null}audioButton.textContent='Enable audio';status.textContent='';return}
 try{
  var AudioContext=window.AudioContext||window.webkitAudioContext;ctx=new AudioContext({latencyHint:'interactive'});await ctx.resume();
  socket=new WebSocket('ws://'+location.host+'/audio?pin=" + Uri.EscapeDataString(pin) + @"');socket.binaryType='arraybuffer';
  socket.onmessage=function(e){
   if(typeof e.data==='string'){var m=JSON.parse(e.data);if(m.error){status.textContent=m.error;return}window.streamAudioFormat=m;nextAt=ctx.currentTime+.08;status.textContent='Audio connected';return}
   var m=window.streamAudioFormat;if(!m)return;
   var bytes=new DataView(e.data), bytesPerSample=m.format==='float32'?4:2, count=Math.floor(e.data.byteLength/(bytesPerSample*m.channels));
   if(!count)return;
   var buffer=ctx.createBuffer(m.channels,count,m.sampleRate);
   for(var c=0;c<m.channels;c++){var channel=buffer.getChannelData(c);for(var i=0;i<count;i++){var offset=(i*m.channels+c)*bytesPerSample;channel[i]=m.format==='float32'?bytes.getFloat32(offset,true):bytes.getInt16(offset,true)/32768}}
   if(nextAt<ctx.currentTime)nextAt=ctx.currentTime+.04;
   if(nextAt-ctx.currentTime>.35)return;
   var source=ctx.createBufferSource();source.buffer=buffer;source.connect(ctx.destination);source.start(nextAt);nextAt+=buffer.duration;
  };
  socket.onerror=function(){status.textContent='Audio connection failed.'};
  socket.onclose=function(){if(ctx){ctx.close();ctx=null}socket=null;audioButton.textContent='Enable audio'};
  audioButton.textContent='Stop audio';status.textContent='Connecting audio…';
 }catch(e){status.textContent='Audio could not start. Tap Enable audio to try again.'}
};
function setFullscreen(){
 if(document.fullscreenElement){document.exitFullscreen&&document.exitFullscreen();document.body.classList.remove('immersive');return}
 document.body.classList.add('immersive');
 if(document.documentElement.requestFullscreen)document.documentElement.requestFullscreen().catch(function(){});
}
document.getElementById('full').onclick=setFullscreen;
document.addEventListener('fullscreenchange',function(){document.getElementById('full').textContent=document.fullscreenElement?'Exit fullscreen':'Fullscreen'});
</script></body></html>";
    }
}
