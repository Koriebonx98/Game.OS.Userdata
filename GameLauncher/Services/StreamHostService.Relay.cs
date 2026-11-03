using System;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using NAudio.Wave;

namespace GameLauncher.Services
{
    /// <summary>
    /// Publishes this PC's screen + desktop audio to a hosted stream relay (see /stream-relay) so anyone
    /// with the player's profile can watch from a browser. Viewers never see this PC's IP address.
    /// </summary>
    public static partial class StreamHostService
    {
        private static CancellationTokenSource? _broadcastCts;
        private static string _broadcastRoom = "";
        private static string _broadcastRelay = "";
        private static string _broadcastKey = "";

        public static bool IsBroadcasting => _broadcastCts != null;
        public static string BroadcastRoomId => _broadcastRoom;
        public static string BroadcastRelayUrl => _broadcastRelay;

        /// <summary>Raised on the publisher thread when the broadcast ends for any reason.</summary>
        public static event Action? BroadcastEnded;

        /// <summary>Creates a room on the relay and starts pushing frames. Returns (roomId, relayUrl).</summary>
        public static async Task<(string RoomId, string RelayUrl)> StartBroadcastAsync(
            string relayUrl, string adminKey, string title, bool includeAudio, int frameRate = 20, int maxWidth = 1280, int quality = 60)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Broadcasting needs Windows screen capture.");
            if (IsBroadcasting) return (_broadcastRoom, _broadcastRelay);
            relayUrl = (relayUrl ?? "").Trim().TrimEnd('/');
            if (!Uri.TryCreate(relayUrl, UriKind.Absolute, out var baseUri) || (baseUri.Scheme != "http" && baseUri.Scheme != "https"))
                throw new InvalidOperationException("Set a valid Stream relay URL (http/https) in Settings first.");

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            using var req = new HttpRequestMessage(HttpMethod.Post, relayUrl + "/api/rooms")
            {
                Content = new StringContent(JsonSerializer.Serialize(new { title }), Encoding.UTF8, "application/json")
            };
            if (!string.IsNullOrWhiteSpace(adminKey)) req.Headers.Add("x-admin-key", adminKey);
            using var resp = await http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"Relay refused the request ({(int)resp.StatusCode}).");
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            string roomId = doc.RootElement.GetProperty("roomId").GetString()!;
            string key = doc.RootElement.GetProperty("ingestKey").GetString()!;

            var wsUri = new UriBuilder(baseUri) { Scheme = baseUri.Scheme == "https" ? "wss" : "ws", Path = $"/ingest/{roomId}", Query = "key=" + Uri.EscapeDataString(key) }.Uri;
            var ws = new ClientWebSocket();
            var cts = new CancellationTokenSource();
            await ws.ConnectAsync(wsUri, cts.Token);

            _broadcastCts = cts; _broadcastRoom = roomId; _broadcastRelay = relayUrl; _broadcastKey = key;
            frameRate = ClampFrameRate(frameRate); maxWidth = ClampMaxWidth(maxWidth); quality = ClampJpegQuality(quality);
            _ = Task.Run(() => RunBroadcast(ws, cts, includeAudio, frameRate, maxWidth, quality));
            return (roomId, relayUrl);
        }

        public static void StopBroadcast()
        {
            var cts = _broadcastCts;
            if (cts == null) return;
            var relay = _broadcastRelay; var room = _broadcastRoom; var key = _broadcastKey;
            cts.Cancel();
            _ = Task.Run(async () =>
            {
                try
                {
                    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                    await http.DeleteAsync($"{relay}/api/rooms/{room}?key={Uri.EscapeDataString(key)}");
                }
                catch { }
            });
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static async Task RunBroadcast(ClientWebSocket ws, CancellationTokenSource cts, bool includeAudio, int fps, int maxWidth, int quality)
        {
            var ct = cts.Token;
            // Frames and audio share one socket, so funnel everything through a single bounded sender.
            var queue = Channel.CreateBounded<(byte[] Data, bool Binary)>(
                new BoundedChannelOptions(48) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
            WasapiLoopbackCapture? audio = null;
            try
            {
                if (includeAudio)
                {
                    try
                    {
                        audio = new WasapiLoopbackCapture();
                        var f = audio.WaveFormat;
                        bool isFloat = f.BitsPerSample == 32 && (f.Encoding == WaveFormatEncoding.IeeeFloat || f is WaveFormatExtensible);
                        bool isPcm16 = f.BitsPerSample == 16;
                        if (isFloat || isPcm16)
                        {
                            queue.Writer.TryWrite((Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                            {
                                type = "audio-format",
                                format = isFloat ? "float32" : "int16",
                                channels = f.Channels,
                                sampleRate = f.SampleRate
                            })), false));
                            int frameSize = f.BitsPerSample / 8 * f.Channels;
                            audio.DataAvailable += (_, e) =>
                            {
                                int size = e.BytesRecorded - e.BytesRecorded % frameSize;
                                if (size <= 0) return;
                                var chunk = new byte[size + 1];
                                chunk[0] = 0x02;
                                Buffer.BlockCopy(e.Buffer, 0, chunk, 1, size);
                                queue.Writer.TryWrite((chunk, true));
                            };
                            audio.StartRecording();
                        }
                        else { audio.Dispose(); audio = null; }
                    }
                    catch { audio?.Dispose(); audio = null; }
                }

                var sender = Task.Run(async () =>
                {
                    try
                    {
                        await foreach (var (data, binary) in queue.Reader.ReadAllAsync(ct))
                            await ws.SendAsync(data, binary ? WebSocketMessageType.Binary : WebSocketMessageType.Text, true, ct);
                    }
                    catch { cts.Cancel(); }
                });

                using var grabber = new MjpegGrabber(maxWidth, quality);
                while (!ct.IsCancellationRequested)
                {
                    var started = Environment.TickCount64;
                    var jpg = grabber.Grab();
                    var msg = new byte[jpg.Length + 1];
                    msg[0] = 0x01;
                    Buffer.BlockCopy(jpg, 0, msg, 1, jpg.Length);
                    queue.Writer.TryWrite((msg, true));
                    int wait = 1000 / fps - (int)(Environment.TickCount64 - started);
                    if (wait > 0) await Task.Delay(wait, ct);
                }
                try { await sender; } catch { }
            }
            catch { }
            finally
            {
                try { audio?.StopRecording(); audio?.Dispose(); } catch { }
                try { ws.Abort(); ws.Dispose(); } catch { }
                if (ReferenceEquals(_broadcastCts, cts))
                {
                    _broadcastCts = null; _broadcastRoom = ""; _broadcastKey = ""; _broadcastRelay = "";
                }
                cts.Cancel();
                try { BroadcastEnded?.Invoke(); } catch { }
            }
        }
    }
}
