using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace GameLauncher.Services
{
    /// <summary>
    /// Game.OS virtual LAN (Windows only). Creates a Wintun adapter with a 10.77.N.x address and carries
    /// IP packets between room members over UDP: direct peer-to-peer when NAT hole punching succeeds,
    /// otherwise through the Game.OS relay (vpn-relay/server.js). Needs wintun.dll next to the launcher and
    /// administrator rights; <see cref="Start"/> reports a readable error otherwise.
    /// </summary>
    public sealed class VirtualNetworkService : IDisposable
    {
        private const string AdapterName = "GameOS";
        private const byte Register = 0x01, RegisterAck = 0x02, RelaySend = 0x10, RelayRecv = 0x11,
                           Direct = 0x20, Punch = 0x21, PunchAck = 0x22;
        private static readonly TimeSpan DirectTimeout = TimeSpan.FromSeconds(15);

        private sealed class Peer
        {
            public int Vip;
            public IPEndPoint EndPoint = new(IPAddress.Any, 0);
            public long LastDirectTicks;
        }

        private readonly ConcurrentDictionary<int, Peer> _peers = new();
        private UdpClient? _udp;
        private IPEndPoint? _relay;
        private IntPtr _adapter, _session;
        private Thread? _tunReader, _netReader, _keepAlive;
        private volatile bool _running;
        private string _token = "";
        private int _myVip, _subnet;

        public bool IsRunning => _running;
        public string Status { get; private set; } = "";
        public string LocalIp { get; private set; } = "";

        public static bool IsSupported =>
            OperatingSystem.IsWindows() && File.Exists(Path.Combine(AppContext.BaseDirectory, "wintun.dll"));

        /// <summary>Starts the adapter and tunnel. Returns false with <see cref="Status"/> set on failure.</summary>
        public bool Start(BackendApiService.VpnSession s)
        {
            Stop();
            if (!OperatingSystem.IsWindows()) { Status = "Virtual network is only available on Windows"; return false; }
            if (!IsSupported) { Status = "wintun.dll is missing next to the launcher"; return false; }
            try
            {
                _token = s.Token; _myVip = s.Vip; _subnet = s.Subnet; LocalIp = s.Ip;
                var addr = Dns.GetHostAddresses(s.RelayHost);
                IPAddress? v4 = Array.Find(addr, a => a.AddressFamily == AddressFamily.InterNetwork);
                if (v4 == null) { Status = "Relay host could not be resolved"; return false; }
                _relay = new IPEndPoint(v4, s.RelayPort);

                var guid = Guid.Empty;
                _adapter = Wintun.WintunCreateAdapter(AdapterName, "Game.OS", ref guid);
                if (_adapter == IntPtr.Zero) { Status = "Could not create the virtual adapter (run Game.OS as administrator)"; return false; }
                _session = Wintun.WintunStartSession(_adapter, 0x400000);
                if (_session == IntPtr.Zero) { Status = "Could not start the virtual adapter session"; Stop(); return false; }

                if (!Netsh($"interface ip set address name=\"{AdapterName}\" static {s.Ip} 255.255.255.0"))
                { Status = "Could not assign the virtual IP (administrator rights needed)"; Stop(); return false; }
                Netsh($"interface ipv4 set subinterface \"{AdapterName}\" mtu=1280 store=active");

                _udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                _running = true;
                _netReader = new Thread(NetLoop) { IsBackground = true, Name = "gameos-vpn-net" };
                _tunReader = new Thread(TunLoop) { IsBackground = true, Name = "gameos-vpn-tun" };
                _keepAlive = new Thread(KeepAliveLoop) { IsBackground = true, Name = "gameos-vpn-keepalive" };
                _netReader.Start(); _tunReader.Start(); _keepAlive.Start();
                Status = $"Virtual network up ({s.Ip})";
                return true;
            }
            catch (DllNotFoundException) { Status = "wintun.dll could not be loaded"; Stop(); return false; }
            catch (Exception ex) { Status = "Virtual network failed: " + ex.Message; Stop(); return false; }
        }

        /// <summary>Number of peers currently reachable directly vs. via the relay.</summary>
        public string PeerSummary()
        {
            int direct = 0, relayed = 0;
            long now = Environment.TickCount64;
            foreach (var p in _peers.Values) { if (IsDirect(p, now)) direct++; else relayed++; }
            return $"{direct} direct, {relayed} relayed";
        }

        private static bool IsDirect(Peer p, long nowTicks) =>
            p.LastDirectTicks != 0 && nowTicks - p.LastDirectTicks < DirectTimeout.TotalMilliseconds;

        private static bool Netsh(string args)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo("netsh", args)
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
                if (p == null) return false;
                p.WaitForExit(10000);
                return p.ExitCode == 0;
            }
            catch { return false; }
        }

        private void KeepAliveLoop()
        {
            var reg = new byte[1 + Encoding.UTF8.GetByteCount(_token)];
            reg[0] = Register;
            Encoding.UTF8.GetBytes(_token, 0, _token.Length, reg, 1);
            while (_running)
            {
                try
                {
                    _udp!.Send(reg, reg.Length, _relay!);
                    var punch = new byte[5];
                    punch[0] = Punch; WriteVip(punch, 1, _myVip);
                    foreach (var p in _peers.Values) _udp.Send(punch, punch.Length, p.EndPoint);
                }
                catch { /* socket closed or transient */ }
                for (int i = 0; i < 20 && _running; i++) Thread.Sleep(250);
            }
        }

        private void NetLoop()
        {
            var any = new IPEndPoint(IPAddress.Any, 0);
            while (_running)
            {
                byte[] msg;
                try { msg = _udp!.Receive(ref any); }
                catch { if (!_running) return; continue; }
                if (msg.Length < 1) continue;
                switch (msg[0])
                {
                    case RegisterAck: HandleAck(msg); break;
                    case RelayRecv when msg.Length > 5: WriteToTun(msg, 5); break;
                    case Direct when msg.Length > 5:
                        if (MarkDirect(any, ReadVip(msg, 1))) WriteToTun(msg, 5);
                        break;
                    case Punch when msg.Length >= 5:
                        if (MarkDirect(any, ReadVip(msg, 1)))
                        {
                            var ack = new byte[5]; ack[0] = PunchAck; WriteVip(ack, 1, _myVip);
                            try { _udp!.Send(ack, ack.Length, any); } catch { }
                        }
                        break;
                    case PunchAck when msg.Length >= 5:
                        MarkDirect(any, ReadVip(msg, 1));
                        break;
                }
            }
        }

        // Only accept direct traffic from the endpoint the relay told us belongs to that vip.
        private bool MarkDirect(IPEndPoint from, int vip)
        {
            if (!_peers.TryGetValue(vip, out var p)) return false;
            if (!p.EndPoint.Equals(from)) return false;
            p.LastDirectTicks = Environment.TickCount64;
            return true;
        }

        private void HandleAck(byte[] msg)
        {
            try
            {
                using var doc = JsonDocument.Parse(new ReadOnlyMemory<byte>(msg, 1, msg.Length - 1));
                var seen = new System.Collections.Generic.HashSet<int>();
                foreach (var el in doc.RootElement.GetProperty("peers").EnumerateArray())
                {
                    int vip = el.GetProperty("vip").GetInt32();
                    var ep = new IPEndPoint(IPAddress.Parse(el.GetProperty("ip").GetString()!), el.GetProperty("port").GetInt32());
                    seen.Add(vip);
                    var peer = _peers.GetOrAdd(vip, _ => new Peer { Vip = vip });
                    if (!peer.EndPoint.Equals(ep)) { peer.EndPoint = ep; peer.LastDirectTicks = 0; }
                }
                foreach (var vip in _peers.Keys) if (!seen.Contains(vip)) _peers.TryRemove(vip, out _);
            }
            catch { /* malformed ack */ }
        }

        private void TunLoop()
        {
            var evt = Wintun.WintunGetReadWaitEvent(_session);
            while (_running)
            {
                var pkt = Wintun.WintunReceivePacket(_session, out uint size);
                if (pkt == IntPtr.Zero) { Wintun.WaitForSingleObject(evt, 250); continue; }
                var buf = new byte[size];
                Marshal.Copy(pkt, buf, 0, (int)size);
                Wintun.WintunReleaseReceivePacket(_session, pkt);
                try { RoutePacket(buf); } catch { /* drop */ }
            }
        }

        private void RoutePacket(byte[] ip)
        {
            if (ip.Length < 20 || (ip[0] >> 4) != 4) return;
            int dstVip = ip[19];
            bool multi = ip[16] >= 224 || dstVip == 255 || dstVip == 0;
            if (multi) { foreach (var p in _peers.Values) SendTo(p, ip); }
            else if (ip[16] == 10 && ip[17] == 77 && ip[18] == _subnet && _peers.TryGetValue(dstVip, out var peer)) SendTo(peer, ip);
        }

        private void SendTo(Peer p, byte[] ip)
        {
            bool direct = IsDirect(p, Environment.TickCount64);
            var buf = new byte[(direct ? 5 : 9) + ip.Length];
            if (direct)
            {
                buf[0] = Direct; WriteVip(buf, 1, _myVip);
                Buffer.BlockCopy(ip, 0, buf, 5, ip.Length);
                _udp!.Send(buf, buf.Length, p.EndPoint);
            }
            else
            {
                buf[0] = RelaySend; WriteVip(buf, 1, _myVip); WriteVip(buf, 5, p.Vip);
                Buffer.BlockCopy(ip, 0, buf, 9, ip.Length);
                _udp!.Send(buf, buf.Length, _relay!);
            }
        }

        private void WriteToTun(byte[] msg, int offset)
        {
            int len = msg.Length - offset;
            var session = _session;
            if (session == IntPtr.Zero || !_running) return;
            var dst = Wintun.WintunAllocateSendPacket(session, (uint)len);
            if (dst == IntPtr.Zero) return;
            Marshal.Copy(msg, offset, dst, len);
            Wintun.WintunSendPacket(session, dst);
        }

        private static void WriteVip(byte[] b, int o, int vip)
        {
            b[o] = 0; b[o + 1] = 0; b[o + 2] = 0; b[o + 3] = (byte)vip;
        }

        private static int ReadVip(byte[] b, int o) => (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];

        public void Stop()
        {
            _running = false;
            try { _udp?.Close(); } catch { }
            _udp = null;
            foreach (var t in new[] { _netReader, _tunReader, _keepAlive }) { try { t?.Join(1000); } catch { } }
            _netReader = _tunReader = _keepAlive = null;
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    if (_session != IntPtr.Zero) Wintun.WintunEndSession(_session);
                    if (_adapter != IntPtr.Zero) Wintun.WintunCloseAdapter(_adapter);
                }
                catch { }
            }
            _session = _adapter = IntPtr.Zero;
            _peers.Clear();
        }

        public void Dispose() => Stop();

        private static class Wintun
        {
            [DllImport("wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr WintunCreateAdapter(string name, string tunnelType, ref Guid requestedGuid);
            [DllImport("wintun.dll")] public static extern void WintunCloseAdapter(IntPtr adapter);
            [DllImport("wintun.dll", SetLastError = true)] public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);
            [DllImport("wintun.dll")] public static extern void WintunEndSession(IntPtr session);
            [DllImport("wintun.dll")] public static extern IntPtr WintunGetReadWaitEvent(IntPtr session);
            [DllImport("wintun.dll")] public static extern IntPtr WintunReceivePacket(IntPtr session, out uint size);
            [DllImport("wintun.dll")] public static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);
            [DllImport("wintun.dll")] public static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint size);
            [DllImport("wintun.dll")] public static extern void WintunSendPacket(IntPtr session, IntPtr packet);
            [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
        }
    }
}
