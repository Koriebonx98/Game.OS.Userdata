using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Open.Nat;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Shared swarm + LFG/group rooms. Every signed-in launcher heartbeats into the backend pool; a host
    /// publishes a room (game + platform) and joiners receive the host's temporary endpoint, which is
    /// stored locally as a hidden friend address and never shown in the UI.
    /// </summary>
    public sealed class LfgService : IDisposable
    {
        public const int DefaultPort = 26500;
        private readonly GameOsClient _client;
        private Timer? _roomTimer;
        private NatDevice? _nat;
        private readonly List<Mapping> _mappings = new();
        private readonly VirtualNetworkService _vpn = new();

        /// <summary>Last connection result shown to the host, e.g. "Public via UPnP" or "LAN/VPN only".</summary>
        public string ConnectionInfo { get; private set; } = "";

        /// <summary>Opens the game port on the router via UPnP and returns the public endpoint, or null when the router refuses.</summary>
        private async Task<string?> TryOpenPublicEndpointAsync(int port)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                _nat = await new NatDiscoverer().DiscoverDeviceAsync(PortMapper.Upnp, cts).ConfigureAwait(false);
                var ip = await _nat.GetExternalIPAsync().ConfigureAwait(false);
                foreach (var proto in new[] { Protocol.Udp, Protocol.Tcp })
                {
                    var m = new Mapping(proto, port, port, 3600, "Game.OS room");
                    await _nat.CreatePortMapAsync(m).ConfigureAwait(false);
                    _mappings.Add(m);
                }
                return $"{ip}:{port}";
            }
            catch { CloseMappings(); return null; }
        }

        private void CloseMappings()
        {
            var nat = _nat; var maps = _mappings.ToList();
            _nat = null; _mappings.Clear();
            if (nat == null) return;
            Task.Run(async () => { foreach (var m in maps) { try { await nat.DeletePortMapAsync(m).ConfigureAwait(false); } catch { } } });
        }

        public LfgService(GameOsClient client) => _client = client;

        public string? HostedRoomId { get; private set; }
        public bool IsHosting => HostedRoomId != null;
        public bool IsAvailable => _client.SupportsSwarm;

        /// <summary>Joins the shared pool; safe to call repeatedly.</summary>
        public async Task JoinSwarmAsync()
        {
            if (!IsAvailable) return;
            try { await _client.SwarmHeartbeatAsync().ConfigureAwait(false); } catch { /* best-effort */ }
        }

        /// <summary>Best address friends can reach this PC on: Radmin/VPN (26.x) first, then private LAN.</summary>
        public static string ResolveHostEndpoint(int port = DefaultPort)
        {
            var ips = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork) ips.Add(ua.Address.ToString());
                }
            }
            catch { /* best-effort */ }
            string ip = ips.FirstOrDefault(i => i.StartsWith("26.")) ?? ips.FirstOrDefault(i => !i.StartsWith("169.254.")) ?? "127.0.0.1";
            return $"{ip}:{port}";
        }

        public async Task<List<LfgRoom>> ListAsync(string game, string platform)
        {
            if (!IsAvailable) return new();
            try { return await _client.ListLfgAsync(game, platform).ConfigureAwait(false); }
            catch { return new(); }
        }

        /// <summary>Publishes an LFG/group room for the game and keeps it alive until <see cref="StopHosting"/>.</summary>
        public async Task HostAsync(string game, string platform, bool group, int maxPlayers = 4)
        {
            StopHosting();
            if (await TryHostOverVirtualNetworkAsync(game, platform, group, maxPlayers).ConfigureAwait(false)) return;
            string? pub = await TryOpenPublicEndpointAsync(DefaultPort).ConfigureAwait(false);
            ConnectionInfo = pub != null ? "Public connection opened via UPnP" : "UPnP unavailable — reachable over LAN/VPN (Radmin/ZeroTier) only";
            string id;
            try
            {
                id = await _client.CreateLfgAsync(game, platform, group ? "group" : "lfg", pub ?? ResolveHostEndpoint(), maxPlayers)
                    .ConfigureAwait(false);
            }
            catch { CloseMappings(); throw; }
            HostedRoomId = id;
            StartRoomTimer();
        }

        private void StartRoomTimer()
        {
            _roomTimer = new Timer(_ =>
            {
                var rid = HostedRoomId;
                if (rid == null) return;
                Task.Run(async () =>
                {
                    try { await _client.LfgHeartbeatAsync(rid).ConfigureAwait(false); } catch { }
                    // Renew the lease before the router drops the mapping.
                    var nat = _nat;
                    if (nat != null)
                        foreach (var m in _mappings.ToList()) { try { await nat.CreatePortMapAsync(m).ConfigureAwait(false); } catch { } }
                });
            }, null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        }

        /// <summary>Creates a room on the Game.OS virtual LAN; this PC hosts at 10.77.N.1. Returns false to fall back to UPnP.</summary>
        private async Task<bool> TryHostOverVirtualNetworkAsync(string game, string platform, bool group, int maxPlayers)
        {
            if (!VirtualNetworkService.IsSupported) return false;
            string? id = null;
            try
            {
                id = await _client.CreateLfgAsync(game, platform, group ? "group" : "lfg", "", maxPlayers, default, vpn: true)
                    .ConfigureAwait(false);
                var session = await _client.GetVpnSessionAsync(id).ConfigureAwait(false);
                if (!_vpn.Start(session)) throw new InvalidOperationException(_vpn.Status);
                HostedRoomId = id;
                ConnectionInfo = $"Game.OS virtual network — your address {session.Ip}";
                StartRoomTimer();
                return true;
            }
            catch
            {
                if (id != null) { try { await _client.CloseLfgAsync(id).ConfigureAwait(false); } catch { } }
                _vpn.Stop();
                return false;
            }
        }

        public string VpnStatus => _vpn.IsRunning ? $"{_vpn.Status} · {_vpn.PeerSummary()}" : "";

        public void StopHosting()
        {
            _vpn.Stop();
            _roomTimer?.Dispose();
            _roomTimer = null;
            var id = HostedRoomId;
            HostedRoomId = null;
            CloseMappings();
            if (id != null)
                Task.Run(async () => { try { await _client.CloseLfgAsync(id).ConfigureAwait(false); } catch { } });
        }

        /// <summary>Joins a room and saves the host's endpoint as a hidden temporary address; returns the host name.</summary>
        public async Task<string> JoinAsync(LfgRoom room)
        {
            var res = await _client.JoinLfgAsync(room.RoomId).ConfigureAwait(false);
            string host = string.IsNullOrEmpty(res.Host) ? room.Host : res.Host;
            if (res.Vpn)
            {
                var session = await _client.GetVpnSessionAsync(room.RoomId).ConfigureAwait(false);
                if (!_vpn.Start(session)) throw new InvalidOperationException(_vpn.Status);
                ConnectionInfo = $"Game.OS virtual network — your address {session.Ip}";
            }
            var existing = FriendIpService.Load(host).Where(e => e.Label != TempLabel).ToList();
            existing.Add(new FriendIpEntry { Label = TempLabel, Address = res.Endpoint, Type = "local" });
            FriendIpService.Save(host, existing);
            return host;
        }

        public const string TempLabel = "Temp room";

        public void Dispose() { StopHosting(); _vpn.Dispose(); }
    }
}
