using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Shared swarm + LFG/group rooms. Every signed-in launcher heartbeats into the backend pool; a host
    /// publishes a room (game + platform) and joiners receive the host's temporary endpoint.
    /// </summary>
    public sealed class LfgService : IDisposable
    {
        public const int DefaultPort = 26500;
        private readonly GameOsClient _client;
        private Timer? _roomTimer;
        private readonly VirtualNetworkService _vpn = new();

        /// <summary>Last connection result shown to the host.</summary>
        public string ConnectionInfo { get; private set; } = "";
        private string _vpnFallbackReason = "";

        public LfgService(GameOsClient client) => _client = client;

        public string? HostedRoomId { get; private set; }
        public string HostedGame { get; private set; } = "";
        public string HostedPlatform { get; private set; } = "";
        public string JoinedEndpoint { get; private set; } = "";
        public string JoinedGame { get; private set; } = "";
        public string JoinedPlatform { get; private set; } = "";
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
            return await _client.ListLfgAsync(game, platform).ConfigureAwait(false);
        }

        /// <summary>Publishes an LFG/group room for the game and keeps it alive until <see cref="StopHosting"/>.</summary>
        public async Task HostAsync(string game, string platform, bool group, int maxPlayers = 4, string? hostAddress = null)
        {
            StopHosting();
            _vpnFallbackReason = "";
            if (string.IsNullOrWhiteSpace(hostAddress)
                && await TryHostOverVirtualNetworkAsync(game, platform, group, maxPlayers).ConfigureAwait(false)) return;
            string id;
            var endpoint = string.IsNullOrWhiteSpace(hostAddress) ? ResolveHostEndpoint() : hostAddress.Trim() + ":" + DefaultPort;
            if (!IPEndPoint.TryParse(endpoint, out var address)
                || address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address.Address))
                throw new InvalidOperationException("Enter a valid local LAN/VPN IPv4 address.");
            bool localAddress = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                .Any(ua => ua.Address.Equals(address.Address));
            if (!localAddress) throw new InvalidOperationException("The selected address is not assigned to an active network adapter.");
            ConnectionInfo = $"Host address {address.Address}. Use the same LAN/VPN; configure the game's own port separately if needed";
            if (!string.IsNullOrEmpty(_vpnFallbackReason))
                ConnectionInfo += $". Game.OS VPN unavailable: {_vpnFallbackReason}";
            id = await _client.CreateLfgAsync(game, platform, group ? "group" : "lfg", address.Address.ToString(), maxPlayers)
                .ConfigureAwait(false);
            HostedRoomId = id;
            HostedGame = game;
            HostedPlatform = platform;
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
                });
            }, null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        }

        /// <summary>Creates a room on the Game.OS virtual LAN; this PC hosts at 10.77.N.1. Returns false to fall back to LAN/VPN.</summary>
        private async Task<bool> TryHostOverVirtualNetworkAsync(string game, string platform, bool group, int maxPlayers)
        {
            if (!VirtualNetworkService.IsSupported || !_client.IsBackendMode) return false;
            string? id = null;
            try
            {
                id = await _client.CreateLfgAsync(game, platform, group ? "group" : "lfg", "", maxPlayers, default, vpn: true)
                    .ConfigureAwait(false);
                var session = await _client.GetVpnSessionAsync(id).ConfigureAwait(false);
                if (!_vpn.Start(session)) throw new InvalidOperationException(_vpn.Status);
                HostedRoomId = id;
                HostedGame = game;
                HostedPlatform = platform;
                ConnectionInfo = $"Game.OS virtual network — your address {session.Ip}";
                StartRoomTimer();
                return true;
            }
            catch (Exception ex)
            {
                if (id != null) { try { await _client.CloseLfgAsync(id).ConfigureAwait(false); } catch { } }
                _vpnFallbackReason = ex.Message;
                _vpn.Stop();
                return false;
            }
        }

        public string VpnStatus => _vpn.IsRunning ? $"{_vpn.Status} · {_vpn.PeerSummary()}" : "";

        public void StopHosting()
        {
            Disconnect();
            _roomTimer?.Dispose();
            _roomTimer = null;
            var id = HostedRoomId;
            HostedRoomId = null;
            HostedGame = HostedPlatform = "";
            if (id != null)
                Task.Run(async () => { try { await _client.CloseLfgAsync(id).ConfigureAwait(false); } catch { } });
        }

        public void Disconnect()
        {
            _vpn.Stop();
            JoinedEndpoint = JoinedGame = JoinedPlatform = "";
        }

        /// <summary>Joins a room and saves the host's endpoint as a hidden temporary address; returns the host name.</summary>
        public async Task<string> JoinAsync(LfgRoom room)
        {
            if (IsHosting) throw new InvalidOperationException("Close your hosted room before joining another room.");
            var res = await _client.JoinLfgAsync(room.RoomId).ConfigureAwait(false);
            string host = string.IsNullOrEmpty(res.Host) ? room.Host : res.Host;
            if (!string.Equals(host, room.Host, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(res.Game, room.Game, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(res.Platform, room.Platform, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The room details do not match the invitation.");
            if (!RoomConnectionService.IsValidEndpoint(res.Endpoint))
                throw new InvalidOperationException("The room returned an invalid host address.");
            _vpn.Stop();
            JoinedEndpoint = JoinedGame = JoinedPlatform = "";
            if (res.Vpn)
            {
                var session = await _client.GetVpnSessionAsync(room.RoomId).ConfigureAwait(false);
                if (!_vpn.Start(session)) throw new InvalidOperationException(_vpn.Status);
                ConnectionInfo = $"Game.OS virtual network — your address {session.Ip}";
            }
            var existing = FriendIpService.Load(host).Where(e => e.Label != TempLabel).ToList();
            existing.Add(new FriendIpEntry { Label = TempLabel, Address = res.Endpoint, Type = "local" });
            FriendIpService.Save(host, existing);
            JoinedEndpoint = res.Endpoint;
            JoinedGame = res.Game;
            JoinedPlatform = res.Platform;
            if (!res.Vpn) ConnectionInfo = "Use the same LAN/VPN as the host";
            return host;
        }

        public const string TempLabel = "Temp room";

        public void Dispose() { StopHosting(); _vpn.Dispose(); }
    }
}
