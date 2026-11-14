using System;
using System.Net;
using System.Net.Sockets;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    public static class RoomConnectionService
    {
        public static bool IsValidEndpoint(string? endpoint)
        {
            if (string.IsNullOrWhiteSpace(endpoint)) return false;
            var parts = endpoint.Split(':');
            return parts.Length <= 2 && IPAddress.TryParse(parts[0], out var ip)
                && ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip)
                && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.Broadcast)
                && (parts.Length == 1 || (int.TryParse(parts[1], out var port) && port > 0 && port <= 65535));
        }

        /// <summary>Appends ":port" when a port is configured and the address has none.</summary>
        public static string WithPort(string address, int port) =>
            port is > 0 and <= 65535 && !address.Contains(':') ? $"{address}:{port}" : address;

        /// <summary>Replaces {IP}, $IP and $TempIP with the room address.</summary>
        public static string ExpandAddress(string text, string address) =>
            text.Replace("$TempIP", address, StringComparison.OrdinalIgnoreCase)
                .Replace("{IP}", address, StringComparison.OrdinalIgnoreCase)
                .Replace("$IP", address, StringComparison.OrdinalIgnoreCase);

        /// <summary>Connect template for a mod-client exe: "-multiplayer -connect {IP}" for iw*/t7/etc. clients, else "-connect {IP}".</summary>
        public static string DefaultTemplate(string? clientExe)
        {
            string name = System.IO.Path.GetFileNameWithoutExtension(clientExe ?? "").ToLowerInvariant();
            bool multiplayerFlag = name.Contains("-mod") || System.Text.RegularExpressions.Regex.IsMatch(name, @"^(iw\d|t\d|s4|h1|h2m)");
            return multiplayerFlag ? "-multiplayer -connect {IP}" : "-connect {IP}";
        }

        /// <summary>Builds the client's connect arguments; <c>{IP}</c> and <c>$IP</c> are both replaced. A blank template uses <see cref="DefaultTemplate"/>.</summary>
        public static string ConnectArgument(string template, string configuredAddress, string roomAddress,
            string roomGame, string roomPlatform, string game, string platform, string? clientExe = null)
        {
            var address = !string.IsNullOrWhiteSpace(roomAddress)
                && string.Equals(PlatformHelper.NormalizeTitleForComparison(roomGame),
                    PlatformHelper.NormalizeTitleForComparison(game), StringComparison.Ordinal)
                && string.Equals(PlatformHelper.NormalizePlatform(roomPlatform),
                    PlatformHelper.NormalizePlatform(platform), StringComparison.OrdinalIgnoreCase)
                ? roomAddress : configuredAddress;
            if (string.IsNullOrWhiteSpace(address)) return "";
            if (string.IsNullOrWhiteSpace(template)) template = DefaultTemplate(clientExe);
            return ExpandAddress(template, address);
        }
    }
}
