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

        public static string ConnectArgument(string template, string configuredAddress, string roomAddress,
            string roomGame, string roomPlatform, string game, string platform)
        {
            var address = !string.IsNullOrWhiteSpace(roomAddress)
                && string.Equals(PlatformHelper.NormalizeTitleForComparison(roomGame),
                    PlatformHelper.NormalizeTitleForComparison(game), StringComparison.Ordinal)
                && string.Equals(PlatformHelper.NormalizePlatform(roomPlatform),
                    PlatformHelper.NormalizePlatform(platform), StringComparison.OrdinalIgnoreCase)
                ? roomAddress : configuredAddress;
            return string.IsNullOrWhiteSpace(template) || string.IsNullOrWhiteSpace(address)
                ? "" : template.Replace("{IP}", address, StringComparison.OrdinalIgnoreCase);
        }
    }
}
