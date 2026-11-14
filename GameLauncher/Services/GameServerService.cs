using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>Runs a game's dedicated-server file (e.g. an iw6-mod server .bat) while its Group/LFG room is hosted.</summary>
    public static class GameServerService
    {
        private static readonly ConcurrentDictionary<string, Process> Running = new(StringComparer.OrdinalIgnoreCase);

        public static bool IsRunning(string game) => Running.TryGetValue(game, out var p) && !p.HasExited;

        private static bool PortOpen(int port)
        {
            try
            {
                var ip = IPGlobalProperties.GetIPGlobalProperties();
                return ip.GetActiveUdpListeners().Any(e => e.Port == port) || ip.GetActiveTcpListeners().Any(e => e.Port == port);
            }
            catch { return false; }
        }

        /// <summary>Server process is alive and, when a port is configured, listening on it.</summary>
        public static bool IsReady(string game)
        {
            if (!IsRunning(game)) return false;
            int port = GameSettingsService.Load(game).ModClient?.ServerPort ?? 0;
            return port <= 0 || PortOpen(port);
        }

        /// <summary>Waits until the server listens on its port (or, with no port set, survives a short startup grace).</summary>
        public static async Task<bool> WaitUntilReadyAsync(string game, TimeSpan timeout)
        {
            int port = GameSettingsService.Load(game).ModClient?.ServerPort ?? 0;
            var end = DateTime.UtcNow + timeout;
            if (port <= 0) { await Task.Delay(TimeSpan.FromSeconds(4)); return IsRunning(game); }
            while (DateTime.UtcNow < end)
            {
                if (!IsRunning(game)) return false;
                if (PortOpen(port)) return true;
                await Task.Delay(500);
            }
            return false;
        }

        /// <summary>Starts the configured server for the game. Returns false when none is configured/available.</summary>
        public static bool TryStart(string game, string address, out string message)
        {
            message = "";
            var mc = GameSettingsService.Load(game).ModClient;
            if (mc == null || !mc.AutoStartServer || string.IsNullOrWhiteSpace(mc.ServerFile)) return false;
            if (!File.Exists(mc.ServerFile)) { message = "Server file not found: " + mc.ServerFile; return false; }
            if (IsRunning(game)) { message = "Server already running"; return true; }
            try
            {
                string args = RoomConnectionService.ExpandAddress(mc.ServerArgs ?? "", address)
                    .Replace("$PORT", mc.ServerPort.ToString(), StringComparison.OrdinalIgnoreCase);
                string ext = Path.GetExtension(mc.ServerFile).ToLowerInvariant();
                var psi = ext is ".bat" or ".cmd" && OperatingSystem.IsWindows()
                    ? new ProcessStartInfo("cmd.exe", $"/c \"{mc.ServerFile}\" {args}")
                    : new ProcessStartInfo(mc.ServerFile, args);
                psi.WorkingDirectory = Path.GetDirectoryName(mc.ServerFile) ?? "";
                psi.UseShellExecute = ext is not (".exe" or ".bat" or ".cmd");
                var proc = Process.Start(psi);
                if (proc == null) { message = "Could not start the server"; return false; }
                Running[game] = proc;
                message = "Dedicated server started";
                return true;
            }
            catch (Exception ex) { message = "Could not start the server: " + ex.Message; return false; }
        }

        public static void Stop(string game)
        {
            if (!Running.TryRemove(game, out var p)) return;
            try { if (!p.HasExited) p.Kill(true); } catch { }
            p.Dispose();
        }
    }
}
