using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace GameLauncher.Services
{
    /// <summary>A named, ordered list of song files.</summary>
    public sealed class MediaPlaylist
    {
        public string Name { get; set; } = "";
        public List<string> Paths { get; set; } = new();
    }

    /// <summary>Saves the user's music playlists to <c>Data\{user}\Media\playlists.json</c>.</summary>
    public static class MediaPlaylistService
    {
        private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
        private static string File_ => Path.Combine(MediaStatsService.DataDir, "playlists.json");

        public static List<MediaPlaylist> Load()
        {
            try
            {
                return File.Exists(File_)
                    ? JsonSerializer.Deserialize<List<MediaPlaylist>>(File.ReadAllText(File_)) ?? new()
                    : new();
            }
            catch (Exception ex) { DevLogService.Log($"[MediaPlaylists] Read failed: {ex.Message}"); return new(); }
        }

        public static void Save(List<MediaPlaylist> playlists)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(File_)!);
                var tmp = File_ + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(playlists, Json));
                File.Move(tmp, File_, overwrite: true);
            }
            catch (Exception ex) { DevLogService.Log($"[MediaPlaylists] Write failed: {ex.Message}"); }
        }
    }
}
