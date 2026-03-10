using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace GameLauncher.Models
{
    public class UserProfile
    {
        [JsonPropertyName("username")]            public string  Username     { get; set; } = "";
        [JsonPropertyName("email")]               public string  Email        { get; set; } = "";
        [JsonPropertyName("password_hash")]       public string  PasswordHash { get; set; } = "";
        [JsonPropertyName("created_at")]          public string  CreatedAt    { get; set; } = "";
        [JsonPropertyName("api_token_issued_at")] public string? TokenIssuedAt{ get; set; }
    }

    public class Game
    {
        [JsonPropertyName("platform")]           public string        Platform           { get; set; } = "";
        [JsonPropertyName("title")]              public string        Title              { get; set; } = "";
        [JsonPropertyName("titleId")]            public string?       TitleId            { get; set; }
        [JsonPropertyName("coverUrl")]           public string?       CoverUrl           { get; set; }
        [JsonPropertyName("screenshots")]        public List<string>? Screenshots        { get; set; }
        [JsonPropertyName("addedAt")]            public string        AddedAt            { get; set; } = "";
        [JsonPropertyName("genre")]              public string?       Genre              { get; set; }
        [JsonPropertyName("description")]        public string?       Description        { get; set; }
        [JsonPropertyName("rating")]             public double?       Rating             { get; set; }
        [JsonPropertyName("price")]              public string?       Price              { get; set; }
        [JsonPropertyName("mods")]               public List<ModLink>? Mods              { get; set; }
        [JsonPropertyName("sysSpecMin")]         public SystemSpec?   SysSpecMin         { get; set; }
        [JsonPropertyName("sysSpecRecommended")] public SystemSpec?   SysSpecRecommended { get; set; }
        [JsonPropertyName("achievementsUrl")]    public string?       AchievementsUrl    { get; set; }
        [JsonPropertyName("trailerUrl")]         public string?       TrailerUrl         { get; set; }
        // UI-only (not persisted) – enriched from demo data
        [JsonIgnore] public string?  CoverColor    { get; set; }
        [JsonIgnore] public string?  CoverGradient { get; set; }
        // UI-only – per-game achievements loaded from AchievementsUrl / passed at login
        [JsonIgnore] public List<Achievement>? GameAchievements { get; set; }
        [JsonIgnore] public string   RatingStars   =>
            Rating.HasValue ? new string('★', (int)System.Math.Round(Rating.Value / 2.0))
                              + new string('☆', 5 - (int)System.Math.Round(Rating.Value / 2.0)) : "—";
    }

    public class ModLink
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("url")]  public string Url  { get; set; } = "";
    }

    public class SystemSpec
    {
        [JsonPropertyName("cpu")]    public string? Cpu    { get; set; }
        [JsonPropertyName("gpu")]    public string? Gpu    { get; set; }
        [JsonPropertyName("ram")]    public string? Ram    { get; set; }
        [JsonPropertyName("os")]     public string? Os     { get; set; }
        [JsonPropertyName("storage")]public string? Storage{ get; set; }
    }

    public class Achievement
    {
        [JsonPropertyName("platform")]      public string  Platform      { get; set; } = "";
        [JsonPropertyName("gameTitle")]     public string  GameTitle     { get; set; } = "";
        [JsonPropertyName("achievementId")] public string  AchievementId { get; set; } = "";
        [JsonPropertyName("name")]          public string  Name          { get; set; } = "";
        [JsonPropertyName("description")]   public string  Description   { get; set; } = "";
        [JsonPropertyName("unlockedAt")]    public string  UnlockedAt    { get; set; } = "";
        /// <summary>Achievement icon image URL from the real Games.Database.</summary>
        [JsonIgnore] public string? IconUrl { get; set; }
    }

    public class FriendRequest
    {
        [JsonPropertyName("from")]   public string From   { get; set; } = "";
        [JsonPropertyName("sentAt")] public string SentAt { get; set; } = "";
    }

    public class Message
    {
        [JsonPropertyName("from")]   public string From   { get; set; } = "";
        [JsonPropertyName("text")]   public string Text   { get; set; } = "";
        [JsonPropertyName("sentAt")] public string SentAt { get; set; } = "";
    }

    public class ActivityEntry
    {
        [JsonPropertyName("platform")]      public string  Platform      { get; set; } = "";
        [JsonPropertyName("gameTitle")]     public string  GameTitle     { get; set; } = "";
        [JsonPropertyName("titleId")]       public string? TitleId       { get; set; }
        [JsonPropertyName("sessionStart")]  public string  SessionStart  { get; set; } = "";
        [JsonPropertyName("sessionEnd")]    public string? SessionEnd    { get; set; }
        [JsonPropertyName("minutesPlayed")] public int     MinutesPlayed { get; set; }
        [JsonPropertyName("loggedAt")]      public string  LoggedAt      { get; set; } = "";
    }

    public class PresenceData
    {
        [JsonPropertyName("username")] public string? Username { get; set; }
        [JsonPropertyName("lastSeen")] public string? LastSeen { get; set; }
    }

    /// <summary>A friend displayed in the Friends screen, populated from presence API.</summary>
    public class FriendEntry
    {
        public string Username      { get; set; } = "";
        /// <summary>First character of Username, upper-cased, for the avatar circle.</summary>
        public string AvatarInitial =>
            Username.Length > 0 ? Username[0].ToString().ToUpper() : "?";
        /// <summary>Online / Away / Offline, derived from lastSeen timestamp.</summary>
        public string Status        { get; set; } = "Offline";
        public string LastSeen      { get; set; } = "Unknown";
        public bool   IsOnline      => Status == "Online";
        public bool   IsAway        => Status == "Away";
    }

    /// <summary>An incoming friend request shown in the Friends screen.</summary>
    public class FriendRequestDisplay
    {
        public string FromUsername  { get; set; } = "";
        public string AvatarInitial =>
            FromUsername.Length > 0 ? FromUsername[0].ToString().ToUpper() : "?";
        public string SentAgo       { get; set; } = "";
    }

    /// <summary>Session data saved locally so players can stay logged in.</summary>
    public class SavedSession
    {
        public string Username    { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string AvatarColor { get; set; } = "#1e90ff";
        public string SavedAt     { get; set; } = "";
    }

    /// <summary>A locally installed game detected by scanning drives.</summary>
    public class LocalGame
    {
        public string Title          { get; set; } = "";
        public string ExecutablePath { get; set; } = "";
        public string DriveRoot      { get; set; } = "";
        public string FolderPath     { get; set; } = "";
        public string ExecutableType { get; set; } = ""; // "exe", "app", "elf"
        /// <summary>All drive locations where this game was found (populated when same title exists on multiple drives).</summary>
        public List<LocalGameDriveEntry> DriveInstances { get; set; } = new();
        [JsonIgnore] public bool HasMultipleDrives => DriveInstances.Count > 1;
        [JsonIgnore] public string DriveCountLabel => $"{DriveInstances.Count} drives";
    }

    /// <summary>A repack archive found in a Repacks directory, ready to install.</summary>
    public class LocalRepack
    {
        public string Title    { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string FileType { get; set; } = ""; // "zip", "rar", "folder"
        public long   SizeBytes{ get; set; }

        private string? _sizeLabel;
        public string SizeLabel =>
            _sizeLabel ??=
                SizeBytes >= 1_073_741_824 ? $"{SizeBytes / 1_073_741_824.0:F1} GB" :
                SizeBytes >= 1_048_576     ? $"{SizeBytes / 1_048_576.0:F0} MB"     :
                SizeBytes >= 1_024         ? $"{SizeBytes / 1_024.0:F0} KB"         :
                $"{SizeBytes} B";
    }

    /// <summary>A store entry shown in the Games Store screen.</summary>
    public class StoreGame
    {
        public string        Title           { get; set; } = "";
        public string        Platform        { get; set; } = "";
        public string        Genre           { get; set; } = "";
        public string        Price           { get; set; } = "";
        public double        Rating          { get; set; }
        public string        Description     { get; set; } = "";
        public bool          IsFeatured      { get; set; }
        public string        ReleaseYear     { get; set; } = "";
        public string        CoverColor      { get; set; } = "#1e1b4b";
        public string        CoverGradient   { get; set; } = "#1e1b4b,#312e81";
        public string?       CoverUrl        { get; set; }
        public List<string>? Screenshots     { get; set; }
        /// <summary>YouTube trailer URL from the real Games.Database.</summary>
        public string?       TrailerUrl      { get; set; }
        /// <summary>Link to the achievements JSON file in the Games.Database.</summary>
        public string?       AchievementsUrl { get; set; }
        public string        RatingStars     =>
            new string('★', (int)System.Math.Round(Rating / 2.0))
            + new string('☆', 5 - (int)System.Math.Round(Rating / 2.0));
    }

    /// <summary>One drive location where a LocalGame was found.</summary>
    public class LocalGameDriveEntry
    {
        public string DriveRoot      { get; set; } = "";
        public string FolderPath     { get; set; } = "";
        public string ExecutablePath { get; set; } = "";
        public string ExecutableType { get; set; } = "";
    }

    /// <summary>A game entry from the public Koriebonx98/Games.Database repository.</summary>
    public class DatabaseGame
    {
        [JsonPropertyName("Title")]    public string? Title   { get; set; }
        [JsonPropertyName("TitleID")]  public string? TitleId { get; set; }
        [JsonPropertyName("CoverUrl")] public string? CoverUrl { get; set; }
        [JsonPropertyName("appid")]    public long?   AppId   { get; set; }
    }
}
