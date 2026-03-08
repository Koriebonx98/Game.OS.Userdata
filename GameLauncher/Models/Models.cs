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
        [JsonPropertyName("addedAt")]            public string        AddedAt            { get; set; } = "";
        [JsonPropertyName("genre")]              public string?       Genre              { get; set; }
        [JsonPropertyName("description")]        public string?       Description        { get; set; }
        [JsonPropertyName("rating")]             public double?       Rating             { get; set; }
        [JsonPropertyName("price")]              public string?       Price              { get; set; }
        [JsonPropertyName("mods")]               public List<ModLink>? Mods              { get; set; }
        [JsonPropertyName("sysSpecMin")]         public SystemSpec?   SysSpecMin         { get; set; }
        [JsonPropertyName("sysSpecRecommended")] public SystemSpec?   SysSpecRecommended { get; set; }
        [JsonPropertyName("achievementsUrl")]    public string?       AchievementsUrl    { get; set; }
        // UI-only (not persisted) – enriched from demo data
        [JsonIgnore] public string?  CoverColor    { get; set; }
        [JsonIgnore] public string?  CoverGradient { get; set; }
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
        [JsonPropertyName("platform")]      public string Platform      { get; set; } = "";
        [JsonPropertyName("gameTitle")]     public string GameTitle     { get; set; } = "";
        [JsonPropertyName("achievementId")] public string AchievementId { get; set; } = "";
        [JsonPropertyName("name")]          public string Name          { get; set; } = "";
        [JsonPropertyName("description")]   public string Description   { get; set; } = "";
        [JsonPropertyName("unlockedAt")]    public string UnlockedAt    { get; set; } = "";
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

    /// <summary>Session data saved locally so players can stay logged in.</summary>
    public class SavedSession
    {
        public string Username    { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string AvatarColor { get; set; } = "#1e90ff";
        public string SavedAt     { get; set; } = "";
    }

    /// <summary>A store entry shown in the Games Store screen.</summary>
    public class StoreGame
    {
        public string   Title         { get; set; } = "";
        public string   Platform      { get; set; } = "";
        public string   Genre         { get; set; } = "";
        public string   Price         { get; set; } = "";
        public double   Rating        { get; set; }
        public string   Description   { get; set; } = "";
        public bool     IsFeatured    { get; set; }
        public string   ReleaseYear   { get; set; } = "";
        public string   CoverColor    { get; set; } = "#1e1b4b";
        public string   CoverGradient { get; set; } = "#1e1b4b,#312e81";
        public string   RatingStars   =>
            new string('★', (int)System.Math.Round(Rating / 2.0))
            + new string('☆', 5 - (int)System.Math.Round(Rating / 2.0));
    }
}
