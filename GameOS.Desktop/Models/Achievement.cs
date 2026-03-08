namespace GameOS.Desktop.Models;

public class Achievement
{
    public string Platform { get; set; } = "";
    public string GameTitle { get; set; } = "";
    public string AchievementId { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string? UnlockedAt { get; set; }
}
