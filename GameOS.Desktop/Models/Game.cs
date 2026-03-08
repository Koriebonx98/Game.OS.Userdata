namespace GameOS.Desktop.Models;

public class Game
{
    public string Platform { get; set; } = "";
    public string Title { get; set; } = "";
    public string? TitleId { get; set; }
    public string? CoverUrl { get; set; }
    public string AddedAt { get; set; } = "";
}
