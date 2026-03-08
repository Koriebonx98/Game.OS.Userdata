namespace GameOS.Desktop.Models;

public class User
{
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string CreatedAt { get; set; } = "";
    public string? ApiToken { get; set; }
    public string? ApiTokenIssuedAt { get; set; }
}
