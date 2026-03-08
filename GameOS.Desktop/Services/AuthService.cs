using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using GameOS.Desktop.Models;

namespace GameOS.Desktop.Services;

public class AuthService
{
    private const int Iterations = 100_000;
    private const int HashSize = 32;

    public static string HashPassword(string password, string username)
    {
        var salt = System.Text.Encoding.UTF8.GetBytes(username.ToLowerInvariant());
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return Convert.ToBase64String(hash);
    }

    public static async Task<(bool Success, string Error)> SignupAsync(string username, string email, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Length < 3)
            return (false, "Username must be at least 3 characters.");
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            return (false, "Please enter a valid email address.");
        if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
            return (false, "Password must be at least 6 characters.");

        var userDir = DataService.GetUserDataPath(username);
        var profilePath = Path.Combine(userDir, "profile.json");
        if (File.Exists(profilePath))
            return (false, "Username already taken.");

        var emailIndex = await GetEmailIndexAsync();
        if (emailIndex.ContainsKey(email.ToLowerInvariant()))
            return (false, "Email already registered.");

        var user = new User
        {
            Username = username,
            Email = email,
            PasswordHash = HashPassword(password, username),
            CreatedAt = DateTime.UtcNow.ToString("o")
        };

        await DataService.WriteJsonAsync(profilePath, user);

        emailIndex[email.ToLowerInvariant()] = username.ToLowerInvariant();
        var indexPath = Path.Combine(DataService.BaseDir, "accounts", "email-index.json");
        await DataService.WriteJsonAsync(indexPath, emailIndex);

        return (true, "");
    }

    public static async Task<(User? User, string Error)> LoginAsync(string emailOrUsername, string password)
    {
        if (string.IsNullOrWhiteSpace(emailOrUsername) || string.IsNullOrWhiteSpace(password))
            return (null, "Please fill in all fields.");

        string resolvedUsername;

        if (emailOrUsername.Contains('@'))
        {
            var emailIndex = await GetEmailIndexAsync();
            if (!emailIndex.TryGetValue(emailOrUsername.ToLowerInvariant(), out var u))
                return (null, "Invalid email or password.");
            resolvedUsername = u;
        }
        else
        {
            resolvedUsername = emailOrUsername.ToLowerInvariant();
        }

        var profilePath = Path.Combine(DataService.GetUserDataPath(resolvedUsername), "profile.json");
        var user = await DataService.ReadJsonAsync<User>(profilePath);
        if (user == null) return (null, "Invalid username or password.");

        var hash = HashPassword(password, user.Username);
        if (hash != user.PasswordHash)
            return (null, "Invalid username or password.");

        return (user, "");
    }

    public static async Task<(bool Success, string Error)> UpdateAccountAsync(
        string username, string currentPassword, string? newEmail, string? newPassword)
    {
        var profilePath = Path.Combine(DataService.GetUserDataPath(username), "profile.json");
        var user = await DataService.ReadJsonAsync<User>(profilePath);
        if (user == null) return (false, "User not found.");

        var hash = HashPassword(currentPassword, user.Username);
        if (hash != user.PasswordHash)
            return (false, "Current password is incorrect.");

        if (!string.IsNullOrWhiteSpace(newEmail) && newEmail != user.Email)
        {
            if (!newEmail.Contains('@'))
                return (false, "Please enter a valid email address.");

            var emailIndex = await GetEmailIndexAsync();
            if (emailIndex.ContainsKey(newEmail.ToLowerInvariant()))
                return (false, "Email already in use.");

            emailIndex.Remove(user.Email.ToLowerInvariant());
            emailIndex[newEmail.ToLowerInvariant()] = username.ToLowerInvariant();
            var indexPath = Path.Combine(DataService.BaseDir, "accounts", "email-index.json");
            await DataService.WriteJsonAsync(indexPath, emailIndex);

            user.Email = newEmail;
        }

        if (!string.IsNullOrWhiteSpace(newPassword))
        {
            if (newPassword.Length < 6)
                return (false, "New password must be at least 6 characters.");
            user.PasswordHash = HashPassword(newPassword, user.Username);
        }

        await DataService.WriteJsonAsync(profilePath, user);
        return (true, "");
    }

    public static async Task<string> GenerateApiTokenAsync(string username)
    {
        var profilePath = Path.Combine(DataService.GetUserDataPath(username), "profile.json");
        var user = await DataService.ReadJsonAsync<User>(profilePath);
        if (user == null) return "";

        var randomHex = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        user.ApiToken = $"gos_{username.ToLowerInvariant()}.{randomHex}";
        user.ApiTokenIssuedAt = DateTime.UtcNow.ToString("o");
        await DataService.WriteJsonAsync(profilePath, user);
        return user.ApiToken;
    }

    public static async Task RevokeApiTokenAsync(string username)
    {
        var profilePath = Path.Combine(DataService.GetUserDataPath(username), "profile.json");
        var user = await DataService.ReadJsonAsync<User>(profilePath);
        if (user == null) return;

        user.ApiToken = null;
        user.ApiTokenIssuedAt = null;
        await DataService.WriteJsonAsync(profilePath, user);
    }

    public static async Task<User?> GetUserAsync(string username)
    {
        var profilePath = Path.Combine(DataService.GetUserDataPath(username), "profile.json");
        return await DataService.ReadJsonAsync<User>(profilePath);
    }

    private static async Task<Dictionary<string, string>> GetEmailIndexAsync()
    {
        var indexPath = Path.Combine(DataService.BaseDir, "accounts", "email-index.json");
        return await DataService.ReadJsonAsync<Dictionary<string, string>>(indexPath)
               ?? new Dictionary<string, string>();
    }
}
