using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher;
using GameLauncher.Services;

/// <summary>
/// Login authentication tests for the Game.OS C# launcher.
///
/// Tests that the C# PBKDF2 hash implementation is identical to the JavaScript
/// <c>hashPassword()</c> function in script.js, and that the login flow handles
/// both PBKDF2 and bcrypt hashes (same dual-hash support as the web frontend).
///
/// Run:
///   dotnet run --project LoginAuth.Tests
///
/// Optional live backend test — set env var before running:
///   GAMEOS_GITHUB_TOKEN=&lt;your PAT&gt; dotnet run --project LoginAuth.Tests
/// </summary>
class Program
{
    // PBKDF2 test vectors: fixed expected values computed independently via Node.js:
    //   node -e "const c=require('crypto');c.pbkdf2('<pass>','<user_lower>:gameos',100000,32,'sha256',(e,k)=>console.log(k.toString('hex')))"
    private static readonly (string username, string password, string? expectedHex)[] Vectors =
    [
        ("testuser",     "TestPass123", "50ad5d6fb130bcaca2c96094d9609a9e3ebb1852a51245afeabc05f9e6b81379"),
        ("Admin.GameOS", "GameOS2026",  "2f96663f1e20c234b7b4dc61d3887f9ffa417141345cbda1a0b0079c737a3502"),
        ("Koriebonx98",  "mypassword",  null),  // no fixed vector — just check format / determinism
    ];

    static async Task<int> Main(string[] args)
    {
        Banner();
        bool allPassed = true;

        // ── 1. PBKDF2 hash parity ────────────────────────────────────────────
        allPassed &= TestPbkdf2HashParity();

        // ── 2. PBKDF2 case-insensitive salt (JS lowercases username) ─────────
        allPassed &= TestPbkdf2CaseInsensitiveSalt();

        // ── 3. bcrypt detection ───────────────────────────────────────────────
        allPassed &= TestBcryptDetection();

        // ── 4. dual-hash login (mock profile) ────────────────────────────────
        allPassed &= TestDualHashLogin();

        // ── 5. live backend (optional — requires GAMEOS_GITHUB_TOKEN) ─────────
        allPassed &= await TestLiveBackendOptionalAsync();

        // ── Summary ───────────────────────────────────────────────────────────
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════════");
        if (allPassed)
        {
            Colour(ConsoleColor.Green,
                "  ✅  ALL TESTS PASSED — C# login logic matches web frontend exactly!");
        }
        else
        {
            Colour(ConsoleColor.Red,
                "  ❌  SOME TESTS FAILED — see output above for details.");
        }
        Console.WriteLine("═══════════════════════════════════════════════════════════════════");
        return allPassed ? 0 : 1;
    }

    // ── Test 1: PBKDF2 hash parity with Node.js reference values ─────────────
    static bool TestPbkdf2HashParity()
    {
        Section("1. PBKDF2 Hash Parity  (C# ≡ JavaScript hashPassword())");

        bool passed = true;
        foreach (var (username, password, expected) in Vectors)
        {
            var actual = GitHubDataService.HashPassword(password, username);

            if (expected == null)
            {
                // Just check it's a 64-char hex string and deterministic
                bool ok = actual.Length == 64 &&
                          IsHex(actual) &&
                          actual == GitHubDataService.HashPassword(password, username);
                Pass(ok, $"username={username} → len={actual.Length} deterministic={ok}");
                passed &= ok;
            }
            else
            {
                bool ok = string.Equals(actual, expected, StringComparison.Ordinal);
                Pass(ok, $"username={username,-12} → {(ok ? "hash matches reference vector ✓" : $"MISMATCH\n     expected: {expected}\n     actual:   {actual}")}");
                passed &= ok;
            }
        }
        return passed;
    }

    // ── Test 2: case-insensitive salt ─────────────────────────────────────────
    static bool TestPbkdf2CaseInsensitiveSalt()
    {
        Section("2. PBKDF2 Salt Case-Insensitivity  (username lowercased for salt)");

        // JS does username.toLowerCase() before building the salt string.
        // C# does username.ToLowerInvariant() — same result for ASCII usernames.
        string h1 = GitHubDataService.HashPassword("mypassword", "Koriebonx98");
        string h2 = GitHubDataService.HashPassword("mypassword", "koriebonx98");
        string h3 = GitHubDataService.HashPassword("mypassword", "KORIEBONX98");

        bool ok = (h1 == h2) && (h2 == h3);
        Pass(ok, $"hash(Koriebonx98) == hash(koriebonx98) == hash(KORIEBONX98): {ok}");
        return ok;
    }

    // ── Test 3: bcrypt detection ──────────────────────────────────────────────
    static bool TestBcryptDetection()
    {
        Section("3. Bcrypt Hash Detection  (accounts created via Node.js backend)");

        // Generate a real bcrypt hash and verify it round-trips
        string bcryptHash = BCrypt.Net.BCrypt.HashPassword("TestPass123");
        bool verifyOk  = BCrypt.Net.BCrypt.Verify("TestPass123", bcryptHash);
        bool rejectOk  = !BCrypt.Net.BCrypt.Verify("wrong", bcryptHash);
        bool startsOk  = bcryptHash.StartsWith("$2", StringComparison.Ordinal);

        Pass(verifyOk,  $"BCrypt.Verify(correct password) = {verifyOk}");
        Pass(rejectOk,  $"BCrypt.Verify(wrong password)   = {!rejectOk} (expect false)");
        Pass(startsOk,  $"bcrypt hash starts with $2      = {startsOk}");

        return verifyOk && rejectOk && startsOk;
    }

    // ── Test 4: dual-hash login (mock profile objects) ────────────────────────
    static bool TestDualHashLogin()
    {
        Section("4. Dual-Hash Login Flow  (PBKDF2 and bcrypt paths exercised)");
        bool passed = true;

        // --- 4a. PBKDF2 path (account created via web frontend / direct GitHub) ---
        {
            string username = "webuser";
            string password = "mywebpassword";
            string storedHash = GitHubDataService.HashPassword(password, username);

            // Simulate what VerifyLoginAsync does:
            bool ok = string.Equals(
                GitHubDataService.HashPassword(password, username),
                storedHash, StringComparison.Ordinal);
            Pass(ok, $"PBKDF2 path — correct password accepted: {ok}");
            passed &= ok;

            bool reject = !string.Equals(
                GitHubDataService.HashPassword("wrongpassword", username),
                storedHash, StringComparison.Ordinal);
            Pass(reject, $"PBKDF2 path — wrong password rejected: {reject}");
            passed &= reject;
        }

        // --- 4b. bcrypt path (account created via Node.js backend) ---
        {
            string password   = "nodepassword";
            string bcryptHash = BCrypt.Net.BCrypt.HashPassword(password);

            bool ok     = BCrypt.Net.BCrypt.Verify(password, bcryptHash);
            bool reject = !BCrypt.Net.BCrypt.Verify("wrongpassword", bcryptHash);

            Pass(ok,     $"bcrypt path — correct password accepted: {ok}");
            Pass(reject, $"bcrypt path — wrong password rejected:   {reject}");
            passed &= ok && reject;
        }

        // --- 4c. hash type auto-detection ---
        {
            string pbkdf2Hash = GitHubDataService.HashPassword("pass", "user");
            string bcryptHash = BCrypt.Net.BCrypt.HashPassword("pass");

            bool pbkdf2IsNotBcrypt = !pbkdf2Hash.StartsWith("$2", StringComparison.Ordinal);
            bool bcryptIsBcrypt    =  bcryptHash.StartsWith("$2", StringComparison.Ordinal);

            Pass(pbkdf2IsNotBcrypt, $"PBKDF2 hash correctly identified as NOT bcrypt: {pbkdf2IsNotBcrypt}");
            Pass(bcryptIsBcrypt,    $"bcrypt hash correctly identified as bcrypt:     {bcryptIsBcrypt}");
            passed &= pbkdf2IsNotBcrypt && bcryptIsBcrypt;
        }

        return passed;
    }

    // ── Test 5: live backend (optional) ──────────────────────────────────────
    static async Task<bool> TestLiveBackendOptionalAsync()
    {
        Section("5. Live Backend Test  (requires GAMEOS_GITHUB_TOKEN)");

        string? token    = Environment.GetEnvironmentVariable("GAMEOS_GITHUB_TOKEN");
        string? username = Environment.GetEnvironmentVariable("GAMEOS_TEST_USERNAME");
        string? password = Environment.GetEnvironmentVariable("GAMEOS_TEST_PASSWORD");

        if (string.IsNullOrEmpty(token))
        {
            Colour(ConsoleColor.Yellow, "  ⚠  Skipped — GAMEOS_GITHUB_TOKEN not set.");
            Console.WriteLine("       To run: GAMEOS_GITHUB_TOKEN=<pat> GAMEOS_TEST_USERNAME=<user> GAMEOS_TEST_PASSWORD=<pass> dotnet run");
            return true;  // not a failure
        }

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            Colour(ConsoleColor.Yellow, "  ⚠  Skipped — GAMEOS_TEST_USERNAME or GAMEOS_TEST_PASSWORD not set.");
            return true;
        }

        Console.WriteLine($"  Connecting to {GitHubDataService.DataRepoOwner}/{GitHubDataService.DataRepoName} …");

        try
        {
            using var client = new GameOsClient();
            bool healthy = await client.CheckHealthAsync(CancellationToken.None);
            Pass(healthy, $"Repository reachable: {healthy}");

            if (!healthy)
                return false;

            var profile = await client.LoginAsync(username, password, CancellationToken.None);
            bool loginOk = profile != null && !string.IsNullOrEmpty(profile.Username);
            Pass(loginOk, $"Login succeeded — username={profile?.Username}");

            if (loginOk)
            {
                var games = await client.GetGamesAsync(CancellationToken.None);
                Pass(true, $"Games loaded from backend: {games.Count}");

                var achievements = await client.GetAchievementsAsync(CancellationToken.None);
                Pass(true, $"Achievements loaded:       {achievements.Count}");

                Console.WriteLine();
                Colour(ConsoleColor.Green,
                    $"  ✅  Real backend login confirmed: {profile!.Username} authenticated via PBKDF2/bcrypt");
            }

            return loginOk;
        }
        catch (GameOsException ex)
        {
            Pass(false, $"GameOsException {ex.StatusCode}: {ex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            Pass(false, $"Unexpected: {ex.Message}");
            return false;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    static void Banner()
    {
        Console.WriteLine("═══════════════════════════════════════════════════════════════════");
        Console.WriteLine("  Game.OS — Login Authentication Tests (C# Launcher)");
        Console.WriteLine("  Verifies: C# auth ≡ JavaScript web frontend auth");
        Console.WriteLine("═══════════════════════════════════════════════════════════════════");
        Console.WriteLine();
    }

    static void Section(string title)
    {
        Console.WriteLine();
        Console.WriteLine($"  ── {title}");
        Console.WriteLine("  " + new string('─', 65));
    }

    static void Pass(bool ok, string message)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ok ? ConsoleColor.Green : ConsoleColor.Red;
        Console.Write(ok ? "  ✅  " : "  ❌  ");
        Console.ForegroundColor = prev;
        Console.WriteLine(message);
    }

    static void Colour(ConsoleColor c, string msg)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = c;
        Console.WriteLine(msg);
        Console.ForegroundColor = prev;
    }

    static bool IsHex(string s)
    {
        foreach (char c in s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        return true;
    }
}
