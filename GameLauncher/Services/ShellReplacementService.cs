using System;
using System.Diagnostics;

namespace GameLauncher.Services;

/// <summary>
/// Switches the current Windows user's shell between Explorer and Game OS via
/// <c>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</c>.
/// Removing the per-user value makes Windows fall back to the machine default (explorer.exe).
/// </summary>
public static class ShellReplacementService
{
    private const string WinlogonKey = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string ValueName   = "Shell";

    public static bool IsSupported => OperatingSystem.IsWindows();

    /// <summary>True when the per-user shell points at this launcher.</summary>
    public static bool IsEnabled()
    {
        if (!IsSupported) return false;
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(WinlogonKey);
            var value = key?.GetValue(ValueName) as string;
            return !string.IsNullOrWhiteSpace(value)
                && value.IndexOf("explorer.exe", StringComparison.OrdinalIgnoreCase) < 0;
        }
        catch { return false; }
    }

    /// <summary>Sets Game OS as the shell (<paramref name="enable"/>) or reverts to Explorer. Returns an error message or null.</summary>
    public static string? SetEnabled(bool enable)
    {
        if (!IsSupported) return "Shell replacement is only available on Windows.";
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(WinlogonKey, writable: true);
            if (key == null) return "Could not open the Winlogon registry key.";
            if (enable)
            {
                var exe = Environment.ProcessPath;
                if (string.IsNullOrEmpty(exe)) return "Could not determine the launcher path.";
                key.SetValue(ValueName, "\"" + exe + "\"", Microsoft.Win32.RegistryValueKind.String);
            }
            else
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
            }
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    /// <summary>Restarts Windows so the new shell takes effect.</summary>
    public static void RestartWindows()
    {
        if (!IsSupported) return;
        try
        {
            Process.Start(new ProcessStartInfo("shutdown", "/r /t 5 /c \"Game OS shell change\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            });
        }
        catch { /* user can restart manually */ }
    }
}
