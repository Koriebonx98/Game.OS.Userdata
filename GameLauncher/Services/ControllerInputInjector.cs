using System;
using System.Collections.Generic;
using GameLauncher.Models;

namespace GameLauncher.Services;

/// <summary>
/// Translates an active <see cref="ControllerProfile"/> button mapping into
/// Win32 <c>SendInput</c> keystrokes forwarded to the current foreground window
/// (the running game).
///
/// Action string format (mirrors the Game.OS.Input companion app):
///   "Empty"             — no action
///   "Key:Enter"         — send a single keystroke
///   "Key:Ctrl+Alt+Del"  — send a key combo (modifiers pressed before the final key)
///
/// All public methods are no-ops on non-Windows platforms.
/// </summary>
public sealed class ControllerInputInjector
{
    private ControllerProfile? _profile;

    /// <summary>Sets the profile whose mappings will be used for injection.</summary>
    public void SetProfile(ControllerProfile? profile) => _profile = profile;

    /// <summary>
    /// Injects the <c>Press</c> action mapped to <paramref name="buttonName"/>
    /// into the current foreground window.
    /// </summary>
    public void InjectPress(string buttonName)
    {
        if (!OperatingSystem.IsWindows() || _profile == null) return;
        if (!_profile.Mappings.TryGetValue(buttonName, out var action)) return;
        Inject(action.Press);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void Inject(string? actionSpec)
    {
        if (string.IsNullOrWhiteSpace(actionSpec) ||
            string.Equals(actionSpec, "Empty", StringComparison.OrdinalIgnoreCase))
            return;

        if (actionSpec.StartsWith("Key:", StringComparison.OrdinalIgnoreCase))
        {
            string keySpec = actionSpec[4..];
            var vks = ParseKeyCombo(keySpec);
            if (vks.Length > 0)
                NativeMethods.SendKeyCombo(vks);
        }
        // Mouse and Launch actions are intentionally not injected here —
        // they require additional context (cursor position, process path) that
        // the injector does not have at this call site.
    }

    /// <summary>
    /// Parses a key-name string (e.g. "Ctrl+Shift+Esc" or "Enter") into an
    /// array of Win32 Virtual Key codes suitable for passing to <see cref="NativeMethods.SendKeyCombo"/>.
    /// Returns an empty array for unrecognised key names.
    /// </summary>
    public static ushort[] ParseKeyCombo(string keySpec)
    {
        var parts = keySpec.Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = new List<ushort>(parts.Length);
        foreach (var part in parts)
        {
            ushort vk = NameToVk(part);
            if (vk != 0) result.Add(vk);
        }
        return result.ToArray();
    }

    private static ushort NameToVk(string name) => name.ToUpperInvariant() switch
    {
        // ── Modifiers ────────────────────────────────────────────────────────
        "CTRL"   or "CONTROL"           => 0xA2, // VK_LCONTROL
        "RCTRL"  or "RCONTROL"          => 0xA3, // VK_RCONTROL
        "SHIFT"  or "LSHIFT"            => 0xA0, // VK_LSHIFT
        "RSHIFT"                         => 0xA1, // VK_RSHIFT
        "ALT"    or "MENU"              => 0x12, // VK_MENU (generic Alt)
        "LALT"                           => 0xA4, // VK_LMENU
        "RALT"   or "ALTGR"             => 0xA5, // VK_RMENU
        "WIN"    or "LWIN"              => 0x5B, // VK_LWIN
        "RWIN"                           => 0x5C, // VK_RWIN

        // ── Navigation ───────────────────────────────────────────────────────
        "ENTER"  or "RETURN"            => 0x0D,
        "ESCAPE" or "ESC"               => 0x1B,
        "SPACE"  or "SPACEBAR"          => 0x20,
        "TAB"                            => 0x09,
        "BACKSPACE" or "BACK"           => 0x08,
        "DELETE" or "DEL"               => 0x2E,
        "INSERT" or "INS"               => 0x2D,
        "HOME"                           => 0x24,
        "END"                            => 0x23,
        "PAGEUP" or "PGUP"              => 0x21,
        "PAGEDOWN" or "PGDN"            => 0x22,
        "LEFT"                           => 0x25,
        "UP"                             => 0x26,
        "RIGHT"                          => 0x27,
        "DOWN"                           => 0x28,
        "PRINTSCREEN" or "PRTSCN"       => 0x2C,
        "PAUSE"                          => 0x13,
        "CAPSLOCK" or "CAPS"            => 0x14,
        "NUMLOCK"                        => 0x90,
        "SCROLLLOCK"                     => 0x91,

        // ── Function keys ────────────────────────────────────────────────────
        "F1"  => 0x70, "F2"  => 0x71, "F3"  => 0x72, "F4"  => 0x73,
        "F5"  => 0x74, "F6"  => 0x75, "F7"  => 0x76, "F8"  => 0x77,
        "F9"  => 0x78, "F10" => 0x79, "F11" => 0x7A, "F12" => 0x7B,

        // ── Alpha keys ───────────────────────────────────────────────────────
        "A" => 0x41, "B" => 0x42, "C" => 0x43, "D" => 0x44, "E" => 0x45,
        "F" => 0x46, "G" => 0x47, "H" => 0x48, "I" => 0x49, "J" => 0x4A,
        "K" => 0x4B, "L" => 0x4C, "M" => 0x4D, "N" => 0x4E, "O" => 0x4F,
        "P" => 0x50, "Q" => 0x51, "R" => 0x52, "S" => 0x53, "T" => 0x54,
        "U" => 0x55, "V" => 0x56, "W" => 0x57, "X" => 0x58, "Y" => 0x59,
        "Z" => 0x5A,

        // ── Digit keys ───────────────────────────────────────────────────────
        "0" => 0x30, "1" => 0x31, "2" => 0x32, "3" => 0x33, "4" => 0x34,
        "5" => 0x35, "6" => 0x36, "7" => 0x37, "8" => 0x38, "9" => 0x39,

        // ── Numpad ───────────────────────────────────────────────────────────
        "NUMPAD0" => 0x60, "NUMPAD1" => 0x61, "NUMPAD2" => 0x62,
        "NUMPAD3" => 0x63, "NUMPAD4" => 0x64, "NUMPAD5" => 0x65,
        "NUMPAD6" => 0x66, "NUMPAD7" => 0x67, "NUMPAD8" => 0x68,
        "NUMPAD9" => 0x69,

        _ => 0
    };
}
