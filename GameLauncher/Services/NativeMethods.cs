using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace GameLauncher.Services;

/// <summary>
/// Minimal Win32 P/Invoke declarations used to bring a game window to the foreground
/// when the user clicks "Resume" on the game detail overlay.
/// All calls are guarded by <see cref="OperatingSystem.IsWindows"/> at the call site.
/// </summary>
internal static class NativeMethods
{
    /// <summary>Restores a minimised window to its normal or maximised state.</summary>
    internal const int SW_RESTORE = 9;
    internal const int VK_LCONTROL = 0xA2;
    internal const int VK_LSHIFT = 0xA0;
    internal const int VK_LEFT = 0x25;
    internal const int VK_UP = 0x26;
    internal const int VK_RIGHT = 0x27;
    internal const int VK_DOWN = 0x28;
    internal const int VK_RETURN = 0x0D;
    internal const int VK_SPACE = 0x20;
    internal const int VK_ESCAPE = 0x1B;
    internal const ushort VK_MEDIA_NEXT_TRACK = 0xB0;
    internal const ushort VK_MEDIA_PREV_TRACK = 0xB1;
    internal const ushort VK_MEDIA_PLAY_PAUSE = 0xB3;
    // PrintScreen key
    internal const ushort VK_SNAPSHOT = 0x2C;
    internal const ushort VK_LWIN     = 0x5B;
    internal const ushort VK_MENU     = 0x12; // Alt

    // SetWindowPos flags
    internal const uint SWP_NOMOVE     = 0x0002;
    internal const uint SWP_NOSIZE     = 0x0001;
    internal const uint SWP_NOACTIVATE = 0x0010;
    internal const uint SWP_SHOWWINDOW = 0x0040;

    /// <summary>Sentinel HWND that places a window above all non-topmost windows.</summary>
    internal static readonly nint HWND_TOPMOST = new nint(-1);

    private const int INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    [DllImport("user32.dll", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetForegroundWindow(nint hWnd);

    [DllImport("user32.dll", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ShowWindow(nint hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = false)]
    internal static extern short GetAsyncKeyState(int vKey);

    /// <summary>
    /// Changes the size, position, and Z-order of a window.
    /// Used to force an overlay window into the topmost Z-band at the Win32 level.
    /// </summary>
    [DllImport("user32.dll", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetWindowPos(nint hWnd, nint hWndInsertAfter,
        int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    internal static bool SendMediaKey(ushort virtualKey)
    {
        var inputs = new INPUT[2];
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki = new KEYBDINPUT { wVk = virtualKey };
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].u.ki = new KEYBDINPUT { wVk = virtualKey, dwFlags = KEYEVENTF_KEYUP };

        uint sent = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        if (sent == 0)
        {
            int error = Marshal.GetLastWin32Error();
            System.Diagnostics.Debug.WriteLine($"[NativeMethods] SendInput failed (VK={virtualKey}, Win32Error={error}).");
            return false;
        }
        return true;
    }

    /// <summary>
    /// Presses a sequence of virtual keys simultaneously then releases them in reverse order.
    /// Used for key combinations like Ctrl+Shift+Esc or Win+Alt+PrintScreen.
    /// </summary>
    internal static bool SendKeyCombo(params ushort[] virtualKeys)
    {
        if (virtualKeys.Length == 0) return false;
        var inputs = new INPUT[virtualKeys.Length * 2];
        int sz = Marshal.SizeOf<INPUT>();
        for (int i = 0; i < virtualKeys.Length; i++)
        {
            inputs[i].type = INPUT_KEYBOARD;
            inputs[i].u.ki = new KEYBDINPUT { wVk = virtualKeys[i] };
        }
        for (int i = 0; i < virtualKeys.Length; i++)
        {
            int idx = virtualKeys.Length + i;
            inputs[idx].type = INPUT_KEYBOARD;
            // Release in reverse order
            inputs[idx].u.ki = new KEYBDINPUT
            {
                wVk = virtualKeys[virtualKeys.Length - 1 - i],
                dwFlags = KEYEVENTF_KEYUP
            };
        }
        return SendInput((uint)inputs.Length, inputs, sz) > 0;
    }

    /// <summary>
    /// Sends a Win+Alt+PrintScreen keystroke combo (Xbox app screenshot).
    /// </summary>
    internal static void TakeScreenshot()
    {
        if (!OperatingSystem.IsWindows()) return;
        SendKeyCombo(VK_LWIN, VK_MENU, VK_SNAPSHOT);
    }

    /// <summary>
    /// Sends a single virtual key down+up to the current foreground window.
    /// </summary>
    internal static bool SendSingleKey(ushort virtualKey)
    {
        var inputs = new INPUT[2];
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki = new KEYBDINPUT { wVk = virtualKey };
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].u.ki = new KEYBDINPUT { wVk = virtualKey, dwFlags = KEYEVENTF_KEYUP };
        return SendInput(2, inputs, Marshal.SizeOf<INPUT>()) > 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public int type;
        public InputUnion u;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public nint dwExtraInfo;
    }

    // ── XInput ───────────────────────────────────────────────────────────────

    /// <summary>XInput Guide/Home button flag (0x0400) present in the extended state.</summary>
    internal const ushort XInputGuideMask = 0x0400;

    /// <summary>
    /// Snapshot of an XInput controller's button / axis state.
    /// Matches the XINPUT_GAMEPAD Win32 structure exactly.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct XINPUT_GAMEPAD
    {
        public ushort wButtons;
        public byte   bLeftTrigger;
        public byte   bRightTrigger;
        public short  sThumbLX;
        public short  sThumbLY;
        public short  sThumbRX;
        public short  sThumbRY;
    }

    /// <summary>
    /// Matches the XINPUT_STATE Win32 structure exactly.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct XINPUT_STATE
    {
        public uint          dwPacketNumber;
        public XINPUT_GAMEPAD Gamepad;
    }

    /// <summary>
    /// Retrieves the current state of the specified XInput controller.
    /// Returns 0 (ERROR_SUCCESS) when a controller is connected,
    /// or 1167 (ERROR_DEVICE_NOT_CONNECTED) otherwise.
    /// xinput1_4.dll ships with Windows 8+ and all subsequent versions.
    /// </summary>
    [DllImport("xinput1_4.dll", EntryPoint = "XInputGetState", SetLastError = false)]
    internal static extern uint XInputGetState(uint dwUserIndex, out XINPUT_STATE pState);

    /// <summary>
    /// Undocumented extended XInput state read that exposes the Guide/Home button (bit 0x0400).
    /// Available in xinput9_1_0.dll (ordinal 100) on Windows Vista+.
    /// Falls back gracefully — callers must catch <see cref="Exception"/> and disable on failure.
    /// </summary>
    [DllImport("xinput9_1_0.dll", EntryPoint = "#100", SetLastError = false)]
    internal static extern uint XInputGetStateEx(uint dwUserIndex, out XINPUT_STATE pState);
}
