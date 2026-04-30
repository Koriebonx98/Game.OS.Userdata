using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Platform;
using GameLauncher.Services;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace GameLauncher.Views;

/// <summary>
/// Avalonia <see cref="NativeControlHost"/> that plays a video on Windows using
/// <see cref="DirectShowPlayer"/> (Windows built-in codecs, no VLC dependency).
/// On non-Windows platforms the host raises <see cref="PlaybackFailed"/> immediately
/// so callers can fall through to the main window.
/// </summary>
internal sealed class DirectShowHost : NativeControlHost
{
    private const uint WS_CHILD   = 0x40000000u;
    private const uint WS_VISIBLE = 0x10000000u;

    private DirectShowPlayer? _player;
    private IntPtr            _hostHwnd;
    private string?           _filePath;

    /// <summary>Raised when the video ends normally.</summary>
    public event Action? PlaybackEnded;

    /// <summary>Raised when the video cannot be played (wrong OS, missing file, error).</summary>
    public event Action? PlaybackFailed;

    /// <summary>Sets the video file path to play once the native window is ready.</summary>
    public void SetSource(string filePath) => _filePath = filePath;

    /// <summary>Stops playback (idempotent).</summary>
    public void Stop() => _player?.Stop();

    // ── NativeControlHost overrides ───────────────────────────────────────────

    protected override IPlatformHandle CreateNativeControlCore(IPlatformHandle parent)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            PlaybackFailed?.Invoke();
            return base.CreateNativeControlCore(parent);
        }

        // Determine render dimensions from the parent HWND client area.
        GetClientRect(parent.Handle, out var rect);
        int w = Math.Max(rect.Right  - rect.Left, 1);
        int h = Math.Max(rect.Bottom - rect.Top,  1);

        // Create a plain Win32 child window as the DirectShow render target.
        // Using the built-in "STATIC" class avoids registering a custom class.
        _hostHwnd = CreateWindowEx(
            0, "STATIC", null,
            WS_CHILD | WS_VISIBLE,
            0, 0, w, h,
            parent.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

        if (_hostHwnd == IntPtr.Zero)
        {
            DevLogService.Log("[DirectShowHost] CreateWindowEx failed.");
            PlaybackFailed?.Invoke();
            return base.CreateNativeControlCore(parent);
        }

        if (!string.IsNullOrEmpty(_filePath) && File.Exists(_filePath))
        {
            _player = new DirectShowPlayer();
            _player.PlaybackEnded += () => PlaybackEnded?.Invoke();
            _player.PlaybackFailed += () => PlaybackFailed?.Invoke();

            if (!_player.TryPlay(_filePath, _hostHwnd, w, h))
            {
                _player.Dispose();
                _player = null;
                PlaybackFailed?.Invoke();
            }
        }
        else
        {
            DevLogService.Log("[DirectShowHost] Source not set or file missing — skipping.");
            PlaybackFailed?.Invoke();
        }

        return new PlatformHandle(_hostHwnd, "HWND");
    }

    protected override void DestroyNativeControlCore(IPlatformHandle control)
    {
        _player?.Stop();
        _player?.Dispose();
        _player = null;

        if (_hostHwnd != IntPtr.Zero)
        {
            DestroyWindow(_hostHwnd);
            _hostHwnd = IntPtr.Zero;
        }
    }

    /// <summary>Keeps the DirectShow video window in sync when the host is resized.</summary>
    protected override Size ArrangeOverride(Size finalSize)
    {
        var size = base.ArrangeOverride(finalSize);
        _player?.UpdateSize((int)size.Width, (int)size.Height);
        return size;
    }

    // ── Win32 P/Invoke ────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint    dwExStyle,
        string  lpClassName,
        string? lpWindowName,
        uint    dwStyle,
        int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);
}
