using System;

namespace GameLauncher.Services;

/// <summary>
/// High-rate XInput reader used only while the built-in browser is on screen (the shell's own poller runs at ~150 ms,
/// far too slow for a smooth virtual mouse). Left stick moves the cursor, right stick scrolls; face buttons / bumpers / Start
/// fire once per press. Feed it with <see cref="Update"/> (pure, testable) or <see cref="Poll"/> (reads XInput on Windows).
/// </summary>
public sealed class BrowserGamepad
{
    private const ushort Up = 0x0001, Down = 0x0002, Left = 0x0004, Right = 0x0008, Start = 0x0010;
    private const ushort Lb = 0x0100, Rb = 0x0200, A = 0x1000, B = 0x2000, X = 0x4000, Y = 0x8000;
    private const double Dead = 0.22;

    public Action<double, double>? OnCursorMove { get; set; }   // pixels
    public Action<double>? OnScroll { get; set; }               // pixels, + = down
    public Action? OnA { get; set; }
    public Action? OnB { get; set; }
    public Action? OnX { get; set; }
    public Action? OnY { get; set; }
    public Action? OnStart { get; set; }
    public Action? OnLb { get; set; }
    public Action? OnRb { get; set; }
    public Action<int, int>? OnDpad { get; set; }               // (dx, dy) once per press

    /// <summary>Virtual-mouse speed 1–10 (pixels per second ≈ speed * 150).</summary>
    public int CursorSpeed { get; set; } = 6;
    public int ScrollSpeed { get; set; } = 6;

    private ushort _prev;
    private int _connected = -1;
    private DateTime _last = DateTime.UtcNow;

    public void Reset() { _prev = 0; _last = DateTime.UtcNow; }

    public void Poll()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (_connected < 0)
                for (uint i = 0; i < 4; i++)
                    if (NativeMethods.XInputGetState(i, out _) == 0) { _connected = (int)i; break; }
            if (_connected < 0) return;
            if (NativeMethods.XInputGetState((uint)_connected, out var st) != 0) { _connected = -1; return; }
            var g = st.Gamepad;
            Update(g.wButtons, g.sThumbLX, g.sThumbLY, g.sThumbRX, g.sThumbRY, DateTime.UtcNow);
        }
        catch { /* XInput unavailable */ }
    }

    public static double Axis(short raw)
    {
        double v = raw / 32767.0;
        double a = Math.Abs(v);
        if (a < Dead) return 0;
        // Rescale beyond the dead-zone and apply a curve for fine control near the centre.
        double scaled = (a - Dead) / (1 - Dead);
        return Math.Sign(v) * scaled * scaled;
    }

    public void Update(ushort buttons, short lx, short ly, short rx, short ry, DateTime now)
    {
        double dt = Math.Clamp((now - _last).TotalSeconds, 0, 0.1);
        _last = now;

        double mx = Axis(lx), my = -Axis(ly);
        if (mx != 0 || my != 0)
        {
            double speed = Math.Clamp(CursorSpeed, 1, 10) * 150.0 * dt;
            OnCursorMove?.Invoke(mx * speed * 2, my * speed * 2);
        }
        double sy = -Axis(ry);
        if (sy != 0) OnScroll?.Invoke(sy * Math.Clamp(ScrollSpeed, 1, 10) * 120.0 * dt);

        ushort pressed = (ushort)(buttons & ~_prev);
        _prev = buttons;
        if ((pressed & A) != 0) OnA?.Invoke();
        if ((pressed & B) != 0) OnB?.Invoke();
        if ((pressed & X) != 0) OnX?.Invoke();
        if ((pressed & Y) != 0) OnY?.Invoke();
        if ((pressed & Start) != 0) OnStart?.Invoke();
        if ((pressed & Lb) != 0) OnLb?.Invoke();
        if ((pressed & Rb) != 0) OnRb?.Invoke();
        int dx = ((pressed & Right) != 0 ? 1 : 0) - ((pressed & Left) != 0 ? 1 : 0);
        int dy = ((pressed & Down) != 0 ? 1 : 0) - ((pressed & Up) != 0 ? 1 : 0);
        if (dx != 0 || dy != 0) OnDpad?.Invoke(dx, dy);
    }
}
