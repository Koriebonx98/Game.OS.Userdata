using System;
using System.Runtime.InteropServices;

namespace GameLauncher.Services;

/// <summary>
/// Polls XInput controller state on Windows and fires button-press callbacks
/// with latch-based repeat prevention (one callback per press until release).
/// Supports D-pad, left stick (with dead-zone), face buttons (A / B / X),
/// shoulder bumpers (LB / RB), and the Start button.
/// All calls are safe to make on non-Windows — they become no-ops.
/// </summary>
internal sealed class XInputService
{
    // ── XInput button bitmasks ────────────────────────────────────────────────
    private const ushort DpadUpMask    = 0x0001;
    private const ushort DpadDownMask  = 0x0002;
    private const ushort DpadLeftMask  = 0x0004;
    private const ushort DpadRightMask = 0x0008;
    private const ushort StartMask     = 0x0010;
    private const ushort LbMask        = 0x0100;
    private const ushort RbMask        = 0x0200;
    private const ushort ButtonAMask   = 0x1000;
    private const ushort ButtonBMask   = 0x2000;
    private const ushort ButtonXMask   = 0x4000;

    // Left stick dead-zone (≈ 25 % of the signed 16-bit full range 32767)
    private const short StickDeadZone = 8000;

    // ── Callbacks ─────────────────────────────────────────────────────────────

    /// <summary>D-pad Up or left-stick tilted upward.</summary>
    public Action? OnUp { get; set; }
    /// <summary>D-pad Down or left-stick tilted downward.</summary>
    public Action? OnDown { get; set; }
    /// <summary>D-pad Left or left-stick tilted left.</summary>
    public Action? OnLeft { get; set; }
    /// <summary>D-pad Right or left-stick tilted right.</summary>
    public Action? OnRight { get; set; }
    /// <summary>A button (cross / confirm on PlayStation).</summary>
    public Action? OnButtonA { get; set; }
    /// <summary>B button (circle / back on PlayStation).</summary>
    public Action? OnButtonB { get; set; }
    /// <summary>X button (square / secondary action on PlayStation).</summary>
    public Action? OnButtonX { get; set; }
    /// <summary>Left Bumper / L1 — previous tab or page.</summary>
    public Action? OnLb { get; set; }
    /// <summary>Right Bumper / R1 — next tab or page.</summary>
    public Action? OnRb { get; set; }
    /// <summary>Start / Options / Menu button — opens the quick menu.</summary>
    public Action? OnStart { get; set; }

    // ── Internal latch state ──────────────────────────────────────────────────
    private ushort _latchedButtons;
    private bool   _stickUpLatched;
    private bool   _stickDownLatched;
    private bool   _stickLeftLatched;
    private bool   _stickRightLatched;
    private int    _connectedIndex  = -1;   // cached slot of the connected controller
    private bool   _xinputAvailable = true; // set false if xinput1_4.dll is missing

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Scans for a connected XInput controller and fires callbacks for each
    /// button that transitions from released → pressed since the last call.
    /// Must be invoked on the UI thread (typically from a DispatcherTimer tick).
    /// </summary>
    public void Poll()
    {
        if (!OperatingSystem.IsWindows() || !_xinputAvailable) return;

        try
        {
            // Re-scan controller slots when none is cached as connected
            if (_connectedIndex < 0)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (NativeMethods.XInputGetState((uint)i, out _) == 0)
                    {
                        _connectedIndex = i;
                        break;
                    }
                }
            }

            if (_connectedIndex < 0) { ResetLatches(); return; }

            uint result = NativeMethods.XInputGetState((uint)_connectedIndex, out var state);
            if (result != 0)
            {
                // Controller disconnected — clear cached slot and latches
                _connectedIndex = -1;
                ResetLatches();
                return;
            }

            ProcessGamepad(state.Gamepad);
        }
        catch (DllNotFoundException)
        {
            // xinput1_4.dll not present (very old Windows) — disable permanently
            _xinputAvailable = false;
        }
        catch
        {
            // Ignore transient failures and try again next tick
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void ProcessGamepad(NativeMethods.XINPUT_GAMEPAD gp)
    {
        ushort b = gp.wButtons;
        Fire(b, DpadUpMask,    ref _latchedButtons, OnUp);
        Fire(b, DpadDownMask,  ref _latchedButtons, OnDown);
        Fire(b, DpadLeftMask,  ref _latchedButtons, OnLeft);
        Fire(b, DpadRightMask, ref _latchedButtons, OnRight);
        Fire(b, ButtonAMask,   ref _latchedButtons, OnButtonA);
        Fire(b, ButtonBMask,   ref _latchedButtons, OnButtonB);
        Fire(b, ButtonXMask,   ref _latchedButtons, OnButtonX);
        Fire(b, LbMask,        ref _latchedButtons, OnLb);
        Fire(b, RbMask,        ref _latchedButtons, OnRb);
        Fire(b, StartMask,     ref _latchedButtons, OnStart);

        // Left stick — treated identically to the D-pad
        FireStick(gp.sThumbLY >  StickDeadZone, ref _stickUpLatched,    OnUp);
        FireStick(gp.sThumbLY < -StickDeadZone, ref _stickDownLatched,  OnDown);
        FireStick(gp.sThumbLX < -StickDeadZone, ref _stickLeftLatched,  OnLeft);
        FireStick(gp.sThumbLX >  StickDeadZone, ref _stickRightLatched, OnRight);
    }

    /// <summary>
    /// Fires <paramref name="action"/> once when <paramref name="mask"/> bit
    /// transitions from clear to set in <paramref name="current"/>, then latches
    /// until the button is released.
    /// </summary>
    private static void Fire(ushort current, ushort mask, ref ushort latched, Action? action)
    {
        bool isDown = (current & mask) != 0;
        if (isDown && (latched & mask) == 0)
        {
            latched |= mask;
            action?.Invoke();
        }
        else if (!isDown)
        {
            latched &= (ushort)~mask;
        }
    }

    private static void FireStick(bool isDown, ref bool latched, Action? action)
    {
        if (isDown && !latched) { latched = true; action?.Invoke(); }
        else if (!isDown) latched = false;
    }

    private void ResetLatches()
    {
        _latchedButtons  = 0;
        _stickUpLatched    = false;
        _stickDownLatched  = false;
        _stickLeftLatched  = false;
        _stickRightLatched = false;
    }
}
