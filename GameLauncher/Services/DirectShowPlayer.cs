using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace GameLauncher.Services;

/// <summary>
/// Windows-native video player that uses DirectShow (quartz.dll) — the same
/// underlying engine as WPF's MediaElement — with no external dependencies.
/// Supports any format covered by Windows' inbox codecs (MP4/H.264 on Windows 10+).
/// </summary>
internal sealed class DirectShowPlayer : IDisposable
{
    // CLSID_FilterGraph  {E436EBB3-524F-11CE-9F53-0020AF0BA770}
    private static readonly Guid ClsidFilterGraph =
        new("E436EBB3-524F-11CE-9F53-0020AF0BA770");

    private const int WS_CHILD        = 0x40000000;
    private const int WS_VISIBLE      = 0x10000000;
    private const int WS_CLIPSIBLINGS = 0x04000000;
    private const int EC_COMPLETE     = 0x01;

    // VFW_E_TIMEOUT = 0x80040227 – returned by WaitForCompletion when no event
    // arrives within the timeout window; this is normal and means keep polling.
    private const int VfwETimeout = unchecked((int)0x80040227);

    private object?        _graph;
    private IMediaControl? _control;
    private IVideoWindow?  _videoWindow;
    private IMediaEvent?   _mediaEvent;

    private Thread?       _eventThread;
    private volatile bool _disposed;

    /// <summary>Raised on the event-polling thread when the video ends normally.</summary>
    public event Action? PlaybackEnded;

    /// <summary>Raised on the event-polling thread when DirectShow reports an error.</summary>
    public event Action? PlaybackFailed;

    /// <summary>
    /// Builds a DirectShow filter graph for <paramref name="filePath"/>, attaches the
    /// video output to <paramref name="ownerHwnd"/>, and starts playback.
    /// </summary>
    /// <returns><see langword="true"/> if playback started successfully.</returns>
    public bool TryPlay(string filePath, IntPtr ownerHwnd, int width, int height)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        try
        {
            var graphType = Type.GetTypeFromCLSID(ClsidFilterGraph, throwOnError: true)!;
            _graph       = Activator.CreateInstance(graphType)!;
            _control     = (IMediaControl)_graph;
            _videoWindow = (IVideoWindow)_graph;
            _mediaEvent  = (IMediaEvent)_graph;

            int hr = _control.RenderFile(filePath);
            if (hr < 0)
            {
                DevLogService.Log($"[DirectShow] RenderFile HRESULT=0x{hr:X8} for '{filePath}'");
                Cleanup();
                return false;
            }

            // Attach video output to the supplied HWND.
            _videoWindow.put_AutoShow(0);            // prevent premature show
            _videoWindow.put_Owner(ownerHwnd);
            _videoWindow.put_WindowStyle(WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE);
            _videoWindow.SetWindowPosition(0, 0, width, height);

            _control.Run();
            DevLogService.Log($"[DirectShow] Playback started: '{filePath}' ({width}×{height})");
            StartEventThread();
            return true;
        }
        catch (Exception ex)
        {
            DevLogService.Log($"[DirectShow] TryPlay failed: {ex.GetType().Name}: {ex.Message}");
            Cleanup();
            return false;
        }
    }

    /// <summary>Repositions the DirectShow video window to fill the owner HWND.</summary>
    public void UpdateSize(int width, int height)
    {
        try { _videoWindow?.SetWindowPosition(0, 0, width, height); }
        catch { /* ignore */ }
    }

    /// <summary>Stops playback (idempotent, safe to call multiple times).</summary>
    public void Stop()
    {
        try { _control?.Stop(); }
        catch { /* ignore */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Cleanup();
    }

    private void StartEventThread()
    {
        _eventThread = new Thread(() =>
        {
            while (!_disposed)
            {
                try
                {
                    int hr = _mediaEvent!.WaitForCompletion(250, out int evCode);
                    if (hr == 0 && evCode == EC_COMPLETE)
                    {
                        DevLogService.Log("[DirectShow] EC_COMPLETE — playback ended.");
                        PlaybackEnded?.Invoke();
                        return;
                    }
                    // VFW_E_TIMEOUT is expected; any other error is fatal.
                    if (hr < 0 && hr != VfwETimeout)
                    {
                        DevLogService.Log($"[DirectShow] WaitForCompletion HRESULT=0x{hr:X8}");
                        PlaybackFailed?.Invoke();
                        return;
                    }
                }
                catch (Exception ex)
                {
                    DevLogService.Log($"[DirectShow] Event thread exception: {ex.Message}");
                    PlaybackFailed?.Invoke();
                    return;
                }
            }
        })
        { IsBackground = true, Name = "DirectShowEventPoller" };

        _eventThread.Start();
    }

    private void Cleanup()
    {
        // COM objects are only created on Windows; nothing to release on other platforms.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        try { _control?.Stop(); } catch { }

        try
        {
            if (_videoWindow != null)
            {
                _videoWindow.put_Visible(0);
                _videoWindow.put_Owner(IntPtr.Zero);
            }
        }
        catch { }

        if (_videoWindow != null) { Marshal.ReleaseComObject(_videoWindow); _videoWindow = null; }
        if (_mediaEvent  != null) { Marshal.ReleaseComObject(_mediaEvent);  _mediaEvent  = null; }
        if (_control     != null) { Marshal.ReleaseComObject(_control);     _control     = null; }
        if (_graph       != null) { Marshal.ReleaseComObject(_graph);       _graph       = null; }
    }

    // ── COM interface declarations ─────────────────────────────────────────────
    // InterfaceIsDual: IUnknown (slots 0-2) + IDispatch (slots 3-6) are implicit;
    // the first declared method maps to vtable slot 7.
    // Method ordering matches the Windows SDK control.idl definitions exactly.

    [ComImport, Guid("56A8689F-0AD4-11CE-B03A-0020AF0BA770")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IMediaControl
    {
        [PreserveSig] int Run();
        [PreserveSig] int Pause();
        [PreserveSig] int Stop();
        [PreserveSig] int GetState([In] int msTimeout, [Out] out int pfs);
        [PreserveSig] int RenderFile([In, MarshalAs(UnmanagedType.BStr)] string strFilename);
    }

    // All put/get pairs declared in IDL order so vtable offsets are correct.
    // put_Owner is at slot 29 (7 base + 22 preceding put/get methods).
    [ComImport, Guid("56A868B4-0AD4-11CE-B03A-0020AF0BA770")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IVideoWindow
    {
        [PreserveSig] int put_Caption([In, MarshalAs(UnmanagedType.BStr)] string strCaption);
        [PreserveSig] int get_Caption([Out, MarshalAs(UnmanagedType.BStr)] out string strCaption);
        [PreserveSig] int put_WindowStyle([In] int windowStyle);
        [PreserveSig] int get_WindowStyle([Out] out int windowStyle);
        [PreserveSig] int put_WindowStyleEx([In] int windowStyleEx);
        [PreserveSig] int get_WindowStyleEx([Out] out int windowStyleEx);
        [PreserveSig] int put_AutoShow([In] int autoShow);
        [PreserveSig] int get_AutoShow([Out] out int autoShow);
        [PreserveSig] int put_WindowState([In] int windowState);
        [PreserveSig] int get_WindowState([Out] out int windowState);
        [PreserveSig] int put_BackgroundPalette([In] int backgroundPalette);
        [PreserveSig] int get_BackgroundPalette([Out] out int backgroundPalette);
        [PreserveSig] int put_Visible([In] int visible);
        [PreserveSig] int get_Visible([Out] out int visible);
        [PreserveSig] int put_Left([In] int left);
        [PreserveSig] int get_Left([Out] out int left);
        [PreserveSig] int put_Width([In] int width);
        [PreserveSig] int get_Width([Out] out int width);
        [PreserveSig] int put_Top([In] int top);
        [PreserveSig] int get_Top([Out] out int top);
        [PreserveSig] int put_Height([In] int height);
        [PreserveSig] int get_Height([Out] out int height);
        [PreserveSig] int put_Owner([In] IntPtr owner);     // OAHWND = LONG_PTR → IntPtr
        [PreserveSig] int get_Owner([Out] out IntPtr owner);
        [PreserveSig] int put_MessageDrain([In] IntPtr drain);
        [PreserveSig] int get_MessageDrain([Out] out IntPtr drain);
        [PreserveSig] int get_BorderColor([Out] out int color);
        [PreserveSig] int put_BorderColor([In] int color);
        [PreserveSig] int get_FullScreenMode([Out] out int fullScreenMode);
        [PreserveSig] int put_FullScreenMode([In] int fullScreenMode);
        [PreserveSig] int SetWindowForeground([In] int focus);
        [PreserveSig] int NotifyOwnerMessage([In] IntPtr hwnd, [In] int uMsg,
                                             [In] IntPtr wParam, [In] IntPtr lParam);
        [PreserveSig] int SetWindowPosition([In] int left, [In] int top,
                                            [In] int width, [In] int height);
    }

    [ComImport, Guid("56A868C0-0AD4-11CE-B03A-0020AF0BA770")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IMediaEvent
    {
        [PreserveSig] int GetEventHandle([Out] out IntPtr hEvent);
        [PreserveSig] int GetEvent([Out] out int lEventCode,
                                   [Out] out IntPtr lParam1,
                                   [Out] out IntPtr lParam2,
                                   [In]  int msTimeout);
        [PreserveSig] int WaitForCompletion([In] int msTimeout, [Out] out int pEvCode);
        [PreserveSig] int CancelDefaultHandling([In] int lEvCode);
        [PreserveSig] int RestoreDefaultHandling([In] int lEvCode);
        [PreserveSig] int FreeEventParams([In] int lEvCode,
                                          [In] IntPtr lParam1,
                                          [In] IntPtr lParam2);
    }
}
