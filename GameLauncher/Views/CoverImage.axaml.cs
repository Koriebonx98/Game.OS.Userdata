using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;

namespace GameLauncher.Views;

/// <summary>
/// Displays a game cover image loaded asynchronously from a URL.
/// When offline or before the image loads, shows a per-game gradient with
/// the title and an optional sub-label (genre/platform).
/// </summary>
public partial class CoverImage : UserControl
{
    // ── Styled Properties ─────────────────────────────────────────────────────

    public static readonly StyledProperty<string?> ImageUrlProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(ImageUrl));

    public static readonly StyledProperty<string?> FallbackTextProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(FallbackText));

    /// <summary>Comma-separated hex colors used for the fallback gradient, e.g. "#1a1a2e,#16213e".</summary>
    public static readonly StyledProperty<string?> FallbackGradientProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(FallbackGradient));

    /// <summary>Optional small label shown above the title on the fallback cover (e.g. genre or platform).</summary>
    public static readonly StyledProperty<string?> SubTextProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(SubText));

    public static readonly StyledProperty<double> LetterFontSizeProperty =
        AvaloniaProperty.Register<CoverImage, double>(nameof(LetterFontSize), defaultValue: 44.0);

    public static readonly StyledProperty<CornerRadius> ImageCornerRadiusProperty =
        AvaloniaProperty.Register<CoverImage, CornerRadius>(nameof(ImageCornerRadius));

    /// <summary>
    /// Optional local file path to a cached cover image (from <see cref="GameMetadataCacheService"/>).
    /// When set, this is used instead of fetching <see cref="ImageUrl"/> over the network.
    /// </summary>
    public static readonly StyledProperty<string?> LocalCachePathProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(LocalCachePath));

    public string? ImageUrl
    {
        get => GetValue(ImageUrlProperty);
        set => SetValue(ImageUrlProperty, value);
    }

    public string? FallbackText
    {
        get => GetValue(FallbackTextProperty);
        set => SetValue(FallbackTextProperty, value);
    }

    public string? FallbackGradient
    {
        get => GetValue(FallbackGradientProperty);
        set => SetValue(FallbackGradientProperty, value);
    }

    public string? SubText
    {
        get => GetValue(SubTextProperty);
        set => SetValue(SubTextProperty, value);
    }

    public double LetterFontSize
    {
        get => GetValue(LetterFontSizeProperty);
        set => SetValue(LetterFontSizeProperty, value);
    }

    public CornerRadius ImageCornerRadius
    {
        get => GetValue(ImageCornerRadiusProperty);
        set => SetValue(ImageCornerRadiusProperty, value);
    }

    public string? LocalCachePath
    {
        get => GetValue(LocalCachePathProperty);
        set => SetValue(LocalCachePathProperty, value);
    }

    // ── Shared HTTP client ────────────────────────────────────────────────────
    private static readonly HttpClient _http = new HttpClient();

    // ── State ─────────────────────────────────────────────────────────────────
    private CancellationTokenSource? _loadCts;

    // ─────────────────────────────────────────────────────────────────────────

    public CoverImage()
    {
        InitializeComponent();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == ImageUrlProperty || change.Property == LocalCachePathProperty)
            TriggerLoad(ImageUrl, LocalCachePath);

        if (change.Property == FallbackTextProperty)
            UpdateFallbackText(change.NewValue as string);

        if (change.Property == FallbackGradientProperty)
            UpdateFallbackGradient(change.NewValue as string);

        if (change.Property == SubTextProperty)
            UpdateSubText(change.NewValue as string);

        if (change.Property == ImageCornerRadiusProperty)
        {
            var cr = (CornerRadius)change.NewValue!;
            if (this.FindControl<Border>("GradBorder") is { } gb) gb.CornerRadius = cr;
            if (this.FindControl<Border>("ImgBorder")  is { } ib) ib.CornerRadius = cr;
        }

        if (change.Property == LetterFontSizeProperty)
        {
            if (this.FindControl<TextBlock>("InitialLetter") is { } tb)
                tb.FontSize = (double)change.NewValue!;
        }
    }

    private void UpdateFallbackText(string? text)
    {
        // Initial letter (large, in background)
        if (this.FindControl<TextBlock>("InitialLetter") is { } tb)
            tb.Text = string.IsNullOrEmpty(text) ? "" : text[0].ToString().ToUpperInvariant();

        // Full title label (on the scrim at the bottom)
        if (this.FindControl<TextBlock>("TitleLabel") is { } tl)
            tl.Text = text ?? "";

        // Show the scrim whenever we have title text
        if (this.FindControl<Border>("TitleScrim") is { } scrim)
            scrim.IsVisible = !string.IsNullOrEmpty(text);
    }

    private void UpdateSubText(string? sub)
    {
        if (this.FindControl<TextBlock>("SubLabel") is { } sl)
        {
            sl.Text      = sub ?? "";
            sl.IsVisible = !string.IsNullOrEmpty(sub);
        }
    }

    private void UpdateFallbackGradient(string? gradientString)
    {
        if (this.FindControl<Border>("GradBorder") is not { } border) return;

        Color start = Color.Parse("#1a1a2e");
        Color end   = Color.Parse("#16213e");

        if (!string.IsNullOrWhiteSpace(gradientString))
        {
            var parts = gradientString.Split(',', StringSplitOptions.TrimEntries);
            if (parts.Length >= 1 && TryParseColor(parts[0], out var c0)) start = c0;
            if (parts.Length >= 2 && TryParseColor(parts[1], out var c1)) end   = c1;
        }

        border.Background = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint   = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops = new GradientStops
            {
                new GradientStop(start, 0),
                new GradientStop(end,   1),
            }
        };
    }

    private static bool TryParseColor(string value, out Color color)
    {
        try { color = Color.Parse(value.Trim()); return true; }
        catch { color = default; return false; }
    }

    // Decoded covers are kept in memory (and downloads on disk) so re-opening a page shows them instantly.
    private const int DecodeWidth = 360;
    private const int MaxCachedBitmaps = 800;
    private static readonly ConcurrentDictionary<string, Bitmap> _bitmapCache = new();
    private static readonly SemaphoreSlim _netGate = new(8);
    private static readonly string _diskCacheDir = Path.Combine(Path.GetTempPath(), "GameOS-CoverCache");

    private static Bitmap Decode(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        try { return Bitmap.DecodeToWidth(ms, DecodeWidth); }
        catch { ms.Position = 0; return new Bitmap(ms); }
    }

    private static void CacheBitmap(string key, Bitmap bmp)
    {
        if (_bitmapCache.Count >= MaxCachedBitmaps) _bitmapCache.Clear();
        _bitmapCache[key] = bmp;
    }

    private static string DiskPath(string url)
    {
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(url)));
        return Path.Combine(_diskCacheDir, hash + ".img");
    }

    private void ShowBitmap(Bitmap bitmap)
    {
        if (this.FindControl<Image>("CoverImg") is { } img) img.Source = bitmap;
        if (this.FindControl<Border>("ImgBorder") is { } ib) ib.IsVisible = true;
    }

    private void TriggerLoad(string? url, string? localCachePath = null)
    {
        // Cancel any previous load
        _loadCts?.Cancel();
        _loadCts?.Dispose();
        _loadCts = null;

        // Reset to fallback view
        if (this.FindControl<Border>("ImgBorder") is { } imgBorder)
            imgBorder.IsVisible = false;

        // Prefer local cache file over network fetch (instant, works offline)
        bool useFile = !string.IsNullOrEmpty(localCachePath) && File.Exists(localCachePath);
        string? key = useFile ? localCachePath : url;
        if (string.IsNullOrWhiteSpace(key)) return;

        if (_bitmapCache.TryGetValue(key, out var cached))
        {
            ShowBitmap(cached);
            return;
        }

        var cts = new CancellationTokenSource();
        _loadCts = cts;
        if (useFile) _ = LoadImageFromFileAsync(localCachePath!, cts.Token);
        else _ = LoadImageAsync(url!, cts.Token);
    }

    private async Task LoadImageFromFileAsync(string path, CancellationToken ct)
    {
        try
        {
            var bitmap = await Task.Run(async () => Decode(await File.ReadAllBytesAsync(path, ct)), ct);
            CacheBitmap(path, bitmap);
            await Dispatcher.UIThread.InvokeAsync(() => { if (!ct.IsCancellationRequested) ShowBitmap(bitmap); });
        }
        catch { /* best-effort — fall through to gradient fallback */ }
    }

    private async Task LoadImageAsync(string url, CancellationToken ct)
    {
        // Only load http/https URLs
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return;

        try
        {
            var disk = DiskPath(url);
            Bitmap bitmap;
            if (File.Exists(disk))
            {
                bitmap = await Task.Run(async () => Decode(await File.ReadAllBytesAsync(disk, ct)), ct);
            }
            else
            {
                await _netGate.WaitAsync(ct);
                byte[] bytes;
                try
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(15));
                    bytes = await _http.GetByteArrayAsync(uri, timeoutCts.Token);
                }
                finally { _netGate.Release(); }
                if (ct.IsCancellationRequested) return;

                bitmap = await Task.Run(() => Decode(bytes), ct);
                try { Directory.CreateDirectory(_diskCacheDir); await File.WriteAllBytesAsync(disk, bytes, CancellationToken.None); }
                catch { /* disk cache is optional */ }
            }

            CacheBitmap(url, bitmap);
            await Dispatcher.UIThread.InvokeAsync(() => { if (!ct.IsCancellationRequested) ShowBitmap(bitmap); });
        }
        catch (OperationCanceledException) { }
        catch
        {
            // Network error / invalid image — keep gradient fallback visible
        }
    }
}
