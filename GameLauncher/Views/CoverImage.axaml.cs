using System;
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

        if (change.Property == ImageUrlProperty)
            TriggerLoad(change.NewValue as string);

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

    private void TriggerLoad(string? url)
    {
        // Cancel any previous load
        _loadCts?.Cancel();
        _loadCts?.Dispose();
        _loadCts = null;

        // Reset to fallback view
        if (this.FindControl<Border>("ImgBorder") is { } imgBorder)
            imgBorder.IsVisible = false;

        if (string.IsNullOrWhiteSpace(url)) return;

        var cts = new CancellationTokenSource();
        _loadCts = cts;
        _ = LoadImageAsync(url, cts.Token);
    }

    private async Task LoadImageAsync(string url, CancellationToken ct)
    {
        // Only load http/https URLs
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(15));

            var bytes = await _http.GetByteArrayAsync(uri, timeoutCts.Token);
            if (ct.IsCancellationRequested) return;

            await using var ms = new MemoryStream(bytes);
            var bitmap = new Bitmap(ms);

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (ct.IsCancellationRequested) return;

                if (this.FindControl<Image>("CoverImg") is { } img)
                    img.Source = bitmap;

                if (this.FindControl<Border>("ImgBorder") is { } ib)
                    ib.IsVisible = true;
            });
        }
        catch (OperationCanceledException) { }
        catch
        {
            // Network error / invalid image — keep gradient fallback visible
        }
    }
}
