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
/// Displays a game cover image loaded asynchronously from a URL,
/// with a gradient fallback showing the game's first letter while loading.
/// </summary>
public partial class CoverImage : UserControl
{
    // ── Styled Properties ─────────────────────────────────────────────────────

    public static readonly StyledProperty<string?> ImageUrlProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(ImageUrl));

    public static readonly StyledProperty<string?> FallbackTextProperty =
        AvaloniaProperty.Register<CoverImage, string?>(nameof(FallbackText));

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
            UpdateInitialLetter(change.NewValue as string);

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

    private void UpdateInitialLetter(string? text)
    {
        if (this.FindControl<TextBlock>("InitialLetter") is not { } tb) return;
        tb.Text = string.IsNullOrEmpty(text) ? "" : text[0].ToString().ToUpperInvariant();
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
