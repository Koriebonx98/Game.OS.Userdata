using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace GameLauncher.Views
{
    /// <summary>
    /// Small always-on-top banner shown over a running game for the broadcast countdown and result,
    /// so the player gets feedback without the launcher being in front.
    /// </summary>
    public sealed class BroadcastCountdownWindow : Window
    {
        private readonly TextBlock _big = new()
        {
            FontSize = 72, FontWeight = FontWeight.Bold, Foreground = Brushes.White,
            HorizontalAlignment = HorizontalAlignment.Center,
        };
        private readonly TextBlock _small = new()
        {
            FontSize = 18, Foreground = Brushes.White, TextWrapping = TextWrapping.Wrap,
            HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center,
        };

        public BroadcastCountdownWindow()
        {
            Width = 360; Height = 220;
            SystemDecorations = SystemDecorations.None;
            Topmost = true; ShowInTaskbar = false; ShowActivated = false;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.Manual;
            Background = Brushes.Transparent;
            TransparencyLevelHint = new[] { WindowTransparencyLevel.Transparent };
            Content = new Border
            {
                Background = new SolidColorBrush(Color.Parse("#E6101018")),
                BorderBrush = new SolidColorBrush(Color.Parse("#DC2626")), BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(16), Padding = new Thickness(20),
                Child = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 6, Children = { _big, _small } },
            };
        }

        public void Set(string big, string small)
        {
            _big.Text = big; _small.Text = small;
            _big.IsVisible = big.Length > 0;
        }

        private void PlaceTopCentre()
        {
            var screen = Screens.Primary;
            if (screen == null) return;
            var scale = screen.Scaling;
            var wa = screen.WorkingArea;
            Position = new PixelPoint(wa.X + (int)((wa.Width - Width * scale) / 2), wa.Y + (int)(40 * scale));
        }

        /// <summary>Counts down, then closes. Returns false if the countdown was cancelled.</summary>
        public static async Task<bool> RunCountdownAsync(int seconds, Func<bool> cancelled)
        {
            return await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                var w = new BroadcastCountdownWindow();
                w.Set(seconds.ToString(), "Broadcast starting… open your game now");
                w.PlaceTopCentre();
                w.Show();
                try
                {
                    for (int i = seconds; i > 0; i--)
                    {
                        w.Set(i.ToString(), "Broadcast starting… get your game on screen");
                        await Task.Delay(1000);
                        if (cancelled()) return false;
                    }
                    return true;
                }
                finally { w.Close(); }
            });
        }

        /// <summary>Shows a short message banner (e.g. "You're live" or an error) and closes it after <paramref name="ms"/>.</summary>
        public static void Flash(string big, string small, int ms)
        {
            Dispatcher.UIThread.Post(async () =>
            {
                var w = new BroadcastCountdownWindow();
                w.Set(big, small);
                w.PlaceTopCentre();
                w.Show();
                await Task.Delay(ms);
                w.Close();
            });
        }
    }
}
