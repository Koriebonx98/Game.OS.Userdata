using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Media;
using NAudio.CoreAudioApi; // Add at the top

namespace PS5_OS
{
    public partial class GuideMenu : Window
    {
        public event EventHandler? RequestHome;
        public event EventHandler? RequestClose;

        private bool _showingAllWindows = false;

        // Sound players for navigation and activation
        private SoundPlayer? _navPlayer;
        private SoundPlayer? _actPlayer;

        private readonly MMDeviceEnumerator _deviceEnumerator = new MMDeviceEnumerator();
        private MMDevice? _defaultDevice;

        public string MediaIconPath { get; }
        public string PowerIconPath { get; }
        public string NotificationsIconPath { get; }
        public string DownloadsIconPath { get; }
        public string HomeIconPath { get; }
        public string SwitcherIconPath { get; }
        public string FriendsIconPath { get; }
        public string RecentGamesIconPath { get; }
        public string InboxIconPath { get; }
        public string BrowserIconPath { get; }

        public GuideMenu()
        {
            MediaIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "Icon.Media.jpg");
            PowerIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "Icon.Power.jpg");
            NotificationsIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "Icon.Notification.jpg");
            DownloadsIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "Icon.Downloads.jpg");
            HomeIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "icon.Home.jpg");
            SwitcherIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "Icon.Switcher.jpg");
            FriendsIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "icon.Friends.jpg");
            RecentGamesIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "icon.RecentGames.jpg");
            InboxIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "icon.Messages.jpg");
            BrowserIconPath = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Resources", "Dashboard", "icon.Browser.jpg");
            DataContext = this;
            InitializeComponent();
            this.Loaded += GuideMenu_Loaded;

            HomeButton.GotFocus += (s, e) => SetMenuText("Home", "Return to the home screen.");
            SwitcherButton.GotFocus += (s, e) => SetMenuText("Switcher", "Switch between games and apps.");
            RecentGamesButton.GotFocus += (s, e) => SetMenuText("Recent Games", "View and launch recently played games.");
            NotificationsButton.GotFocus += (s, e) => SetMenuText("Notifications", "View your notifications.");
            DownloadsButton.GotFocus += (s, e) => SetMenuText("Downloads", "Manage downloads and updates.");
            PowerMenuButton.GotFocus += (s, e) => SetMenuText("Power", "Choose a power option.");

            // Add missing button titles
            FriendsButton.GotFocus += (s, e) => SetMenuText("Friends", "View and manage your friends list.");
            InboxButton.GotFocus += (s, e) => SetMenuText("Inbox", "Check your messages and notifications.");
            MediaButton.GotFocus += (s, e) => SetMenuText("Media Controls", "Control playback and volume.");

            ShutdownButton.GotFocus += (s, e) => PlayNavigation();
            RestartButton.GotFocus += (s, e) => PlayNavigation();
            SleepButton.GotFocus += (s, e) => PlayNavigation();

            SettingsButton.GotFocus += (s, e) => SetMenuText("Settings", "Adjust system preferences.");
            SettingsButton.Click += SettingsButton_Click;

            TryLoadAudioPlayers();

            _defaultDevice = _deviceEnumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);

            // Subscribe to volume change notifications
            if (_defaultDevice != null)
            {
                _defaultDevice.AudioEndpointVolume.OnVolumeNotification += AudioEndpointVolume_OnVolumeNotification;
            }
            BrowserButton.GotFocus += (s, e) => SetMenuText("Browser", "Open the web browser.");

        }

        private void TryLoadAudioPlayers()
        {
            try
            {
                var baseDir = System.IO.Path.Combine(AppContext.BaseDirectory, "Data", "Resources", "Dashboard");
                var navPath = System.IO.Path.Combine(baseDir, "navigation.wav");
                var actPath = System.IO.Path.Combine(baseDir, "activation.wav");

                if (System.IO.File.Exists(navPath))
                {
                    _navPlayer = new SoundPlayer(navPath);
                    _navPlayer.Load();
                }
                if (System.IO.File.Exists(actPath))
                {
                    _actPlayer = new SoundPlayer(actPath);
                    _actPlayer.Load();
                }
            }
            catch
            {
                _navPlayer = null;
                _actPlayer = null;
            }
        }

        private void PlayNavigation()
        {
            try { _navPlayer?.Play(); } catch { }
        }

        private void PlayActivation()
        {
            try { _actPlayer?.Play(); } catch { }
        }

        private void GuideMenu_Loaded(object sender, RoutedEventArgs e)
        {
            HomeButton.Focus();
        }

        private void SetMenuText(string title, string subtitle)
        {
            MenuTitle.Text = title;
            MenuSubtitle.Text = subtitle;
        }

        // Add a helper to highlight the volume bar
        private void HighlightVolumeBar(bool highlight)
        {
            if (highlight)
            {
                VolumeSlider.BorderBrush = Brushes.DeepSkyBlue;
                VolumeSlider.BorderThickness = new Thickness(3);
                VolumeSlider.Background = new SolidColorBrush(Color.FromRgb(30, 30, 60));
            }
            else
            {
                VolumeSlider.ClearValue(BorderBrushProperty);
                VolumeSlider.ClearValue(BorderThicknessProperty);
                VolumeSlider.ClearValue(BackgroundProperty);
            }
        }

        protected override void OnPreviewKeyDown(KeyEventArgs e)
        {
            // Handle Alt+F4 to close topmost external window
            if (e.Key == Key.F4 && (Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt)
            {
                HandleAltF4Close();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Escape && MediaOverlay.Visibility == Visibility.Visible)
            {
                MediaOverlay.Visibility = Visibility.Collapsed;
                MediaButton.Focus();
                PlayNavigation();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Escape && RecentGamesOverlay.Visibility == Visibility.Visible)
            {
                RecentGamesOverlay.Visibility = Visibility.Collapsed;
                HomeButton.Focus();
                PlayNavigation();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Escape && PowerMenuOverlay.Visibility == Visibility.Visible)
            {
                PowerMenuOverlay.Visibility = Visibility.Collapsed;
                HomeButton.Focus();
                PlayNavigation();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Escape)
            {
                if (SwitcherOverlay.Visibility == Visibility.Visible)
                {
                    if (_showingAllWindows)
                    {
                        ShowSwitcherView();
                        PlayNavigation();
                        e.Handled = true;
                        return;
                    }
                    else
                    {
                        SwitcherOverlay.Visibility = Visibility.Collapsed;
                        AllWindowsScroll.Visibility = Visibility.Collapsed;
                        _showingAllWindows = false;
                        HomeButton.Focus();
                        PlayNavigation();
                        e.Handled = true;
                        return;
                    }
                }
                else
                {
                    RequestClose?.Invoke(this, EventArgs.Empty);
                    PlayNavigation();
                    e.Handled = true;
                    return;
                }
            }

            var buttons = new[] {
    SettingsButton,
    HomeButton, SwitcherButton, RecentGamesButton, NotificationsButton, DownloadsButton,
    FriendsButton, InboxButton, MediaButton, BrowserButton,
    PowerMenuButton
};
            int focusedIndex = -1;
            for (int i = 0; i < buttons.Length; i++)
            {
                if (buttons[i].IsKeyboardFocused)
                {
                    focusedIndex = i;
                    break;
                }
            }

            // Main menu navigation (left/right)
            if (focusedIndex != -1)
            {
                if (e.Key == Key.Right)
                {
                    buttons[(focusedIndex + 1) % buttons.Length].Focus();
                    PlayNavigation();
                    e.Handled = true;
                }
                else if (e.Key == Key.Left)
                {
                    buttons[(focusedIndex - 1 + buttons.Length) % buttons.Length].Focus();
                    PlayNavigation();
                    e.Handled = true;
                }
                // Add up/down navigation for main menu if needed
                else if (e.Key == Key.Up)
                {
                    buttons[(focusedIndex - 1 + buttons.Length) % buttons.Length].Focus();
                    PlayNavigation();
                    e.Handled = true;
                }
                else if (e.Key == Key.Down)
                {
                    buttons[(focusedIndex + 1) % buttons.Length].Focus();
                    PlayNavigation();
                    e.Handled = true;
                }
                else if (e.Key == Key.Enter || e.Key == Key.Space)
                {
                    buttons[focusedIndex].RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    PlayActivation();
                    e.Handled = true;
                }
            }

            // Recent Games overlay navigation (left/right, up/down)
            if (RecentGamesOverlay.Visibility == Visibility.Visible)
            {
                var gameButtons = new List<Button>();
                foreach (var child in RecentGamesPanel.Children)
                {
                    if (child is Button btn)
                        gameButtons.Add(btn);
                }

                if (gameButtons.Count > 0)
                {
                    int gameFocusedIndex = -1;
                    for (int i = 0; i < gameButtons.Count; i++)
                    {
                        if (gameButtons[i].IsKeyboardFocused)
                        {
                            gameFocusedIndex = i;
                            break;
                        }
                    }

                    if (gameFocusedIndex != -1)
                    {
                        if (e.Key == Key.Right || e.Key == Key.Down)
                        {
                            gameButtons[(gameFocusedIndex + 1) % gameButtons.Count].Focus();
                            PlayNavigation();
                            e.Handled = true;
                            return;
                        }
                        else if (e.Key == Key.Left || e.Key == Key.Up)
                        {
                            gameButtons[(gameFocusedIndex - 1 + gameButtons.Count) % gameButtons.Count].Focus();
                            PlayNavigation();
                            e.Handled = true;
                            return;
                        }
                        else if (e.Key == Key.Enter || e.Key == Key.Space)
                        {
                            gameButtons[gameFocusedIndex].RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                            PlayActivation();
                            e.Handled = true;
                            return;
                        }
                    }
                    else
                    {
                        gameButtons[0].Focus();
                        PlayNavigation();
                        e.Handled = true;
                        return;
                    }
                }
            }

            // Media Controls navigation
            if (MediaOverlay.Visibility == Visibility.Visible)
            {
                var mediaButtons = new[] { RewindButton, PlayPauseButton, StopButton, FastForwardButton };

                // If a media button is focused and Down is pressed, move to VolumeSlider
                if (mediaButtons.Any(b => b.IsKeyboardFocused) && e.Key == Key.Down)
                {
                    VolumeSlider.Focus();
                    e.Handled = true;
                    return;
                }

                // If PlayPauseButton is focused and Enter/Space is pressed, trigger play/pause
                if (PlayPauseButton.IsKeyboardFocused && (e.Key == Key.Enter || e.Key == Key.Space))
                {
                    PlayActivation();
                    SendMediaPlayPause();
                    e.Handled = true;
                    return;
                }

                // If VolumeSlider is focused
                if (VolumeSlider.IsKeyboardFocused)
                {
                    HighlightVolumeBar(true);

                    // Down closes the media menu
                    if (e.Key == Key.Down)
                    {
                        MediaOverlay.Visibility = Visibility.Collapsed;
                        MediaButton.Focus();
                        PlayNavigation();
                        e.Handled = true;
                        return;
                    }

                    // Up moves back to PlayPauseButton
                    if (e.Key == Key.Up)
                    {
                        HighlightVolumeBar(false);
                        PlayPauseButton.Focus();
                        e.Handled = true;
                        return;
                    }

                    // Left/Right: adjust volume in steps of 10
                    if (e.Key == Key.Left)
                    {
                        SetVolumeByStep(-10);
                        e.Handled = true;
                        return;
                    }
                    if (e.Key == Key.Right)
                    {
                        SetVolumeByStep(10);
                        e.Handled = true;
                        return;
                    }
                }
                else
                {
                    HighlightVolumeBar(false);
                }
            }

            base.OnPreviewKeyDown(e);
        }

        // Helper to set volume in steps of 10
        private void SetVolumeByStep(int delta)
        {
            if (_defaultDevice != null)
            {
                double current = Math.Round(_defaultDevice.AudioEndpointVolume.MasterVolumeLevelScalar * 100.0);
                double newVol = Math.Max(0, Math.Min(100, current + delta));
                _defaultDevice.AudioEndpointVolume.MasterVolumeLevelScalar = (float)(newVol / 100.0);
                VolumeSlider.Value = newVol;
                // Optionally, persist volume here if needed
            }
        }

        private void HomeButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            SwitcherOverlay.Visibility = Visibility.Collapsed;
            AllWindowsScroll.Visibility = Visibility.Collapsed;
            _showingAllWindows = false;
            RequestHome?.Invoke(this, EventArgs.Empty);
        }

        private void SwitcherButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            ShowSwitcherView();
        }

        private void ShowSwitcherView()
        {
            _showingAllWindows = false;
            var windows = EnumerateOpenWindows();
            IntPtr activeHwnd = GetForegroundWindow();
            string activeTitle = null;
            foreach (var win in windows)
            {
                if (win.Hwnd == activeHwnd)
                {
                    activeTitle = win.Title;
                    break;
                }
            }

            ActiveWindowTile.Content = activeTitle ?? "(None)";
            ActiveWindowTile.Tag = windows.FirstOrDefault(w => w.Hwnd == activeHwnd);
            ActiveWindowTile.Visibility = Visibility.Visible;

            OtherWindowsPanel.Children.Clear();
            OtherWindowsPanel.Visibility = Visibility.Visible;
            int maxOther = 3;
            int count = 0;
            Button? firstBtn = null;
            foreach (var win in windows)
            {
                if (win.Hwnd == activeHwnd) continue;
                if (count < maxOther)
                {
                    var btn = new Button
                    {
                        Content = win.Title,
                        Tag = win, // <-- Store WindowInfo object
                        Style = (Style)FindResource("SwitcherTileStyle"),
                        Margin = new Thickness(16, 8, 16, 0)
                    };
                    btn.Click += SwitcherTile_Click;
                    OtherWindowsPanel.Children.Add(btn);
                    if (firstBtn == null)
                        firstBtn = btn;
                    count++;
                }
            }
            bool showMore = (windows.Length - (activeTitle != null ? 1 : 0) > maxOther);
            MoreButton.Visibility = showMore ? Visibility.Visible : Visibility.Collapsed;
            AllWindowsScroll.Visibility = Visibility.Collapsed;

            SwitcherOverlay.Visibility = Visibility.Visible;
            SetMenuText("Switcher", "Select a window to switch to.");

            // Focus first item in switcher menu
            if (firstBtn != null)
                firstBtn.Focus();
            else
                ActiveWindowTile.Focus();
        }

        // Show all open windows when "More" is clicked or Enter is pressed
        private void ShowAllWindows_Click(object sender, RoutedEventArgs e)
        {
            ShowAllWindows();
        }

        private void MoreButton_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter || e.Key == Key.Space)
            {
                ShowAllWindows();
                e.Handled = true;
            }
        }

        private void ShowAllWindows()
        {
            _showingAllWindows = true;
            var windows = EnumerateOpenWindows();
            AllWindowsPanel.Children.Clear();

            Button? firstBtn = null;
            foreach (var win in windows)
            {
                var btn = new Button
                {
                    Content = win.Title,
                    Tag = win, // <-- Store WindowInfo object
                    Style = (Style)FindResource("SwitcherTileStyle"),
                    Margin = new Thickness(16, 8, 16, 0)
                };
                btn.Click += SwitcherTile_Click;
                AllWindowsPanel.Children.Add(btn);
                if (firstBtn == null)
                    firstBtn = btn;
            }
            AllWindowsScroll.Visibility = Visibility.Visible;
            ActiveWindowTile.Visibility = Visibility.Collapsed;
            OtherWindowsPanel.Visibility = Visibility.Collapsed;
            MoreButton.Visibility = Visibility.Collapsed;

            // Set focus to the first button if available
            if (firstBtn != null)
                firstBtn.Focus();
        }

        // Hide all windows panel when leaving switcher
        private void NotificationsButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            SwitcherOverlay.Visibility = Visibility.Collapsed;
            AllWindowsScroll.Visibility = Visibility.Collapsed;
            _showingAllWindows = false;
            MessageBox.Show("Notifications: Dummy action.", "Notifications");
            RequestClose?.Invoke(this, EventArgs.Empty);
        }

        private void DownloadsButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            SwitcherOverlay.Visibility = Visibility.Collapsed;
            AllWindowsScroll.Visibility = Visibility.Collapsed;
            _showingAllWindows = false;
            MessageBox.Show("Downloads: Dummy action.", "Downloads");
            RequestClose?.Invoke(this, EventArgs.Empty);
        }

        // Show message box on tile click
        private void SwitcherTile_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            if (sender is Button btn && btn.Tag is WindowInfo win)
            {
                SetForegroundWindow(win.Hwnd);
                this.Close(); // Close the GuideMenu after switching
            }
        }

        // Recent Games section (reads from JSON like dashboard)
        public string AccountName { get; set; } = "Default"; // Set this when creating GuideMenu

        private sealed class LastPlayedEntry
        {
            public string? Title { get; set; }
            public string? GameName { get; set; }
            public string? CoverUri { get; set; }
            public string? PlatformName { get; set; }
            public string? CanonicalTitle => !string.IsNullOrWhiteSpace(GameName) ? GameName : Title;
        }

        private static string SanitizeForPath(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "Unknown";
            var s = input.Trim();
            if ((s.StartsWith("\"") && s.EndsWith("\"")) || (s.StartsWith("'") && s.EndsWith("'")))
                s = s.Substring(1, s.Length - 2).Trim();
            s = s.Replace(":", " - ");
            s = s.Replace("/", " - ").Replace("/", " - ").Replace("\\", " - ");
            s = s.Replace("–", "-").Replace("—", "-");
            s = s.Replace('_', ' ');
            var invalid = System.IO.Path.GetInvalidFileNameChars();
            var sb = new StringBuilder(s.Length);
            foreach (var ch in s)
            {
                if (invalid.Contains(ch))
                    sb.Append(' ');
                else
                    sb.Append(ch);
            }
            s = sb.ToString();
            s = System.Text.RegularExpressions.Regex.Replace(s, @"\s*-\s*", " - ");
            s = System.Text.RegularExpressions.Regex.Replace(s, @"\s{2,}", " ").Trim();
            s = System.Text.RegularExpressions.Regex.Replace(s, @"-+", "-");
            s = s.Trim(' ', '-', '_');
            s = System.Text.RegularExpressions.Regex.Replace(s, @"\s{2,}", " ").Trim();
            return string.IsNullOrWhiteSpace(s) ? "Unknown" : s;
        }

        private static string ResolveCoverUri(string? providedCoverUri, string title, string? platform)
        {
            // 1) prefer provided CoverUri if valid
            if (!string.IsNullOrWhiteSpace(providedCoverUri))
            {
                try
                {
                    if (Uri.TryCreate(providedCoverUri, UriKind.Absolute, out var u))
                    {
                        if (u.IsFile)
                        {
                            var local = u.LocalPath;
                            if (System.IO.File.Exists(local))
                                return u.AbsoluteUri;
                        }
                        else
                        {
                            // remote or pack URI - accept it
                            return providedCoverUri!;
                        }
                    }
                    else
                    {
                        // relative/pack-style, accept as-is
                        return providedCoverUri!;
                    }
                }
                catch { /* fall through to fallback search */ }
            }

            // 2) try multiple candidate filenames in Data/Resources/Game Covers/<PlatformFolder>/<SanitizedTitle>/
            try
            {
                // Map known platform identifiers to folder names used in your Data tree.
                var platformMap = new System.Collections.Generic.Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    { "3DS", "Nintendo - 3DS" },
                    { "DSI", "Nintendo - DSi" },
                    { "DS", "Nintendo - DS" },
                    { "Switch", "Nintendo - Switch" },
                    { "N64", "Nintendo - N64" },
                    { "NES", "Nintendo - NES" },
                    { "SNES", "Nintendo - SNES" },
                    { "GB", "Nintendo - GB" },
                    { "GBA", "Nintendo - GBA" },
                    { "GBC", "Nintendo - GBC" },
                    { "Wii", "Nintendo - Wii" },
                    { "Xbox", "Microsoft - Xbox" },
                    { "Xbox 360", "Microsoft - Xbox 360" },
                    { "PS1", "Sony - Playstation" },
                    { "PS2", "Sony - Playstation 2" },
                    { "PS3", "Sony - Playstation 3" },
                    { "PS4", "Sony - Playstation 4" },
                    { "PSP", "Sony - PSP" },
                    { "PSV", "Sony - PSV" },
                    { "PC", "PC (Windows)" }
                };

                var platformKey = string.IsNullOrWhiteSpace(platform) ? string.Empty : platform.Trim();
                string platformFolder;
                if (!string.IsNullOrEmpty(platformKey) && platformMap.TryGetValue(platformKey, out var mapped))
                {
                    platformFolder = mapped;
                }
                else
                {
                    platformFolder = string.IsNullOrWhiteSpace(platform) ? "Unknown" : SanitizeForPath(platform!);
                }

                // Build a set of title variants similar to GameItem (handle ":" differences)
                var titleVariants = new System.Collections.Generic.List<string> { title ?? string.Empty };
                if (!string.IsNullOrEmpty(title))
                {
                    var v1 = title.Replace(":", " - ");
                    var v2 = title.Replace(":", "-");
                    if (!titleVariants.Contains(v1, StringComparer.OrdinalIgnoreCase)) titleVariants.Add(v1);
                    if (!titleVariants.Contains(v2, StringComparer.OrdinalIgnoreCase)) titleVariants.Add(v2);
                }

                var baseDir = AppContext.BaseDirectory;
                var checkedPaths = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var variant in titleVariants)
                {
                    var gameFolder = string.IsNullOrWhiteSpace(variant) ? "Unknown" : SanitizeForPath(variant);

                    var candidates = new[]
                    {
                        System.IO.Path.Combine(baseDir, "Data", "Resources", "Game Covers", platformFolder, gameFolder, "Cover.png"),
                        System.IO.Path.Combine(baseDir, "Data", "Resources", "Game Covers", platformFolder, gameFolder, "cover.png"),
                        System.IO.Path.Combine(baseDir, "Data", "Resources", "Game Covers", platformFolder, gameFolder, "Cover.jpg"),
                        System.IO.Path.Combine(baseDir, "Data", "Resources", "Game Covers", platformFolder, gameFolder, "cover.jpg"),
                        System.IO.Path.Combine(baseDir, "Data", "Resources", "Game Covers", platformFolder, gameFolder, "cover/jpeg")
                    };

                    foreach (var p in candidates)
                    {
                        if (!checkedPaths.Add(p)) continue;

                        try
                        {
                            if (System.IO.File.Exists(p))
                            {
                                return new Uri(p, UriKind.Absolute).AbsoluteUri;
                            }
                        }
                        catch
                        {
                            // ignore and try next candidate
                        }
                    }
                }
            }
            catch
            {
                // ignore and fall back
            }

            // 3) fallback local resource
            return "/Images/sample1.jpg";
        }

        // --- Add this helper to fetch the preferred executable path for a game ---
        private static string? GetPreferredExePathForTitle(string title, string? platform)
        {
            try
            {
                string accountFolder;
                if (Application.Current?.Properties["LoggedInAccountPath"] is string p && !string.IsNullOrWhiteSpace(p))
                    accountFolder = p;
                else if (Application.Current?.Properties["LoggedInAccount"] is string name && !string.IsNullOrWhiteSpace(name))
                    accountFolder = System.IO.Path.Combine(AppContext.BaseDirectory, "Data", "Accounts", name);
                else
                    accountFolder = System.IO.Path.Combine(AppContext.BaseDirectory, "Data", "Accounts", "Guest");

                var allDataFile = System.IO.Path.Combine(accountFolder, "All.GamesData.json");
                if (!System.IO.File.Exists(allDataFile)) return null;

                var json = System.IO.File.ReadAllText(allDataFile);
                var opts = new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var parsed = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.List<System.Text.Json.JsonElement>>(json, opts);
                if (parsed == null) return null;

                foreach (var el in parsed)
                {
                    string? gameName = null;
                    string? exePath = null;
                    string? plat = null;
                    if (el.ValueKind == System.Text.Json.JsonValueKind.Object)
                    {
                        if (el.TryGetProperty("GameName", out var gn) && gn.ValueKind == System.Text.Json.JsonValueKind.String)
                            gameName = gn.GetString();
                        if (el.TryGetProperty("ExePath", out var ep) && ep.ValueKind == System.Text.Json.JsonValueKind.String)
                            exePath = ep.GetString();
                        if (el.TryGetProperty("PlatformName", out var pf) && pf.ValueKind == System.Text.Json.JsonValueKind.String)
                            plat = pf.GetString();
                    }
                    if (!string.IsNullOrWhiteSpace(gameName) && gameName.Trim().Equals(title.Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        // If platform is specified, prefer exact match
                        if (string.IsNullOrWhiteSpace(platform) || string.IsNullOrWhiteSpace(plat) || plat.Trim().Equals(platform.Trim(), StringComparison.OrdinalIgnoreCase))
                            return exePath;
                    }
                }
            }
            catch { }
            return null;
        }

        private void PopulateRecentGames()
        {
            RecentGamesPanel.Children.Clear();
            try
            {
                // Get account folder (use same logic as Dashboard)
                string accountFolder;
                if (Application.Current?.Properties["LoggedInAccountPath"] is string p && !string.IsNullOrWhiteSpace(p))
                    accountFolder = p;
                else if (Application.Current?.Properties["LoggedInAccount"] is string name && !string.IsNullOrWhiteSpace(name))
                    accountFolder = System.IO.Path.Combine(AppContext.BaseDirectory, "Data", "Accounts", name);
                else
                    accountFolder = System.IO.Path.Combine(AppContext.BaseDirectory, "Data", "Accounts", "Guest");

                var jsonPath = System.IO.Path.Combine(accountFolder, "LastPlayed.json");
                if (!System.IO.File.Exists(jsonPath)) return;
                var json = System.IO.File.ReadAllText(jsonPath);
                var opts = new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                var entries = new System.Collections.Generic.List<LastPlayedEntry>();

                // Try to parse as objects first
                try
                {
                    var parsedObjects = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.List<System.Text.Json.JsonElement>>(json, opts);
                    if (parsedObjects != null && parsedObjects.Count > 0)
                    {
                        foreach (var el in parsedObjects)
                        {
                            var lp = new LastPlayedEntry();
                            if (el.ValueKind == System.Text.Json.JsonValueKind.Object)
                            {
                                if (el.TryGetProperty("GameName", out var gn) && gn.ValueKind == System.Text.Json.JsonValueKind.String)
                                    lp.GameName = gn.GetString();
                                else if (el.TryGetProperty("Title", out var t) && t.ValueKind == System.Text.Json.JsonValueKind.String)
                                    lp.Title = t.GetString();
                                if (el.TryGetProperty("PlatformName", out var pf) && pf.ValueKind == System.Text.Json.JsonValueKind.String)
                                    lp.PlatformName = pf.GetString();
                                if (el.TryGetProperty("CoverUri", out var cu) && cu.ValueKind == System.Text.Json.JsonValueKind.String)
                                    lp.CoverUri = cu.GetString();
                            }
                            else if (el.ValueKind == System.Text.Json.JsonValueKind.String)
                            {
                                lp.Title = el.GetString();
                            }
                            if (!string.IsNullOrWhiteSpace(lp.CanonicalTitle))
                                entries.Add(lp);
                        }
                    }
                }
                catch
                {
                    // fallback: try array of strings
                    try
                    {
                        var arr = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.List<string>>(json, opts);
                        if (arr != null)
                        {
                            foreach (var s in arr)
                            {
                                if (!string.IsNullOrWhiteSpace(s))
                                    entries.Add(new LastPlayedEntry { Title = s });
                            }
                        }
                    }
                    catch
                    {
                        entries.Clear();
                    }
                }

                entries = entries
    .Where(e => !string.IsNullOrWhiteSpace(e?.CanonicalTitle))
    .GroupBy(e => e.CanonicalTitle, StringComparer.OrdinalIgnoreCase)
    .Select(g => g.First())
    .Take(5)
    .ToList();

                foreach (var entry in entries)
                {
                    var title = entry.CanonicalTitle ?? "Unknown";
                    var platform = entry.PlatformName;
                    var displayText = !string.IsNullOrWhiteSpace(platform) ? $"{title} ({platform})" : title;
                    var coverUri = ResolveCoverUri(entry.CoverUri, title, platform);

                    var img = new Image
                    {
                        Width = 160,
                        Height = 90,
                        Stretch = Stretch.UniformToFill,
                        Margin = new Thickness(0, 8, 0, 8),
                        HorizontalAlignment = HorizontalAlignment.Center
                    };

                    bool found = false;
                    ImageSource? loaded = null;
                    try
                    {
                        var bmp = new BitmapImage();
                        bmp.BeginInit();
                        bmp.CacheOption = BitmapCacheOption.OnLoad;

                        if (Uri.TryCreate(coverUri, UriKind.Absolute, out var absoluteUri))
                        {
                            bmp.UriSource = absoluteUri;
                            found = System.IO.File.Exists(absoluteUri.LocalPath);
                        }
                        else if (coverUri.StartsWith("/", StringComparison.Ordinal))
                        {
                            bmp.UriSource = new Uri($"pack://application:,,,{coverUri}", UriKind.Absolute);
                            found = true;
                        }
                        else
                        {
                            bmp.UriSource = new Uri(coverUri, UriKind.RelativeOrAbsolute);
                            found = System.IO.File.Exists(coverUri);
                        }

                        bmp.EndInit();
                        bmp.Freeze();
                        loaded = bmp;
                    }
                    catch
                    {
                        found = false;
                        loaded = null;
                    }

                    img.Source = loaded;

                    var btn = new Button
                    {
                        Content = new StackPanel
                        {
                            Orientation = Orientation.Vertical,
                            HorizontalAlignment = HorizontalAlignment.Center,
                            Children =
                            {
                                img,
                                new TextBlock
                                {
                                    Text = displayText,
                                    Foreground = Brushes.White,
                                    FontWeight = FontWeights.SemiBold,
                                    FontSize = 18,
                                    Margin = new Thickness(0, 8, 0, 0),
                                    TextAlignment = TextAlignment.Center,
                                    HorizontalAlignment = HorizontalAlignment.Center
                                }
                            }
                        },
                        Style = (Style)FindResource("RecentGameTileStyle"),
                        Margin = new Thickness(16, 8, 16, 0),
                        Tag = title
                    };

                    btn.Click += (s, e) =>
                    {
                        PlayActivation();

                        // Use same logic as Dashboard Play button
                        var game = new GameItem(title, coverUri);

                        var owner = Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
                        var info = new GameInfoWindow(game)
                        {
                            Owner = owner
                        };
                        info.LaunchGame();

                        this.Close(); // Optionally close GuideMenu after launch
                    };

                    RecentGamesPanel.Children.Add(btn);
                }
            }
            catch
            {
                // Ignore errors
            }
        }

        // Window enumeration helpers
        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        private const uint GW_OWNER = 4;

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        private class WindowInfo
        {
            public IntPtr Hwnd;
            public string Title;
        }

        private WindowInfo[] EnumerateOpenWindows()
        {
            var windows = new System.Collections.Generic.List<WindowInfo>();
            var seenTitles = new System.Collections.Generic.HashSet<string>();
            int currentProcessId = Process.GetCurrentProcess().Id;

            // Add process names to exclude (case-insensitive)
            var excludedProcesses = new[] {
                "explorer", // Windows Explorer
                "SearchUI", // Cortana/Search
                "ShellExperienceHost", // Shell UI
                "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp", // Windows Input Experience
                "TextInputHost", // Windows Input Experience
                "StartMenuExperienceHost", // Start Menu
                "SystemSettings", // Settings
                "ApplicationFrameHost" // UWP host
            };

            EnumWindows((hWnd, lParam) =>
            {
                if (!IsWindowVisible(hWnd)) return true;
                if (IsIconic(hWnd)) return true; // skip minimized windows
                if (GetWindow(hWnd, GW_OWNER) != IntPtr.Zero) return true; // skip owned/tool windows

                // Skip system windows by class name
                var classSb = new StringBuilder(256);
                GetClassName(hWnd, classSb, classSb.Capacity);
                var className = classSb.ToString();
                if (className == "Progman" || className == "Shell_TrayWnd") return true;

                GetWindowThreadProcessId(hWnd, out int pid);
                if (pid == currentProcessId) return true; // skip own app

                // Get process name and filter out unwanted ones
                try
                {
                    var proc = Process.GetProcessById(pid);
                    var procName = proc.ProcessName;
                    foreach (var excluded in excludedProcesses)
                    {
                        if (procName.Equals(excluded, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
                catch
                {
                    // Ignore processes we can't access
                    return true;
                }

                int length = GetWindowTextLength(hWnd);
                if (length == 0) return true;

                var sb = new StringBuilder(length + 1);
                GetWindowText(hWnd, sb, sb.Capacity);

                var title = sb.ToString();
                if (string.IsNullOrWhiteSpace(title)) return true; // skip empty titles
                if (!seenTitles.Add(title)) return true; // skip duplicate titles

                windows.Add(new WindowInfo { Hwnd = hWnd, Title = title });
                return true;
            }, IntPtr.Zero);

            return windows.ToArray();
        }

        private void RecentGamesButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            ShowRecentGamesView();
        }

        private void ShowRecentGamesView()
        {
            SwitcherOverlay.Visibility = Visibility.Collapsed;
            AllWindowsScroll.Visibility = Visibility.Collapsed;
            RecentGamesOverlay.Visibility = Visibility.Visible;
            SetMenuText("Recent Games", "Select a recently played game.");

            PopulateRecentGames();

            // Focus first game button if available
            if (RecentGamesPanel.Children.Count > 0 && RecentGamesPanel.Children[0] is Button btn)
                btn.Focus();
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();

            var settingsWindow = new PS5_OS.SettingsWindow();
            settingsWindow.Owner = null; // Optional: remove owner if you want it non-modal
            settingsWindow.Show();

            this.Close();
        }
        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        private void DirectLaunchGame(string title, string? platform)
        {
            try
            {
                var exePathRaw = GetPreferredExePathForTitle(title, platform);
                string exePath, workingDir;
                if (!TryResolveExecutable(exePathRaw, title, out exePath, out workingDir))
                {
                    MessageBox.Show("Game executable not found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var startInfo = new ProcessStartInfo(exePath)
                {
                    WorkingDirectory = workingDir,
                    UseShellExecute = true
                };
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to launch game: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private bool TryResolveExecutable(string? inputPath, string displayTitle, out string exePath, out string workingDir)
        {
            exePath = string.Empty;
            workingDir = string.Empty;

            try
            {
                if (string.IsNullOrWhiteSpace(inputPath))
                    return false;

                var candidate = inputPath!;
                try { candidate = System.IO.Path.GetFullPath(candidate); } catch { }

                if (System.IO.Path.HasExtension(candidate) && System.IO.File.Exists(candidate))
                {
                    exePath = candidate;
                    workingDir = System.IO.Path.GetDirectoryName(candidate) ?? Environment.CurrentDirectory;
                    return true;
                }

                string folder = candidate;
                if (System.IO.Path.HasExtension(candidate))
                {
                    var parent = System.IO.Path.GetDirectoryName(candidate);
                    if (!string.IsNullOrWhiteSpace(parent) && System.IO.Directory.Exists(parent))
                        folder = parent;
                }
                else if (!System.IO.Directory.Exists(folder))
                {
                    var parent = System.IO.Path.GetDirectoryName(folder);
                    if (!string.IsNullOrWhiteSpace(parent) && System.IO.Directory.Exists(parent))
                        folder = parent;
                }

                if (!System.IO.Directory.Exists(folder))
                    return false;

                // 1) exact match Game.DisplayTitle.exe
                if (!string.IsNullOrWhiteSpace(displayTitle))
                {
                    try
                    {
                        var exact = System.IO.Path.Combine(folder, displayTitle + ".exe");
                        if (System.IO.File.Exists(exact))
                        {
                            exePath = exact;
                            workingDir = folder;
                            return true;
                        }

                        var match = System.IO.Directory.EnumerateFiles(folder, "*.exe", System.IO.SearchOption.TopDirectoryOnly)
                            .FirstOrDefault(f => System.IO.Path.GetFileName(f).IndexOf(displayTitle, StringComparison.OrdinalIgnoreCase) >= 0);
                        if (!string.IsNullOrWhiteSpace(match))
                        {
                            exePath = match;
                            workingDir = folder;
                            return true;
                        }
                    }
                    catch { }
                }

                // 2) any top-level exe in folder
                try
                {
                    var any = System.IO.Directory.EnumerateFiles(folder, "*.exe", System.IO.SearchOption.TopDirectoryOnly).FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(any))
                    {
                        exePath = any;
                        workingDir = folder;
                        return true;
                    }
                }
                catch { }

                // 3) search immediate subdirectories (depth 1)
                try
                {
                    foreach (var sub in System.IO.Directory.EnumerateDirectories(folder))
                    {
                        try
                        {
                            var top = System.IO.Directory.EnumerateFiles(sub, "*.exe", System.IO.SearchOption.TopDirectoryOnly).FirstOrDefault();
                            if (!string.IsNullOrWhiteSpace(top))
                            {
                                exePath = top;
                                workingDir = System.IO.Path.GetDirectoryName(top) ?? sub;
                                return true;
                            }

                            if (!string.IsNullOrWhiteSpace(displayTitle))
                            {
                                var nested = System.IO.Directory.EnumerateFiles(sub, "*.exe", System.IO.SearchOption.AllDirectories)
                                    .FirstOrDefault(f => System.IO.Path.GetFileName(f).IndexOf(displayTitle, StringComparison.OrdinalIgnoreCase) >= 0);
                                if (!string.IsNullOrWhiteSpace(nested))
                                {
                                    exePath = nested;
                                    workingDir = System.IO.Path.GetDirectoryName(nested) ?? sub;
                                    return true;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
            catch { }

            return false;
        }

        private void PowerMenuButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            SwitcherOverlay.Visibility = Visibility.Collapsed;
            AllWindowsScroll.Visibility = Visibility.Collapsed;
            RecentGamesOverlay.Visibility = Visibility.Collapsed;
            PowerMenuOverlay.Visibility = Visibility.Visible;
            SetMenuText("Power", "Choose a power option.");
            ShutdownButton.Focus();
        }

        private void ShutdownButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            PowerMenuOverlay.Visibility = Visibility.Collapsed;
            // Actual shutdown command (uncomment to enable)
            // Process.Start("shutdown", "/s /t 0");
            MessageBox.Show("System would shut down now.", "Shutdown");
            RequestClose?.Invoke(this, EventArgs.Empty);
        }

        private void RestartButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            PowerMenuOverlay.Visibility = Visibility.Collapsed;
            // Actual restart command (uncomment to enable)
            // Process.Start("shutdown", "/r /t 0");
            MessageBox.Show("System would restart now.", "Restart");
            RequestClose?.Invoke(this, EventArgs.Empty);
        }

        private void SleepButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            PowerMenuOverlay.Visibility = Visibility.Collapsed;
            // Actual sleep command (uncomment to enable)
            // Application.SetSuspendState(PowerState.Suspend, true, true);
            MessageBox.Show("System would sleep now.", "Sleep");
            RequestClose?.Invoke(this, EventArgs.Empty);
        }

        private void CancelPowerButton_Click(object sender, RoutedEventArgs e)
        {
            PlayNavigation();
            PowerMenuOverlay.Visibility = Visibility.Collapsed;
            HomeButton.Focus();
        }
        private void FriendsButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MessageBox.Show("Friends: View and manage your friends list.", "Friends");
        }

        private void InboxButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MessageBox.Show("Inbox: Check your messages and notifications.", "Inbox");
        }

        private void RewindButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MessageBox.Show("Media: Rewind.", "Rewind");
        }

        private void PlayPauseButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            SendMediaPlayPause();
        }

        // Win32 API for sending media key
        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, [In] INPUT[] pInputs, int cbSize);

        private const int INPUT_KEYBOARD = 1;
        private const ushort VK_MEDIA_PLAY_PAUSE = 0xB3;
        private const uint KEYEVENTF_KEYDOWN = 0x0000;
        private const uint KEYEVENTF_KEYUP = 0x0002;
        private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;

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
            public IntPtr dwExtraInfo;
        }

        private void SendMediaPlayPause()
        {
            // Set desktop as foreground window to avoid focus issues
            SetForegroundWindow(GetDesktopWindow());
            var inputs = new INPUT[2];
            inputs[0].type = INPUT_KEYBOARD;
            inputs[0].u.ki = new KEYBDINPUT
            {
                wVk = VK_MEDIA_PLAY_PAUSE,
                wScan = 0,
                dwFlags = KEYEVENTF_KEYDOWN,
                time = 0,
                dwExtraInfo = IntPtr.Zero
            };
            inputs[1].type = INPUT_KEYBOARD;
            inputs[1].u.ki = new KEYBDINPUT
            {
                wVk = VK_MEDIA_PLAY_PAUSE,
                wScan = 0,
                dwFlags = KEYEVENTF_KEYUP,
                time = 0,
                dwExtraInfo = IntPtr.Zero
            };
            SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MessageBox.Show("Media: Stop.", "Stop");
        }

        private void FastForwardButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MessageBox.Show("Media: Fast Forward.", "Fast Forward");
        }

        private void VolumeButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MessageBox.Show("Volume: Adjust volume.", "Volume");
        }

        private void MediaButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            MediaOverlay.Visibility = Visibility.Visible;
            SetMenuText("Media Controls", "Control playback and volume.");

            // Set slider to current system volume (0-100 scale)
            if (_defaultDevice != null)
            {
                double vol = Math.Round(_defaultDevice.AudioEndpointVolume.MasterVolumeLevelScalar * 100.0);
                VolumeSlider.Value = Math.Max(0, Math.Min(100, vol));
            }

            RewindButton.Focus();
        }

        private void CloseMediaButton_Click(object sender, RoutedEventArgs e)
        {
            PlayNavigation();
            MediaOverlay.Visibility = Visibility.Collapsed;
            MediaButton.Focus();
        }

        private void VolumeSlider_GotFocus(object sender, RoutedEventArgs e)
        {
            HighlightVolumeBar(true);
        }

        private void VolumeSlider_LostFocus(object sender, RoutedEventArgs e)
        {
            HighlightVolumeBar(false);
        }

        private void VolumeSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_defaultDevice != null)
            {
                // No need to snap, slider only allows multiples of 10
                float volume = (float)(VolumeSlider.Value / 100.0);
                _defaultDevice.AudioEndpointVolume.MasterVolumeLevelScalar = volume;

                // Persist volume (optional)
                // Properties.Settings.Default.LastVolume = VolumeSlider.Value;
                // Properties.Settings.Default.Save();
            }
        }

        private void AudioEndpointVolume_OnVolumeNotification(AudioVolumeNotificationData data)
        {
            // Update slider on UI thread
            Dispatcher.Invoke(() =>
            {
                double vol = Math.Round(data.MasterVolume * 100.0);
                VolumeSlider.Value = Math.Max(0, Math.Min(100, vol));
            });
        }

        // Add these Win32 API imports and constant for closing windows
        [DllImport("user32.dll")]

        private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private const uint WM_CLOSE = 0x0010;

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();
            PowerMenuOverlay.Visibility = Visibility.Collapsed;
            HandleAltF4Close();
        }

        // Handles Alt+F4 logic for closing topmost external window
        private void HandleAltF4Close()
        {
            IntPtr targetHwnd = FindTopmostExternalWindow();
            GetWindowThreadProcessId(targetHwnd, out int targetPid);
            int thisPid = Process.GetCurrentProcess().Id;
            if (targetHwnd == IntPtr.Zero || targetPid == thisPid || targetPid == 0)
            {
                MessageBox.Show("No external window is currently underneath the quick menu, or you tried to close your own app.", "Exit", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                try
                {
                    PostMessage(targetHwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                    System.Threading.Thread.Sleep(800);
                    if (IsWindowVisible(targetHwnd))
                    {
                        try
                        {
                            var proc = Process.GetProcessById(targetPid);
                            proc.Kill();
                            MessageBox.Show($"Process '{proc.ProcessName}' was force-closed.", "Exit", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Failed to close process: {ex.Message}", "Exit", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to send exit command: {ex.Message}", "Exit", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            this.Close();
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetTopWindow(IntPtr hWnd);
        private const uint GW_HWNDNEXT = 2;

        private IntPtr FindTopmostExternalWindow()
        {
            // Use the same logic as Switcher: get the first open window from EnumerateOpenWindows()
            var windows = EnumerateOpenWindows();
            if (windows.Length > 0)
            {
                return windows[0].Hwnd;
            }
            return IntPtr.Zero;
        }

        private void BrowserButton_Click(object sender, RoutedEventArgs e)
        {
            PlayActivation();

            // List of common browser process names
            var browserProcesses = new[] { "chrome", "msedge", "firefox", "iexplore", "opera", "brave" };
            var foundWindow = false;

            // Enumerate open windows and look for a browser
            foreach (var win in EnumerateOpenWindows())
            {
                try
                {
                    GetWindowThreadProcessId(win.Hwnd, out int pid);
                    var proc = Process.GetProcessById(pid);
                    if (browserProcesses.Any(name => proc.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase)))
                    {
                        // Found a browser window, bring it to foreground
                        SetForegroundWindow(win.Hwnd);
                        foundWindow = true;
                        break;
                    }
                }
                catch
                {
                    // Ignore inaccessible processes
                }
            }

            if (!foundWindow)
            {
                // No browser found, open Google in default browser
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "https://www.google.com",
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to open browser: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }

            // Always close the Guide Menu after switching or opening browser
            this.Close();
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetDesktopWindow();
    }
}