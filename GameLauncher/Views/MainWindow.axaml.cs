using System;
using System.ComponentModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Threading;
using Avalonia.VisualTree;
using GameLauncher.Services;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _globalHotkeyPoller = new()
    {
        Interval = TimeSpan.FromMilliseconds(150)
    };
    private MainViewModel? _boundVm;
    private bool _globalHotkeyLatched;
    private bool _overlayUpLatched;
    private bool _overlayDownLatched;
    private bool _overlayLeftLatched;
    private bool _overlayRightLatched;
    private bool _overlayEnterLatched;
    private bool _overlaySpaceLatched;
    private bool _overlayEscapeLatched;
    private bool _overlayLbLatched;
    private bool _overlayRbLatched;

    // Separate overlay window for the global Quick Menu (shown over games without
    // restoring the full launcher — mirrors the Steam/NVIDIA overlay pattern).
    private QuickMenuWindow? _quickMenuWindow;

    // ── XInput controller support ────────────────────────────────────────────
    private readonly XInputService _xinput = new();
    private readonly DispatcherTimer _xinputPoller = new()
    {
        Interval = TimeSpan.FromMilliseconds(150)
    };
    // Controller input injection — forwards active profile mappings to the running game.
    private readonly Services.ControllerInputInjector _controllerInjector = new();

    public MainWindow()
    {
        InitializeComponent();
        KeyDown += OnKeyDown;
        DataContextChanged += OnDataContextChanged;
        Opened += (_, _) => RefreshGlobalHotkeyPolling();
        Closed += OnMainWindowClosed;
        _globalHotkeyPoller.Tick += OnGlobalHotkeyTick;
        _xinputPoller.Tick += OnXInputTick;
        WireXInputCallbacks();
    }

    private void OnMainWindowClosed(object? sender, EventArgs e)
    {
        _globalHotkeyPoller.Stop();
        _xinputPoller.Stop();
        _quickMenuWindow?.Close();
        _quickMenuWindow = null;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_boundVm != null)
        {
            _boundVm.PropertyChanged -= OnMainViewModelPropertyChanged;
            _boundVm.SettingsVm.SettingsApplied -= RefreshGlobalHotkeyPolling;
        }

        if (DataContext is MainViewModel vm)
        {
            _boundVm = vm;
            vm.PropertyChanged += OnMainViewModelPropertyChanged;
            vm.SettingsVm.SettingsApplied += RefreshGlobalHotkeyPolling;

            // Capture the window state at the time of minimise so we can restore
            // to the same state (FullScreen, Normal, Maximized) when the game exits.
            WindowState _stateBeforeMinimize = WindowState;

            vm.MinimizeWindowRequested = () =>
            {
                _stateBeforeMinimize = WindowState;
                WindowState = WindowState.Minimized;
            };
            vm.RestoreWindowRequested  = () =>
            {
                WindowState = _stateBeforeMinimize;
                Activate();
            };
            vm.BringToForegroundRequested = () =>
            {
                if (WindowState == WindowState.Minimized)
                    WindowState = _stateBeforeMinimize;
                Activate();
            };
            // Wire the "Update available" dialog so it shows a native message box.
            vm.ShowUpdateDialogRequested = async tag =>
            {
                var dialog = new Avalonia.Controls.Window
                {
                    Title           = "Update Available",
                    Width           = 360,
                    Height          = 180,
                    CanResize       = false,
                    ShowInTaskbar   = false,
                    WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.CenterOwner,
                    SystemDecorations = Avalonia.Controls.SystemDecorations.Full,
                };

                bool updateNow = false;
                var tcs = new System.Threading.Tasks.TaskCompletionSource<bool>();

                var updateBtn = new Avalonia.Controls.Button
                {
                    Content = "Update Now",
                    Margin  = new Avalonia.Thickness(0, 0, 8, 0),
                    Padding = new Avalonia.Thickness(16, 8),
                };
                var laterBtn = new Avalonia.Controls.Button
                {
                    Content = "Update Later",
                    Padding = new Avalonia.Thickness(16, 8),
                };
                updateBtn.Click += (_, _) => { updateNow = true; dialog.Close(); };
                laterBtn.Click  += (_, _) => { dialog.Close(); };
                dialog.Closed   += (_, _) => tcs.TrySetResult(updateNow);

                dialog.Content = new Avalonia.Controls.StackPanel
                {
                    Margin  = new Avalonia.Thickness(24),
                    Spacing = 16,
                    Children =
                    {
                        new Avalonia.Controls.TextBlock
                        {
                            Text         = $"Game.OS {tag} is available.",
                            FontSize     = 16,
                            FontWeight   = Avalonia.Media.FontWeight.SemiBold,
                            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                        },
                        new Avalonia.Controls.TextBlock
                        {
                            Text         = "Do you want to download and install it now?",
                            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                        },
                        new Avalonia.Controls.StackPanel
                        {
                            Orientation = Avalonia.Layout.Orientation.Horizontal,
                            Children    = { updateBtn, laterBtn },
                        },
                    },
                };

                await dialog.ShowDialog(this);
                return await tcs.Task;
            };
            RefreshGlobalHotkeyPolling();
            if (OperatingSystem.IsWindows() && !_xinputPoller.IsEnabled)
                _xinputPoller.Start();
        }
        else
        {
            _boundVm = null;
            RefreshGlobalHotkeyPolling();
            _xinputPoller.Stop();
        }
    }

    /// <summary>
    /// Handles global keyboard and gamepad navigation.
    /// Xbox / PlayStation controllers connected via XInput/DirectInput are reported
    /// as standard keyboard keys by Windows:
    ///   Escape / B-button  → close overlays / go back / close nav menu
    ///   Enter / A-button   → confirm; when nav open, navigates to highlighted item
    ///   Left               → open nav sidebar (when not in detail / text input / at dashboard card 0)
    ///   Right              → close nav sidebar (when open)
    ///   Up / Down          → when nav open: move highlight without switching; on dash: scroll cards;
    ///                        in library: scroll game list
    ///   PageUp  / LB       → navigate to previous page (always available)
    ///   PageDown / RB      → navigate to next page (always available)
    ///   F5                 → refresh / reload library
    ///   Left Shift + Left Ctrl → toggle Quick Menu overlay
    ///   Y                  → focus search box (library / store)
    ///   X                  → cycle filter (library platform / store platform)
    /// </summary>
    /// <summary>
    /// After a navigation key, scrolls the highlighted (focused / active) item into view so the
    /// page and side lists follow the controller cursor.
    /// </summary>
    private void ScheduleScrollHighlightedIntoView()
    {
        Dispatcher.UIThread.Post(() =>
        {
            var target = this.GetVisualDescendants().OfType<Control>().FirstOrDefault(c =>
                c.IsEffectivelyVisible &&
                (c.Classes.Contains("focused") ||
                 (c.Classes.Contains("active") && c.Classes.Contains("settings-nav-item"))));
            target?.BringIntoView();
        }, DispatcherPriority.Background);
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        ScheduleScrollHighlightedIntoView();
        if (DataContext is not MainViewModel vm) return;

        // Left Shift + Left Ctrl → Quick Menu toggle (takes priority).
        // Handle both orderings: user may press Shift first then Ctrl, or Ctrl first then Shift.
        bool isShiftCtrl = (e.Key == Key.LeftCtrl  && e.KeyModifiers.HasFlag(KeyModifiers.Shift)) ||
                           (e.Key == Key.LeftShift && e.KeyModifiers.HasFlag(KeyModifiers.Control));
        if (isShiftCtrl)
        {
            vm.ToggleQuickMenu();
            e.Handled = true;
            return;
        }

        // While quick menu is open, prioritize quick-menu navigation.
        if (vm.ShowQuickMenu)
        {
            bool textInputFocused = IsTextInputFocused();
            bool isXb360QuickMenu = vm.QuickMenuVm.IsXb360Theme;
            switch (e.Key)
            {
                case Key.Left:
                    if (!textInputFocused)
                    {
                        if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360Blade(-1);
                        else vm.QuickMenuVm.MoveHubSelection(-1);
                    }
                    e.Handled = true;
                    return;
                case Key.Right:
                    if (!textInputFocused)
                    {
                        if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360Blade(1);
                        else vm.QuickMenuVm.MoveHubSelection(1);
                    }
                    e.Handled = true;
                    return;
                // LB / RB → blade navigation (PageUp = LB, PageDown = RB).
                case Key.PageUp:
                    if (!textInputFocused && isXb360QuickMenu) vm.QuickMenuVm.MoveXb360Blade(-1);
                    e.Handled = true;
                    return;
                case Key.PageDown:
                    if (!textInputFocused && isXb360QuickMenu) vm.QuickMenuVm.MoveXb360Blade(1);
                    e.Handled = true;
                    return;
                case Key.Up:
                    if (!textInputFocused)
                    {
                        if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360CenterItem(-1);
                    }
                    e.Handled = true;
                    return;
                case Key.Down:
                    if (!textInputFocused)
                    {
                        if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360CenterItem(1);
                    }
                    e.Handled = true;
                    return;
                case Key.Enter:
                case Key.Space:
                    if (!textInputFocused) vm.QuickMenuVm.ActivateSelectedHub();
                    e.Handled = true;
                    return;
                // Y button → navigate to Game OS Home / Dashboard.
                case Key.Y:
                    if (!textInputFocused && isXb360QuickMenu) vm.QuickMenuVm.GoToGameOsHomeCommand.Execute(null);
                    e.Handled = true;
                    return;
                case Key.Escape:
                case Key.BrowserBack:
                    if (!vm.QuickMenuVm.HandleBackNavigation())
                        vm.ShowQuickMenu = false;
                    e.Handled = true;
                    return;
                default:
                    // Block all remaining key events from reaching the background Game OS.
                    e.Handled = true;
                    return;
            }
        }

        // ── Nav sidebar open: Up/Down move highlight; Enter navigates to highlighted item ──
        if (vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile && !IsTextInputFocused())
        {
            switch (e.Key)
            {
                case Key.Up:
                    vm.NavHighlightIndex = Math.Max(0, vm.NavHighlightIndex - 1);
                    e.Handled = true;
                    return;
                case Key.Down:
                    vm.NavHighlightIndex = Math.Min(_navPages.Length - 1, vm.NavHighlightIndex + 1);
                    e.Handled = true;
                    return;
                case Key.Enter:
                case Key.Space:
                    // Navigate to highlighted item and close sidebar
                    vm.NavigateCommand.Execute(_navPages[vm.NavHighlightIndex]);
                    e.Handled = true;
                    return;
                case Key.Escape:
                case Key.BrowserBack:
                    vm.IsNavExpanded = false;
                    e.Handled = true;
                    return;
                case Key.Right:
                    // Right closes the nav sidebar
                    vm.IsNavExpanded = false;
                    e.Handled = true;
                    return;
            }
        }

        // Game detail: arrow keys move the highlight between every control on the page
        if (vm.ShowDetail && !vm.ShowQuickMenu && !IsTextInputFocused() &&
            e.Key is Key.Up or Key.Down or Key.Left or Key.Right &&
            DetailHost?.HandleNavKey(e.Key, activateWithEnter: false) == true)
        {
            e.Handled = true;
            return;
        }

        // XB360 dashboard navigation
        bool isXb360 = string.Equals(vm.SettingsVm.DesignTheme, "XB360", StringComparison.OrdinalIgnoreCase);
        if (vm.IsHome && isXb360 && !vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile && !IsTextInputFocused())
        {
            switch (e.Key)
            {
                case Key.Left:
                    vm.DashboardVm.MoveXb360Blade(-1);
                    e.Handled = true;
                    return;
                case Key.Right:
                    vm.DashboardVm.MoveXb360Blade(1);
                    e.Handled = true;
                    return;
                case Key.Up:
                    vm.DashboardVm.MoveXb360GameFocus(-1);
                    e.Handled = true;
                    return;
                case Key.Down:
                    vm.DashboardVm.MoveXb360GameFocus(1);
                    e.Handled = true;
                    return;
                case Key.Enter:
                    vm.DashboardVm.PlayXb360FocusedGameCommand.Execute(null);
                    e.Handled = true;
                    return;
            }
        }

        // Default dashboard: hero "Continue Playing" button + Continue Playing cards
        bool isDefaultDash = string.Equals(vm.SettingsVm.DesignTheme, "Default", StringComparison.OrdinalIgnoreCase);
        if (vm.IsHome && isDefaultDash && !vm.ShowQuickMenu && !vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile && !IsTextInputFocused())
        {
            switch (e.Key)
            {
                case Key.Right:
                case Key.Down:
                    vm.DashboardVm.MoveDefaultFocus(1);
                    e.Handled = true;
                    return;
                case Key.Left:
                    if (vm.DashboardVm.IsAtDefaultFirstItem) OpenNavWithCurrentHighlight(vm);
                    else vm.DashboardVm.MoveDefaultFocus(-1);
                    e.Handled = true;
                    return;
                case Key.Up:
                    vm.DashboardVm.MoveDefaultFocus(-1);
                    e.Handled = true;
                    return;
                case Key.Enter:
                    vm.DashboardVm.OpenDefaultFocused();
                    e.Handled = true;
                    return;
                case Key.X:
                    vm.DashboardVm.PlayDefaultFocused();
                    e.Handled = true;
                    return;
            }
        }

        // PS5/Switch dashboard navigation
        bool usesCardDashboardNavigation =
            string.Equals(vm.SettingsVm.DesignTheme, "PS5", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(vm.SettingsVm.DesignTheme, "Switch", StringComparison.OrdinalIgnoreCase);
        if (vm.IsHome && usesCardDashboardNavigation && !vm.ShowQuickMenu && !vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile && !IsTextInputFocused())
        {
            switch (e.Key)
            {
                case Key.Right:
                    vm.DashboardVm.MoveFocus(1);
                    e.Handled = true;
                    return;
                case Key.Left:
                    // At first card (index 0) or no focused card → open nav menu
                    if (vm.DashboardVm.IsAtFirstTile)
                    {
                        OpenNavWithCurrentHighlight(vm);
                        e.Handled = true;
                        return;
                    }
                    vm.DashboardVm.MoveFocus(-1);
                    e.Handled = true;
                    return;
                case Key.Down:
                    // Move to next recent game card (same as Right)
                    vm.DashboardVm.MoveFocus(1);
                    e.Handled = true;
                    return;
                case Key.Up:
                    // Move to previous recent game card (same as Left but stays on dash)
                    if (!vm.DashboardVm.IsAtFirstTile)
                        vm.DashboardVm.MoveFocus(-1);
                    e.Handled = true;
                    return;
                case Key.Enter:
                    // A button on a focused card → open game detail/info page
                    vm.DashboardVm.ActivateFocusedTile();
                    e.Handled = true;
                    return;
                case Key.X:
                    // X → launch the highlighted game
                    vm.DashboardVm.LaunchFocusedTile();
                    e.Handled = true;
                    return;
            }
        }

        if (!vm.IsSettings) _settingsInContent = false;
        // Settings controller navigation (left menu ↔ right content)
        if (vm.IsSettings && !vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded)
        {
            if (HandleSettingsKey(vm, e.Key, IsTextInputFocused()))
            {
                e.Handled = true;
                return;
            }
        }

        // Library controller navigation (when not in a text input so Y can open search)
        if (vm.IsLibrary && !vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded)
        {
            if (HandleLibraryKey(vm, e.Key, IsTextInputFocused()))
            {
                e.Handled = true;
                return;
            }
        }

        // Store controller navigation
        if (vm.IsStore && !vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded)
        {
            bool inSearch = IsTextInputFocused();
            switch (e.Key)
            {
                // Y → focus search box
                case Key.Y when !inSearch:
                    vm.StoreVm.FocusSearchRequested?.Invoke();
                    e.Handled = true;
                    return;
                // X → cycle platform filter
                case Key.X when !inSearch:
                    vm.StoreVm.CyclePlatform();
                    e.Handled = true;
                    return;
                // LB/RB → switch Games / App Store tabs
                case Key.PageUp:
                case Key.PageDown:
                    vm.StoreVm.CycleTab();
                    e.Handled = true;
                    return;
            }
        }

        switch (e.Key)
        {
            // Navigate back from a detail or friend-profile overlay
            // Also close nav sidebar when open
            case Key.Escape:
            case Key.BrowserBack:
                if (vm.ShowQuickMenu)
                {
                    if (!vm.QuickMenuVm.HandleBackNavigation())
                        vm.ShowQuickMenu = false;
                    e.Handled = true;
                }
                else if (vm.ShowDetail)
                {
                    if (DetailHost != null) DetailHost.HandleBack();
                    else vm.DetailVm.CloseCommand.Execute(null);
                    e.Handled = true;
                }
                else if (vm.ShowFriendProfile)
                {
                    vm.CloseFriendProfileCommand.Execute(null);
                    e.Handled = true;
                }
                else if (vm.IsNavExpanded)
                {
                    vm.IsNavExpanded = false;
                    e.Handled = true;
                }
                break;

            // LB / PageUp → previous page (always works regardless of nav state)
            case Key.PageUp:
                if (!vm.ShowDetail && !vm.ShowFriendProfile)
                {
                    NavigatePrev(vm);
                    e.Handled = true;
                }
                break;

            // RB / PageDown → next page (always works regardless of nav state)
            case Key.PageDown:
                if (!vm.ShowDetail && !vm.ShowFriendProfile)
                {
                    NavigateNext(vm);
                    e.Handled = true;
                }
                break;

            // Left arrow → open the nav sidebar (when not in a text input and not on the
            // dashboard — on the dashboard Left is consumed by game-card scrolling above).
            case Key.Left:
                if (!vm.ShowDetail && !vm.ShowFriendProfile && !IsTextInputFocused() && !vm.IsHome)
                {
                    if (!vm.IsNavExpanded)
                    {
                        OpenNavWithCurrentHighlight(vm);
                        e.Handled = true;
                    }
                }
                break;

            // Right arrow → close the nav sidebar (when open)
            case Key.Right:
                if (!vm.ShowDetail && !vm.ShowFriendProfile && !IsTextInputFocused())
                {
                    if (vm.IsNavExpanded)
                    {
                        vm.IsNavExpanded = false;
                        e.Handled = true;
                    }
                }
                break;
        }
    }

    /// <summary>
    /// Opens the nav sidebar and initialises the highlight to the currently active page,
    /// so the user sees their current position when navigating with Up/Down.
    /// </summary>
    private static void OpenNavWithCurrentHighlight(MainViewModel vm)
    {
        int pageIdx = System.Array.IndexOf(_navPages, vm.ActivePage);
        vm.NavHighlightIndex = pageIdx >= 0 ? pageIdx : 0;
        vm.IsNavExpanded = true;
    }

    // ── Settings page navigation ──────────────────────────────────────────
    private static readonly string[] _settingsSections =
        ["app", "emulator", "playtime", "sync", "account", "customise", "design",
         "system", "notifications", "developer", "controller"];

    /// <summary>True while the D-pad cursor is in the right-hand settings content.</summary>
    private bool _settingsInContent;

    private SettingsView? FindSettingsView() =>
        this.GetVisualDescendants().OfType<SettingsView>().FirstOrDefault();

    private static bool IsSettingsContentControl(Control c) =>
        c.Focusable && c.IsEffectivelyVisible && c.IsEffectivelyEnabled && c.IsTabStop &&
        !c.Classes.Contains("settings-nav-item") &&
        (c is Button or ToggleButton or ComboBox or TextBox or Slider or NumericUpDown);

    private bool EnterSettingsContent()
    {
        var view = FindSettingsView();
        var first = view?.GetVisualDescendants().OfType<Control>().FirstOrDefault(IsSettingsContentControl);
        if (first == null) return false;
        first.Focus(NavigationMethod.Directional);
        first.BringIntoView();
        return true;
    }

    private void ActivateSettingsFocused()
    {
        switch (FocusManager?.GetFocusedElement())
        {
            case ToggleButton t: t.IsChecked = !(t.IsChecked ?? false); break;
            case Button b:
                if (b.Command?.CanExecute(b.CommandParameter) == true) b.Command.Execute(b.CommandParameter);
                else b.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                break;
            case ComboBox c: c.IsDropDownOpen = !c.IsDropDownOpen; break;
        }
    }

    /// <summary>
    /// Settings: Up/Down pick a category on the left; A enters the category's options;
    /// B goes back to the left menu; B on the left menu closes Settings.
    /// </summary>
    private bool HandleSettingsKey(MainViewModel vm, Key key, bool inTextInput)
    {
        var sv = vm.SettingsVm;
        if (!_settingsInContent)
        {
            switch (key)
            {
                case Key.Up:
                case Key.Down:
                {
                    int idx = Array.IndexOf(_settingsSections, sv.SelectedSection);
                    idx = Math.Clamp((idx < 0 ? 0 : idx) + (key == Key.Up ? -1 : 1), 0, _settingsSections.Length - 1);
                    sv.SelectSectionCommand.Execute(_settingsSections[idx]);
                    return true;
                }
                case Key.Enter:
                case Key.Right:
                    _settingsInContent = EnterSettingsContent();
                    return true;
                case Key.Escape:
                case Key.BrowserBack:
                    vm.NavigateCommand.Execute("dashboard");
                    return true;
            }
            return false;
        }

        if (inTextInput && key != Key.Escape && key != Key.BrowserBack) return false;

        // A ComboBox with an open drop-down handles its own keys.
        if (FocusManager?.GetFocusedElement() is ComboBox { IsDropDownOpen: true } && key != Key.Escape)
            return false;

        switch (key)
        {
            case Key.Up:
            case Key.Down:
            {
                var items = FindSettingsView()?.GetVisualDescendants().OfType<Control>()
                                .Where(IsSettingsContentControl).ToList();
                if (items == null || items.Count == 0) return true;
                int cur = items.IndexOf(FocusManager?.GetFocusedElement() as Control ?? items[0]);
                int nxt = Math.Clamp((cur < 0 ? 0 : cur) + (key == Key.Up ? -1 : 1), 0, items.Count - 1);
                items[nxt].Focus(NavigationMethod.Directional);
                items[nxt].BringIntoView();
                return true;
            }
            case Key.Enter:
                ActivateSettingsFocused();
                return true;
            case Key.Escape:
            case Key.BrowserBack:
                _settingsInContent = false;
                FocusManager?.ClearFocus();
                return true;
        }
        return false;
    }

    /// <summary>
    /// Games-library controller/keyboard handling shared by both input paths.
    /// Returns true when the key was consumed. Up/Down move a row, Left/Right move a card,
    /// X opens the filter box, Y opens the on-screen keyboard, B closes either overlay.
    /// </summary>
    private static bool HandleLibraryKey(MainViewModel vm, Key key, bool inSearch)
    {
        var lib = vm.LibraryVm;

        if (lib.IsKeyboardOpen)
        {
            switch (key)
            {
                case Key.Up:     lib.MoveKeyboard(-1, 0); break;
                case Key.Down:   lib.MoveKeyboard(1, 0);  break;
                case Key.Left:   lib.MoveKeyboard(0, -1); break;
                case Key.Right:  lib.MoveKeyboard(0, 1);  break;
                case Key.Enter:  lib.PressKeyboardKey();  break;
                case Key.X:      lib.BackspaceSearch();   break;
                case Key.Y:
                case Key.Escape:
                case Key.BrowserBack: lib.CloseKeyboard(); break;
                default: return true; // swallow everything else while open
            }
            return true;
        }

        if (lib.IsFilterMenuOpen)
        {
            switch (key)
            {
                case Key.Up:    lib.MoveFilterMenu(-1); break;
                case Key.Down:  lib.MoveFilterMenu(1);  break;
                case Key.Enter: lib.ApplyFilterMenuSelection(); break;
                case Key.X:
                case Key.Escape:
                case Key.BrowserBack: lib.CloseFilterMenu(); break;
                default: return true;
            }
            return true;
        }

        if (inSearch) return false;

        switch (key)
        {
            case Key.Y:        lib.OpenKeyboard();           return true;
            case Key.X:        lib.OpenFilterMenu();         return true;
            case Key.Left:     lib.MoveGameFocus(-1);        return true;
            case Key.Right:    lib.MoveGameFocus(1);         return true;
            case Key.Up:       lib.MoveGameFocusRow(-1);     return true;
            case Key.Down:     lib.MoveGameFocusRow(1);      return true;
            case Key.Enter:    lib.ActivateFocusedGame();    return true;
            case Key.PageUp:   lib.CycleInstallFilter(-1);   return true;
            case Key.PageDown: lib.CycleInstallFilter(1);    return true;
        }
        return false;
    }

    /// <summary>Returns true when a TextBox or similar input control has keyboard focus.</summary>
    private bool IsTextInputFocused()
    {
        var focused = FocusManager?.GetFocusedElement();
        return focused is TextBox or NumericUpDown;
    }

    private static readonly string[] _navPages =
        ["dashboard", "library", "store", "friends", "inbox", "profile", "settings", "media"];

    private static void NavigatePrev(MainViewModel vm)
    {
        int idx = System.Array.IndexOf(_navPages, vm.ActivePage);
        if (idx > 0)
            vm.NavigateCommand.Execute(_navPages[idx - 1]);
    }

    private static void NavigateNext(MainViewModel vm)
    {
        int idx = System.Array.IndexOf(_navPages, vm.ActivePage);
        if (idx >= 0 && idx < _navPages.Length - 1)
            vm.NavigateCommand.Execute(_navPages[idx + 1]);
    }

    private void RefreshGlobalHotkeyPolling()
    {
        if (OperatingSystem.IsWindows() && _boundVm?.SettingsVm.EnableGlobalQuickMenuHotkey == true)
        {
            if (!_globalHotkeyPoller.IsEnabled)
                _globalHotkeyPoller.Start();
        }
        else
        {
            _globalHotkeyPoller.Stop();
            _globalHotkeyLatched = false;
        }
    }

    private void OnGlobalHotkeyTick(object? sender, EventArgs e)
    {
        if (!OperatingSystem.IsWindows() || _boundVm == null || !_boundVm.SettingsVm.EnableGlobalQuickMenuHotkey)
            return;

        bool ctrlDown  = (GameLauncher.Services.NativeMethods.GetAsyncKeyState(GameLauncher.Services.NativeMethods.VK_LCONTROL) & 0x8000) != 0;
        bool shiftDown = (GameLauncher.Services.NativeMethods.GetAsyncKeyState(GameLauncher.Services.NativeMethods.VK_LSHIFT)   & 0x8000) != 0;
        bool bothDown  = ctrlDown && shiftDown;

        if (bothDown && !_globalHotkeyLatched)
        {
            _globalHotkeyLatched = true;
            OpenGlobalQuickMenu();
        }
        else if (!bothDown)
        {
            _globalHotkeyLatched = false;
        }

        ForwardOverlayQuickMenuKeys();
    }

    private void ForwardOverlayQuickMenuKeys()
    {
        if (!OperatingSystem.IsWindows() || _boundVm == null || _quickMenuWindow?.IsVisible != true)
        {
            ResetOverlayKeyLatches();
            return;
        }

        var vm = _boundVm.QuickMenuVm;
        HandleOverlayKeyState(Services.NativeMethods.VK_LEFT, ref _overlayLeftLatched, () =>
        {
            if (vm.IsXb360Theme) vm.MoveXb360Blade(-1);
            else vm.MoveHubSelection(-1);
        });
        HandleOverlayKeyState(Services.NativeMethods.VK_RIGHT, ref _overlayRightLatched, () =>
        {
            if (vm.IsXb360Theme) vm.MoveXb360Blade(1);
            else vm.MoveHubSelection(1);
        });
        HandleOverlayKeyState(Services.NativeMethods.VK_UP, ref _overlayUpLatched, () =>
        {
            if (vm.IsXb360Theme) vm.MoveXb360CenterItem(-1);
        });
        HandleOverlayKeyState(Services.NativeMethods.VK_DOWN, ref _overlayDownLatched, () =>
        {
            if (vm.IsXb360Theme) vm.MoveXb360CenterItem(1);
        });
        HandleOverlayKeyState(Services.NativeMethods.VK_RETURN, ref _overlayEnterLatched, vm.ActivateSelectedHub);
        HandleOverlayKeyState(Services.NativeMethods.VK_SPACE, ref _overlaySpaceLatched, vm.ActivateSelectedHub);
        HandleOverlayKeyState(Services.NativeMethods.VK_ESCAPE, ref _overlayEscapeLatched, () =>
        {
            if (!vm.HandleBackNavigation())
                vm.DismissCommand.Execute(null);
        });
        // LB (PageUp) / RB (PageDown) — tab navigation within the overlay
        const int VK_PRIOR = 0x21; // PageUp
        const int VK_NEXT  = 0x22; // PageDown
        HandleOverlayKeyState(VK_PRIOR, ref _overlayLbLatched, () =>
        {
            if (vm.IsXb360Theme) vm.MoveXb360Blade(-1);
            else vm.MoveHubSelection(-1);
        });
        HandleOverlayKeyState(VK_NEXT, ref _overlayRbLatched, () =>
        {
            if (vm.IsXb360Theme) vm.MoveXb360Blade(1);
            else vm.MoveHubSelection(1);
        });
    }

    private static void HandleOverlayKeyState(int virtualKey, ref bool latched, Action onPressed)
    {
        bool isDown = (Services.NativeMethods.GetAsyncKeyState(virtualKey) & 0x8000) != 0;
        if (isDown)
        {
            if (!latched)
            {
                latched = true;
                onPressed();
            }
        }
        else
        {
            latched = false;
        }
    }

    private void ResetOverlayKeyLatches()
    {
        _overlayUpLatched = false;
        _overlayDownLatched = false;
        _overlayLeftLatched = false;
        _overlayRightLatched = false;
        _overlayEnterLatched = false;
        _overlaySpaceLatched = false;
        _overlayEscapeLatched = false;
        _overlayLbLatched = false;
        _overlayRbLatched = false;
    }

    /// <summary>
    /// Opens the Quick Menu overlay without restoring or focusing the main launcher window.
    /// When a game is running and the launcher is minimised, shows a separate always-on-top
    /// borderless window positioned at the right edge of the screen — matching the Steam /
    /// NVIDIA overlay pattern for borderless-windowed apps and games.
    /// When the launcher is already in the foreground (no game running), toggles the
    /// inline quick menu panel instead.
    /// </summary>
    private void OpenGlobalQuickMenu()
    {
        if (_boundVm == null) return;

        bool gameIsRunning = _boundVm.DetailVm.IsGameRunning;
        bool launcherMinimized = WindowState == WindowState.Minimized;
        bool launcherUnfocused = !IsActive;

        // If a game is running, the launcher is minimized, or the launcher is unfocused,
        // use the separate overlay window so we never steal focus from another app.
        if (gameIsRunning || launcherMinimized || launcherUnfocused)
        {
            _boundVm.QuickMenuVm.Refresh(
                currentUsername:     _boundVm.ProfileVm.Username,
                currentGameTitle:     _boundVm.DetailVm.IsGameRunning ? _boundVm.DetailVm.Title : null,
                currentGamePlatform:  _boundVm.DetailVm.IsGameRunning ? _boundVm.DetailVm.Platform : null,
                sessionStartedAt:     _boundVm.DetailVm.IsGameRunning
                    ? Services.PlaytimeService.GetActiveSessionStart(_boundVm.DetailVm.Platform, _boundVm.DetailVm.Title)
                      ?? Services.PlaytimeService.GetAnyActiveSessionStart()
                    : null,
                onlineFriends:        _boundVm.FriendsVm.OnlineFriends
                    .Select(f => new FriendPresenceVm
                    {
                        Username = f.Username,
                        CurrentGame = f.CurrentGame ?? "",
                        Status = f.Status
                    })
                    .ToList(),
                allFriends:           _boundVm.FriendsVm.OnlineFriends
                    .Concat(_boundVm.FriendsVm.OfflineFriends)
                    .Select(f => new FriendPresenceVm
                    {
                        Username = f.Username,
                        CurrentGame = f.CurrentGame ?? "",
                        Status = f.Status
                    })
                    .ToList(),
                unreadCount:          _boundVm.InboxVm.PendingInvites.Count + _boundVm.InboxVm.Conversations.Count,
                lastMessage:          _boundVm.InboxVm.Conversations
                    .OrderByDescending(c => c.LastMessageAt)
                    .Select(c => c.LastMessage)
                    .FirstOrDefault(),
                unlockedAchievements: _boundVm.DetailVm.HasAchievements ? _boundVm.DetailVm.Achievements.Count(a => a.IsUnlocked) : 0,
                totalAchievements:    _boundVm.DetailVm.HasAchievements ? _boundVm.DetailVm.Achievements.Count : 0,
                achievements:         _boundVm.DetailVm.Achievements,
                recentGames:          _boundVm.DashboardVm.Ps5RecentGames.ToList(),
                activePageKey:        _boundVm.ActivePage,
                pendingDownloadCount: _boundVm.LibraryVm.ReadyToInstall.Count,
                quickMenuTheme:       _boundVm.SettingsVm.QuickMenuTheme);

            if (_quickMenuWindow == null)
            {
                _quickMenuWindow = new QuickMenuWindow { DataContext = _boundVm.QuickMenuVm };
                // Wire dismiss so closing the overlay window is reflected in the VM
                _boundVm.QuickMenuVm.OnDismiss = () =>
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        _boundVm.ShowQuickMenu = false;
                        _quickMenuWindow?.Hide();
                    });
                };
            }

            if (_quickMenuWindow.IsVisible)
            {
                _quickMenuWindow.Hide();
                _boundVm.ShowQuickMenu = false;
            }
            else
            {
                bool activateOverlay = _boundVm.SettingsVm.CompatibilityOverlayMode;
                _quickMenuWindow.ShowOverGame(activateOverlay);
            }
            return;
        }

        // Launcher is in the foreground — the inline quick menu is toggled by
        // OnKeyDown (which fires synchronously on the key press and is always
        // processed before the 150 ms poller tick).  Calling ToggleQuickMenu()
        // here as well would create a second toggle within 150 ms that immediately
        // closes the menu the user just opened, causing the open/close glitch.
    }

    private void OnMainViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_boundVm != null && e.PropertyName == nameof(MainViewModel.ShowDetail))
        {
            OnShowDetailChanged(_boundVm.ShowDetail);
            return;
        }

        if (_boundVm == null || e.PropertyName != nameof(MainViewModel.ShowQuickMenu))
            return;

        // When the inline quick menu is dismissed, also hide the overlay window if visible.
        if (!_boundVm.ShowQuickMenu)
            _quickMenuWindow?.Hide();
    }

    // ── Game detail navigation ────────────────────────────────────────────────

    private GameDetailView? DetailHost => this.FindControl<GameDetailView>("GameDetailHost");

    private int _detailFocusToken;

    /// <summary>Highlights Play when the detail page opens; clears stale focus when it closes.</summary>
    private void OnShowDetailChanged(bool show)
    {
        int token = ++_detailFocusToken;
        if (!show)
        {
            FocusManager?.ClearFocus();
            return;
        }

        // Detail data (installed state etc.) can arrive a moment after the page opens,
        // so retry until the user moves the highlight themselves.
        void TryFocus()
        {
            if (token != _detailFocusToken || _boundVm?.ShowDetail != true) return;
            var focused = FocusManager?.GetFocusedElement() as Control;
            if (focused == null || !(DetailHost?.IsVisualAncestorOf(focused) ?? false) || _detailAutoFocused == focused)
            {
                DetailHost?.FocusDefault();
                _detailAutoFocused = FocusManager?.GetFocusedElement() as Control;
            }
        }
        _detailAutoFocused = null;
        Dispatcher.UIThread.Post(TryFocus, DispatcherPriority.Background);
        DispatcherTimer.RunOnce(TryFocus, TimeSpan.FromMilliseconds(350));
        DispatcherTimer.RunOnce(TryFocus, TimeSpan.FromMilliseconds(1200));
    }

    private Control? _detailAutoFocused;

    // ── XInput controller support ─────────────────────────────────────────────

    /// <summary>
    /// Wires XInput button callbacks once, mapping each controller button to the
    /// same navigation actions that the keyboard path uses.
    /// Console button mapping:
    ///   D-pad / left stick / right stick → directional navigation (Up / Down / Left / Right)
    ///   A (cross)          → confirm / select   (Enter)
    ///   B (circle)         → back / cancel      (Escape)
    ///   X (square)         → secondary action   (X key — open game detail)
    ///   Y (triangle)       → tertiary action    (Y key — play focused item)
    ///   Back / Select      → back / cancel      (Escape)
    ///   LB / L1            → previous page      (PageUp)
    ///   RB / R1            → next page          (PageDown)
    ///   LT / L2            → disabled (reserved; does not page-switch tabs)
    ///   RT / R2            → disabled (reserved; does not page-switch tabs)
    ///   Guide / Home / Xbox → toggle Quick Menu (≡ Left Ctrl + Left Shift)
    ///   Share              → screenshot via Win+Alt+PrintScreen
    /// </summary>
    private void WireXInputCallbacks()
    {
        _xinput.OnUp      = () => HandleControllerKey(Key.Up);
        _xinput.OnDown    = () => HandleControllerKey(Key.Down);
        _xinput.OnLeft    = () => HandleControllerKey(Key.Left);
        _xinput.OnRight   = () => HandleControllerKey(Key.Right);
        _xinput.OnButtonA = () => HandleControllerKey(Key.Enter);
        _xinput.OnButtonB = () => HandleControllerKey(Key.Escape);
        _xinput.OnButtonX = () => HandleControllerKey(Key.X);
        _xinput.OnButtonY = () => HandleControllerKey(Key.Y);
        _xinput.OnBack    = () => HandleControllerKey(Key.Escape);
        _xinput.OnLb      = () => HandleControllerKey(Key.PageUp);
        _xinput.OnRb      = () => HandleControllerKey(Key.PageDown);
        // Leave analog triggers unbound in launcher navigation so LT/RT do not switch tabs/pages.
        _xinput.OnLt      = null;
        _xinput.OnRt      = null;

        // Start does not open the Quick Menu; only Guide / Home / Xbox does.
        _xinput.OnStart = null;

        // Guide / Home / Xbox button → open/toggle the Quick Menu
        _xinput.OnGuide = () =>
        {
            if (_boundVm == null) return;
            bool gameRunning       = _boundVm.DetailVm.IsGameRunning;
            bool launcherMinimized = WindowState == WindowState.Minimized;
            bool launcherUnfocused = !IsActive;
            if (gameRunning || launcherMinimized || launcherUnfocused)
                OpenGlobalQuickMenu();
            else
                _boundVm.ToggleQuickMenu();
        };

        // Share button → Win+Alt+PrintScreen screenshot (Xbox app / Game Bar)
        _xinput.OnShare = () =>
        {
            if (!OperatingSystem.IsWindows()) return;
            GameLauncher.Services.NativeMethods.TakeScreenshot();
        };
    }

    /// <summary>
    /// Called every 150 ms by the XInput poller; delegates to
    /// <see cref="XInputService.Poll"/> which fires the wired callbacks.
    /// Also refreshes the active controller profile for injection whenever the
    /// running game changes.
    /// </summary>
    private void OnXInputTick(object? sender, EventArgs e)
    {
        if (!OperatingSystem.IsWindows() || _boundVm == null) return;

        // Keep the injector's active profile in sync with the running game.
        if (_boundVm.DetailVm.IsGameRunning)
        {
            var profile = _boundVm.DetailVm.ActiveControllerProfile;
            _controllerInjector.SetProfile(profile);
        }
        else
        {
            _controllerInjector.SetProfile(null);
        }

        _xinput.Poll();
    }

    /// <summary>
    /// Handles a virtual key dispatched from the XInput controller, applying
    /// the same navigation logic as the keyboard handler but without requiring
    /// a focused window (works even when the launcher is behind a game).
    ///
    /// When a game is running and the Quick Menu is not open, all directional
    /// and action inputs are forwarded to the game via the active controller
    /// profile (virtual injection) — Game OS navigation is suppressed so that
    /// the game remains fully playable through the mapped profile.
    /// </summary>
    private void HandleControllerKey(Key key)
    {
        ScheduleScrollHighlightedIntoView();
        if (_boundVm == null) return;
        var vm = _boundVm;

        // If the overlay quick menu window is visible, forward all input to its VM.
        if (_quickMenuWindow?.IsVisible == true)
        {
            var qvm = vm.QuickMenuVm;
            bool isXb360Overlay = qvm.IsXb360Theme;
            switch (key)
            {
                case Key.Left:
                    if (isXb360Overlay) qvm.MoveXb360Blade(-1); else qvm.MoveHubSelection(-1);
                    return;
                case Key.Right:
                    if (isXb360Overlay) qvm.MoveXb360Blade(1); else qvm.MoveHubSelection(1);
                    return;
                case Key.Up:
                    if (isXb360Overlay) qvm.MoveXb360CenterItem(-1);
                    return;
                case Key.Down:
                    if (isXb360Overlay) qvm.MoveXb360CenterItem(1);
                    return;
                case Key.Enter:
                    qvm.ActivateSelectedHub();
                    return;
                case Key.Y:
                    if (isXb360Overlay) qvm.GoToGameOsHomeCommand.Execute(null);
                    return;
                case Key.Escape:
                    if (!qvm.HandleBackNavigation()) qvm.DismissCommand.Execute(null);
                    return;
            }
            return;
        }

        // While the inline quick menu is open, prioritise its navigation.
        if (vm.ShowQuickMenu)
        {
            bool isXb360QuickMenu = vm.QuickMenuVm.IsXb360Theme;
            switch (key)
            {
                case Key.Left:
                    if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360Blade(-1);
                    else vm.QuickMenuVm.MoveHubSelection(-1);
                    return;
                case Key.Right:
                    if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360Blade(1);
                    else vm.QuickMenuVm.MoveHubSelection(1);
                    return;
                case Key.Up:
                    if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360CenterItem(-1);
                    return;
                case Key.Down:
                    if (isXb360QuickMenu) vm.QuickMenuVm.MoveXb360CenterItem(1);
                    return;
                case Key.Enter:
                    vm.QuickMenuVm.ActivateSelectedHub();
                    return;
                case Key.Y:
                    if (isXb360QuickMenu) vm.QuickMenuVm.GoToGameOsHomeCommand.Execute(null);
                    return;
                case Key.Escape:
                    if (!vm.QuickMenuVm.HandleBackNavigation()) vm.ShowQuickMenu = false;
                    return;
            }
            return;
        }

        // A game is running and the quick menu is closed — block Game OS navigation
        // and inject the button press into the game via the active controller profile.
        // The Start / Guide callbacks bypass this guard entirely (handled above through
        // the OnStart / OnGuide wiring) so they continue to open the Quick Menu.
        if (vm.DetailVm.IsGameRunning)
        {
            string? xInputButtonName = key switch
            {
                Key.Up       => "DPadUp",
                Key.Down     => "DPadDown",
                Key.Left     => "DPadLeft",
                Key.Right    => "DPadRight",
                Key.Enter    => "A",
                Key.Escape   => "B",
                Key.X        => "X",
                Key.Y        => "Y",
                Key.PageUp   => "LeftShoulder",
                Key.PageDown => "RightShoulder",
                _            => null
            };
            if (xInputButtonName != null)
                _controllerInjector.InjectPress(xInputButtonName);
            return;
        }

        // ── Nav sidebar open: Up/Down move highlight; Enter navigates to highlighted item ──
        if (vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile)
        {
            switch (key)
            {
                case Key.Up:
                    vm.NavHighlightIndex = Math.Max(0, vm.NavHighlightIndex - 1);
                    return;
                case Key.Down:
                    vm.NavHighlightIndex = Math.Min(_navPages.Length - 1, vm.NavHighlightIndex + 1);
                    return;
                case Key.Enter:
                case Key.Y:
                    // Navigate to highlighted item (nav auto-closes via Navigate())
                    vm.NavigateCommand.Execute(_navPages[vm.NavHighlightIndex]);
                    return;
                case Key.Escape:
                    vm.IsNavExpanded = false;
                    return;
                case Key.Right:
                    vm.IsNavExpanded = false;
                    return;
            }
        }

        // A game is running and the quick menu is closed — block Game OS navigation
        // and inject the button press into the game via the active controller profile.
        // The Start / Guide callbacks bypass this guard entirely (handled above through
        // the OnStart / OnGuide wiring) so they continue to open the Quick Menu.
        if (vm.DetailVm.IsGameRunning)
        {
            string? xInputButtonName = key switch
            {
                Key.Up       => "DPadUp",
                Key.Down     => "DPadDown",
                Key.Left     => "DPadLeft",
                Key.Right    => "DPadRight",
                Key.Enter    => "A",
                Key.Escape   => "B",
                Key.X        => "X",
                Key.Y        => "Y",
                Key.PageUp   => "LeftShoulder",
                Key.PageDown => "RightShoulder",
                _            => null
            };
            if (xInputButtonName != null)
                _controllerInjector.InjectPress(xInputButtonName);
            return;
        }

        // Game detail: D-pad moves the highlight, A activates, B / Y go back
        if (vm.ShowDetail && !vm.IsNavExpanded)
        {
            switch (key)
            {
                case Key.Up:
                case Key.Down:
                case Key.Left:
                case Key.Right:
                case Key.Enter:
                    DetailHost?.HandleNavKey(key, activateWithEnter: true);
                    return;
                case Key.Escape:
                case Key.Y:
                    if (DetailHost != null) DetailHost.HandleBack();
                    else vm.DetailVm.CloseCommand.Execute(null);
                    return;
            }
        }

        // XB360 dashboard navigation (blade-style carousel)
        bool isXb360 = string.Equals(vm.SettingsVm.DesignTheme, "XB360", StringComparison.OrdinalIgnoreCase);
        if (vm.IsHome && isXb360 && !vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile)
        {
            switch (key)
            {
                case Key.Left:  vm.DashboardVm.MoveXb360Blade(-1); return;
                case Key.Right: vm.DashboardVm.MoveXb360Blade(1);  return;
                case Key.Up:    vm.DashboardVm.MoveXb360GameFocus(-1); return;
                case Key.Down:  vm.DashboardVm.MoveXb360GameFocus(1);  return;
                case Key.Enter: vm.DashboardVm.PlayXb360FocusedGameCommand.Execute(null); return;
                case Key.Y:     vm.DashboardVm.OpenFocusedCardDetailCommand.Execute(null); return;
            }
        }

        // Default dashboard: hero "Continue Playing" button + Continue Playing cards
        bool isDefaultDashController = string.Equals(vm.SettingsVm.DesignTheme, "Default", StringComparison.OrdinalIgnoreCase);
        if (vm.IsHome && isDefaultDashController && !vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile)
        {
            switch (key)
            {
                case Key.Right:
                case Key.Down:
                    vm.DashboardVm.MoveDefaultFocus(1);
                    return;
                case Key.Left:
                    if (vm.DashboardVm.IsAtDefaultFirstItem) OpenNavWithCurrentHighlight(vm);
                    else vm.DashboardVm.MoveDefaultFocus(-1);
                    return;
                case Key.Up:
                    vm.DashboardVm.MoveDefaultFocus(-1);
                    return;
                case Key.Enter:
                    vm.DashboardVm.OpenDefaultFocused();
                    return;
                case Key.X:
                    vm.DashboardVm.PlayDefaultFocused();
                    return;
            }
        }

        // PS5 / Switch dashboard navigation
        bool usesCardDashboardNavigationController =
            string.Equals(vm.SettingsVm.DesignTheme, "PS5",    StringComparison.OrdinalIgnoreCase) ||
            string.Equals(vm.SettingsVm.DesignTheme, "Switch", StringComparison.OrdinalIgnoreCase);
        if (vm.IsHome && usesCardDashboardNavigationController && !vm.IsNavExpanded && !vm.ShowDetail && !vm.ShowFriendProfile)
        {
            switch (key)
            {
                case Key.Right:
                    vm.DashboardVm.MoveFocus(1);
                    return;
                case Key.Left:
                    // At first card (index 0) or no focused card → open nav menu
                    if (vm.DashboardVm.IsAtFirstTile)
                    {
                        OpenNavWithCurrentHighlight(vm);
                        return;
                    }
                    vm.DashboardVm.MoveFocus(-1);
                    return;
                case Key.Down:
                    // Move to next recent game card
                    vm.DashboardVm.MoveFocus(1);
                    return;
                case Key.Up:
                    // Move to previous recent game card
                    if (!vm.DashboardVm.IsAtFirstTile)
                        vm.DashboardVm.MoveFocus(-1);
                    return;
                case Key.Enter:
                    // A button → open game detail/info page
                    vm.DashboardVm.ActivateFocusedTile();
                    return;
                case Key.X:
                    // X → launch the highlighted game
                    vm.DashboardVm.LaunchFocusedTile();
                    return;
            }
        }

        if (!vm.IsSettings) _settingsInContent = false;
        // Settings controller navigation (left menu ↔ right content)
        if (vm.IsSettings && !vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded)
        {
            if (HandleSettingsKey(vm, key, false))
                return;
        }

        // Library controller navigation shortcuts
        if (vm.IsLibrary && !vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded)
        {
            if (HandleLibraryKey(vm, key, false))
                return;
        }

        // Store controller navigation
        if (vm.IsStore && !vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded)
        {
            switch (key)
            {
                case Key.Y:
                    Dispatcher.UIThread.Post(() => vm.StoreVm.FocusSearchRequested?.Invoke());
                    return;
                case Key.X:
                    vm.StoreVm.CyclePlatform();
                    return;
                case Key.PageUp:
                case Key.PageDown:
                    vm.StoreVm.CycleTab();
                    return;
            }
        }

        // Global navigation — back, page prev/next, nav sidebar, and confirm
        switch (key)
        {
            case Key.Escape:
                if (vm.ShowDetail)             vm.DetailVm.CloseCommand.Execute(null);
                else if (vm.ShowFriendProfile) vm.CloseFriendProfileCommand.Execute(null);
                else if (vm.IsNavExpanded)     vm.IsNavExpanded = false;
                break;

            // Y (triangle / Y-button) = back/cancel at global level (when not library/store/dashboard)
            case Key.Y:
                if (vm.ShowDetail)             vm.DetailVm.CloseCommand.Execute(null);
                else if (vm.ShowFriendProfile) vm.CloseFriendProfileCommand.Execute(null);
                else if (vm.IsNavExpanded)     vm.IsNavExpanded = false;
                break;

            case Key.PageUp:
                if (!vm.ShowDetail && !vm.ShowFriendProfile) NavigatePrev(vm);
                break;

            case Key.PageDown:
                if (!vm.ShowDetail && !vm.ShowFriendProfile) NavigateNext(vm);
                break;

            case Key.Left:
                // On the dashboard, Left is consumed by card-focus logic above.
                // Elsewhere, Left opens the nav sidebar.
                if (!vm.ShowDetail && !vm.ShowFriendProfile && !vm.IsNavExpanded && !vm.IsHome)
                    OpenNavWithCurrentHighlight(vm);
                break;

            case Key.Right:
                if (!vm.ShowDetail && !vm.ShowFriendProfile && vm.IsNavExpanded)
                    vm.IsNavExpanded = false;
                break;
        }
    }
}
