using System;
using System.Collections.Generic;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

/// <summary>One toggleable on-screen asset of a dashboard design.</summary>
public sealed record DashboardAssetDef(string Key, string Label);

/// <summary>Which assets each dashboard design offers in Settings → Design → ⚙, plus default accents.</summary>
public static class DashboardCatalog
{
    public static readonly IReadOnlyList<string> Designs = new[] { "Default", Xb360Og, Xb360Kinetic, "PS5", "Wii", "Switch", "SteamBPM" };

    public const string Xb360Og = "XB360 OG";
    public const string Xb360Kinetic = "XB360 Kinetic";

    public static bool IsXb360(string? design) =>
        string.Equals(design, Xb360Og, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(design, Xb360Kinetic, StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<DashboardAssetDef> AssetsFor(string design) => AssetsForDesign(design);

    private static IReadOnlyList<DashboardAssetDef> AssetsForDesign(string design) => design switch
    {
        "Wii" => new DashboardAssetDef[]
        {
            new("clock", "Clock"), new("date", "Date"), new("wiibutton", "Wii button"),
            new("settings", "Settings button"), new("inbox", "Inbox button"), new("arrow", "Next-page arrow"),
        },
        "Switch" => new DashboardAssetDef[]
        {
            new("profile", "Profile picture"), new("clock", "Clock"), new("status", "Wi-Fi / battery icons"),
            new("title", "Game title"), new("info", "Game info panel"), new("shortcuts", "Shortcut bar"),
            new("hints", "Button hints"), new("background", "Game background"),
        },
        "PS5" => new DashboardAssetDef[] { new("header", "Header (Games / Media)") },
        Xb360Og => new DashboardAssetDef[]
        {
            new("profile", "Profile & greeting"), new("achievements", "Recent achievements"),
        },
        Xb360Kinetic => new DashboardAssetDef[]
        {
            new("tabs", "Tab header (home / social / …)"), new("profile", "Profile picture"),
            new("clock", "Clock"), new("hints", "Button hints"),
        },
        "SteamBPM" => new DashboardAssetDef[]
        {
            new("title", "Title"), new("clock", "Clock"), new("profile", "Profile picture"),
        },
        _ => new DashboardAssetDef[]
        {
            new("greeting", "Greeting"), new("stats", "Stats row"), new("featured", "Featured / last played banner"),
            new("recent", "Continue Playing"), new("media", "Media"), new("achievements", "Recent achievements"),
        },
    };

    public static string DefaultAccent(string design) => design switch
    {
        "Wii" => "#7cb7d6",
        "Switch" => "#00c3e3",
        "PS5" => "#0070D1",
        Xb360Og or Xb360Kinetic => "#1f9d1f",
        "SteamBPM" => "#1a9fff",
        _ => "#58a6ff",
    };

    public static string Normalise(string? design)
    {
        // Legacy single "XB360" design maps to the original dashboard.
        if (string.Equals(design?.Trim(), "XB360", StringComparison.OrdinalIgnoreCase)) return Xb360Og;
        foreach (var d in Designs)
            if (string.Equals(d, design?.Trim(), StringComparison.OrdinalIgnoreCase)) return d;
        return "Default";
    }

    public static bool TryParseColor(string? hex, out Color color)
    {
        color = default;
        return !string.IsNullOrWhiteSpace(hex) && Color.TryParse(hex.Trim(), out color);
    }
}

/// <summary>The active dashboard's options as bindable properties (visibility flags, accent, scale, offset).</summary>
public partial class DashboardOptionsVm : ObservableObject
{
    public string Design { get; private set; } = "Default";
    private DashboardOptions _o = new();

    [ObservableProperty] private IBrush _accentBrush = new SolidColorBrush(Color.Parse("#58a6ff"));
    [ObservableProperty] private double _scale = 1.0;
    [ObservableProperty] private double _offsetX;
    [ObservableProperty] private double _offsetY;

    public void Load(string design, DashboardOptions? options)
    {
        Design = DashboardCatalog.Normalise(design);
        _o = options ?? new DashboardOptions();
        Scale = Math.Clamp(_o.Scale <= 0 ? 1.0 : _o.Scale, 0.6, 1.4);
        OffsetX = _o.OffsetX;
        OffsetY = _o.OffsetY;
        var accent = DashboardCatalog.TryParseColor(_o.AccentColor, out var c)
            ? c : Color.Parse(DashboardCatalog.DefaultAccent(Design));
        AccentBrush = new SolidColorBrush(accent);
        OnPropertyChanged(string.Empty);
    }

    private bool Get(string key) => !_o.Assets.TryGetValue(key, out var v) || v;

    public bool ShowGreeting     => Get("greeting");
    public bool ShowStats        => Get("stats");
    public bool ShowFeatured     => Get("featured");
    public bool ShowRecent       => Get("recent");
    public bool ShowMedia        => Get("media");
    public bool ShowAchievements => Get("achievements");
    public bool ShowClock        => Get("clock");
    public bool ShowDate         => Get("date");
    public bool ShowWiiButton    => Get("wiibutton");
    public bool ShowSettings     => Get("settings");
    public bool ShowInbox        => Get("inbox");
    public bool ShowArrow        => Get("arrow");
    public bool ShowProfile      => Get("profile");
    public bool ShowStatus       => Get("status");
    public bool ShowTitle        => Get("title");
    public bool ShowInfo         => Get("info");
    public bool ShowShortcuts    => Get("shortcuts");
    public bool ShowHints        => Get("hints");
    public bool ShowBackground   => Get("background");
    public bool ShowHeader       => Get("header");
    public bool ShowTabs         => Get("tabs");

    public bool IsXb360Kinetic => Design == DashboardCatalog.Xb360Kinetic;
    public bool IsXb360Og      => Design == DashboardCatalog.Xb360Og;
}

/// <summary>One asset checkbox in the Settings editor.</summary>
public partial class DashboardAssetToggleVm : ObservableObject
{
    public string Key { get; }
    public string Label { get; }
    [ObservableProperty] private bool _isOn;
    public DashboardAssetToggleVm(string key, string label, bool isOn) { Key = key; Label = label; _isOn = isOn; }
}
