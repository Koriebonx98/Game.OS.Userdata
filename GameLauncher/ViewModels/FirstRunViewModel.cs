using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>Console-style first-run flow: welcome → disclosure → emulator auto-setup → ready. Fully controller driven.</summary>
public partial class FirstRunViewModel : ViewModelBase
{
    public const string DisclosureText =
        "Game.OS is a launcher that brings your games, emulators and store accounts together in one place. " +
        "It does not provide, sell or distribute any games, ROMs, BIOS files, firmware or keys, and it is not affiliated with any console maker or store.\n\n" +
        "You are responsible for the games and ROMs you add. Only use content you own or are legally allowed to use, " +
        "and follow the laws and licence terms that apply where you live.";

    [NotifyPropertyChangedFor(nameof(IsWelcome), nameof(IsDisclosure), nameof(IsEmulators), nameof(IsReady), nameof(PrimaryHint), nameof(StepLabel))]
    [ObservableProperty] private int _step;
    [NotifyPropertyChangedFor(nameof(PrimaryHint))]
    [ObservableProperty] private string _emulatorsFolder = "";
    [ObservableProperty] private string _emulatorStatus = "Choose the folder where you keep your emulators and Game OS will set them up for you.";
    [NotifyPropertyChangedFor(nameof(PrimaryHint))]
    [ObservableProperty] private bool _hasDetections;

    private System.Collections.Generic.List<DetectedEmulator> _detected = new();

    public ObservableCollection<string> DetectedLines { get; } = new();

    public bool IsWelcome    => Step == 0;
    public bool IsDisclosure => Step == 1;
    public bool IsEmulators  => Step == 2;
    public bool IsReady      => Step == 3;
    public string StepLabel  => $"Step {Step + 1} of 4";

    public string PrimaryHint => Step switch
    {
        0 => "A  Get started",
        1 => "A  I understand and agree",
        2 => HasDetections ? "A  Set up these emulators" : "A  Choose emulators folder",
        _ => "A  Enter Game.OS",
    };

    /// <summary>Set by the view: opens the folder picker and passes back the chosen path.</summary>
    public Action<Action<string>>? BrowseFolderRequested { get; set; }

    /// <summary>Raised when the flow finishes so the host can hide it and reload settings.</summary>
    public Action? Completed { get; set; }

    [RelayCommand]
    private void BrowseEmulatorsFolder() => BrowseFolderRequested?.Invoke(p => _ = ScanAsync(p));

    private async Task ScanAsync(string folder)
    {
        EmulatorsFolder = folder;
        EmulatorStatus = "Looking for emulators…";
        DetectedLines.Clear();
        _detected = await Task.Run(() => EmulatorDetectorService.Detect(folder));
        foreach (var d in _detected)
            DetectedLines.Add($"{d.Platform}  ·  {d.Name}");
        HasDetections = _detected.Count > 0;
        EmulatorStatus = HasDetections
            ? $"Found {_detected.Count} emulator setup(s). Press A to apply them, or Y to pick another folder."
            : "No known emulators found in that folder. Press Y to try another folder, or X to skip.";
    }

    [RelayCommand]
    public void Primary()
    {
        switch (Step)
        {
            case 2:
                if (HasDetections) { ApplyDetected(); Step = 3; }
                else BrowseEmulatorsFolder();
                break;
            case 3: Finish(); break;
            default: Step++; break;
        }
    }

    [RelayCommand] public void Back() { if (Step > 0) Step--; }

    [RelayCommand] public void Skip() { if (Step == 2) Step = 3; }

    private void ApplyDetected()
    {
        int n = EmulatorDetectorService.Apply(_detected);
        DevLogService.Log($"[FirstRun] Auto-configured {n} emulator(s) from '{EmulatorsFolder}'.");
    }

    private void Finish()
    {
        var s = AppSettingsService.Load();
        s.HasAcceptedDisclosure = true;
        s.HasCompletedFirstRunSetup = true;
        AppSettingsService.Save(s);
        Completed?.Invoke();
    }

    /// <summary>Controller handling. A next · B back · Y choose folder · X skip. Always consumes.</summary>
    public bool HandleKey(string name)
    {
        switch (name)
        {
            case "A": Primary(); break;
            case "B": Back(); break;
            case "Y": if (Step == 2) BrowseEmulatorsFolder(); break;
            case "X": Skip(); break;
        }
        return true;
    }
}
