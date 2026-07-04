using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace GameLauncher.ViewModels;

public partial class MediaViewModel : ObservableObject
{
    // ── VLC local file player ─────────────────────────────────────────────────
    /// <summary>True when the in-app VLC file-player overlay is visible.</summary>
    [ObservableProperty] private bool   _isVlcPlayerOpen;
    /// <summary>File name of the media currently loaded in the VLC player.</summary>
    [ObservableProperty] private string _vlcMediaPath = "";

    /// <summary>
    /// Delegate set by the View code-behind. When invoked, the View shows a file
    /// picker and—once the user selects a file—starts VLC playback in the overlay.
    /// </summary>
    public Action? PlayLocalVideoRequested { get; set; }

    // ── Media folder shortcuts ────────────────────────────────────────────────

    [RelayCommand]
    private void OpenMoviesFolder() => OpenMediaFolder(
        Environment.GetFolderPath(Environment.SpecialFolder.MyVideos));

    [RelayCommand]
    private void OpenMusicFolder() => OpenMediaFolder(
        Environment.GetFolderPath(Environment.SpecialFolder.MyMusic));

    [RelayCommand]
    private void OpenTvShowsFolder() => OpenMediaFolder(
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
            "TV Shows"));

    [RelayCommand]
    private void OpenGamesFolder() => OpenMediaFolder(ResolveNamedFolder("Games"));

    [RelayCommand]
    private void OpenRomsFolder() => OpenMediaFolder(ResolveNamedFolder("Roms"));

    /// <summary>
    /// Returns the path of the first existing <c>{driveRoot}/{folderName}</c>
    /// directory found across all drives.  Falls back to
    /// <c>{MyDocuments}/{folderName}</c> when none exists, creating it if needed.
    /// </summary>
    private static string ResolveNamedFolder(string folderName)
    {
        // Check all drive roots (same logic used by GameScannerService)
        var existing = GameScannerService.GetDriveRoots()
            .Select(root => Path.Combine(root, folderName))
            .FirstOrDefault(Directory.Exists);

        if (existing != null) return existing;

        // Fall back to a folder in My Documents so the user can see where to put files
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            folderName);
    }

    private static void OpenMediaFolder(string folderPath)
    {
        try
        {
            if (!Directory.Exists(folderPath))
                Directory.CreateDirectory(folderPath);

            Process.Start(new ProcessStartInfo
            {
                FileName        = folderPath,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            DevLogService.Log($"[MediaViewModel] OpenMediaFolder failed for '{folderPath}': {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ── VLC commands ─────────────────────────────────────────────────────────

    [RelayCommand]
    private void PlayLocalVideo()
    {
        DevLogService.Log("[MediaViewModel] PlayLocalVideo requested");
        PlayLocalVideoRequested?.Invoke();
    }

    [RelayCommand]
    private void CloseVlcPlayer()
    {
        IsVlcPlayerOpen = false;
        VlcMediaPath    = "";
    }
}
