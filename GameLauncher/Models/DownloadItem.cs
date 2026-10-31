using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.Models
{
    public enum DownloadKind { Direct, Torrent }

    public enum DownloadState { Queued, Downloading, Paused, Seeding, Extracting, Completed, Failed, Cancelled }

    /// <summary>One entry in Downloads.json (direct download or torrent).</summary>
    public partial class DownloadItem : ObservableObject
    {
        [JsonPropertyName("id")]       public string Id { get; set; } = Guid.NewGuid().ToString("N");
        [JsonPropertyName("kind")]     [JsonConverter(typeof(JsonStringEnumConverter))] public DownloadKind Kind { get; set; }
        [JsonPropertyName("url")]      public string Url { get; set; } = "";
        /// <summary>Game, Mod or Other.</summary>
        [JsonPropertyName("category")] public string Category { get; set; } = "Game";
        [JsonPropertyName("platform")] public string Platform { get; set; } = "PC";
        [JsonPropertyName("folder")]   public string Folder { get; set; } = "";
        [JsonPropertyName("created")]  public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        [JsonPropertyName("completed")] public DateTime? CompletedUtc { get; set; }
        [JsonPropertyName("segments")] public List<long> SegmentProgress { get; set; } = new();
        [JsonPropertyName("extracted")] public bool Extracted { get; set; }
        /// <summary>Torrent info-hash (hex) so the torrent can be resumed.</summary>
        [JsonPropertyName("infoHash")] public string InfoHash { get; set; } = "";

        [ObservableProperty] [property: JsonPropertyName("name")]  private string _name = "";
        [ObservableProperty] [property: JsonPropertyName("file")]  private string _filePath = "";
        [ObservableProperty] [property: JsonPropertyName("size")]  private long _totalBytes;
        [ObservableProperty] [property: JsonPropertyName("done")]  private long _downloadedBytes;
        [ObservableProperty] [property: JsonPropertyName("state")] [property: JsonConverter(typeof(JsonStringEnumConverter))] private DownloadState _state = DownloadState.Queued;
        [ObservableProperty] [property: JsonPropertyName("error")] private string _error = "";

        [ObservableProperty] [property: JsonIgnore] private long _speedBytesPerSec;
        [ObservableProperty] [property: JsonIgnore] private double _extractProgress;

        [JsonIgnore] public double Progress => TotalBytes > 0 ? Math.Min(100.0, DownloadedBytes * 100.0 / TotalBytes) : 0;
        [JsonIgnore] public string KindLabel => Kind == DownloadKind.Torrent ? "TORRENT" : "DIRECT";
        [JsonIgnore] public string TargetLabel => $"{Category} · {Platform}";
        [JsonIgnore] public bool IsActive => State is DownloadState.Downloading or DownloadState.Queued or DownloadState.Extracting or DownloadState.Seeding;
        [JsonIgnore] public bool CanPause => State is DownloadState.Downloading or DownloadState.Queued or DownloadState.Seeding;
        [JsonIgnore] public bool CanResume => State is DownloadState.Paused or DownloadState.Failed or DownloadState.Cancelled;
        [JsonIgnore] public string StatusText => State switch
        {
            DownloadState.Downloading => $"{Format(DownloadedBytes)} / {(TotalBytes > 0 ? Format(TotalBytes) : "?")} · {Format(SpeedBytesPerSec)}/s",
            DownloadState.Seeding     => $"Seeding · {Format(SpeedBytesPerSec)}/s up",
            DownloadState.Extracting  => $"Extracting… {ExtractProgress:F0}%",
            DownloadState.Failed      => $"Failed: {Error}",
            DownloadState.Completed   => $"Completed · {Format(TotalBytes)}",
            _                         => State.ToString(),
        };

        partial void OnTotalBytesChanged(long value) { OnPropertyChanged(nameof(Progress)); OnPropertyChanged(nameof(StatusText)); }
        partial void OnDownloadedBytesChanged(long value) { OnPropertyChanged(nameof(Progress)); OnPropertyChanged(nameof(StatusText)); }
        partial void OnSpeedBytesPerSecChanged(long value) => OnPropertyChanged(nameof(StatusText));
        partial void OnExtractProgressChanged(double value) => OnPropertyChanged(nameof(StatusText));
        partial void OnErrorChanged(string value) => OnPropertyChanged(nameof(StatusText));
        partial void OnStateChanged(DownloadState value)
        {
            OnPropertyChanged(nameof(StatusText)); OnPropertyChanged(nameof(IsActive));
            OnPropertyChanged(nameof(CanPause)); OnPropertyChanged(nameof(CanResume));
        }

        public static string Format(long bytes) =>
            bytes >= 1_073_741_824 ? $"{bytes / 1_073_741_824.0:F2} GB"
            : bytes >= 1_048_576   ? $"{bytes / 1_048_576.0:F1} MB"
            : bytes >= 1024        ? $"{bytes / 1024.0:F0} KB"
            : $"{bytes} B";
    }
}
