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
        /// <summary>Page the link was found on and its cookies; many file hosts reject requests without them.</summary>
        [JsonPropertyName("referer")]  public string Referer { get; set; } = "";
        [JsonPropertyName("cookie")]   public string Cookie { get; set; } = "";
        /// <summary>True when the user typed a file name, so server-supplied names must not replace it.</summary>
        /// <summary>Game / ROM this download belongs to (from a saved link or the browser's game context).</summary>
        [JsonPropertyName("game")]     public string GameTitle { get; set; } = "";
        [JsonPropertyName("customName")] public bool CustomName { get; set; }

        [ObservableProperty] [property: JsonPropertyName("name")]  private string _name = "";
        [ObservableProperty] [property: JsonPropertyName("file")]  private string _filePath = "";
        [ObservableProperty] [property: JsonPropertyName("size")]  private long _totalBytes;
        [ObservableProperty] [property: JsonPropertyName("done")]  private long _downloadedBytes;
        [ObservableProperty] [property: JsonPropertyName("state")] [property: JsonConverter(typeof(JsonStringEnumConverter))] private DownloadState _state = DownloadState.Queued;
        [ObservableProperty] [property: JsonPropertyName("error")] private string _error = "";

        [ObservableProperty] [property: JsonIgnore] private long _speedBytesPerSec;
        [ObservableProperty] [property: JsonIgnore] private double _extractProgress;
        [ObservableProperty] [property: JsonIgnore] private bool _isSelected;

        [JsonIgnore] public double Progress => TotalBytes > 0 ? Math.Min(100.0, DownloadedBytes * 100.0 / TotalBytes) : 0;
        [JsonIgnore] public string KindLabel => Kind == DownloadKind.Torrent ? "TORRENT" : "DIRECT";
        [JsonIgnore] public string TargetLabel => string.IsNullOrEmpty(GameTitle) ? $"{Category} · {Platform}" : $"{GameTitle} · {Category} · {Platform}";
        [JsonIgnore] public bool IsActive => State is DownloadState.Downloading or DownloadState.Queued or DownloadState.Extracting or DownloadState.Seeding;
        [JsonIgnore] public bool CanPause => State is DownloadState.Downloading or DownloadState.Queued or DownloadState.Seeding;
        [JsonIgnore] public bool CanResume => State is DownloadState.Paused or DownloadState.Failed or DownloadState.Cancelled;
        [JsonIgnore] public string StatusText => State switch
        {
            DownloadState.Downloading => $"{Format(DownloadedBytes)} / {(TotalBytes > 0 ? Format(TotalBytes) : "?")} · {Format(SpeedBytesPerSec)}/s{EtaSuffix}",
            DownloadState.Seeding     => $"Seeding · {Format(SpeedBytesPerSec)}/s up",
            DownloadState.Extracting  => $"Extracting… {ExtractProgress:F0}%",
            DownloadState.Failed      => $"Failed: {Error}",
            DownloadState.Completed   => $"Completed · {Format(TotalBytes)}",
            _                         => State.ToString(),
        };

        /// <summary>Time left based on a smoothed speed, so the estimate doesn't jump every second.</summary>
        [JsonIgnore] public string EtaText
        {
            get
            {
                if (State != DownloadState.Downloading || TotalBytes <= 0 || _smoothSpeed < 1) return "";
                var t = TimeSpan.FromSeconds(Math.Max(0, TotalBytes - DownloadedBytes) / _smoothSpeed);
                return t.TotalHours >= 1 ? $"{(int)t.TotalHours}h {t.Minutes:D2}m" : t.TotalMinutes >= 1 ? $"{t.Minutes}m {t.Seconds:D2}s" : $"{t.Seconds}s";
            }
        }
        private string EtaSuffix => EtaText.Length > 0 ? $" · ETA {EtaText}" : "";
        private double _smoothSpeed;

        partial void OnTotalBytesChanged(long value) { OnPropertyChanged(nameof(Progress)); OnPropertyChanged(nameof(StatusText)); }
        partial void OnDownloadedBytesChanged(long value) { OnPropertyChanged(nameof(Progress)); OnPropertyChanged(nameof(StatusText)); }
        partial void OnSpeedBytesPerSecChanged(long value)
        {
            _smoothSpeed = _smoothSpeed < 1 ? value : _smoothSpeed * 0.8 + value * 0.2;
            if (value == 0) _smoothSpeed = 0;
            OnPropertyChanged(nameof(StatusText)); OnPropertyChanged(nameof(EtaText));
        }
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
