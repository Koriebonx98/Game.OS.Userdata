using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.ViewModels;

/// <summary>One editable <c>key = value</c> entry of a Xenia config toml; booleans are shown as Enable/Disable switches.</summary>
public partial class XeniaSettingVm : ViewModelBase
{
    public string Section { get; init; } = "";
    public string Key { get; init; } = "";
    public int Line { get; init; }
    public bool IsBool { get; init; }
    public string OriginalValue { get; init; } = "";
    public string Label => Section.Length == 0 ? Key : Section + " › " + Key;

    [ObservableProperty] private string _value = "";

    public bool IsText => !IsBool;
    public bool IsOn
    {
        get => Value == "true";
        set { Value = value ? "true" : "false"; }
    }

    partial void OnValueChanged(string value) => OnPropertyChanged(nameof(IsOn));
    public bool IsChanged => Value.Trim() != OriginalValue;
}
