using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.ViewModels;

public sealed partial class OsKeyVm : ObservableObject
{
    public string Label { get; init; } = "";
    [ObservableProperty] private string _display = "";
    public bool IsWide => Label.Length > 1;
    [ObservableProperty] private bool _isHighlighted;
}

public sealed class OsKeyRowVm
{
    public List<OsKeyVm> Keys { get; init; } = new();
}

/// <summary>
/// The launcher's controller-driven on-screen keyboard, reusable by any page (browser address bar / web inputs, downloads URL).
/// Open() with the starting text; text changes are pushed live through the callback, "Go" also fires the submit callback.
/// </summary>
public sealed partial class OnScreenKeyboardViewModel : ObservableObject
{
    private static readonly string[][] Layout =
    {
        new[] { "1","2","3","4","5","6","7","8","9","0" },
        new[] { "q","w","e","r","t","y","u","i","o","p" },
        new[] { "a","s","d","f","g","h","j","k","l","'" },
        new[] { "z","x","c","v","b","n","m",":","-","." },
        new[] { "/","_","@","?","=","&","%","#","+","~" },
        new[] { "Shift","Space","Backspace","Clear","Go","Done" },
    };

    private Action<string>? _onChanged;
    private Action<string>? _onSubmit;
    private int _row, _col;
    private bool _upper;

    [ObservableProperty] private bool _isOpen;
    [ObservableProperty] private string _text = "";
    [ObservableProperty] private string _title = "";

    public ObservableCollection<OsKeyRowVm> Rows { get; } = new();

    public OnScreenKeyboardViewModel()
    {
        foreach (var row in Layout)
            Rows.Add(new OsKeyRowVm { Keys = row.Select(k => new OsKeyVm { Label = k, Display = k }).ToList() });
    }

    public void Open(string initial, string title, Action<string> onChanged, Action<string>? onSubmit = null)
    {
        _onChanged = onChanged;
        _onSubmit = onSubmit;
        Title = title;
        Text = initial ?? "";
        _upper = false;
        _row = 1; _col = 0;
        Refresh();
        IsOpen = true;
    }

    public void Close() { IsOpen = false; _onChanged = null; _onSubmit = null; }

    public void Move(int dx, int dy)
    {
        if (!IsOpen) return;
        int r = Math.Clamp(_row + dy, 0, Rows.Count - 1);
        int len = Rows[r].Keys.Count;
        // Rows have different lengths, so keep the horizontal position proportional when changing row.
        int c = dy != 0 ? Math.Min(len - 1, (int)Math.Round(_col * (len - 1.0) / Math.Max(1, Rows[_row].Keys.Count - 1)))
                        : Math.Clamp(_col + dx, 0, len - 1);
        _row = r; _col = c;
        Refresh();
    }

    public void PressSelected() => Press(Rows[_row].Keys[_col]);

    public void PressTapped(OsKeyVm key)
    {
        for (int r = 0; r < Rows.Count; r++)
            for (int c = 0; c < Rows[r].Keys.Count; c++)
                if (ReferenceEquals(Rows[r].Keys[c], key)) { _row = r; _col = c; }
        Refresh();
        Press(key);
    }

    private void Press(OsKeyVm key)
    {
        switch (key.Label)
        {
            case "Shift": _upper = !_upper; Refresh(); return;
            case "Space": Set(Text + " "); return;
            case "Backspace": Backspace(); return;
            case "Clear": Set(""); return;
            case "Done": Close(); return;
            case "Go": { var cb = _onSubmit; var t = Text; Close(); cb?.Invoke(t); return; }
            default: Set(Text + (_upper ? key.Label.ToUpperInvariant() : key.Label)); return;
        }
    }

    public void Backspace()
    {
        if (Text.Length > 0) Set(Text[..^1]);
    }

    private void Set(string value)
    {
        Text = value;
        _onChanged?.Invoke(value);
    }

    private void Refresh()
    {
        for (int r = 0; r < Rows.Count; r++)
            for (int c = 0; c < Rows[r].Keys.Count; c++)
            {
                var k = Rows[r].Keys[c];
                k.IsHighlighted = r == _row && c == _col;
                k.Display = k.Label.Length == 1 && _upper ? k.Label.ToUpperInvariant() : k.Label;
            }
    }

    /// <summary>Shared controller mapping: D-pad moves, A types, X backspace, Y submits, B closes. Returns true (always consumes).</summary>
    public bool HandleKey(string name)
    {
        switch (name)
        {
            case "Up": Move(0, -1); break;
            case "Down": Move(0, 1); break;
            case "Left": Move(-1, 0); break;
            case "Right": Move(1, 0); break;
            case "A": PressSelected(); break;
            case "X": Backspace(); break;
            case "Y": { var cb = _onSubmit; var t = Text; Close(); cb?.Invoke(t); break; }
            case "B": Close(); break;
        }
        return true;
    }
}
