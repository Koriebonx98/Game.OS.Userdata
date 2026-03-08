using Avalonia.Data.Converters;
using Avalonia.Media;
using System;
using System.Globalization;

namespace GameOS.Desktop.ViewModels;

public class IntToBoolConverter : IValueConverter
{
    public static readonly IntToBoolConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (parameter is string p && p == "invert")
            return value is int i && i == 0;
        return value is int n && n > 0;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Returns first part of "True Text|False Text" when bool is true, second when false.
/// Also used for loading text: "Loading...|Default Text".
/// </summary>
public class LoadingTextConverter : IValueConverter
{
    public static readonly LoadingTextConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var isTrue = value is bool b && b;
        var parts = (parameter as string ?? "|").Split('|');
        return isTrue ? parts[0] : (parts.Length > 1 ? parts[1] : parts[0]);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class BoolToColorConverter : IValueConverter
{
    public static readonly BoolToColorConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var isTrue = value is bool b && b;
        return isTrue ? new SolidColorBrush(Color.Parse("#27ae60")) : new SolidColorBrush(Color.Parse("#8899aa"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts a hex colour string (e.g. "#e94560") to a <see cref="SolidColorBrush"/>.
/// Falls back to a neutral purple if parsing fails.
/// </summary>
public class HexColorToBrushConverter : IValueConverter
{
    public static readonly HexColorToBrushConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string hex)
        {
            try { return new SolidColorBrush(Color.Parse(hex)); }
            catch { /* fall through */ }
        }
        return new SolidColorBrush(Color.Parse("#533483"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
