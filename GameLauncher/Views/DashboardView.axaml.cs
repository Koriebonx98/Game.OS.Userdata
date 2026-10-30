using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Media;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class DashboardView : UserControl
{
    private DashboardOptionsVm? _options;

    public DashboardView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_options != null) _options.PropertyChanged -= OnOptionsChanged;
            _options = (DataContext as DashboardViewModel)?.Options;
            if (_options != null) _options.PropertyChanged += OnOptionsChanged;
            ApplyOptions();
        };
    }

    private void OnOptionsChanged(object? sender, PropertyChangedEventArgs e) => ApplyOptions();

    private void ApplyOptions()
    {
        if (_options == null) return;
        // {DynamicResource DashAccent} in the dashboards follows this brush.
        Resources["DashAccent"] = _options.AccentBrush;
        if (this.FindControl<Grid>("Stage") is { } stage)
        {
            var group = new TransformGroup();
            group.Children.Add(new ScaleTransform(_options.Scale, _options.Scale));
            group.Children.Add(new TranslateTransform(_options.OffsetX, _options.OffsetY));
            stage.RenderTransform = group;
        }
    }
}
