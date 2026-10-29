using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System.Linq;

namespace GameLauncher.Views.GamesLib;

public partial class GamesLibOverlays : UserControl
{
    public GamesLibOverlays()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is System.ComponentModel.INotifyPropertyChanged n)
                n.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == "FilterMenuIndex")
                        Dispatcher.UIThread.Post(ScrollFilterIntoView, DispatcherPriority.Background);
                };
        };
    }

    /// <summary>Keeps the highlighted filter row visible so the list scrolls with the selection.</summary>
    private void ScrollFilterIntoView()
    {
        var list = this.FindControl<ItemsControl>("FilterList");
        if (list == null) return;
        foreach (var row in list.GetVisualDescendants().OfType<Border>())
            if (row.Classes.Contains("hl")) { row.BringIntoView(); return; }
    }
}
