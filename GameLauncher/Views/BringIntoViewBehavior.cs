using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace GameLauncher.Views;

/// <summary>Scrolls a control into view when its bound "Active" flag becomes true (controller focus follow).</summary>
public static class BringIntoViewBehavior
{
    public static readonly AttachedProperty<bool> ActiveProperty =
        AvaloniaProperty.RegisterAttached<Control, Control, bool>("Active");

    public static bool GetActive(Control c) => c.GetValue(ActiveProperty);
    public static void SetActive(Control c, bool v) => c.SetValue(ActiveProperty, v);

    static BringIntoViewBehavior()
    {
        ActiveProperty.Changed.AddClassHandler<Control>((c, e) =>
        {
            if (e.NewValue is true)
                Dispatcher.UIThread.Post(() => c.BringIntoView(), DispatcherPriority.Background);
        });
    }
}
