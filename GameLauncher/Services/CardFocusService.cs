namespace GameLauncher.Services;

public static class CardFocusService
{
    public static int Reset() => -1;

    public static int Move(int currentIndex, int itemCount, int offset)
    {
        if (itemCount <= 0) return Reset();
        if (currentIndex < 0) return 0;
        return System.Math.Clamp(currentIndex + offset, 0, itemCount - 1);
    }
}
