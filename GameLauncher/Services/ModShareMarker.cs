using System;

namespace GameLauncher.Services
{
    public static partial class ModShareService
    {
        public const string Marker = "\u2063\u2063GOSMOD1:";

        public static bool IsShareMessage(string? text) =>
            text != null && text.StartsWith(Marker, StringComparison.Ordinal);
    }
}
