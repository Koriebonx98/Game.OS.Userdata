using System.IO;

namespace GameLauncher.Services
{
    /// <summary>
    /// Shared file-system helpers used by service classes in this namespace.
    /// </summary>
    internal static class StorageHelpers
    {
        /// <summary>
        /// Returns a sanitised version of <paramref name="name"/> that is safe to
        /// use as a directory name on all supported platforms (Windows, Linux, macOS).
        /// </summary>
        internal static string SanitiseName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_";
            name = name.Replace(':', '-');
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c.ToString(), "");
            return name.Trim();
        }
    }
}
