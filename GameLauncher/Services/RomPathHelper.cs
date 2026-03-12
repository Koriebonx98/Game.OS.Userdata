using System;
using System.IO;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Pure-static helpers for computing ROM copy/move destination paths so that
    /// moved/copied ROMs land in the folder layout that <see cref="GameScannerService"/>
    /// expects:
    /// <code>
    ///   Roms/{PlatformFolder}/Games/{RomFile}
    ///   Roms/{PlatformFolder}/Games/{GameName}/{RomFile}
    ///   Roms/{PlatformFolder}/Games/{TitleID}/          (folder-based PS3/PS4)
    /// </code>
    /// These helpers are extracted from <c>GameDetailViewModel</c> so they can be
    /// shared with and tested by <c>GameScanner.Tests</c>.
    /// </summary>
    internal static class RomPathHelper
    {
        private static readonly char[] DirSeps =
        {
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar,
        };

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Walks up the path of <paramref name="romPath"/> to find the first ancestor
        /// directory named "Games" whose parent is inside a "Roms" directory,
        /// matching the expected scanner layout: <c>Roms/{Platform}/Games/</c>.
        /// Returns <see langword="null"/> when the path does not follow the expected layout.
        /// </summary>
        public static string? FindRomsGamesDir(string romPath)
        {
            string? dir = Path.GetDirectoryName(romPath.TrimEnd(DirSeps));

            while (dir != null)
            {
                string  name        = Path.GetFileName(dir);
                string? parent      = Path.GetDirectoryName(dir);
                string? grandParent = parent == null ? null : Path.GetDirectoryName(parent);

                if (string.Equals(name, "Games", StringComparison.OrdinalIgnoreCase) &&
                    grandParent != null &&
                    string.Equals(Path.GetFileName(grandParent), "Roms",
                        StringComparison.OrdinalIgnoreCase))
                {
                    return dir;
                }

                dir = parent;
            }

            return null;
        }

        /// <summary>
        /// Returns the actual platform folder name used on disk for the given ROM path,
        /// e.g. <c>"Sony - PlayStation 2"</c> from <c>…/Roms/Sony - PlayStation 2/Games/…</c>.
        /// Falls back to <paramref name="fallbackPlatform"/> when the path does not
        /// follow the expected <c>Roms/{folder}/Games/</c> layout.
        /// </summary>
        public static string GetRomPlatformFolderName(string romPath, string fallbackPlatform)
        {
            string? gamesDir    = FindRomsGamesDir(romPath);
            string? platformDir = gamesDir == null ? null : Path.GetDirectoryName(gamesDir);
            string  folderName  = platformDir == null ? "" : Path.GetFileName(platformDir);
            return string.IsNullOrEmpty(folderName) ? fallbackPlatform : folderName;
        }

        /// <summary>
        /// Computes the destination path for a <em>file-based</em> ROM when it is
        /// copied or moved to <paramref name="destDriveRoot"/>.
        /// <para>
        /// The destination preserves any sub-folder between <c>Games/</c> and the ROM
        /// file so the scanner can reconstruct the same title from the folder name, e.g.:
        /// <c>…/Roms/Sony - PlayStation 2/Games/GTA SA/gta_sa.iso</c>
        /// → <c>{destDriveRoot}/Roms/Sony - PlayStation 2/Games/GTA SA/gta_sa.iso</c>
        /// </para>
        /// </summary>
        /// <param name="romFilePath">Full path to the ROM file on the source drive.</param>
        /// <param name="romFolderPath">
        ///   The parent folder of the ROM as recorded in the drive entry
        ///   (<c>LocalGameDriveEntry.FolderPath</c>).  May be empty, in which case
        ///   the directory component of <paramref name="romFilePath"/> is used.
        /// </param>
        /// <param name="destDriveRoot">Root of the destination drive, e.g. <c>E:\</c>.</param>
        /// <param name="fallbackPlatform">
        ///   Normalised platform string used when <paramref name="romFilePath"/> is not
        ///   inside a <c>Roms/{folder}/Games/</c> hierarchy.
        /// </param>
        /// <returns>Full destination path for the ROM file.</returns>
        public static string ComputeFileRomDestPath(
            string romFilePath,
            string romFolderPath,
            string destDriveRoot,
            string fallbackPlatform)
        {
            string platformFolder = GetRomPlatformFolderName(romFilePath, fallbackPlatform);
            string destGamesDir   = Path.Combine(destDriveRoot, "Roms", platformFolder, "Games");

            string srcDir = string.IsNullOrEmpty(romFolderPath)
                ? (Path.GetDirectoryName(romFilePath) ?? "")
                : romFolderPath.TrimEnd(DirSeps);

            string? srcGamesDir = FindRomsGamesDir(romFilePath);

            string destDir;
            if (!string.IsNullOrEmpty(srcGamesDir))
            {
                string relSub = Path.GetRelativePath(srcGamesDir, srcDir);
                destDir = (relSub == "." || string.IsNullOrEmpty(relSub))
                    ? destGamesDir
                    : Path.Combine(destGamesDir, relSub);
            }
            else
            {
                destDir = destGamesDir;
            }

            return Path.Combine(destDir, Path.GetFileName(romFilePath));
        }

        /// <summary>
        /// Computes the destination folder for a <em>folder-based</em> ROM (e.g. a PS3/PS4
        /// TitleID directory) when it is copied or moved to <paramref name="destDriveRoot"/>.
        /// </summary>
        /// <param name="romFolderPath">Full path to the ROM directory on the source drive.</param>
        /// <param name="destDriveRoot">Root of the destination drive, e.g. <c>E:\</c>.</param>
        /// <param name="fallbackPlatform">
        ///   Normalised platform string used when <paramref name="romFolderPath"/> is not
        ///   inside a <c>Roms/{folder}/Games/</c> hierarchy.
        /// </param>
        /// <returns>Full destination folder path.</returns>
        public static string ComputeFolderRomDestPath(
            string romFolderPath,
            string destDriveRoot,
            string fallbackPlatform)
        {
            string platformFolder = GetRomPlatformFolderName(romFolderPath, fallbackPlatform);
            string destGamesDir   = Path.Combine(destDriveRoot, "Roms", platformFolder, "Games");
            string folderName     = Path.GetFileName(romFolderPath.TrimEnd(DirSeps));
            return Path.Combine(destGamesDir, folderName);
        }
    }
}
