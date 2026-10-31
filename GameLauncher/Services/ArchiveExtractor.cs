using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SharpCompress.Archives;

namespace GameLauncher.Services
{
    /// <summary>
    /// Extracts .zip / .rar / .7z / .tar(.gz) archives with the managed SharpCompress library,
    /// so no external 7-Zip install is needed. Guards against path traversal ("zip-slip") and
    /// reports byte-based progress. Multi-part RAR sets (.part1.rar / .r00) are opened from the first volume.
    /// </summary>
    public static class ArchiveExtractor
    {
        private static readonly string[] ArchiveExtensions = { ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz" };

        public static bool IsArchive(string path)
        {
            string ext = Path.GetExtension(path ?? "").ToLowerInvariant();
            return ArchiveExtensions.Contains(ext);
        }

        /// <summary>For "name.part2.rar" returns "name.part1.rar" (or the part-01 variant) when it exists; otherwise the input.</summary>
        public static string ResolveFirstVolume(string path)
        {
            string dir  = Path.GetDirectoryName(path) ?? "";
            string file = Path.GetFileName(path);
            var m = System.Text.RegularExpressions.Regex.Match(file, @"^(?<n>.+)\.part0*(?<i>\d+)\.rar$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!m.Success) return path;
            string n = m.Groups["n"].Value;
            int width = m.Groups["i"].Value.Length;
            foreach (string cand in new[] { $"{n}.part{1.ToString().PadLeft(width, '0')}.rar", $"{n}.part1.rar" })
            {
                string full = Path.Combine(dir, cand);
                if (File.Exists(full)) return full;
            }
            return path;
        }

        /// <summary>
        /// Extracts <paramref name="archivePath"/> into <paramref name="destFolder"/>.
        /// <paramref name="progress"/> receives 0–100. Throws on failure (corrupt / missing volume / bad path).
        /// </summary>
        public static Task ExtractAsync(string archivePath, string destFolder,
            IProgress<double>? progress = null, CancellationToken ct = default)
            => Task.Run(() => Extract(archivePath, destFolder, progress, ct), ct);

        public static void Extract(string archivePath, string destFolder,
            IProgress<double>? progress = null, CancellationToken ct = default)
        {
            if (!File.Exists(archivePath))
                throw new FileNotFoundException("Archive not found.", archivePath);

            archivePath = ResolveFirstVolume(archivePath);
            Directory.CreateDirectory(destFolder);
            string destRoot = Path.GetFullPath(destFolder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            using var archive = ArchiveFactory.OpenArchive(archivePath);
            var files = archive.Entries.Where(e => !e.IsDirectory && !string.IsNullOrEmpty(e.Key)).ToList();
            long total = files.Sum(e => Math.Max(0, e.Size));
            long done = 0;
            var buffer = new byte[1024 * 128];

            foreach (var entry in files)
            {
                ct.ThrowIfCancellationRequested();
                string rel = entry.Key!.Replace('\\', '/').TrimStart('/');
                string target = Path.GetFullPath(Path.Combine(destFolder, rel.Replace('/', Path.DirectorySeparatorChar)));
                if (!target.StartsWith(destRoot, StringComparison.Ordinal))
                    throw new InvalidDataException($"Blocked unsafe archive path: {entry.Key}");

                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var src = entry.OpenEntryStream();
                using var dst = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None, buffer.Length);
                int read;
                while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    dst.Write(buffer, 0, read);
                    done += read;
                    if (total > 0) progress?.Report(Math.Min(100.0, done * 100.0 / total));
                }
            }
            progress?.Report(100);
        }
    }
}
