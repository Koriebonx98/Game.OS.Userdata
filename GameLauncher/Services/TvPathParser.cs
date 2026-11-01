using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace GameLauncher.Services
{
    /// <summary>Show, season and episode read from a TV file's path.</summary>
    public sealed record TvInfo(string Show, int Season, int Episode, int EpisodeEnd, string EpisodeTitle)
    {
        public bool HasNumber => Episode > 0;
        /// <summary>"S01E02" (or "S01E02-E03" for a double episode); empty when the file has no episode number.</summary>
        public string Code => Episode <= 0 ? "" : $"S{Season:00}E{Episode:00}" + (EpisodeEnd > Episode ? $"-E{EpisodeEnd:00}" : "");
    }

    /// <summary>
    /// Understands the usual TV layouts (like Kodi does):
    ///   Show/Season/Episodes/EpisodeName/file, Show/Season/Episodes/files, Show/Season/files, Show/files
    /// and the file name styles S01E02, S01.E02, S01 E02, 1x02, "Season 1 Episode 2", E02 / Ep02, 102 and "02 - Name".
    /// </summary>
    public static class TvPathParser
    {
        private const RegexOptions Ci = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        private static readonly Regex SeasonDir = new(@"^(?:season|series|staffel|saison|temporada|stagione|s)[\s._-]*(\d{1,3})(?![\da-z])", Ci);
        private static readonly Regex SpecialsDir = new(@"^(?:specials?|extras)$", Ci);
        private static readonly Regex EpisodesDir = new(@"^(?:episodes?|eps)$", Ci);

        private static readonly Regex SxxExx = new(@"(?<![a-z0-9])s(\d{1,3})[\s._-]*e(\d{1,4})(?:(?:-|[\s._]?e)[\s._]*e?(\d{1,4})(?![\dp]))?", Ci);
        private static readonly Regex NxNN = new(@"(?<![\dx])(\d{1,2})x(\d{2,3})(?![\dp])", Ci);
        private static readonly Regex Verbose = new(@"season[\s._-]*(\d{1,3})[\s._-]*(?:episode|ep|e)[\s._-]*(\d{1,4})", Ci);
        private static readonly Regex EpOnly = new(@"(?<![a-z0-9])(?:episode|ep|e)[\s._-]?(\d{1,4})(?![a-z0-9])", Ci);
        private static readonly Regex Digits3 = new(@"(?<=[\s._-])(\d)(\d{2})(?![\dp])", Ci);
        private static readonly Regex LeadingNumber = new(@"^\s*(\d{1,3})(?:\s*[-._)]\s*|\s+)(?=\S)", Ci);
        private static readonly Regex OnlyNumber = new(@"^\s*(\d{1,3})\s*$", Ci);
        private static readonly Regex ReleaseTail = new(
            @"[\s._\-\[(]*\b(2160p|1440p|1080p|720p|576p|480p|4k|uhd|hdr\d*|bluray|blu-ray|brrip|bdrip|web-?dl|webrip|web|hdtv|dvdrip|x26[45]|h[\s.]?26[45]|hevc|aac\d*|ac3|dts|remux|proper|repack)\b.*$", Ci);

        public static bool IsSeasonFolder(string name, out int season)
        {
            season = 0;
            var m = SeasonDir.Match(name.Trim());
            if (m.Success) { season = int.Parse(m.Groups[1].Value); return true; }
            return SpecialsDir.IsMatch(name.Trim());
        }

        private static string Tidy(string s)
        {
            s = ReleaseTail.Replace(s, "");
            s = Regex.Replace(s, @"[\._]+", " ");
            s = Regex.Replace(s, @"\s+", " ");
            return s.Trim(' ', '-', '(', '[', ')', ']', ',');
        }

        private static bool HasLetters(string s) => Regex.IsMatch(s, @"\p{L}");

        /// <param name="segments">Path under the TV category folder; the last entry is the file name.</param>
        public static TvInfo Parse(string[] segments) => Parse(segments, true);

        private static TvInfo Parse(string[] segments, bool useEpisodeFolder)
        {
            string file = segments[^1];
            string stem = Path.GetFileNameWithoutExtension(file);

            string show = "";
            int folderSeason = 0;
            bool hasSeasonFolder = false;
            string episodeFolder = "";
            for (int i = 0; i < segments.Length - 1; i++)
            {
                string d = segments[i];
                if (IsSeasonFolder(d, out int sn)) { folderSeason = sn; hasSeasonFolder = true; }
                else if (i == 0) show = d.Trim();
                else if (EpisodesDir.IsMatch(d.Trim())) { }
                else episodeFolder = d.Trim();
            }

            int season = 0, ep = 0, end = 0;
            int matchStart = -1, matchEnd = -1;
            bool seasonFromFile = false;

            Match m;
            if ((m = SxxExx.Match(stem)).Success)
            {
                season = int.Parse(m.Groups[1].Value); ep = int.Parse(m.Groups[2].Value); seasonFromFile = true;
                if (m.Groups[3].Success && int.TryParse(m.Groups[3].Value, out int e2) && e2 > ep && e2 - ep < 20) end = e2;
            }
            else if ((m = NxNN.Match(stem)).Success)
            { season = int.Parse(m.Groups[1].Value); ep = int.Parse(m.Groups[2].Value); seasonFromFile = true; }
            else if ((m = Verbose.Match(stem)).Success)
            { season = int.Parse(m.Groups[1].Value); ep = int.Parse(m.Groups[2].Value); seasonFromFile = true; }
            else if ((m = EpOnly.Match(stem)).Success)
                ep = int.Parse(m.Groups[1].Value);
            else if ((m = Digits3.Match(ReleaseTail.Replace(stem, ""))).Success)
            { season = int.Parse(m.Groups[1].Value); ep = int.Parse(m.Groups[2].Value); seasonFromFile = true; }
            else if ((m = LeadingNumber.Match(stem)).Success)
                ep = int.Parse(m.Groups[1].Value);
            else if ((m = OnlyNumber.Match(stem)).Success)
                ep = int.Parse(m.Groups[1].Value);

            bool matched = m.Success && ep > 0;
            if (matched) { matchStart = m.Index; matchEnd = m.Index + m.Length; }
            if (!seasonFromFile) season = folderSeason > 0 || hasSeasonFolder ? folderSeason : 1;
            if (!matched) { season = hasSeasonFolder ? folderSeason : 0; ep = 0; }

            // Show name: the show folder, otherwise whatever precedes the episode number in the file name.
            if (show.Length == 0)
            {
                string before = matched ? stem[..matchStart] : stem;
                show = Tidy(before);
                if (show.Length == 0) show = "Unknown show";
            }

            // Episode title: text after the number, else the episode folder, else the plain file name.
            string title = "";
            if (matched) title = Tidy(stem[matchEnd..]);
            else title = Tidy(stem);
            if (!HasLetters(title)) title = "";
            if (title.Equals(show, StringComparison.OrdinalIgnoreCase) && matched) title = "";

            // Show/Season/Episodes/<episode folder>/<file>: the folder may carry the number / name the file lacks (video.mkv, ...).
            if (useEpisodeFolder && episodeFolder.Length > 0 && segments.Length >= 2 && segments[^2].Trim() == episodeFolder)
            {
                var alt = segments[..^2].Concat(new[] { episodeFolder + ".mkv" }).ToArray();
                var f = Parse(alt, false);
                if (!matched && (f.Episode > 0 || f.EpisodeTitle.Length > 0))
                    return new TvInfo(show, f.Episode > 0 ? f.Season : season, f.Episode, f.EpisodeEnd, f.EpisodeTitle);
                if (matched && title.Length == 0 && f.EpisodeTitle.Length > 0)
                    title = f.EpisodeTitle;
            }
            return new TvInfo(show, season, ep, end, title);
        }
    }
}
