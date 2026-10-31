using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// uBlock-style content blocker for the built-in browser.
    /// Network rules: hostname rules ("||host^" from EasyList-format lists, plain hostnames, built-in list).
    /// Cosmetic rules: generic "##selector" element-hiding rules. Top-level navigations to blocked hosts are
    /// cancelled; inside pages a script blocks fetch/XHR/beacons, removes ad scripts/frames/images and hides ad containers.
    /// </summary>
    public static class AdBlockService
    {
        public static readonly string[] FilterListUrls =
        {
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0",
        };

        private static readonly string CacheDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "AdBlock");

        private static readonly string[] BuiltInHosts =
        {
            "doubleclick.net","googlesyndication.com","googleadservices.com","google-analytics.com","googletagmanager.com",
            "googletagservices.com","adservice.google.com","pagead2.googlesyndication.com","adnxs.com","adsrvr.org","adform.net",
            "advertising.com","adcolony.com","admob.com","amazon-adsystem.com","taboola.com","outbrain.com","criteo.com","criteo.net",
            "rubiconproject.com","pubmatic.com","openx.net","casalemedia.com","indexww.com","smartadserver.com","moatads.com",
            "scorecardresearch.com","quantserve.com","quantcast.com","hotjar.com","mixpanel.com","segment.io","segment.com",
            "facebook.net","connect.facebook.net","ads-twitter.com","analytics.twitter.com","ads.linkedin.com","bat.bing.com",
            "adsymptotic.com","yieldmo.com","sharethrough.com","teads.tv","media.net","revcontent.com","mgid.com","zedo.com",
            "propellerads.com","popads.net","popcash.net","exoclick.com","juicyads.com","trafficjunky.net","trafficfactory.biz",
            "adsterra.com","hilltopads.net","clickadu.com","onclickads.net","onclkds.com","a-ads.com","bidvertiser.com",
            "infolinks.com","chartbeat.com","newrelic.com","bugsnag.com","crazyegg.com","mouseflow.com","fullstory.com",
            "ad.doubleclick.net","stats.g.doubleclick.net","2mdn.net","serving-sys.com","turn.com","bluekai.com","krxd.net",
            "demdex.net","everesttech.net","omtrdc.net","adition.com","contextweb.com","lijit.com","sovrn.com","gumgum.com",
            "33across.com","tapad.com","liveramp.com","rlcdn.com","adroll.com","perfectaudience.com","bidswitch.net",
            "ads.yahoo.com","advertising.yahoo.com","adtech.com","adtechus.com","yandex.ru/ads","an.yandex.ru","mc.yandex.ru",
        };

        private static HashSet<string> _hosts = new(BuiltInHosts.Where(h => !h.Contains('/')), StringComparer.OrdinalIgnoreCase);
        private static List<string> _cosmetic = new();
        private static HashSet<string> _userHosts = new(StringComparer.OrdinalIgnoreCase);
        private static List<string> _userCosmetic = new();
        private static HashSet<string> _allow = new(StringComparer.OrdinalIgnoreCase);
        private static bool _loadedCache;

        public static long BlockedCount;
        public static int RuleCount => _hosts.Count + _cosmetic.Count + _userHosts.Count + _userCosmetic.Count;

        private const string CosmeticBase =
            "[id^='google_ads'],[id^='div-gpt-ad'],[id*='AdContainer'],ins.adsbygoogle,.adsbygoogle,.ad-banner,.ad-container," +
            ".ad-slot,.ad-wrapper,.advert,.advertisement,.advertisment,.sponsored-ad,.sponsored-content,.banner-ad,.top-ad," +
            ".bottom-ad,.sidebar-ad,.google-ad,.dfp-ad,.taboola,.outbrain,[class*='taboola'],[id*='taboola'],[id^='ad-'],[id^='ads-']," +
            "[class^='ad-'],[class*=' ad-slot'],iframe[src*='doubleclick'],iframe[src*='googlesyndication'],a[href*='doubleclick.net/']," +
            "a[href*='googleadservices.com'],.ytp-ad-overlay-container,.ytd-ad-slot-renderer,ytd-ad-slot-renderer,ytd-banner-promo-renderer," +
            "#masthead-ad,#player-ads";

        /// <summary>Applies the user's custom rules and allow-list (call when settings change).</summary>
        public static void Configure(string customFilters, string allowList)
        {
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var cosmetic = new List<string>();
            foreach (var raw in (customFilters ?? "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('!') || line.StartsWith('#') && !line.StartsWith("##")) continue;
                if (line.StartsWith("##")) { cosmetic.Add(line.Substring(2)); continue; }
                string? h = ParseHostRule(line);
                if (h != null) hosts.Add(h);
            }
            _userHosts = hosts;
            _userCosmetic = cosmetic;
            _allow = new HashSet<string>((allowList ?? "").Split('\n').Select(a => a.Trim().ToLowerInvariant()).Where(a => a.Length > 0),
                StringComparer.OrdinalIgnoreCase);
            EnsureCacheLoaded();
        }

        public static bool IsAllowListed(string? host) => !string.IsNullOrEmpty(host) && MatchesAny(host, _allow);

        /// <summary>True if a request to <paramref name="url"/> should be blocked on a page from <paramref name="pageHost"/>.</summary>
        public static bool ShouldBlock(string url, string? pageHost = null)
        {
            if (IsAllowListed(pageHost)) return false;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https")) return false;
            string host = u.Host;
            if (IsAllowListed(host)) return false;
            bool blocked = MatchesAny(host, _hosts) || MatchesAny(host, _userHosts);
            if (blocked) Interlocked.Increment(ref BlockedCount);
            return blocked;
        }

        private static bool MatchesAny(string host, HashSet<string> set)
        {
            if (set.Count == 0) return false;
            string h = host.ToLowerInvariant();
            while (true)
            {
                if (set.Contains(h)) return true;
                int dot = h.IndexOf('.');
                if (dot < 0 || h.IndexOf('.', dot + 1) < 0) return false; // never match a bare TLD
                h = h.Substring(dot + 1);
            }
        }

        /// <summary>Parses "||host^", "||host^$third-party", a plain hostname or a "0.0.0.0 host" hosts-file line.</summary>
        internal static string? ParseHostRule(string line)
        {
            line = line.Trim();
            if (line.Length == 0 || line.StartsWith('!') || line.StartsWith('[') || line.Contains("##") || line.Contains("#@#") || line.StartsWith("@@")) return null;
            if (line.StartsWith("||"))
            {
                string rest = line.Substring(2);
                int end = rest.IndexOfAny(new[] { '^', '/', '$', '*', '|', ':' });
                string host = end < 0 ? rest : rest.Substring(0, end);
                // Only whole-host rules; path-specific rules would over-block.
                if (end >= 0 && rest[end] != '^' && rest[end] != '$' && rest[end] != '|') return null;
                if (end >= 0 && rest[end] == '^' && end + 1 < rest.Length && rest[end + 1] != '$' && rest[end + 1] != '|') return null;
                return IsValidHost(host) ? host.ToLowerInvariant() : null;
            }
            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            string candidate = parts.Length == 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") ? parts[1] : parts.Length == 1 ? parts[0] : "";
            return IsValidHost(candidate) ? candidate.ToLowerInvariant() : null;
        }

        private static bool IsValidHost(string h) =>
            h.Length > 3 && h.Contains('.') && h.All(c => char.IsLetterOrDigit(c) || c is '.' or '-') && !h.StartsWith('.') && !h.EndsWith('.');

        // ── Filter lists (download + cache) ───────────────────────────────────

        /// <summary>Downloads EasyList / EasyPrivacy / ad-server lists to the cache and reloads them. Returns the number of rules loaded.</summary>
        public static async Task<int> UpdateListsAsync(CancellationToken ct = default)
        {
            Directory.CreateDirectory(CacheDir);
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-AdBlock/1.0");
            for (int i = 0; i < FilterListUrls.Length; i++)
            {
                try
                {
                    string text = await http.GetStringAsync(FilterListUrls[i], ct);
                    await File.WriteAllTextAsync(Path.Combine(CacheDir, $"list{i}.txt"), text, ct);
                }
                catch (Exception ex) { DevLogService.Log($"[AdBlock] list {i} failed: {ex.Message}"); }
            }
            _loadedCache = false;
            EnsureCacheLoaded();
            return RuleCount;
        }

        private static void EnsureCacheLoaded()
        {
            if (_loadedCache) return;
            _loadedCache = true;
            var hosts = new HashSet<string>(BuiltInHosts.Where(h => !h.Contains('/')), StringComparer.OrdinalIgnoreCase);
            var cosmetic = new List<string>();
            try
            {
                if (Directory.Exists(CacheDir))
                    foreach (var file in Directory.EnumerateFiles(CacheDir, "list*.txt"))
                        foreach (var line in File.ReadLines(file))
                        {
                            if (line.StartsWith("##") && cosmetic.Count < 1500 && line.Length < 120 && !line.Contains(":-abp") && !line.Contains(":has-text"))
                                cosmetic.Add(line.Substring(2));
                            else if (ParseHostRule(line) is { } h)
                                hosts.Add(h);
                        }
            }
            catch (Exception ex) { DevLogService.Log($"[AdBlock] cache load failed: {ex.Message}"); }
            _hosts = hosts;
            _cosmetic = cosmetic;
        }

        // ── In-page script ────────────────────────────────────────────────────

        /// <summary>Script injected after a page loads; idempotent. Returns null when blocking should not apply to this page.</summary>
        public static string? BuildPageScript(string? pageHost, bool cosmetic, bool blockPopups)
        {
            if (IsAllowListed(pageHost)) return null;
            EnsureCacheLoaded();

            // Cap what is pushed into the page; the full set still guards navigations.
            var hostList = _hosts.Concat(_userHosts).Distinct(StringComparer.OrdinalIgnoreCase).Take(6000).ToArray();
            string hostsJson = JsonSerializer.Serialize(hostList);
            // One rule per selector so a single invalid selector cannot disable the rest.
            var selectors = CosmeticBase.Split(',').Concat(_userCosmetic).Concat(_cosmetic.Take(800)).Select(SafeSelector).Where(x => x.Length > 0);
            string cssJson = JsonSerializer.Serialize(string.Join("\n", selectors.Select(x => x + "{display:none !important;visibility:hidden !important}")));

            var sb = new StringBuilder();
            sb.Append("(function(){if(window.__gosAdblock)return;window.__gosAdblock=true;");
            sb.Append("var H=new Set(").Append(hostsJson).Append(");");
            sb.Append("function bad(u){try{var h=new URL(u,location.href).hostname.toLowerCase();while(h){if(H.has(h))return true;var i=h.indexOf('.');if(i<0||h.indexOf('.',i+1)<0)return false;h=h.slice(i+1);}}catch(e){}return false;}");
            sb.Append("var of=window.fetch;if(of)window.fetch=function(r){var u=(r&&r.url)||r;if(bad(u))return Promise.reject(new TypeError('blocked'));return of.apply(this,arguments);};");
            sb.Append("var ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){if(bad(u)){this.send=function(){};return;}return ox.apply(this,arguments);};");
            sb.Append("if(navigator.sendBeacon){var ob=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){return bad(u)?true:ob(u,d);};}");
            sb.Append("function sweep(n){var l=(n||document).querySelectorAll?(n||document).querySelectorAll('script[src],iframe[src],img[src],link[href],embed[src]'):[];for(var i=0;i<l.length;i++){var e=l[i];if(bad(e.src||e.href))e.remove();}}");
            sb.Append("sweep();new MutationObserver(function(ms){for(var i=0;i<ms.length;i++)for(var j=0;j<ms[i].addedNodes.length;j++){var n=ms[i].addedNodes[j];if(n.nodeType===1){if((n.src||n.href)&&bad(n.src||n.href))n.remove();else sweep(n);}}}).observe(document.documentElement,{childList:true,subtree:true});");
            if (cosmetic)
                sb.Append("var st=document.createElement('style');st.textContent=").Append(cssJson).Append(";(document.head||document.documentElement).appendChild(st);");
            if (blockPopups)
                sb.Append("var ow=window.open;window.open=function(u){if(window.__gosUserGesture&&Date.now()-window.__gosUserGesture<1000)return ow.apply(this,arguments);return null;};document.addEventListener('click',function(){window.__gosUserGesture=Date.now();},true);");
            sb.Append("})();");
            return sb.ToString();
        }

        private static string SafeSelector(string s) => s.Replace("{", "").Replace("}", "").Replace("\n", "").Trim();
    }
}
