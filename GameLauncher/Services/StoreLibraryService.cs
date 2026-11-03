using System.Collections.Generic;

namespace GameLauncher.Services
{
    /// <summary>
    /// Merges a store library (Epic, GOG, Xbox …) into the Game.OS games database via the contribution queue.
    /// The games DB is checked first: games that already list the store URL are skipped, games that exist
    /// without it are queued as a store-URL merge, unknown games are queued as new (editions never create duplicates).
    /// </summary>
    public static class StoreLibraryService
    {
        public sealed record StoreGame(string Id, string Title, string? Url = null, Dictionary<string, object?>? Meta = null);

        public sealed record SubmitResult(int AlreadyComplete, int StoreMerges, int NewGames, int Duplicates);

        public static SubmitResult Submit(string store, IEnumerable<StoreGame> games)
        {
            string host = "";
            foreach (var s in StoreAccountsService.Stores)
                if (s.Name == store) { host = s.StoreUrlHost; break; }

            int complete = 0, merges = 0, fresh = 0, dups = 0;
            foreach (var g in games)
            {
                if (string.IsNullOrWhiteSpace(g.Title)) continue;
                var presence = GitHubDataService.CheckPcGame(g.Title, host);
                if (presence == GitHubDataService.DbPresence.Complete) { complete++; continue; }
                if (!DatabaseContributionQueue.EnqueueStoreGame(store, g.Id, g.Title, g.Url, g.Meta)) { dups++; continue; }
                if (presence == GitHubDataService.DbPresence.MissingStore) merges++; else fresh++;
            }
            DevLogService.Log($"[StoreLibrary] {store}: {fresh} new, {merges} store merges, {complete} already complete, {dups} duplicates skipped.");
            return new SubmitResult(complete, merges, fresh, dups);
        }
    }
}
