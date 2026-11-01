#!/usr/bin/env python3
"""Process the Games.Database contribution queue (run from a Games.Database checkout).

For every Queue/Games/{Platform}/*.json item:
  1. Look the game up in {Platform}.Games.json (store id, then fuzzy title, then TitleID).
  2. If the game is missing or has empty metadata, ask a provider about it:
       - Steam items      -> Steam store API (appdetails)
       - everything else  -> Wikipedia (must be a video-game article for that platform)
  3. Provider found it  -> add the game (or fill EMPTY fields) and merge the store.
     Not found          -> a new game is NOT added; the item is retried and dropped after
                           MAX_ATTEMPTS runs. Network errors never count as an attempt.
  4. Known game with complete metadata -> only the store link is merged (no provider call).
Titles that differ only by a subtitle ("Witcher 3" / "The Witcher 3: Wild Hunt") are treated as
the same game only when Wikipedia's redirect for the shorter title lands on the longer one, so
"Far Cry 3" and "Far Cry 3: Blood Dragon" stay separate. The same check (plus exact-title
matching) is used to merge duplicates already in the database, within MAX_DEDUP_CALLS per run.
New platforms get their {Platform}.Games.json created. Existing data is never overwritten.
"""
import glob
import json
import os
import re
import sys
import time
import unicodedata
import urllib.parse
import urllib.request

MAX_DESC = 500
MAX_ATTEMPTS = 6
MAX_DEDUP_CALLS = int(os.environ.get('MAX_DEDUP_CALLS', '40'))
DEDUP_CACHE = 'Queue/dedup-checked.json'
MAX_PROVIDER_CALLS = int(os.environ.get('MAX_PROVIDER_CALLS', '120'))
UA = 'GameOS-DB-Queue/1.0 (https://github.com/Koriebonx98/Game.OS.Userdata)'

PLATFORM_NAMES = {
    'PC': ['Windows', 'PC'],
    'PS1': ['PlayStation (console)', 'PlayStation', 'PS1'],
    'PS2': ['PlayStation 2', 'PS2'],
    'PS3': ['PlayStation 3', 'PS3'],
    'PS4': ['PlayStation 4', 'PS4'],
    'PS5': ['PlayStation 5', 'PS5'],
    'PSP': ['PlayStation Portable', 'PSP'],
    'PS Vita': ['PlayStation Vita', 'PS Vita'],
    'Xbox 360': ['Xbox 360'],
    'Xbox One': ['Xbox One'],
    'Switch': ['Nintendo Switch', 'Switch'],
}

EDITION = re.compile(
    r'\s*(?:[-:–]\s*)?(?:game of the year|goty|complete|definitive|enhanced|deluxe|'
    r'ultimate|gold|special|standard|anniversary|remastered|director.s cut)'
    r'(?:\s+edition)?\s*$')


def norm(t):
    """Same game across stores: ignore case/accents/punctuation, a leading "The",
    bracketed notes, trademark marks and trailing edition names."""
    t = unicodedata.normalize('NFKD', t or '')
    t = ''.join(c for c in t if not unicodedata.combining(c)).lower()
    t = re.sub(r'[™®©]|\(.*?\)|\[.*?\]', ' ', t).replace('&', ' and ')
    t = re.sub(r'^\s*the\s+', '', t).strip()
    for _ in range(2):
        t = EDITION.sub('', t)
    return re.sub(r'[^0-9a-z]', '', t)


def first(entry, keys):
    for k in keys:
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None


def get_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# ── Providers: return dict (found), None (not a real game) or raise (network error) ──

def steam_provider(item):
    appid = item.get('AppId') or item.get('StoreId')
    if not appid:
        return None
    data = get_json(f'https://store.steampowered.com/api/appdetails?appids={int(appid)}&l=english')
    info = (data.get(str(int(appid))) or {})
    d = info.get('data') if info.get('success') else None
    if not d or d.get('type') != 'game':
        return None
    desc = (d.get('short_description') or '').strip()
    return {
        'Title': (d.get('name') or '').strip() or item['Title'],
        'Description': desc[:MAX_DESC],
        'StorePageUrl': f'https://store.steampowered.com/app/{int(appid)}/',
        'image': f'https://cdn.akamai.steamstatic.com/steam/apps/{int(appid)}/library_600x900.jpg',
    }


def wikipedia_provider(item, platform):
    wanted = norm(item['Title'])
    if len(wanted) < 3:
        return None
    names = PLATFORM_NAMES.get(platform, [platform])
    q = urllib.parse.quote(f"{item['Title']} {names[0]} video game")
    data = get_json(
        'https://en.wikipedia.org/w/api.php?action=query&format=json&generator=search'
        f'&gsrsearch={q}&gsrlimit=5&prop=extracts%7Cinfo&exintro=1&explaintext=1'
        '&exlimit=max&inprop=url')
    for pg in ((data.get('query') or {}).get('pages') or {}).values():
        bare = re.sub(r'\s*\(.*?\)\s*$', '', pg.get('title', ''))
        extract = pg.get('extract', '')
        url = pg.get('fullurl', '')
        if norm(bare) != wanted:
            continue
        if 'video game' not in extract.lower():
            continue
        if not any(n.lower() in extract.lower() for n in names):
            continue
        if not url.startswith('https://en.wikipedia.org/'):
            continue
        desc = extract.split('\n')[0].strip()
        if len(desc) > MAX_DESC:
            desc = desc[:MAX_DESC].rstrip() + '…'
        return {'Title': item['Title'], 'Description': desc, 'StorePageUrl': url}
    return None


def run_provider(item, platform):
    if (item.get('Store') or '').lower() == 'steam':
        return steam_provider(item)
    return wikipedia_provider(item, platform)


# ── Alias resolution (subtitle differences) ──

_alias_cache = {}


def wiki_canonical(title):
    """Title of the Wikipedia article the given title redirects to (None if no article)."""
    if title in _alias_cache:
        return _alias_cache[title]
    q = urllib.parse.quote(title)
    data = get_json('https://en.wikipedia.org/w/api.php?action=query&format=json&redirects=1'
                    f'&titles={q}')
    result = None
    for pg in ((data.get('query') or {}).get('pages') or {}).values():
        if 'missing' not in pg:
            result = re.sub(r'\s*\(.*?\)\s*$', '', pg.get('title', ''))
    time.sleep(1)
    _alias_cache[title] = result
    return result


def subtitle_candidate(short_key, long_key):
    """long_key = short_key + a lettered subtitle (so "fifa2" never matches "fifa22")."""
    return (len(short_key) >= 5 and short_key[-1].isdigit() and long_key != short_key
            and long_key.startswith(short_key) and long_key[len(short_key)].isalpha())


def same_game_by_alias(title_a, title_b, budget):
    """True when the shorter title is a Wikipedia redirect to the longer one.
    budget is a one-item list holding the remaining provider calls."""
    ka, kb = norm(title_a), norm(title_b)
    if ka == kb:
        return True
    short, long_ = (title_a, title_b) if len(ka) < len(kb) else (title_b, title_a)
    if not subtitle_candidate(norm(short), norm(long_)):
        return False
    if budget[0] <= 0:
        raise RuntimeError('alias budget exhausted')
    budget[0] -= 1
    canon = wiki_canonical(short)
    return bool(canon) and norm(canon) == norm(long_)


# ── Database helpers ──

def load_platform(platform):
    path = f'{platform}.Games.json'
    if os.path.isfile(path):
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
        data = json.loads(text)
        if isinstance(data, list):
            return path, text, data, data
        key = 'Games' if 'Games' in data else 'games' if 'games' in data else None
        if key is None:
            return path, text, data, None
        return path, text, data, data[key]
    print(f'🆕 {path} does not exist — creating platform "{platform}".')
    data = {'Platform': platform, 'Games': []}
    return path, '', data, data['Games']


def build_index(arr):
    idx = {'title': {}, 'id': {}, 'store': {}}
    for e in arr:
        index_entry(idx, e)
    return idx


def index_entry(idx, e):
    if not isinstance(e, dict):
        return
    if e.get('appid') not in (None, ''):
        idx['store'].setdefault(('steam', str(e['appid'])), e)
    for st in e.get('stores') or []:
        if isinstance(st, dict) and st.get('name') and st.get('id'):
            idx['store'].setdefault((st['name'].lower(), str(st['id'])), e)
    t = first(e, ['Title', 'title', 'game_name', 'name'])
    if t:
        idx['title'].setdefault(norm(t), []).append(e)
    for alt in e.get('AlternateNames') or []:
        if isinstance(alt, str) and alt.strip():
            idx['title'].setdefault(norm(alt), []).append(e)
    i = first(e, ['TitleID', 'title_id', 'titleId'])
    if i:
        idx['id'].setdefault(i.lower(), e)


def find_existing(idx, item, budget=None):
    store = (item.get('Store') or '').lower()
    store_id = str(item.get('StoreId') or '').strip()
    if store and store_id and (store, store_id) in idx['store']:
        return idx['store'][(store, store_id)]
    # Same title but a different TitleID / appid is a different release, not a match
    probe = {'TitleID': item.get('TitleID') or '',
             'appid': item.get('AppId') if (item.get('Store') or '').lower() == 'steam' else None}
    for e in idx['title'].get(norm(item['Title']), []):
        if compatible(e, probe):
            return e
    tid = (item.get('TitleID') or '').strip().lower()
    if tid and tid in idx['id']:
        return idx['id'][tid]
    if budget is not None:
        key = norm(item['Title'])
        for k, entries in list(idx['title'].items()):
            if not (subtitle_candidate(k, key) or subtitle_candidate(key, k)):
                continue
            for e in entries:
                if compatible(e, probe) and same_game_by_alias(
                        entry_title(e) or k, item['Title'], budget):
                    return e
    return None


def has_metadata(entry):
    return bool(first(entry, ['Description', 'description'])) and \
           bool(first(entry, ['StorePageUrl', 'store_page_url'])) and \
           (entry.get('appid') in (None, '') or bool(entry.get('image')))


def fill(entry, values):
    """Set only EMPTY fields; returns True if anything changed."""
    changed = False
    aliases = {
        'Description': ['Description', 'description'],
        'StorePageUrl': ['StorePageUrl', 'store_page_url'],
        'TitleID': ['TitleID', 'title_id', 'titleId'],
        'appid': ['appid'],
        'image': ['image'],
    }
    for field, value in values.items():
        if value in (None, ''):
            continue
        if not any(entry.get(n) not in (None, '') for n in aliases.get(field, [field])):
            entry[field] = value
            changed = True
    return changed


def merge_store(entry, item):
    store = (item.get('Store') or '').strip()
    url = (item.get('StorePageUrl') or '').strip()
    if not store or not url.startswith('https://'):
        return False
    stores = entry.setdefault('stores', [])
    if any(isinstance(x, dict) and (x.get('name') or '').lower() == store.lower() for x in stores):
        return False
    s = {'name': store, 'url': url}
    if item.get('StoreId'):
        s['id'] = str(item['StoreId'])
    stores.append(s)
    return True


def entry_title(e):
    return first(e, ['Title', 'title', 'game_name', 'name']) or ''


def merge_entries(keep, drop):
    """Fold `drop` into `keep`: fill empty fields, union stores, remember the other title."""
    for k, v in drop.items():
        if k in ('stores', 'AlternateNames', 'Title', 'title'):
            continue
        if keep.get(k) in (None, '', [], {}) and v not in (None, '', [], {}):
            keep[k] = v
    for st in drop.get('stores') or []:
        if isinstance(st, dict):
            stores = keep.setdefault('stores', [])
            if not any(isinstance(x, dict) and (x.get('name') or '').lower() == (st.get('name') or '').lower()
                       for x in stores):
                stores.append(st)
    t_keep, t_drop = entry_title(keep), entry_title(drop)
    alts = keep.setdefault('AlternateNames', [])
    for t in [t_drop] + list(drop.get('AlternateNames') or []):
        if t and norm(t) != norm(t_keep) and t not in alts:
            alts.append(t)
    if not alts:
        del keep['AlternateNames']


def compatible(a, b):
    """Entries with different TitleIDs or Steam appids are different releases — never merge."""
    ta, tb = (first(a, ['TitleID', 'title_id', 'titleId']) or '').lower(), \
             (first(b, ['TitleID', 'title_id', 'titleId']) or '').lower()
    if ta and tb and ta != tb:
        return False
    aa, ab = a.get('appid'), b.get('appid')
    return not (aa not in (None, '') and ab not in (None, '') and str(aa) != str(ab))


def pick_keeper(a, b):
    """Prefer the entry with complete metadata, then the longer (fuller) title."""
    ra = (has_metadata(a), len(entry_title(a)))
    rb = (has_metadata(b), len(entry_title(b)))
    return (a, b) if ra >= rb else (b, a)


def dedupe_platform(arr, checked, budget):
    """Merge duplicate entries already in the database. Returns number of merges."""
    merged = 0
    groups = {}
    for e in arr:
        if isinstance(e, dict) and entry_title(e):
            groups.setdefault(norm(entry_title(e)), []).append(e)
    drop_ids = set()
    for key, group in groups.items():
        base = group[0]
        for other in group[1:]:
            if not compatible(base, other):
                continue
            keep, drop = pick_keeper(base, other)
            merge_entries(keep, drop)
            drop_ids.add(id(drop))
            base = keep
            merged += 1
    # subtitle duplicates, confirmed through Wikipedia redirects
    keys = sorted(k for k in groups if k)
    survivors = {k: next((e for e in groups[k] if id(e) not in drop_ids), None) for k in keys}
    for i, k in enumerate(keys):
        if not k[-1:].isdigit() or len(k) < 5:
            continue
        j = i + 1
        while j < len(keys) and keys[j].startswith(k):
            k2 = keys[j]
            j += 1
            a, b = survivors.get(k), survivors.get(k2)
            if a is None or b is None or id(a) in drop_ids or id(b) in drop_ids:
                continue
            if not subtitle_candidate(k, k2) or not compatible(a, b):
                continue
            pair = f'{k}|{k2}'
            if pair in checked:
                continue
            try:
                same = same_game_by_alias(entry_title(a), entry_title(b), budget)
            except RuntimeError:
                return merged
            except Exception as ex:
                print(f'⚠️  Alias check failed for "{entry_title(a)}": {ex}')
                return merged
            checked.add(pair)
            if same:
                keep, drop = pick_keeper(a, b)
                merge_entries(keep, drop)
                drop_ids.add(id(drop))
                survivors[k] = survivors[k2] = keep
                merged += 1
    if drop_ids:
        arr[:] = [e for e in arr if id(e) not in drop_ids]
    return merged


def save_platform(path, text, data):
    pretty = '\n  ' in text[:300]
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        if pretty:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write('\n')
        else:
            json.dump(data, fh, separators=(',', ':'), ensure_ascii=False)


def main():
    files = sorted(glob.glob('Queue/Games/*/*.json'))
    print(f'📥 {len(files)} queued item(s).')

    by_platform, remove = {}, []
    for f in files:
        try:
            with open(f, encoding='utf-8') as fh:
                item = json.load(fh)
            platform = os.path.basename(os.path.dirname(f))
            item['Title'] = (item.get('Title') or '').strip()
            if not item['Title'] or not re.fullmatch(r'[A-Za-z0-9._ -]+', platform):
                raise ValueError('missing title or invalid platform')
            by_platform.setdefault(platform, []).append((f, item))
        except Exception as e:
            print(f'⚠️  Dropping invalid queue file {f}: {e}')
            remove.append(f)

    # Existing platforms are scanned for duplicates on every run, even with an empty queue
    for pf in glob.glob('*.Games.json'):
        by_platform.setdefault(os.path.basename(pf)[:-len('.Games.json')], [])

    stats = {'added': 0, 'filled': 0, 'rejected': 0, 'deferred': 0, 'deduped': 0}
    calls = 0
    alias_budget = [MAX_DEDUP_CALLS]
    try:
        with open(DEDUP_CACHE, encoding='utf-8') as fh:
            checked = set(json.load(fh))
    except Exception:
        checked = set()
    checked_before = len(checked)

    for platform, items in by_platform.items():
        path, text, data, arr = load_platform(platform)
        if arr is None:
            print(f'⚠️  {path} has no games array — skipping.')
            continue
        changed_file = False
        merged = dedupe_platform(arr, checked, alias_budget)
        if merged:
            print(f'🧹 {path}: merged {merged} duplicate entr{"y" if merged == 1 else "ies"}')
            stats['deduped'] += merged
            changed_file = True
        idx = build_index(arr)

        for f, item in items:
            url = (item.get('StorePageUrl') or '').strip()
            item['StorePageUrl'] = url if url.startswith('https://') else ''
            try:
                existing = find_existing(idx, item, alias_budget)
            except Exception as e:
                print(f'⚠️  Alias lookup failed for "{item["Title"]}" ({platform}): {e} — will retry.')
                stats['deferred'] += 1
                continue

            if existing is not None and has_metadata(existing):
                if merge_store(existing, item):
                    stats['filled'] += 1
                    changed_file = True
                remove.append(f)
                continue

            if calls >= MAX_PROVIDER_CALLS:
                stats['deferred'] += 1
                continue
            calls += 1
            try:
                found = run_provider(item, platform)
                time.sleep(1.5)
            except Exception as e:
                print(f'⚠️  Provider error for "{item["Title"]}" ({platform}): {e} — will retry.')
                stats['deferred'] += 1
                continue

            if found is None:
                if existing is not None:
                    # Already in the database: still merge the store, just no new metadata.
                    changed_file |= merge_store(existing, item)
                    remove.append(f)
                    continue
                item['Attempts'] = int(item.get('Attempts') or 0) + 1
                if item['Attempts'] >= MAX_ATTEMPTS:
                    print(f'🗑️  "{item["Title"]}" ({platform}) not verified after {MAX_ATTEMPTS} runs — dropped.')
                    stats['rejected'] += 1
                    remove.append(f)
                else:
                    with open(f, 'w', encoding='utf-8') as fh:
                        json.dump(item, fh, ensure_ascii=False)
                    stats['deferred'] += 1
                continue

            tid = (item.get('TitleID') or '').strip()
            if existing is None:
                entry = {'Title': found['Title']}
                arr.append(entry)
                stats['added'] += 1
            else:
                entry = existing
                stats['filled'] += 1
            values = {k: v for k, v in found.items() if k != 'Title'}
            values['TitleID'] = tid
            if (item.get('Store') or '').lower() == 'steam' and item.get('AppId'):
                values['appid'] = item['AppId']
            fill(entry, values)
            item['StorePageUrl'] = item['StorePageUrl'] or found.get('StorePageUrl', '')
            merge_store(entry, item)
            index_entry(idx, entry)
            changed_file = True
            remove.append(f)

        if changed_file:
            save_platform(path, text, data)
            print(f'✅ {path} updated')

    for f in remove:
        os.remove(f)
    if len(checked) != checked_before:
        os.makedirs(os.path.dirname(DEDUP_CACHE), exist_ok=True)
        with open(DEDUP_CACHE, 'w', encoding='utf-8') as fh:
            json.dump(sorted(checked), fh)

    summary = f"+{stats['added']} new, {stats['filled']} merged/filled, {stats['rejected']} rejected, {stats['deduped']} duplicates merged"
    print(f"📊 {summary}, {stats['deferred']} left queued")
    gh_env = os.environ.get('GITHUB_ENV')
    if gh_env:
        with open(gh_env, 'a') as env:
            env.write(f"SUMMARY={summary}\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
