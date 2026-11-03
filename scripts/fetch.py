#!/usr/bin/env python3
"""
Security Watch — news collector.

Runs on GitHub Actions every ~20 minutes:
  1. pulls RSS/Atom feeds, Google News searches and GDELT searches
  2. tags every headline with places (country → region → continent) and
     security domains, plus a severity level
  3. merges with the previous run's data (read back from the live site),
     drops duplicates and anything older than the time window
  4. writes  <out>/data/news.json  and copies the web page next to it

Everything is configured in ../config/*.yaml — this file rarely needs editing.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import html
import json
import os
import re
import shutil
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlparse
import csv
import io
import zipfile

import feedparser
import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
SITE = ROOT / "site"

UA = "Mozilla/5.0 (compatible; SecurityWatch/1.0; +https://github.com/)"
TIMEOUT = (8, 20)          # (connect, read) seconds
TRANSLATE_BUDGET = 300     # seconds per run spent translating headlines
GDELT_BUDGET = 150         # stop asking GDELT after this many seconds
RUN_BUDGET = 480           # whole run must finish well inside GitHub's limit
NOW = datetime.now(timezone.utc)


def log(*a):
    print(*a, flush=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Text helpers
# ─────────────────────────────────────────────────────────────────────────────

def norm(text: str) -> str:
    """Strip accents and normalise quotes so 'Côte d’Ivoire' == "Cote d'Ivoire"."""
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return (text.replace("’", "'").replace("‘", "'")
                .replace("“", '"').replace("”", '"')
                .replace("–", "-").replace("—", "-").replace(" ", " "))


TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def clean(text: str) -> str:
    text = html.unescape(TAG_RE.sub(" ", text or ""))
    return WS_RE.sub(" ", text).strip()


def is_case_sensitive(term: str) -> bool:
    letters = re.sub(r"[^A-Za-z]", "", term)
    return bool(letters) and letters.isupper() and len(letters) <= 6


def term_pattern(term: str, plural: bool) -> str:
    """Regex for one alias/keyword. '*' at the end = any word ending."""
    term = norm(term).strip()
    wildcard = term.endswith("*")
    if wildcard:
        term = term[:-1]
    parts = re.split(r"[\s\-]+", term)
    p = r"[\s\-]*".join(re.escape(x) for x in parts if x)
    if wildcard:
        p += r"[\w\-]*"
    elif plural and term[-1:].isalpha():
        p += r"(?:s|es)?"
    if is_case_sensitive(term):
        p = "(?-i:" + p + ")"
    return p


def build_regex(terms, plural=False):
    terms = sorted({t for t in terms if t and t.strip()}, key=lambda t: -len(t))
    if not terms:
        return None
    body = "|".join(term_pattern(t, plural) for t in terms)
    return re.compile(r"(?<![\w])(?:" + body + r")(?![\w])", re.IGNORECASE)


def canon(s: str) -> str:
    return re.sub(r"[\s\-\.']", "", norm(s).lower())


# ─────────────────────────────────────────────────────────────────────────────
#  Geography
# ─────────────────────────────────────────────────────────────────────────────

class Gazetteer:
    def __init__(self, data: dict):
        self.taxonomy: dict[str, dict[str, list[str]]] = {}
        self.country_region: dict[str, str] = {}
        self.region_continent: dict[str, str] = {}
        self.lookup: dict[str, tuple[str, str]] = {}   # canon alias → (kind, name)
        self.excludes: dict[str, re.Pattern] = {}
        terms: list[str] = []

        def add(alias, kind, name):
            key = canon(alias)
            if not key:
                return
            prev = self.lookup.get(key)
            if prev and prev != (kind, name):
                log(f"  ! alias '{alias}' used twice ({prev[1]} / {name}) — keeping {prev[1]}")
                return
            self.lookup[key] = (kind, name)
            terms.append(alias)

        for continent, cblock in data.items():
            self.taxonomy[continent] = {}
            for alias in (cblock or {}).get("_terms", []) or []:
                add(alias, "continent", continent)
            for region, rblock in (cblock or {}).items():
                if region == "_terms":
                    continue
                self.taxonomy[continent][region] = []
                self.region_continent[region] = continent
                for alias in (rblock or {}).get("_terms", []) or []:
                    add(alias, "region", region)
                for country, spec in (rblock or {}).items():
                    if country == "_terms":
                        continue
                    if isinstance(spec, dict):
                        aliases = spec.get("aliases", []) or []
                        if spec.get("exclude"):
                            self.excludes[country] = re.compile(spec["exclude"], re.I)
                    else:
                        aliases = spec or []
                    self.taxonomy[continent][region].append(country)
                    self.country_region[country] = region
                    add(country, "country", country)
                    for a in aliases:
                        add(a, "country", country)
        self.regex = build_regex(terms, plural=True)

    def resolve(self, name: str):
        """A hint like 'West Africa' / 'Nigeria' / 'Africa' → (kind, name)."""
        if name in self.country_region:
            return ("country", name)
        if name in self.region_continent:
            return ("region", name)
        if name in self.taxonomy:
            return ("continent", name)
        return None

    def match(self, title: str, summary: str = ""):
        countries, regions, continents = [], [], []
        text = norm(title) + " \n " + norm(summary)
        for m in self.regex.finditer(text):
            key = canon(m.group(0))
            hit = (self.lookup.get(key)
                   or (key.endswith("es") and self.lookup.get(key[:-2]))
                   or (key.endswith("s") and self.lookup.get(key[:-1])))
            if not hit:
                continue
            kind, name = hit
            if kind == "country":
                ex = self.excludes.get(name)
                if ex and ex.search(text):
                    continue
                if name not in countries:
                    countries.append(name)
            elif kind == "region" and name not in regions:
                regions.append(name)
            elif kind == "continent" and name not in continents:
                continents.append(name)
        return countries, regions, continents

    def expand(self, countries, regions, continents):
        regs = list(regions)
        for c in countries:
            r = self.country_region[c]
            if r not in regs:
                regs.append(r)
        conts = list(continents)
        for r in regs:
            k = self.region_continent[r]
            if k not in conts:
                conts.append(k)
        return countries[:5], regs[:5], conts[:4]


# ─────────────────────────────────────────────────────────────────────────────
#  Domains & severity
# ─────────────────────────────────────────────────────────────────────────────

class Tagger:
    def __init__(self, cfg: dict):
        self.domains = []
        for did, d in cfg["domains"].items():
            self.domains.append((did, build_regex(d.get("keywords", []), plural=True),
                                 build_regex(d.get("exclude", []))))
        self.fallback = cfg.get("fallback", {"id": "other"})["id"]
        sev = cfg.get("severity", {})
        self.high = build_regex(sev.get("high", []))
        self.elevated = build_regex(sev.get("elevated", []))
        self.mag_high = float(sev.get("magnitude_high", 6.5))
        self.mag_elev = float(sev.get("magnitude_elevated", 5.8))
        self.noise = re.compile(cfg["noise"], re.I) if cfg.get("noise") else None
        self.meta = [{"id": did, "label": d["label"], "color": d.get("color", "#888")}
                     for did, d in cfg["domains"].items()]
        fb = cfg.get("fallback", {})
        self.meta.append({"id": self.fallback, "label": fb.get("label", "Other"),
                          "color": fb.get("color", "#888")})

    def tag(self, title: str, summary: str):
        text = norm(title) + " \n " + norm(summary)
        found = []
        for did, rx, ex in self.domains:
            t = ex.sub(" ", text) if ex else text
            if rx and rx.search(t):
                found.append(did)
        return found

    def severity(self, title: str) -> int:
        t = norm(title)
        mag = magnitude(t)
        if mag is not None:
            if mag >= self.mag_high:
                return 2
            if mag >= self.mag_elev:
                return 1
        if self.high and self.high.search(t):
            return 2
        if self.elevated and self.elevated.search(t):
            return 1
        return 0


MAG_RE = re.compile(r"\b(?:M|Mw|Mag(?:nitude)?)[\s:=]*([3-9]\.\d)\b", re.I)


def magnitude(title: str):
    m = MAG_RE.search(title)
    return float(m.group(1)) if m else None


# ─────────────────────────────────────────────────────────────────────────────
#  Fetchers — each returns (raw_items, status)
#  raw item: {title, url, source, published(datetime), summary}
# ─────────────────────────────────────────────────────────────────────────────

session = requests.Session()
session.headers.update({"User-Agent": UA, "Accept": "*/*"})


def to_dt(struct):
    if not struct:
        return None
    try:
        return datetime.fromtimestamp(calendar.timegm(struct), tz=timezone.utc)
    except Exception:
        return None


def parse_feed(content: bytes, default_source: str):
    parsed = feedparser.parse(content)
    out = []
    for e in parsed.entries:
        title = clean(e.get("title", ""))
        link = e.get("link") or ""
        if not title or not link:
            continue
        src = default_source
        if e.get("source") and e.source.get("title"):
            src = clean(e.source.get("title"))
        elif e.get("news_source"):                      # Bing News
            src = clean(e.get("news_source"))
        if "bing.com/news/apiclick" in link:            # Bing wraps the real link
            real = parse_qs(urlparse(link).query).get("url")
            if real:
                link = real[0]
        out.append({
            "title": title,
            "url": link,
            "source": src,
            "published": to_dt(e.get("published_parsed") or e.get("updated_parsed")),
            "summary": clean(e.get("summary", ""))[:400],
        })
    if not out and parsed.bozo and not parsed.entries:
        raise ValueError(f"not a readable feed ({type(parsed.bozo_exception).__name__})")
    return out


def fetch_feed(feed: dict):
    t0 = time.time()
    try:
        r = session.get(feed["url"], timeout=TIMEOUT)
        r.raise_for_status()
        items = parse_feed(r.content, feed["name"])
        return items, {"ok": True, "count": len(items), "ms": int((time.time() - t0) * 1000)}
    except Exception as ex:
        return [], {"ok": False, "count": 0, "error": short_err(ex),
                    "ms": int((time.time() - t0) * 1000)}


def short_err(ex) -> str:
    if isinstance(ex, requests.HTTPError) and ex.response is not None:
        return f"HTTP {ex.response.status_code}"
    if isinstance(ex, requests.Timeout):
        return "timed out"
    if isinstance(ex, requests.ConnectionError):
        return "could not connect"
    return str(ex)[:120]


def gnews_url(query: str, ed: dict, when: str = "1d") -> str:
    """Google News search feed. `ed` = edition: hl, gl, ceid (e.g. fr / FR / FR:fr)."""
    hl = ed.get("hl", "en-US")
    gl = ed.get("gl", "US")
    ceid = ed.get("ceid") or f"{gl}:{hl.split('-')[0]}"
    q = f"when:{when} {query}"
    return (f"https://news.google.com/rss/search?q={quote_plus(q)}"
            f"&hl={hl}&gl={gl}&ceid={quote_plus(ceid)}")


def bing_url(query: str, market: str = "en-US") -> str:
    """Bing News search feed, last 24 hours."""
    return (f"https://www.bing.com/news/search?q={quote_plus(query)}&format=rss&count=100"
            f"&mkt={market}&qft=interval%3d%227%22")


def strip_publisher(title: str, source: str) -> str:
    if source and title.endswith(" - " + source):
        return title[: -(len(source) + 3)].strip()
    return re.sub(r"\s+-\s+[^-]{2,60}$", "", title).strip()


def fetch_gdelt(domain: str, query: str, gd: dict):
    langs = gd.get("languages") or []
    q = query
    if langs:
        lq = " OR ".join(f"sourcelang:{l}" for l in langs)
        q += f" ({lq})" if len(langs) > 1 else f" {lq}"
    url = ("https://api.gdeltproject.org/api/v2/doc/doc?"
           f"query={quote_plus(q)}&mode=artlist&format=json&sort=datedesc"
           f"&maxrecords={int(gd.get('max_per_query', 75))}&timespan={gd.get('timespan', '3h')}")
    t0 = time.time()
    last = None
    for attempt in range(2):
        try:
            r = session.get(url, timeout=(10, 50))
            if r.status_code == 429:
                last = "rate limited (HTTP 429)"
                time.sleep(6)
                continue
            r.raise_for_status()
            text = r.text.strip()
            if not text.startswith("{"):
                # GDELT answers query problems in plain text
                raise ValueError(text[:120] or "empty response")
            data = json.loads(text, strict=False)
            items = []
            for a in data.get("articles", []) or []:
                title = clean(a.get("title", ""))
                if not title or not a.get("url"):
                    continue
                pub = None
                sd = a.get("seendate", "")
                try:
                    pub = datetime.strptime(sd, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                except Exception:
                    pass
                items.append({"title": title, "url": a["url"],
                              "source": a.get("domain") or "GDELT",
                              "published": pub, "summary": ""})
            return items, {"ok": True, "count": len(items), "ms": int((time.time() - t0) * 1000)}
        except Exception as ex:
            last = short_err(ex)
            break      # slow or broken: give up on this search, don't retry
    return [], {"ok": False, "count": 0, "error": last, "ms": int((time.time() - t0) * 1000)}


# GDELT raw event files (a separate server from the GDELT search service)
GDELT_ROOTS = {   # CAMEO root code → (domains, severity)
    "13": (["conflict"], 0),               # threaten
    "14": (["political"], 0),              # protest
    "15": (["conflict"], 0),               # military posturing
    "17": (["political"], 1),              # coerce (arrests, crackdowns)
    "18": (["conflict"], 1),               # assault
    "19": (["conflict"], 1),               # fight
    "20": (["conflict", "terrorism"], 2),  # mass violence
}
SLUG_JUNK = re.compile(r"^(\d+|[0-9a-f]{8,}|index|article|story|news|amp|html?|php)$", re.I)


def slug_title(url: str):
    path = urlparse(url).path
    best = ""
    for seg in path.split("/"):
        seg = re.sub(r"\.(s?html?|php|aspx?|cms)$", "", seg, flags=re.I)
        if seg.count("-") + seg.count("_") > best.count("-") + best.count("_"):
            best = seg
    words = [w for w in re.split(r"[-_+]+", best) if w and not SLUG_JUNK.match(w)]
    if len(words) < 4:
        return None
    t = " ".join(words)
    return t[:1].upper() + t[1:]


def fetch_gdelt_files(gf: dict):
    t0 = time.time()
    base = "http://data.gdeltproject.org/gdeltv2/"
    try:
        r = session.get(base + "lastupdate.txt", timeout=TIMEOUT)
        r.raise_for_status()
        export = next(l.split()[-1] for l in r.text.splitlines() if ".export.CSV.zip" in l)
        stamp = re.search(r"/(\d{14})\.export", export).group(1)
        latest = datetime.strptime(stamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        files = [base + (latest - timedelta(minutes=15 * k)).strftime("%Y%m%d%H%M%S") + ".export.CSV.zip"
                 for k in range(int(gf.get("files", 2)))]
        roots = {str(x) for x in gf.get("event_types", list(GDELT_ROOTS))}
        min_sources = int(gf.get("min_sources", 1))
        by_url: dict[str, dict] = {}
        for f in files:
            try:
                z = session.get(f, timeout=(8, 60))
                z.raise_for_status()
            except Exception:
                continue
            with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
                name = zf.namelist()[0]
                text = zf.read(name).decode("utf-8", "replace")
            for row in csv.reader(io.StringIO(text), delimiter="\t"):
                if len(row) < 61:
                    continue
                root = row[28]
                if root not in roots or int(row[32] or 0) < min_sources:
                    continue
                url = row[60].strip()
                if not url.startswith("http"):
                    continue
                e = by_url.setdefault(url, {"roots": set(), "places": [], "added": row[59]})
                e["roots"].add(root)
                place = row[52].strip()
                if place and place not in e["places"] and len(e["places"]) < 3:
                    e["places"].append(place)
        items = []
        for url, e in by_url.items():
            title = slug_title(url)
            if not title:
                continue
            doms, sev = [], 0
            for rc in sorted(e["roots"]):
                d, s = GDELT_ROOTS.get(rc, ([], 0))
                doms += [x for x in d if x not in doms]
                sev = max(sev, s)
            try:
                pub = datetime.strptime(e["added"], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            except Exception:
                pub = None
            items.append({"title": title, "url": url,
                          "source": urlparse(url).netloc.replace("www.", ""),
                          "published": pub,
                          "summary": "Location: " + "; ".join(e["places"]) if e["places"] else "",
                          "domains": doms, "sev": sev})
        return items, {"ok": True, "count": len(items), "ms": int((time.time() - t0) * 1000)}
    except Exception as ex:
        return [], {"ok": False, "count": 0, "error": short_err(ex), "ms": int((time.time() - t0) * 1000)}


# ─────────────────────────────────────────────────────────────────────────────
#  Building items
# ─────────────────────────────────────────────────────────────────────────────

STOP = set("""a an the of in on at to for from by with and or as is are was were be been
over after amid into says say said will would could new news live update updates video
watch latest report reports""".split())


def story_key(title: str) -> str:
    t = norm(title).lower()
    t = re.sub(r"\s+[\-\|]\s+[^\-\|]{2,40}$", "", t)          # trailing " - Site"
    words = [w for w in re.findall(r"[a-z0-9]+", t) if w not in STOP and len(w) > 2]
    return " ".join(words[:12]) or t[:80]


def make_id(title: str) -> str:
    return hashlib.sha1(story_key(title).encode()).hexdigest()[:12]


class Builder:
    def __init__(self, gaz: Gazetteer, tagger: Tagger, window_start: datetime):
        self.gaz, self.tagger, self.window_start = gaz, tagger, window_start
        self.items: dict[str, dict] = {}

    def add(self, raw: dict, via: str, *, specialist=False, domain=None, hint=None,
            drop_if=None, min_magnitude=None, forced_domain=None, force_place=None):
        title = raw["title"]
        orig = raw.get("orig")                 # original-language headline, if translated
        lang = raw.get("lang", "en")
        if via == "gnews" and not orig:
            title = strip_publisher(title, raw["source"])
        if len(title) < 12:
            return "short"
        if lang != "en" and not orig and not specialist:
            return "untranslated"              # can't judge relevance yet; retried next run
        if drop_if and re.search(drop_if, title, re.I):
            return "dropped"
        if min_magnitude is not None:
            mag = magnitude(norm(title))
            if mag is not None and mag < float(min_magnitude):
                return "dropped"
        pub = raw.get("published") or NOW
        if pub > NOW + timedelta(minutes=10):
            pub = NOW
        if pub < self.window_start:
            return "old"
        summary = raw.get("summary", "")
        if summary and norm(summary).lower().startswith(norm(title).lower()[:40]):
            summary = ""        # many feeds repeat the headline as the summary

        if not specialist and self.tagger.noise and self.tagger.noise.search(title):
            return "noise"
        domains = self.tagger.tag(title, summary)
        for d in reversed(raw.get("domains") or []):
            if d not in domains:
                domains.insert(0, d)
        if forced_domain and forced_domain not in domains:
            domains.insert(0, forced_domain)
        if not domains:
            if not specialist:
                return "off-topic"
            domains = [domain or self.tagger.fallback]

        c, r, k = self.gaz.match(title, summary)
        if not (c or r or k) and hint:
            res = self.gaz.resolve(hint)
            if res:
                kind, name = res
                c, r, k = ([name], [], []) if kind == "country" else \
                          ([], [name], []) if kind == "region" else ([], [], [name])
        if force_place and force_place not in c:
            # result of a search for this specific country: always file it there
            c = c[:4] + [force_place]
        c, r, k = self.gaz.expand(c, r, k)

        item = {
            "id": make_id(orig or title), "t": title, "u": raw["url"], "s": raw["source"],
            "p": iso(pub), "f": iso(NOW), "x": "" if lang != "en" else summary[:220],
            "c": c, "g": r, "k": k, "d": domains[:4],
            "sev": max(self.tagger.severity(title), int(raw.get("sev", 0))),
            "v": via, "n": 1, "o": [],
        }
        if lang != "en":
            item["l"] = lang
            if orig:
                item["ot"] = orig
        self.merge(item)
        return "kept"

    def merge(self, item: dict):
        cur = self.items.get(item["id"])
        if cur:
            merge_items(cur, item)
        else:
            self.items[item["id"]] = item


def merge_items(cur: dict, item: dict) -> dict:
    """Fold a second report of the same story into the first."""
    known = {cur["s"]} | {o["s"] for o in cur.get("o", [])}
    if item["s"] not in known:
        cur["n"] = cur.get("n", 1) + 1
        if len(cur["o"]) < 6:
            cur["o"].append({"s": item["s"], "u": item["u"]})
        known.add(item["s"])
    for o in item.get("o", []):
        if o["s"] not in known:
            cur["n"] = cur.get("n", 1) + 1
            known.add(o["s"])
            if len(cur["o"]) < 6:
                cur["o"].append(o)
    for key in ("c", "g", "k", "d"):
        for v in item.get(key, []):
            if v not in cur[key]:
                cur[key].append(v)
    cur["sev"] = max(cur.get("sev", 0), item.get("sev", 0))
    if item["p"] < cur["p"]:
        cur["p"] = item["p"]
    if item.get("f", "9") < cur.get("f", "9"):
        cur["f"] = item["f"]
    if not cur.get("x") and item.get("x"):
        cur["x"] = item["x"]
    if item.get("ot") and not cur.get("ot") and cur.get("l") == item.get("l"):
        cur["t"], cur["ot"] = item["t"], item["ot"]
    # prefer a curated feed as the main link over aggregators
    rank = {"rss": 0, "gnews": 1, "bing": 1, "gdelt": 2, "gdeltfile": 3}
    if rank.get(item["v"], 3) < rank.get(cur["v"], 3):
        if cur["s"] != item["s"]:
            cur["o"] = [o for o in cur["o"] if o["s"] != item["s"]]
            cur["o"].insert(0, {"s": cur["s"], "u": cur["u"]})
            cur["o"] = cur["o"][:6]
        cur["t"], cur["u"], cur["s"], cur["v"] = item["t"], item["u"], item["s"], item["v"]
    return cur


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
#  Previous run
# ─────────────────────────────────────────────────────────────────────────────

def previous_data_url(sources_cfg: dict):
    explicit = os.environ.get("SITE_URL") or sources_cfg.get("settings", {}).get("site_url")
    if explicit:
        return explicit.rstrip("/") + "/data/news.json"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None
    owner, name = repo.split("/", 1)
    base = f"https://{owner.lower()}.github.io"
    if name.lower() != f"{owner.lower()}.github.io":
        base += f"/{name}"
    return base + "/data/news.json"


def load_previous(path_or_url):
    if not path_or_url:
        return []
    try:
        if path_or_url.startswith("http"):
            r = session.get(path_or_url, params={"t": int(time.time())}, timeout=TIMEOUT)
            if r.status_code == 404:
                log("  no previous data yet (first run)")
                return []
            r.raise_for_status()
            data = r.json()
        else:
            data = json.loads(Path(path_or_url).read_text())
        items = data.get("items", [])
        log(f"  loaded {len(items)} items from previous run")
        return items
    except Exception as ex:
        log(f"  could not load previous data: {short_err(ex)}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="_site", help="output folder for the website")
    ap.add_argument("--previous", help="file or URL of the last news.json (auto-detected on GitHub)")
    ap.add_argument("--no-translate", action="store_true")
    args = ap.parse_args()
    t_start = time.time()

    sources = yaml.safe_load((CONFIG / "sources.yaml").read_text(encoding="utf-8"))
    places = yaml.safe_load((CONFIG / "places.yaml").read_text(encoding="utf-8"))
    domcfg = yaml.safe_load((CONFIG / "domains.yaml").read_text(encoding="utf-8"))
    settings = sources.get("settings", {})
    window_h = int(settings.get("window_hours", 48))
    max_items = int(settings.get("max_items", 6000))
    window_start = NOW - timedelta(hours=window_h)

    log("Loading tagging rules…")
    gaz = Gazetteer(places)
    tagger = Tagger(domcfg)
    domain_ids = {d["id"] for d in tagger.meta}
    previous = load_previous(args.previous or previous_data_url(sources))

    # Every source becomes a job: (name, kind, url, fetch_fn, add_kwargs, via, lang)
    jobs = []

    for feed in sources.get("feeds") or []:
        kw = {"specialist": bool(feed.get("specialist")), "domain": feed.get("domain"),
              "hint": feed.get("hint"), "drop_if": feed.get("drop_if"),
              "min_magnitude": feed.get("min_magnitude")}
        if kw["domain"] and kw["domain"] not in domain_ids:
            log(f"  ! unknown domain '{kw['domain']}' on {feed['name']}")
        jobs.append((feed["name"], "feed", feed["url"], lambda f=feed: fetch_feed(f), kw, "rss",
                     feed.get("lang", "en")))

    def search_jobs(engine, label, make_url, queries, lang, via):
        for name, query, kw in queries:
            url = make_url(query)
            jobs.append((f"{label} · {name}", engine, url,
                         lambda u=url, l=label: fetch_feed({"name": l, "url": u}), kw, via, lang))

    gn = sources.get("google_news") or {}
    english_queries = []
    sec = gn.get("security_terms", "")
    for q in gn.get("regional", []) or []:
        english_queries.append((q["hint"], f"{sec} ({q['places']})" if sec else q["places"],
                                {"specialist": True, "hint": q["hint"]}))
    for q in gn.get("topical", []) or []:
        english_queries.append((q["domain"], q["query"],
                                {"specialist": True, "domain": q["domain"], "forced_domain": q["domain"]}))
    when = gn.get("when", "1d")
    if gn.get("enabled", True):
        ed = {"hl": gn.get("language", "en-US"), "gl": gn.get("country", "US"), "ceid": gn.get("ceid")}
        search_jobs("google_news", "Google News", lambda q, e=ed: gnews_url(q, e, when),
                    english_queries, "en", "gnews")
        for ed in gn.get("editions", []) or []:
            lang = ed["lang"]
            esec = ed.get("security_terms", "")
            qs = [(f"{lang} · {q['hint']}", f"{esec} ({q['places']})" if esec else q["places"],
                   {"specialist": True, "hint": q["hint"]}) for q in ed.get("queries", [])]
            search_jobs("google_news", "Google News", lambda q, e=ed: gnews_url(q, e, when),
                        qs, lang, "gnews")

    # Country-by-country searches (rotating; countries without recent news first)
    cs = sources.get("country_search") or {}
    if cs.get("enabled", False):
        all_countries = [c for regs in gaz.taxonomy.values() for cs_ in regs.values() for c in cs_]
        cjobs = []
        terms = cs.get("terms", "")
        en_ed = {"hl": gn.get("language", "en-US"), "gl": gn.get("country", "US"), "ceid": gn.get("ceid")}
        for c in all_countries:
            q = (cs.get("names") or {}).get(c) or f'"{c}"'
            cjobs.append((c, "en", f"{terms} ({q})" if terms else q, en_ed))
        for lang, spec in (cs.get("local") or {}).items():
            lterms = spec.get("terms", "")
            for c, q in (spec.get("countries") or {}).items():
                if c not in gaz.country_region:
                    log(f"  ! country_search: unknown country '{c}' ({lang})")
                    continue
                cjobs.append((c, lang, f"{lterms} ({q})" if lterms else q, spec.get("edition", {})))
        recent = set()
        cutoff = iso(NOW - timedelta(hours=24))
        for it in previous:
            if it.get("p", "") >= cutoff:
                recent.update(it.get("c") or [])
        per_run = int(cs.get("per_run", 75))
        missing = [j for j in cjobs if j[0] not in recent]
        missing.sort(key=lambda j: j[1] != "en")       # English search first for each quiet country
        rest = [j for j in cjobs if j[0] in recent]
        if rest:
            off = (int(NOW.timestamp()) // 1200 * per_run) % len(rest)
            rest = rest[off:] + rest[:off]
        chosen = (missing + rest)[:per_run]
        log(f"Country searches: {len(chosen)} of {len(cjobs)} this run "
            f"({len(set(j[0] for j in missing))} countries had no recent reports and go first)")
        cwhen = cs.get("when", "2d")
        for c, lang, query, ed in chosen:
            url = gnews_url(query, ed, cwhen)
            jobs.append((f"Country · {c}" + ("" if lang == "en" else f" ({lang})"), "country_search", url,
                         lambda u=url: fetch_feed({"name": "Google News", "url": u}),
                         {"specialist": True, "hint": c, "force_place": c}, "gnews", lang))

    bn = sources.get("bing_news") or {}
    if bn.get("enabled", False):
        search_jobs("bing_news", "Bing News", lambda q: bing_url(q, bn.get("market", "en-US")),
                    english_queries if bn.get("use_google_queries", True) else [], "en", "bing")

    gf = sources.get("gdelt_files") or {}
    if gf.get("enabled", False):
        jobs.append(("GDELT event files", "gdelt", "http://data.gdeltproject.org/gdeltv2/lastupdate.txt",
                     lambda: fetch_gdelt_files(gf), {"specialist": True}, "gdeltfile", "en"))

    # 1 ── fetch everything (in parallel, politely)
    log(f"Fetching {len(jobs)} sources…")
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda j: j[3](), jobs))

    gd = sources.get("gdelt") or {}
    if gd.get("enabled", False):
        g_start = time.time()
        for i, (dom, query) in enumerate((gd.get("queries") or {}).items()):
            if time.time() - g_start > GDELT_BUDGET:
                results.append(([], {"ok": False, "count": 0, "error": "skipped — GDELT was slow"}))
            else:
                if i:
                    time.sleep(5.5)
                results.append(fetch_gdelt(dom, query, gd))
            d = dom if dom in domain_ids else None
            jobs.append((f"GDELT · {dom}", "gdelt", "https://api.gdeltproject.org/api/v2/doc/doc", None,
                         {"specialist": True, "domain": d, "forced_domain": d}, "gdelt", "en"))

    # 2 ── previous run (for merging, and so headlines are only translated once)
    known_tr = {it["ot"]: it["t"] for it in previous if it.get("ot")}

    # 3 ── translate non-English headlines
    status = []
    pending: dict[str, list[str]] = {}
    for job, (raw, st) in zip(jobs, results):
        lang = job[6]
        for r in raw:
            r["lang"] = lang
            if lang == "en":
                continue
            t = r["title"]
            if job[5] == "gnews":
                t = strip_publisher(t, r["source"])
            r["title_src"] = t
            if t in known_tr:
                r["orig"], r["title"] = t, known_tr[t]
            else:
                pending.setdefault(lang, [])
                if t not in pending[lang]:
                    pending[lang].append(t)
    if pending and not args.no_translate:
        try:
            from translate import Translator
            tr = Translator(session, log)
            total = sum(len(v) for v in pending.values())
            log(f"Translating {total} new headlines in {len(pending)} languages…")
            deadline = time.time() + TRANSLATE_BUDGET
            done: dict[str, str] = {}
            for lang, texts in sorted(pending.items(), key=lambda kv: -len(kv[1])):
                done.update(tr.translate(lang, texts, deadline))
            for raw, _ in results:
                for r in raw:
                    t = r.get("title_src")
                    if t and not r.get("orig") and t in done:
                        r["orig"], r["title"] = t, done[t]
            if tr.downloaded and os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
                    fh.write("models_changed=true\n")
            for lang, st in sorted(tr.status.items()):
                status.append({"name": f"Translator · {lang} → en", "kind": "translator", "url": "",
                               "ok": st["ok"], "count": len(pending.get(lang, [])), "kept": st["count"],
                               "error": st.get("error", "")})
                log(f"  [{'ok ' if st['ok'] else 'ERR'}] translator {lang}: {st['count']} translated"
                    + (f" — {st['error']}" if st.get("error") else ""))
        except Exception as ex:
            log(f"  translator unavailable: {ex}")
            status.append({"name": "Translator", "kind": "translator", "url": "", "ok": False,
                           "count": 0, "kept": 0, "error": str(ex)[:120]})

    # 4 ── tag and de-duplicate
    builder = Builder(gaz, tagger, window_start)
    src_status = []
    for (name, kind, url, _, kw, via, lang), (raw, st) in zip(jobs, results):
        outcome = {}
        for r in raw:
            res = builder.add(r, via, **kw)
            outcome[res] = outcome.get(res, 0) + 1
        st = dict(st)
        st.update({"name": name, "kind": kind, "url": url, "kept": outcome.get("kept", 0), "lang": lang})
        src_status.append(st)
        flag = "ok " if st["ok"] else "ERR"
        log(f"  [{flag}] {name}: {st['count']} fetched, {st['kept']} kept"
            + (f" — {st.get('error')}" if not st["ok"] else "")
            + (f"  (dropped: {', '.join(f'{k} {v}' for k, v in outcome.items() if k != 'kept')})"
               if st["ok"] and st["kept"] < st["count"] else ""))
    status = src_status + status
    log(f"This run: {len(builder.items)} distinct stories")

    # 5 ── merge with the previous run
    merged = {}
    for it in previous:
        if it.get("p", "") >= iso(window_start) and it.get("id"):
            it.setdefault("o", []); it.setdefault("n", 1)
            for key in ("c", "g", "k", "d"):
                it.setdefault(key, [])
            merged[it["id"]] = it
    for it in builder.items.values():
        old = merged.get(it["id"])
        merged[it["id"]] = merge_items(old, it) if old else it
    ranked = sorted(merged.values(), key=lambda i: i["p"], reverse=True)
    items = ranked[:max_items]
    # The size cap drops the oldest stories first; make sure quiet countries
    # keep their (older) stories so every country stays represented.
    keep_min = int(settings.get("min_per_country", 15))
    per = {}
    for it in items:
        for c in it.get("c") or []:
            per[c] = per.get(c, 0) + 1
    kept_ids = {it["id"] for it in items}
    for it in ranked[max_items:]:
        need = [c for c in it.get("c") or [] if per.get(c, 0) < keep_min]
        if need and it["id"] not in kept_ids:
            items.append(it)
            kept_ids.add(it["id"])
            for c in it.get("c") or []:
                per[c] = per.get(c, 0) + 1
    items.sort(key=lambda i: i["p"], reverse=True)
    covered = {c for it in items for c in it.get("c") or []}
    absent = [c for c in gaz.country_region if c not in covered]
    log(f"Countries with reports: {len(gaz.country_region) - len(absent)}/{len(gaz.country_region)}"
        + (f" — none yet for: {', '.join(absent)}" if absent else ""))

    if not items:
        log("No items at all — every source failed. Leaving the current site untouched.")
        sys.exit(1)

    # 6 ── write the site
    out = Path(args.out)
    (out / "data").mkdir(parents=True, exist_ok=True)
    if SITE.exists():
        for f in SITE.iterdir():
            if f.is_file():
                shutil.copy2(f, out / f.name)
    payload = {
        "title": settings.get("title", "Security Watch"),
        "generated": iso(NOW),
        "window_hours": window_h,
        "run_seconds": round(time.time() - t_start, 1),
        "new_this_run": sum(1 for i in items if i.get("f") == iso(NOW)),
        "taxonomy": gaz.taxonomy,
        "domains": tagger.meta,
        "links": sources.get("links", []),
        "sources": status,
        "items": items,
    }
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    (out / "data" / "news.json").write_text(data, encoding="utf-8")
    ok = sum(1 for s in status if s["ok"])
    log(f"Wrote {len(items)} items ({len(data)//1024} KB). Sources OK: {ok}/{len(status)}. "
        f"Took {payload['run_seconds']}s.")


if __name__ == "__main__":
    main()
