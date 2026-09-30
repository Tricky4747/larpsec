import feedparser
import requests
import urllib.parse
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple


class DynamicNewsIngestor:
    """
    Supplychainer Stage 1: Dynamic News Ingestion.
    Consumes live external intelligence from Google News RSS.

    Changes vs original:
      * Returns (text, source) where source is "LIVE" or "FALLBACK", so callers
        can tell real intelligence from the offline default.
      * Uses requests with a per-call timeout instead of the process-wide
        socket.setdefaulttimeout() (which leaked into every other socket user).
      * Failed fetches are cached briefly, so an offline server doesn't pay the
        timeout on every request.
      * prefetch() fetches many (location, mode) pairs in parallel.
    """
    def __init__(self):
        self.cache: Dict[str, Tuple[float, str, str]] = {}  # {query: (ts, text, source)}
        self.cache_ttl = 900      # 15 min for live results
        self.fail_ttl = 120       # 2 min for fallbacks, so we retry soon
        self.timeout = 2.0
        self._lock = threading.Lock()

        self.fallback_news = {
            "sea": "Maritime congestion reported at major transshipment hubs. Berthing delays expected.",
            "air": "Aviation fuel surcharge volatility and cargo handling backlogs noted in international airports.",
            "road": "Highway traffic density increasing in primary logistics corridors.",
            "rail": "Rail freight scheduling adjustments due to infrastructure maintenance."
        }

    def get_latest_news_with_source(self, location: str, transport_mode: str) -> Tuple[str, str]:
        query = f"{location} {transport_mode} logistics disruption"
        now = time.time()

        with self._lock:
            hit = self.cache.get(query)
        if hit:
            ts, text, source = hit
            ttl = self.cache_ttl if source == "LIVE" else self.fail_ttl
            if now - ts < ttl:
                return text, source

        text, source = None, "FALLBACK"
        try:
            url = ("https://news.google.com/rss/search?q="
                   f"{urllib.parse.quote(query)}&hl=en-US&gl=US&ceid=US:en")
            resp = requests.get(url, timeout=self.timeout,
                                headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)
            if feed.entries:
                text = " | ".join(e.title for e in feed.entries[:3])
                source = "LIVE"
        except Exception as e:
            print(f"[NEWS] fetch failed for '{query}': {e}")

        if text is None:
            text = self.fallback_news.get(transport_mode.lower(),
                                          "Normal operational conditions reported.")

        with self._lock:
            self.cache[query] = (now, text, source)
        return text, source

    def get_latest_news(self, location: str, transport_mode: str) -> str:
        """Backwards-compatible: text only."""
        return self.get_latest_news_with_source(location, transport_mode)[0]

    def prefetch(self, pairs: List[Tuple[str, str]], max_workers: int = 8) -> Dict[Tuple[str, str], Tuple[str, str]]:
        """Fetch many (location, mode) pairs concurrently. Returns {pair: (text, source)}."""
        pairs = list(dict.fromkeys(pairs))  # de-dupe, keep order
        if not pairs:
            return {}
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            results = list(ex.map(lambda p: self.get_latest_news_with_source(*p), pairs))
        return dict(zip(pairs, results))