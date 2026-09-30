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

    Returns both the fetched text and its source ("LIVE" or "FALLBACK") so
    callers can distinguish real external intelligence from the deterministic
    offline fallback.
    """

    def __init__(self):
        self.cache: Dict[str, Tuple[float, str, str]] = {}
        self.cache_ttl = 900       # 15 minutes for live results
        self.fail_ttl = 120        # 2 minutes for fallbacks
        self.timeout = 2.0
        self._lock = threading.Lock()

        self.fallback_news = {
            "sea": "Maritime congestion reported at major transshipment hubs. Berthing delays expected.",
            "air": "Aviation fuel surcharge volatility and cargo handling backlogs noted in international airports.",
            "road": "Highway traffic density increasing in primary logistics corridors.",
            "rail": "Rail freight scheduling adjustments due to infrastructure maintenance.",
        }

    def get_latest_news_with_source(
        self, location: str, transport_mode: str
    ) -> Tuple[str, str]:
        normalized_mode = (transport_mode or "").strip().lower()
        query = f"{location} {normalized_mode} logistics disruption"
        now = time.time()

        with self._lock:
            hit = self.cache.get(query)

        if hit:
            ts, text, source = hit
            ttl = self.cache_ttl if source == "LIVE" else self.fail_ttl
            if now - ts < ttl:
                return text, source

        text = None
        source = "FALLBACK"

        try:
            url = (
                "https://news.google.com/rss/search?q="
                f"{urllib.parse.quote(query)}&hl=en-US&gl=US&ceid=US:en"
            )
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            response.raise_for_status()

            feed = feedparser.parse(response.content)
            if feed.entries:
                text = " | ".join(entry.title for entry in feed.entries[:3])
                source = "LIVE"
        except Exception as exc:
            print(f"[NEWS] fetch failed for '{query}': {exc}")

        if text is None:
            text = self.fallback_news.get(
                normalized_mode, "Normal operational conditions reported."
            )

        with self._lock:
            self.cache[query] = (now, text, source)

        return text, source

    def get_latest_news(self, location: str, transport_mode: str) -> str:
        """Backwards-compatible text-only API."""
        return self.get_latest_news_with_source(location, transport_mode)[0]

    def prefetch(
        self, pairs: List[Tuple[str, str]], max_workers: int = 8
    ) -> Dict[Tuple[str, str], Tuple[str, str]]:
        """Fetch many (location, mode) pairs concurrently."""
        pairs = list(dict.fromkeys(pairs))
        if not pairs:
            return {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(
                executor.map(
                    lambda pair: self.get_latest_news_with_source(*pair),
                    pairs,
                )
            )
        return dict(zip(pairs, results))
