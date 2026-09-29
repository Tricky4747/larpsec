import feedparser
import urllib.parse
import urllib.request
import time
from typing import List, Dict

class DynamicNewsIngestor:
    """
    Supplychainer Stage 1: Dynamic News Ingestion.
    Consumes live external intelligence from Google News RSS.
    Implements location-aware text retrieval and caching.
    """
    def __init__(self):
        self.cache = {} # {query: (timestamp, content)}
        self.cache_ttl = 900 # 15 minutes
        
        # Operational Physics Fallbacks (Offline Reliability)
        self.fallback_news = {
            "sea": "Maritime congestion reported at major transshipment hubs. Berthing delays expected.",
            "air": "Aviation fuel surcharge volatility and cargo handling backlogs noted in international airports.",
            "road": "Highway traffic density increasing in primary logistics corridors.",
            "rail": "Rail freight scheduling adjustments due to infrastructure maintenance."
        }

    def get_latest_news(self, location: str, transport_mode: str) -> str:
        """
        Fetches live news for a specific geographic node and transport mode.
        """
        location = location.strip() if location else location
        normalized_mode = transport_mode.strip().lower()
        mode_terms = {
            "sea": "maritime",
            "air": "aviation cargo",
            "road": "highway",
            "rail": "rail freight",
        }
        query_mode = mode_terms.get(normalized_mode, normalized_mode)
        query = f"{location} {query_mode} logistics disruption"
        
        # 1. Check Cache
        now = time.time()
        if query in self.cache:
            ts, content = self.cache[query]
            if now - ts < self.cache_ttl:
                print(f"[TRACE] News cache used: location={location} mode={normalized_mode}")
                return content

        # 2. Live Ingestion (Google News RSS)
        t_start = time.perf_counter()
        print(f"[TRACE] STEP 7: News fetch started: location={location} mode={normalized_mode}")
        try:
            encoded_query = urllib.parse.quote(query)
            rss_url = f"https://news.google.com/rss/search?q={encoded_query}&hl=en-US&gl=US&ceid=US:en"
            
            with urllib.request.urlopen(rss_url, timeout=2.0) as response:
                feed = feedparser.parse(response)
            
            if feed.entries:
                top_headlines = [entry.title for entry in feed.entries[:3]]
                content = " | ".join(top_headlines)
                self.cache[query] = (now, content)
                print(
                    f"[TRACE] STEP 8: News fetched: location={location} "
                    f"mode={normalized_mode} headlines={len(top_headlines)} "
                    f"duration={time.perf_counter()-t_start:.4f}s"
                )
                return content

            print(f"[TRACE] STEP 8: News fallback used: location={location} mode={normalized_mode}")
            return self.fallback_news.get(normalized_mode, "Normal operational conditions reported.")
            
        except Exception as e:
            print(f"[TRACE] News fetch failed: location={location} mode={normalized_mode} error={e}")
            
        # 3. Defensive Fallback
        print(f"[TRACE] STEP 8: News fallback used: location={location} mode={normalized_mode}")
        return self.fallback_news.get(normalized_mode, "Normal operational conditions reported.")
