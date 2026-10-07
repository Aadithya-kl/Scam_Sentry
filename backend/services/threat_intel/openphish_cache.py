import asyncio
import time
import httpx
import logging
from typing import Set, Dict, Optional

logger = logging.getLogger("scamsentry")

class OpenPhishCache:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OpenPhishCache, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self):
        if self.initialized:
            return
        self.feed_urls: Set[str] = set()
        self.last_refresh: float = 0.0
        self.status = "UNAVAILABLE" # UNAVAILABLE, READY, FEED_REFRESHING
        # The lock is created lazily on the running event loop. Creating it at
        # import time can bind it to a different loop (e.g. TestClient's portal).
        self._lock: Optional[asyncio.Lock] = None
        self._task: Optional[asyncio.Task] = None
        self.refresh_interval = 3600 # 1 hour
        self.initialized = True

    @property
    def lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def start(self) -> asyncio.Task:
        """Start the background fetch + periodic refresh loop (non-blocking).

        Returns the owned task so the caller's lifespan can cancel it on shutdown.
        Calling start() twice while running is a no-op.
        """
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="openphish-refresh")
        return self._task

    async def shutdown(self) -> None:
        """Cancel the background task and wait for it to finish. Idempotent."""
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        # Drop the loop-bound lock so a later loop (next TestClient) gets a fresh one.
        self._lock = None

    async def initialize(self):
        """Backward-compatible entrypoint: fetch once, then keep refreshing."""
        await self._run()

    async def _run(self):
        await self.refresh_feed()
        while True:
            await asyncio.sleep(self.refresh_interval)
            await self.refresh_feed()

    async def refresh_feed(self):
        async with self.lock:
            prev_status = self.status
            self.status = "FEED_REFRESHING"
            logger.info("[OPENPHISH] Fetching community feed...")
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ScamSentry/1.0"}
                async with httpx.AsyncClient(timeout=10.0, headers=headers, follow_redirects=True) as client:
                    resp = await client.get("https://openphish.com/feed.txt")
                    if resp.status_code == 200:
                        lines = resp.text.splitlines()
                        self.feed_urls = set(line.strip() for line in lines if line.strip())
                        self.last_refresh = time.time()
                        self.status = "READY"
                        logger.info(f"[OPENPHISH] Feed loaded with {len(self.feed_urls)} URLs.")
                    else:
                        logger.error(f"[OPENPHISH] Failed to fetch feed: HTTP {resp.status_code}")
                        self.status = prev_status if self.feed_urls else "UNAVAILABLE"
            except asyncio.CancelledError:
                # Shutdown during a fetch: restore a truthful status and propagate.
                self.status = "READY" if self.feed_urls else "UNAVAILABLE"
                raise
            except Exception as e:
                logger.error(f"[OPENPHISH] Failed to fetch feed: {type(e).__name__}")
                self.status = prev_status if self.feed_urls else "UNAVAILABLE"

    def check_url(self, url: str) -> bool:
        return url in self.feed_urls

    def get_health(self) -> Dict:
        now = time.time()
        age_minutes = int((now - self.last_refresh) / 60) if self.last_refresh > 0 else 0
        
        status = self.status
        if status == "READY" and age_minutes > 120:
            status = "STALE"
            
        return {
            "status": status,
            "cache_loaded": len(self.feed_urls) > 0,
            "feed_age_minutes": age_minutes,
            "url_count": len(self.feed_urls)
        }

openphish_cache = OpenPhishCache()
