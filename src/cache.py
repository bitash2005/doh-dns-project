import time
import threading
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Union

from dnslib import DNSRecord


@dataclass
class CacheItem:
    value: bytes
    expires_at: float


class DNSCache:
    """
    Cache ساده برای DNS responses (bytes)
    - کلید: (qname_lower_with_dot, qtype_int)
    - TTL: از پاسخ DNS (min TTL در Answer ها) استخراج می‌شود
    - اگر Answer نداشت => default_ttl
    """

    def __init__(self, default_ttl: int = 60, max_items: int = 5000):
        self.default_ttl = int(default_ttl)
        self.max_items = int(max_items)

        self._lock = threading.Lock()
        self._data: Dict[Tuple[str, int], CacheItem] = {}

    def _norm(self, name: str) -> str:
        n = name.strip().lower()
        return n if n.endswith(".") else n + "."

    def _now(self) -> float:
        return time.time()

    def _prune_expired_nolock(self) -> None:
        now = self._now()
        expired = [k for k, v in self._data.items() if v.expires_at <= now]
        for k in expired:
            del self._data[k]

    def _enforce_limit_nolock(self) -> None:
        # حذف ساده: اول expired، بعد اگر زیاد بود چندتا رو حذف کن
        self._prune_expired_nolock()
        if len(self._data) <= self.max_items:
            return
        # حذف قدیمی‌ترین‌ها
        items = sorted(self._data.items(), key=lambda kv: kv[1].expires_at)
        for k, _ in items[: max(0, len(self._data) - self.max_items)]:
            self._data.pop(k, None)

    def stats(self) -> dict:
        with self._lock:
            now = self._now()
            alive = sum(1 for v in self._data.values() if v.expires_at > now)
            return {"items_total": len(self._data), "items_alive": alive}

    def get(self, qname: str, qtype_int: int) -> Optional[bytes]:
        key = (self._norm(qname), int(qtype_int))
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            if item.expires_at <= self._now():
                # expire شده
                self._data.pop(key, None)
                return None
            return item.value

    def set(self, qname: str, qtype_int: int, resp_bytes: Union[bytes, bytearray], ttl: Optional[int] = None) -> None:
        if not resp_bytes:
            return
        ttl_use = self.default_ttl if ttl is None else max(0, int(ttl))
        key = (self._norm(qname), int(qtype_int))
        with self._lock:
            self._data[key] = CacheItem(value=bytes(resp_bytes), expires_at=self._now() + ttl_use)
            self._enforce_limit_nolock()

    def set_from_response(self, qname: str, qtype_int: int, resp_bytes: Union[bytes, bytearray]) -> None:
        """
        TTL را از DNS response استخراج می‌کند:
        - اگر Answer وجود داشت => min TTL در rr ها
        - اگر Answer خالی بود => default_ttl
        """
        if not resp_bytes:
            return

        ttl_use = self.default_ttl
        try:
            r = DNSRecord.parse(bytes(resp_bytes))
            if r.rr:
                ttls = [rr.ttl for rr in r.rr if hasattr(rr, "ttl")]
                if ttls:
                    ttl_use = max(0, int(min(ttls)))
        except Exception:
            ttl_use = self.default_ttl

        self.set(qname, qtype_int, resp_bytes, ttl=ttl_use)
