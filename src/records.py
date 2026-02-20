from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Any


SUPPORTED_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR"}


@dataclass
class Record:
    rtype: str        # "A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR"
    value: str        # IP یا target یا text
    ttl: int = 60
    priority: int = 10  # فقط برای MX


class RecordStore:
    def __init__(self):
        # کلید: (name_lower_with_dot, rtype)  مقدار: لیست Record
        self._data: Dict[Tuple[str, str], List[Record]] = {}

    # -----------------------------
    # CRUD
    # -----------------------------
    def add(self, name: str, rtype: str, value: str, ttl: int = 60, priority: int = 10):
        rtype_u = (rtype or "").upper().strip()
        if rtype_u not in SUPPORTED_TYPES:
            raise ValueError(f"Unsupported record type: {rtype_u}")

        if not name or not str(name).strip():
            raise ValueError("Record name (domain) cannot be empty")

        if value is None or not str(value).strip():
            raise ValueError("Record value cannot be empty")

        ttl_i = int(ttl)
        if ttl_i <= 0:
            raise ValueError("TTL must be a positive integer")

        pr_i = int(priority)
        if rtype_u == "MX" and pr_i < 0:
            raise ValueError("MX priority must be >= 0")

        key = (self._norm(name), rtype_u)
        rec = Record(rtype=rtype_u, value=str(value).strip(), ttl=ttl_i, priority=pr_i)
        self._data.setdefault(key, []).append(rec)

    def delete(self, name: str, rtype: Optional[str] = None) -> int:
        """
        اگر rtype=None باشد همه رکوردهای آن نام را حذف می‌کند.
        خروجی: تعداد آیتم حذف شده
        """
        name_n = self._norm(name)

        if rtype is None:
            # حذف همه typeها برای این name
            keys = [k for k in list(self._data.keys()) if k[0] == name_n]
            removed = 0
            for k in keys:
                removed += len(self._data.get(k, []))
                self._data.pop(k, None)
            return removed

        rtype_u = (rtype or "").upper().strip()
        if rtype_u not in SUPPORTED_TYPES:
            # اگر نوع نامعتبر بود، چیزی حذف نمی‌کنیم
            return 0

        key = (name_n, rtype_u)
        removed = len(self._data.get(key, []))
        self._data.pop(key, None)
        return removed

    def lookup(self, name: str, rtype: str) -> List[Record]:
        rtype_u = (rtype or "").upper().strip()
        if rtype_u not in SUPPORTED_TYPES:
            return []
        return self._data.get((self._norm(name), rtype_u), [])

    # -----------------------------
    # For UI / Admin
    # -----------------------------
    def list_all(self) -> List[Dict[str, Any]]:
        """
        خروجی مناسب UI:
        [
          {"domain": "test.local.", "type": "A", "value": "10.0.0.1", "ttl": 60, "priority": None},
          ...
        ]
        """
        out: List[Dict[str, Any]] = []
        for (domain, rtype), recs in self._data.items():
            for r in recs:
                out.append({
                    "domain": domain,
                    "type": rtype,
                    "value": r.value,
                    "ttl": r.ttl,
                    "priority": r.priority if rtype == "MX" else None
                })

        out.sort(key=lambda x: (x["domain"], x["type"], str(x["value"])))
        return out

    def get_types_for_name(self, name: str) -> List[str]:
        """
        اختیاری: برای دیباگ/نمایش در UI
        """
        name_n = self._norm(name)
        types = sorted({rtype for (n, rtype) in self._data.keys() if n == name_n})
        return types

    # -----------------------------
    # Helpers
    # -----------------------------
    def _norm(self, name: str) -> str:
        n = str(name).strip().lower()
        return n if n.endswith(".") else n + "."
