"""
V3AuditLogger - redacted（V3redacted）
redacted ASF-BGT AuditLogger redacted
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional


class V3AuditLogger:
    """
    V3 redacted
    redacted：log(event, session_id, data)
    """

    def __init__(self, file_path: Optional[str] = None):
        self.records: List[Dict[str, Any]] = []
        self.file_path = file_path
        self._last_hash = "0" * 64

    def log(self, event: str, session_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """redacted"""
        ts = time.time()
        # Explicit annotation: without it mypy infers dict[str, object] from the
        # mixed value types and then rejects assigning record_hash into
        # self._last_hash (declared str).
        record: Dict[str, Any] = {
            "record_id": f"rec_{uuid.uuid4().hex[:12]}",
            "event": event,
            "session_id": session_id,
            "data": data,
            "timestamp": ts,
            "previous_hash": self._last_hash,
        }
        record["record_hash"] = self._compute_hash(record)
        self.records.append(record)
        self._last_hash = record["record_hash"]
        return record

    def _compute_hash(self, record: Dict[str, Any]) -> str:
        """redacted（redacted）"""
        h = {
            "record_id": record["record_id"],
            "event": record["event"],
            "session_id": record["session_id"],
            "data": json.dumps(record["data"], sort_keys=True, ensure_ascii=False),
            "timestamp": record["timestamp"],
            "previous_hash": record["previous_hash"],
        }
        return hashlib.sha256(json.dumps(h, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def get_records(self) -> List[Dict[str, Any]]:
        return self.records

    def export_chain(self) -> List[Dict[str, Any]]:
        """redacted"""
        return self.records

    def summary(self) -> Dict[str, Any]:
        return {
            "total_records": len(self.records),
            "events": list(set(r["event"] for r in self.records)),
        }

    def verify_chain(self) -> bool:
        """redacted：redacted **redacted** redacted。

        redacted ``previous_hash`` redacted，redacted ``record_hash``，
        redacted ``data`` redacted True —— redacted。
        redacted。
        """
        for i, record in enumerate(self.records):
            expected_previous = "0" * 64 if i == 0 else self.records[i - 1]["record_hash"]
            if record["previous_hash"] != expected_previous:
                return False
            # redacted：redacted，redacted。
            if self._compute_hash(record) != record["record_hash"]:
                return False
        return True
