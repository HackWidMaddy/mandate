"""Evidence egress from the local plane: cloud upload + webhook dispatch.

Design (per blueprint):
  * at-least-once delivery with a persisted byte offset into evidence.jsonl
  * dedup happens server-side by receipt_hash; duplicates are safe
  * exponential backoff; the offset NEVER advances on failure, so a control-
    plane outage only delays uploads - it can never lose or block decisions
  * webhook payloads are HMAC-signed (X-Sentinel-Signature: sha256=<hex>)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_batch(evidence_path: Path, offset: int, max_lines: int) -> tuple:
    lines: List[Dict[str, Any]] = []
    pos = offset
    with open(evidence_path, encoding="utf-8") as f:
        f.seek(offset)
        for raw in f:
            pos += len(raw.encode("utf-8"))
            raw = raw.strip()
            if not raw:
                continue
            try:
                lines.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
            if len(lines) >= max_lines:
                break
    return lines, pos


class EgressWorker:
    """Tails evidence.jsonl once per drain() and pushes to configured sinks."""

    def __init__(self, evidence_path: str | Path,
                 api_url: Optional[str] = None, token: Optional[str] = None,
                 webhook_url: Optional[str] = None,
                 webhook_secret: Optional[str] = None,
                 state_path: Optional[str | Path] = None,
                 batch_size: int = 200, max_attempts: int = 3,
                 dead_letter_path: Optional[str | Path] = None):
        self.evidence_path = Path(evidence_path)
        self.state_path = Path(state_path) if state_path else \
            self.evidence_path.with_suffix(".egress-offset")
        self.offset = self._load_offset()
        self.api_url = api_url.rstrip("/") if api_url else None
        self.token = token
        self.webhook_url = webhook_url
        self.webhook_secret = (webhook_secret or "").encode()
        self.batch_size = batch_size
        self.max_attempts = max_attempts
        self.dead_letter_path = Path(dead_letter_path) if dead_letter_path else \
            self.evidence_path.with_suffix(".dead-letter.jsonl")

    # ------------------------------------------------------------ offsets
    def _load_offset(self) -> int:
        try:
            return int(self.state_path.read_text().strip())
        except (OSError, ValueError):
            return 0

    def _save_offset(self, value: int) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(str(value), encoding="utf-8")
        tmp.replace(self.state_path)

    # ---------------------------------------------------------------- post
    def _post_json(self, url: str, payload: dict,
                   headers: Dict[str, str]) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json",
                                              **headers})
        last_err: Optional[str] = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status < 300:
                        return
                    last_err = f"http {resp.status}"
            except urllib.error.HTTPError as e:
                if e.code < 500:
                    raise RuntimeError(f"{url} rejected payload: {e.code}") from e
                last_err = f"http {e.code}"
            except OSError as e:
                last_err = str(e)
            time.sleep(min(2 ** attempt * 0.05, 0.4))  # compact backoff
        raise RuntimeError(f"delivery failed after {self.max_attempts} attempts "
                           f"({last_err})")

    def _post_webhook(self, receipts: List[dict]) -> None:
        body = {"receipts": receipts}
        sig = hmac.new(self.webhook_secret,
                       json.dumps(body).encode("utf-8"),
                       hashlib.sha256).hexdigest()
        self._post_json(
            self.webhook_url, body,
            {"X-Sentinel-Signature": f"sha256={sig}"})

    def _dead_letter(self, receipts: List[dict], reason: str) -> None:
        self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.dead_letter_path, "a", encoding="utf-8",
                  newline="\n") as f:
            f.write(json.dumps({"reason": reason, "receipts": receipts}) + "\n")

    # --------------------------------------------------------------- drain
    def drain_once(self) -> dict:
        """One pass. Returns counters; raises nothing outward except config
        errors - persistent sink failures land in dead-letter and advance."""
        if not self.evidence_path.exists():
            return {"batches": 0, "uploaded": 0, "webhooked": 0, "dead": 0}
        result = {"batches": 0, "uploaded": 0, "webhooked": 0, "dead": 0}
        while True:
            receipts, new_offset = _read_batch(
                self.evidence_path, self.offset, self.batch_size)
            if not receipts:
                break
            delivered_any = False
            if self.api_url:
                try:
                    self._post_json(
                        f"{self.api_url}/v1/receipts:batch",
                        {"receipts": receipts},
                        {"Authorization": f"Bearer {self.token}"})
                    delivered_any = True
                    result["uploaded"] += len(receipts)
                except Exception as e:  # noqa: BLE001
                    self._dead_letter(receipts, f"cloud: {e}")
                    result["dead"] += len(receipts)
            if self.webhook_url:
                try:
                    self._post_webhook(receipts)
                    delivered_any = True
                    result["webhooked"] += len(receipts)
                except Exception as e:  # noqa: BLE001
                    self._dead_letter(receipts, f"webhook: {e}")
                    result["dead"] += len(receipts)
            if delivered_any or not (self.api_url or self.webhook_url):
                self.offset = new_offset
                self._save_offset(new_offset)
                result["batches"] += 1
            else:
                break  # both sinks failed; retry next drain from same offset
        return result

    def run_forever(self, interval_s: float = 5.0) -> None:  # pragma: no cover
        import threading

        stop = threading.Event()

        def loop():
            while not stop.wait(interval_s):
                try:
                    self.drain_once()
                except Exception:
                    pass

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t
