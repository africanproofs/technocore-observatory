"""Collectors: each takes a `TechnocoreClient` and returns a plain dict.

Every collector is tolerant of shape drift in technocore.chat's JSON — the
service is a live, evolving third-party API and these functions must not
raise on an unexpected (but plausible) payload shape. They raise only
`TechnocoreError` (network/HTTP failures), which callers in `cli.py` catch.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from technocore_mcp.client import TechnocoreClient

# ---- module constants -----------------------------------------------------

DEFAULT_CENSUS_LIMIT = 100
DEFAULT_DUP_ROOM = "lobby"
DEFAULT_DUP_SAMPLE = 200
TOP_ROOMS_N = 10
TOP_TEMPLATES_N = 5
TOP_TEMPLATE_MIN_COUNT = 2
TEMPLATE_TEXT_CHARS = 80
HEALTH_READ_ROOM = "lobby"
HEALTH_READ_LIMIT = 5

TRIPWIRE_RE = re.compile(r"faucet|testnet|airdrop|mint|claim|token|wallet", re.I)


def census(client: TechnocoreClient) -> dict:
    """Room census + engagement rollup from `/rooms`."""
    data = client.rooms_overview(limit=DEFAULT_CENSUS_LIMIT)

    if isinstance(data, dict):
        rooms = data.get("rooms") or []
        engagement = data.get("engagement")
    elif isinstance(data, list):
        rooms = data
        engagement = None
    else:
        rooms = []
        engagement = None

    rooms = [r for r in rooms if isinstance(r, dict)]

    def _last_seq(r: dict) -> int:
        try:
            return int(r.get("last_seq") or 0)
        except (TypeError, ValueError):
            return 0

    total_last_seq = sum(_last_seq(r) for r in rooms)
    top = sorted(rooms, key=_last_seq, reverse=True)[:TOP_ROOMS_N]
    top_rooms = [
        {"name": r.get("room") or r.get("name"), "last_seq": r.get("last_seq"), "topic": r.get("topic")}
        for r in top
    ]

    return {
        "rooms_shown": len(rooms),
        "engagement": engagement,
        "total_last_seq": total_last_seq,
        "top_rooms": top_rooms,
    }


def duplicates(client: TechnocoreClient, room: str = DEFAULT_DUP_ROOM, sample: int = DEFAULT_DUP_SAMPLE) -> dict:
    """Duplicate-share sample over a room's visible tail."""
    messages = client.read_room(room, since=0, limit=sample)
    if not isinstance(messages, list):
        messages = []

    texts: list[str] = []
    authors: set[object] = set()
    for m in messages:
        if not isinstance(m, dict):
            continue
        texts.append(str(m.get("text") or "").strip())
        frm = m.get("from")
        if frm is not None:
            authors.add(frm)

    n = len(texts)
    distinct_texts = len(set(texts))
    duplicate_share = 0.0 if n == 0 else 1 - (distinct_texts / n)

    counts = Counter(texts)
    top_templates = [
        {"text": text[:TEMPLATE_TEXT_CHARS], "count": count}
        for text, count in counts.most_common()
        if count >= TOP_TEMPLATE_MIN_COUNT
    ][:TOP_TEMPLATES_N]

    return {
        "room": room,
        "sample": n,
        "distinct_texts": distinct_texts,
        "duplicate_share": round(duplicate_share, 3),
        "distinct_authors": len(authors),
        "top_templates": top_templates,
    }


def api_surface(client: TechnocoreClient, baseline_path: Path) -> dict:
    """Diff the current `/openapi.json` path set + `/llms.txt` hash against a
    committed baseline file, then overwrite the baseline with the current
    state (so tomorrow's diff is against today)."""
    openapi_text = client.fetch_doc("openapi.json")
    try:
        openapi = json.loads(openapi_text)
    except ValueError:
        openapi = {}
    paths = sorted((openapi.get("paths") or {}).keys()) if isinstance(openapi, dict) else []

    llms = client.fetch_doc("llms.txt")
    llms_sha256 = hashlib.sha256(llms.encode("utf-8")).hexdigest()

    baseline_created = not baseline_path.exists()
    baseline: dict = {}
    if not baseline_created:
        try:
            baseline = json.loads(baseline_path.read_text())
        except (ValueError, OSError):
            baseline = {}

    baseline_paths = set(baseline.get("paths") or [])
    added = sorted(p for p in paths if p not in baseline_paths)
    removed = sorted(p for p in baseline_paths if p not in paths)
    tripwire = [p for p in added if TRIPWIRE_RE.search(p)]
    llms_changed = False if baseline_created else (baseline.get("llms_sha256") != llms_sha256)

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(
            {
                "paths": paths,
                "llms_sha256": llms_sha256,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=1,
        )
    )

    return {
        "paths_total": len(paths),
        "added": added,
        "removed": removed,
        "tripwire": tripwire,
        "llms_changed": llms_changed,
        "baseline_created": baseline_created,
    }


def health(client: TechnocoreClient) -> dict:
    """healthz latency/status + a real read-latency probe."""
    result: dict = {"healthz_ms": None, "healthz_status": None, "read_ms": None}
    errors: list[str] = []

    try:
        h = client.health()
        result["healthz_ms"] = h["latency_ms"]
        result["healthz_status"] = h["status"]
    except Exception as e:  # noqa: BLE001 - deliberately broad, this is a probe
        errors.append(str(e))

    try:
        started = time.monotonic()
        client.read_room(HEALTH_READ_ROOM, limit=HEALTH_READ_LIMIT)
        result["read_ms"] = int((time.monotonic() - started) * 1000)
    except Exception as e:  # noqa: BLE001 - deliberately broad, this is a probe
        errors.append(str(e))

    if errors:
        result["error"] = "; ".join(errors)
    return result
