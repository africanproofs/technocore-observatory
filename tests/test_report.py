"""Offline tests for observatory.report and observatory.collect.duplicates.

No network, no technocore-mcp client instantiation — everything here is
plain dicts and a tiny stub object.
"""

from __future__ import annotations

from observatory import collect, report


def _fake_summary(tripwire: list[str]) -> dict:
    return {
        "date": "2026-08-27",
        "generated_at": "2026-08-27T00:00:00+00:00",
        "census": {
            "rooms_shown": 12,
            "engagement": {"messages_last_hour": 340},
            "total_last_seq": 98765,
            "top_rooms": [{"name": "lobby", "last_seq": 4321, "topic": "general"}],
        },
        "duplicates": {
            "room": "lobby",
            "sample": 200,
            "distinct_texts": 150,
            "duplicate_share": 0.25,
            "distinct_authors": 40,
            "top_templates": [{"text": "gm agents", "count": 12}],
        },
        "api": {
            "paths_total": 9,
            "added": ["/faucet/claim"] if tripwire else [],
            "removed": [],
            "tripwire": tripwire,
            "llms_changed": False,
            "baseline_created": False,
        },
        "health": {"healthz_ms": 42, "healthz_status": 200, "read_ms": 55},
    }


def test_render_report_shows_faucet_tripwire() -> None:
    summary = _fake_summary(tripwire=["/faucet/claim"])
    text = report.render_report(summary)
    assert "FAUCET-PATTERN" in text


def test_render_report_no_tripwire_no_faucet_line() -> None:
    summary = _fake_summary(tripwire=[])
    text = report.render_report(summary)
    assert "FAUCET-PATTERN" not in text


def test_render_digest_one_line_within_cap_and_has_date_and_tripwire() -> None:
    summary = _fake_summary(tripwire=["/faucet/claim"])
    digest = report.render_digest(summary)
    assert "\n" not in digest
    assert len(digest) <= 900
    assert summary["date"] in digest
    assert "FAUCET-PATTERN" in digest


def test_render_digest_no_tripwire_omits_faucet_pattern() -> None:
    summary = _fake_summary(tripwire=[])
    digest = report.render_digest(summary)
    assert "FAUCET-PATTERN" not in digest
    assert len(digest) <= 900


class _FakeClient:
    """Minimal stand-in for TechnocoreClient.read_room, nothing else."""

    def __init__(self, messages: list[dict]):
        self._messages = messages

    def read_room(self, room: str, since: int = 0, limit: int = 200) -> list[dict]:
        return self._messages


def test_duplicates_computes_share_and_top_templates() -> None:
    messages = [
        {"seq": 1, "ts": 1, "from": "a", "text": "gm agents"},
        {"seq": 2, "ts": 2, "from": "b", "text": "gm agents"},
        {"seq": 3, "ts": 3, "from": "c", "text": "gm agents"},
        {"seq": 4, "ts": 4, "from": "d", "text": "unique one"},
        {"seq": 5, "ts": 5, "from": "e", "text": "unique two"},
        {"seq": 6, "ts": 6, "from": "f", "text": "unique three"},
    ]
    client = _FakeClient(messages)
    result = collect.duplicates(client, room="lobby", sample=200)

    assert result["sample"] == 6
    assert result["distinct_texts"] == 4
    # 1 - 4/6 = 0.333...
    assert result["duplicate_share"] == round(1 - 4 / 6, 3)
    assert result["distinct_authors"] == 6

    templates = {t["text"]: t["count"] for t in result["top_templates"]}
    assert templates.get("gm agents") == 3
