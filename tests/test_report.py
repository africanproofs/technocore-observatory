"""Offline tests for observatory.report and observatory.collect.duplicates.

No network, no technocore-mcp client instantiation — everything here is
plain dicts and a tiny stub object.
"""

from __future__ import annotations

import pytest

from observatory import collect, report

# A stand-in commit SHA. render_digest/render_note now REQUIRE a sha (FIX 1:
# never a mutable `blob/master` link) -- production always resolves a real
# one via `observatory.cli.resolve_pushed_commit` before calling either.
_SHA = "a" * 40


def _fake_read_cap() -> dict:
    return {
        "room": "lobby",
        "probes": [{"requested": 50, "returned": 50}, {"requested": 1000, "returned": 200}],
        "observed_cap": 200,
        "room_last_seq": 50_000,
        "openapi_declared_max": 200,
        "openapi_probe_status": collect.OPENAPI_STATUS_DECLARED,
        "cap_demonstrated": True,
        "evidence": "cap declared in the service's OpenAPI (limit maximum) and confirmed by probes",
        "monotonic": True,
    }


def _fake_sequence_continuity() -> dict:
    return {
        "room": "lobby",
        "first_visible_seq": 100,
        "last_visible_seq": 300,
        "visible_count": 190,
        "span": 201,
        "missing_in_span": 11,
        "gaps": [{"after": 150, "before": 160, "missing": 9}],
        "room_last_seq": 50_000,
        "history_before_window": 99,
    }


def _fake_signature_retention() -> dict:
    return {
        "room": "lobby",
        "sample": 50,
        "signed_lane_records": 10,
        "unsigned_lane_records": 40,
        "observed_top_level_keys": ["from", "sig", "text"],
        "search_truncated": False,
        "signature_field": "sig",
        "signature_path": "sig",
        "signatures_exposed": 8,
        "signed_lane_with_signature": 8,
        "empty_signature_fields": 0,
        "offline_verified": 7,
        "offline_failed": 0,
        "offline_unverifiable": 1,
        "unverifiable_reasons": ["missing or invalid nonce"],
        "verdict": "signatures exposed; some could not be checked",
    }


def _fake_summary(tripwire: list[str], **overrides: dict) -> dict:
    summary = {
        "date": "2026-08-27",
        "generated_at": "2026-08-27T00:00:00+00:00",
        "census": {
            "rooms_shown": 12,
            "rooms_shown_limit": 100,
            "rooms_total": 37_320,
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
        "read_cap": _fake_read_cap(),
        "sequence_continuity": _fake_sequence_continuity(),
        "signature_retention": _fake_signature_retention(),
    }
    summary.update(overrides)
    return summary


def test_render_report_shows_tripwire_keyword_match() -> None:
    summary = _fake_summary(tripwire=["/faucet/claim"])
    text = report.render_report(summary)
    assert "Observed keyword match on a newly seen API path" in text
    assert "/faucet/claim" in text


def test_render_report_no_tripwire_no_keyword_match_line() -> None:
    summary = _fake_summary(tripwire=[])
    text = report.render_report(summary)
    assert "Observed keyword match on a newly seen API path" not in text


def test_render_digest_one_line_within_cap_and_has_date_and_tripwire() -> None:
    summary = _fake_summary(tripwire=["/faucet/claim"])
    digest = report.render_digest(summary, _SHA)
    assert "\n" not in digest
    assert len(digest) <= 900
    assert summary["date"] in digest
    assert "new-path keyword match" in digest
    assert "/faucet/claim" in digest


def test_render_digest_no_tripwire_omits_keyword_match_note() -> None:
    summary = _fake_summary(tripwire=[])
    digest = report.render_digest(summary, _SHA)
    assert "new-path keyword match" not in digest
    assert len(digest) <= 900


def test_render_digest_uses_the_exact_sha_in_the_permalink_not_master() -> None:
    # FIX 1: the digest must link to an immutable commit, never the mutable
    # `blob/master`.
    summary = _fake_summary(tripwire=[])
    digest = report.render_digest(summary, _SHA)
    assert f"/blob/{_SHA}/reports/{summary['date']}.md" in digest
    assert "/blob/master/" not in digest


def test_render_digest_includes_the_three_new_clauses_when_measurements_succeed() -> None:
    summary = _fake_summary(tripwire=[])
    digest = report.render_digest(summary, _SHA)

    assert "read-cap=200" in digest
    assert "seq-gaps=11" in digest
    assert "sig-check=8/10" in digest


def test_render_digest_omits_cap_clause_on_read_cap_error() -> None:
    summary = _fake_summary(tripwire=[], read_cap={"error": "boom"})
    digest = report.render_digest(summary, _SHA)

    assert "read-cap=" not in digest
    # the other two new clauses are unaffected by read_cap's failure
    assert "seq-gaps=" in digest
    assert "sig-check=" in digest
    assert "\n" not in digest
    assert len(digest) <= 900


def test_render_digest_omits_continuity_clause_on_note() -> None:
    seq = dict(_fake_sequence_continuity())
    seq["note"] = "non-integer sequence values"
    summary = _fake_summary(tripwire=[], sequence_continuity=seq)
    digest = report.render_digest(summary, _SHA)

    assert "seq-gaps=" not in digest
    assert "read-cap=" in digest
    assert "sig-check=" in digest


def test_render_digest_omits_continuity_clause_on_error() -> None:
    summary = _fake_summary(tripwire=[], sequence_continuity={"error": "boom"})
    digest = report.render_digest(summary, _SHA)
    assert "seq-gaps=" not in digest


def test_render_digest_omits_signature_clause_when_no_signed_lane_records() -> None:
    sig = dict(_fake_signature_retention())
    sig["signed_lane_records"] = 0
    summary = _fake_summary(tripwire=[], signature_retention=sig)
    digest = report.render_digest(summary, _SHA)

    assert "sig-check=" not in digest
    assert "read-cap=" in digest
    assert "seq-gaps=" in digest


def test_render_digest_omits_signature_clause_on_error() -> None:
    summary = _fake_summary(tripwire=[], signature_retention={"error": "boom"})
    digest = report.render_digest(summary, _SHA)
    assert "sig-check=" not in digest


def test_render_digest_omits_signature_clause_when_search_truncated() -> None:
    # FIX 5a: a truncated search cannot support a "no field found" claim, so
    # the sig-check clause is omitted entirely rather than published as if
    # the sample had been fully examined.
    sig = dict(_fake_signature_retention())
    sig["search_truncated"] = True
    summary = _fake_summary(tripwire=[], signature_retention=sig)
    digest = report.render_digest(summary, _SHA)
    assert "sig-check=" not in digest


def test_render_digest_all_new_clauses_omitted_still_renders_old_fields_only() -> None:
    summary = _fake_summary(
        tripwire=[],
        read_cap={"error": "boom"},
        sequence_continuity={"error": "boom"},
        signature_retention={"error": "boom"},
    )
    digest = report.render_digest(summary, _SHA)

    assert "read-cap=" not in digest
    assert "seq-gaps=" not in digest
    assert "sig-check=" not in digest
    # old fields are untouched by the new collectors all failing
    assert "rooms-shown=12 (limit 100)" in digest
    assert "dup-share=25.0%" in digest
    assert "\n" not in digest
    assert len(digest) <= 900


# ---- FIX C: too-long digest/note fails, never truncates -------------------


def test_render_digest_raises_instead_of_truncating_when_over_cap() -> None:
    # A pile of long "new path" tripwire matches easily blows past
    # DIGEST_MAX_CHARS (900) -- FIX C: this must never silently truncate
    # (which could cut into the permalink or attribution footer at the end
    # of the string); it must raise instead.
    huge_tripwire = [f"/faucet/claim/very-long-suspicious-path-segment-{i:04d}" for i in range(40)]
    summary = _fake_summary(tripwire=huge_tripwire)

    with pytest.raises(report.PublicationTooLongError):
        report.render_digest(summary, _SHA)


def test_render_note_raises_instead_of_truncating_when_over_cap() -> None:
    huge_tripwire = [f"/faucet/claim/very-long-suspicious-path-segment-{i:04d}" for i in range(120)]
    summary = _fake_summary(tripwire=huge_tripwire)

    with pytest.raises(report.PublicationTooLongError):
        report.render_note(summary, _SHA)


def test_render_digest_within_cap_does_not_raise() -> None:
    summary = _fake_summary(tripwire=["/faucet/claim"])
    digest = report.render_digest(summary, _SHA)
    assert len(digest) <= report.DIGEST_MAX_CHARS
    assert "…" not in digest


# ---- FIX F: wording provable from what the code actually measures --------


def test_report_total_last_seq_does_not_overclaim_volume_or_totality() -> None:
    summary = _fake_summary(tripwire=[])
    text = report.render_report(summary)
    assert "message volume proxy" not in text
    assert "high-water mark" in text
    assert "NOT retained message volume" in text
    assert "sum of last_seq across the" in text


def test_report_baseline_established_says_next_successful_run_not_tomorrow() -> None:
    summary = _fake_summary(
        tripwire=[],
        api={
            "paths_total": 5,
            "added": [],
            "removed": [],
            "tripwire": [],
            "llms_changed": False,
            "baseline_created": True,
        },
    )
    text = report.render_report(summary)
    assert "diffs begin tomorrow" not in text
    assert "diffs begin with the next successful run" in text


def test_report_llms_changed_says_no_prior_baseline_on_first_run() -> None:
    summary = _fake_summary(
        tripwire=[],
        api={
            "paths_total": 5,
            "added": [],
            "removed": [],
            "tripwire": [],
            "llms_changed": False,
            "baseline_created": True,
        },
    )
    text = report.render_report(summary)
    assert "llms.txt changed: no prior baseline" in text
    assert "llms.txt changed: no\n" not in text


def test_report_llms_changed_renders_yes_no_on_a_real_comparison() -> None:
    summary = _fake_summary(
        tripwire=[],
        api={
            "paths_total": 5,
            "added": [],
            "removed": [],
            "tripwire": [],
            "llms_changed": False,
            "baseline_created": False,
        },
    )
    text = report.render_report(summary)
    assert "llms.txt changed: no" in text
    assert "no prior baseline" not in text


def test_render_digest_totally_empty_summary_does_not_imply_measurements() -> None:
    digest = report.render_digest({"date": "2026-08-27"}, _SHA)
    assert "2026-08-27" in digest
    assert "no measurements available" in digest
    assert "\n" not in digest


def test_cap_clause_never_uses_room_last_seq_as_evidence_text() -> None:
    # Regression for FINDING 2: even a huge room_last_seq with no OpenAPI
    # declared max must not be rendered as a demonstrated cap.
    rc = dict(_fake_read_cap())
    rc["cap_demonstrated"] = False
    rc["openapi_declared_max"] = None
    rc["openapi_probe_status"] = collect.OPENAPI_STATUS_NO_MAXIMUM
    rc["evidence"] = "probes returned at most 200 records but the service publishes no limit maximum"
    summary = _fake_summary(tripwire=[], read_cap=rc)
    digest = report.render_digest(summary, _SHA)

    assert "read-cap=200 (undemonstrated)" in digest


def test_cap_clause_recomputes_cap_demonstrated_rather_than_trusting_stored_bool() -> None:
    # FIX 4c: a HAND-EDITED/stale `cap_demonstrated=True` sitting next to a
    # probe trace that doesn't actually support it must never be trusted by
    # the renderer.
    rc = dict(_fake_read_cap())
    rc["cap_demonstrated"] = True  # lies: the raw trace below doesn't support this
    rc["openapi_probe_status"] = collect.OPENAPI_STATUS_NO_MAXIMUM
    rc["openapi_declared_max"] = None
    summary = _fake_summary(tripwire=[], read_cap=rc)
    digest = report.render_digest(summary, _SHA)

    assert "read-cap=200 (undemonstrated)" in digest
    assert "declared+confirmed" not in digest

    text = report.render_report(summary)
    assert "cap demonstrated: no" in text


# ---- FIX D: the printed cap is derived from the probe trace, never the ----
# ---- stored `observed_cap` field, which could disagree with it. ----------


def test_cap_derives_from_probes_not_a_disagreeing_stored_observed_cap() -> None:
    rc = dict(_fake_read_cap())
    # The probes clearly max out at 200 -- but `observed_cap` claims 9999.
    # A renderer that trusted this stored field would publish a number the
    # probe table right next to it flatly contradicts.
    rc["observed_cap"] = 9999
    summary = _fake_summary(tripwire=[], read_cap=rc)

    digest = report.render_digest(summary, _SHA)
    assert "read-cap=200" in digest
    assert "9999" not in digest

    text = report.render_report(summary)
    assert "observed cap: 200" in text
    assert "9999" not in text


def test_cap_clause_omitted_when_probes_are_missing() -> None:
    rc = dict(_fake_read_cap())
    del rc["probes"]
    summary = _fake_summary(tripwire=[], read_cap=rc)

    digest = report.render_digest(summary, _SHA)
    assert "read-cap=" not in digest

    text = report.render_report(summary)
    assert "not derivable" in text
    assert "observed cap: 200" not in text


def test_cap_clause_omitted_when_probes_are_empty() -> None:
    rc = dict(_fake_read_cap())
    rc["probes"] = []
    summary = _fake_summary(tripwire=[], read_cap=rc)

    digest = report.render_digest(summary, _SHA)
    assert "read-cap=" not in digest


def test_cap_clause_omitted_when_a_probe_entry_is_malformed() -> None:
    rc = dict(_fake_read_cap())
    rc["probes"] = [{"requested": 50, "returned": 50}, {"requested": 1000, "returned": "not-an-int"}]
    summary = _fake_summary(tripwire=[], read_cap=rc)

    digest = report.render_digest(summary, _SHA)
    assert "read-cap=" not in digest

    text = report.render_report(summary)
    assert "not derivable" in text


def test_health_clause_omitted_on_non_2xx_status_despite_present_latency() -> None:
    # FIX 3: health() records latency unconditionally (the probe still
    # measured SOMETHING even for a 500), but a non-2xx status must never be
    # published under a latency-shaped clause -- that would read as a
    # health signal.
    health = {"healthz_ms": 5, "healthz_status": 500, "read_ms": 10}
    summary = _fake_summary(tripwire=[], health=health)
    digest = report.render_digest(summary, _SHA)
    assert "healthz=5ms" not in digest
    assert "healthz=500" in digest


def test_health_clause_present_on_genuine_2xx() -> None:
    health = {"healthz_ms": 5, "healthz_status": 200, "read_ms": 10}
    summary = _fake_summary(tripwire=[], health=health)
    digest = report.render_digest(summary, _SHA)
    assert "healthz=5ms" in digest


def test_render_report_health_section_gates_latency_on_2xx() -> None:
    health = {"healthz_ms": 5, "healthz_status": 503, "read_ms": 10}
    summary = _fake_summary(tripwire=[], health=health)
    text = report.render_report(summary)
    assert "non-2xx status 503" in text
    assert "healthz latency: 5 ms" not in text


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


# ---- FIX F: pyproject/README wording -------------------------------------


def test_pyproject_description_does_not_overclaim_deterministic_measurements() -> None:
    """FIX F: the METHOD is deterministic; the MEASUREMENTS are point-in-time
    and not archived -- the old description's "Deterministic daily
    observatory" phrasing read as a claim about the measurements too."""
    import pathlib

    pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text()
    assert "Deterministic daily observatory" not in text
    assert "deterministic" in text.lower()


def test_readme_scopes_templated_traffic_claim_to_the_sample() -> None:
    """FIX F: "a lot of templated traffic" generalized beyond the sampled
    lobby tail this repo actually measures."""
    import pathlib

    readme = pathlib.Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text()
    assert "observable room traffic includes a lot of" not in text
    assert "distinct authors\nare actually posting" not in text
    assert "distinct `from` identifiers" in text
