"""Turns the seven collector dicts into a summary, a markdown report, and the
two short signed strings (digest + note). No network calls here — pure
formatting over already-collected data.
"""

from __future__ import annotations

from datetime import datetime, timezone

from observatory.collect import OPENAPI_STATUS_DECLARED

REPO_URL = "https://github.com/africanproofs/technocore-observatory"
SIGNER_DID = "did:key:z6MksYze47qWaCvBK92UNzjuis5eqRdfX4C8SfaD8ynKWyNp"
DIGEST_MAX_CHARS = 900
NOTE_MAX_CHARS = 2000


class PublicationTooLongError(Exception):
    """Raised by `render_digest`/`render_note` when the composed text would
    exceed its char cap (FIX C). The permalink and attribution footer sit at
    the END of both strings -- silently truncating with an ellipsis (the old
    behavior) could cut into the URL or the attribution itself, posting a
    broken or misattributed permanent record. There is no safe truncation
    here: a caller (`observatory.cli.publish`) must catch this and refuse to
    publish, never post a shortened string instead."""


def build_summary(
    census: dict,
    dup: dict,
    api: dict,
    health: dict,
    read_cap: dict,
    sequence_continuity: dict,
    signature_retention: dict,
) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "date": now.strftime("%Y-%m-%d"),
        "generated_at": now.isoformat(),
        "census": census,
        "duplicates": dup,
        "api": api,
        "health": health,
        "read_cap": read_cap,
        "sequence_continuity": sequence_continuity,
        "signature_retention": signature_retention,
    }


def _report_url(date: str, sha: str) -> str:
    """An IMMUTABLE permalink to the report at the exact commit `sha` --
    never `blob/master` (FIX 1), which is a mutable pointer that can move
    out from under a post that already went out permanently, or point at
    content that was never actually pushed. `sha` is required: the only
    caller of this in production, `publish`, must resolve and verify it
    BEFORE building anything that gets posted (see `observatory.cli.
    resolve_pushed_commit`)."""
    return f"{REPO_URL}/blob/{sha}/reports/{date}.md"


def _cell(value) -> str:
    """Neutralize untrusted text before it enters a Markdown table cell.

    Room names, topics, and message text are anonymous attacker-controlled
    input. Unescaped, a `|` breaks the table and `[x](url)`/backticks/newlines
    can render hostile links or misleading content in AP's public report. Strip
    the structure: collapse whitespace, and defang the Markdown-active chars
    (adversarial review v3.0, minor — the "hostile links in AP's report"
    vector).
    """
    s = "" if value is None else str(value)
    s = " ".join(s.split())  # collapse newlines/tabs/runs of spaces
    for ch in ("\\", "|", "`", "[", "]", "<", ">"):
        s = s.replace(ch, "\\" + ch if ch in ("\\", "|", "`") else " ")
    # Defang bare URLs — GitHub auto-links a raw https:// even without brackets,
    # so a room topic could render a clickable hostile link in AP's report
    # (review #4). Break the scheme so it renders as inert text.
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return s[:120]


def render_report(summary: dict) -> str:
    date = summary.get("date", "unknown")
    census = summary.get("census") or {}
    dup = summary.get("duplicates") or {}
    api = summary.get("api") or {}
    health = summary.get("health") or {}
    rc = summary.get("read_cap") or {}
    seq = summary.get("sequence_continuity") or {}
    sig = summary.get("signature_retention") or {}

    lines: list[str] = []
    lines.append(f"# Technocore observatory — {date}")
    lines.append("")
    lines.append(
        "Measurements of technocore.chat, computed by the code in this "
        "repository (the METHOD is deterministic and public; the "
        "measurements themselves are point-in-time — e.g. health latency and "
        "a room's live tail — and the raw responses they were computed from "
        "are not separately archived, so re-running the method later "
        "reproduces the method, not necessarily this day's numbers). When a "
        "run is published (`observatory publish`), a signed digest citing "
        "this exact, already-pushed report commit is posted to room "
        f"`african-proofs` on technocore.chat by {SIGNER_DID} (African "
        "Proofs) — not every run is published."
    )
    lines.append("")

    # ---- census ---------------------------------------------------------
    lines.append("## Network census")
    lines.append("")
    if "error" in census:
        lines.append(f"- error: {census['error']}")
    else:
        lines.append(
            f"- rooms shown: {census.get('rooms_shown')} "
            f"(request limit {census.get('rooms_shown_limit')} — NOT a claim "
            f"that this is the total room count)"
        )
        rooms_total = census.get("rooms_total")
        if rooms_total is not None:
            lines.append(f"- rooms total (service-reported, `/rooms`'s own `total` field): {rooms_total}")
        # FIX F: this is neither a service-wide total (it only sums the
        # `rooms_shown` rooms this limited census call actually returned)
        # nor a volume measurement (`last_seq` is a high-water mark on
        # sequence numbers ever ASSIGNED to a room, not a count of messages
        # still retained -- see `_room_last_seq`'s docstring). "message
        # volume proxy" overclaimed both.
        lines.append(
            f"- sum of last_seq across the {census.get('rooms_shown')} rooms "
            f"returned by this census (a high-water mark on sequence numbers "
            f"ever assigned in each of those rooms, NOT retained message "
            f"volume, and not a total across the service's rooms): "
            f"{census.get('total_last_seq')}"
        )
        engagement = census.get("engagement")
        if isinstance(engagement, dict) and engagement:
            lines.append("")
            lines.append("Engagement rollup:")
            lines.append("")
            for k, v in engagement.items():
                lines.append(f"- {k}: {v}")
        top_rooms = census.get("top_rooms") or []
        if top_rooms:
            lines.append("")
            lines.append(
                "Caveat: room names and topics are caller-chosen, "
                "world-writable strings (technocore.chat's own `/rooms` "
                "schema marks them untrusted), not vetted identifiers."
            )
            lines.append("")
            lines.append("| name | last_seq | topic |")
            lines.append("|---|---|---|")
            for r in top_rooms:
                lines.append(f"| {_cell(r.get('name'))} | {r.get('last_seq')} | {_cell(r.get('topic'))} |")
    lines.append("")

    # ---- duplicates -------------------------------------------------------
    lines.append("## Duplicate sampling")
    lines.append("")
    if "error" in dup:
        lines.append(f"- error: {dup['error']}")
    else:
        share_pct = round((dup.get("duplicate_share") or 0) * 100, 1)
        lines.append(f"- room: {dup.get('room')}")
        lines.append(f"- sample size: {dup.get('sample')}")
        lines.append(f"- duplicate share: {share_pct}%")
        lines.append(f"- distinct authors: {dup.get('distinct_authors')}")
        top_templates = dup.get("top_templates") or []
        if top_templates:
            lines.append("")
            lines.append("| count | text |")
            lines.append("|---|---|")
            for t in top_templates:
                lines.append(f"| {t.get('count')} | {_cell(t.get('text'))} |")
    lines.append("")
    lines.append(
        "Caveat: this is the room's visible tail, not a census of the service."
    )
    lines.append("")

    # ---- api surface -------------------------------------------------------
    lines.append("## API surface")
    lines.append("")
    if "error" in api:
        lines.append(f"- error: {api['error']}")
    else:
        lines.append(f"- paths total: {api.get('paths_total')}")
        if api.get("baseline_created"):
            # FIX F: "diffs begin tomorrow" promises a specific next run,
            # which this repo cannot actually promise (the next run could
            # fail and leave the baseline unchanged -- see FIX 6). The
            # honest claim is only about WHEN a diff becomes possible at
            # all: the next run that succeeds.
            lines.append("- baseline established — diffs begin with the next successful run")
        else:
            added = api.get("added") or []
            removed = api.get("removed") or []
            if added or removed:
                if added:
                    lines.append(f"- added: {', '.join(added)}")
                if removed:
                    lines.append(f"- removed: {', '.join(removed)}")
            else:
                lines.append("- no changes")
        tripwire = api.get("tripwire") or []
        if tripwire:
            lines.append("")
            lines.append(
                "**Observed keyword match on a newly seen API path** "
                "(tripwire keywords: faucet, testnet, airdrop, mint, claim, "
                f"token, wallet): {', '.join(tripwire)}"
            )
        # FIX F: on the very first (baseline-establishing) run there is no
        # prior baseline to compare against, so `llms_changed=False` is not
        # a real "no change" finding -- rendering it as "no" implies a
        # comparison that never happened.
        if api.get("baseline_created"):
            lines.append("- llms.txt changed: no prior baseline")
        else:
            lines.append(f"- llms.txt changed: {'yes' if api.get('llms_changed') else 'no'}")
    lines.append("")

    # ---- health -------------------------------------------------------
    lines.append("## Health")
    lines.append("")
    if "error" in health and health.get("healthz_ms") is None and health.get("read_ms") is None:
        lines.append(f"- error: {health['error']}")
    else:
        status = health.get("healthz_status")
        healthz_ms = health.get("healthz_ms")
        # FIX 3: latency is only published under a genuine 2xx -- a non-2xx
        # status must never be reported under a "latency" label that reads
        # as a health signal, since a slow-but-failing probe and a
        # fast-but-failing probe would otherwise render identically to a
        # healthy one.
        if _is_plain_int(status) and 200 <= status < 300 and _is_plain_int(healthz_ms):
            lines.append(f"- healthz latency: {healthz_ms} ms (status {status})")
        elif status is not None:
            lines.append(f"- healthz: non-2xx status {status} — latency not reported under a failing probe")
        else:
            lines.append("- healthz: no status recorded")
        lines.append(f"- read latency: {health.get('read_ms')} ms")
        if "error" in health:
            lines.append(f"- partial error: {health['error']}")
    lines.append("")

    # ---- read cap -------------------------------------------------------
    lines.append("## Read cap")
    lines.append("")
    if "error" in rc:
        lines.append(f"- error: {rc['error']}")
    else:
        lines.append(f"- room: {rc.get('room')}")
        # FIX D: derived from the probe table below, never the stored
        # `observed_cap` field -- see `_recompute_observed_cap`.
        recomputed_observed_cap = _recompute_observed_cap(rc)
        if recomputed_observed_cap is None:
            lines.append("- observed cap: not derivable — no usable probe trace")
        else:
            lines.append(f"- observed cap: {recomputed_observed_cap} (max records returned by any probe)")
        openapi_status = rc.get("openapi_probe_status")
        status_label = {
            OPENAPI_STATUS_DECLARED: "declared",
            "no_maximum_declared": "examined, no maximum declared",
            "openapi_unavailable": "could not be fetched/parsed — NOT the same as no maximum",
        }.get(openapi_status, str(openapi_status))
        lines.append(
            f"- OpenAPI-declared limit maximum (from /openapi.json's `/r/{{room}}` "
            f"`limit` parameter): {rc.get('openapi_declared_max')} ({status_label})"
        )
        lines.append(
            f"- room last_seq (context only, from /rooms — a high-water mark on "
            f"sequence numbers ever assigned, NOT a record count, and NOT used as "
            f"cap evidence): {rc.get('room_last_seq')}"
        )
        # Re-validated here rather than trusting the stored `cap_demonstrated`
        # boolean (FIX 4c) -- the published sentence is only ever as true as
        # the raw probe trace sitting right next to it.
        recomputed_cap_demonstrated = _recompute_cap_demonstrated(rc)
        lines.append(
            f"- cap demonstrated: {'yes' if recomputed_cap_demonstrated else 'no'} — {rc.get('evidence')}"
        )
        lines.append(f"- monotonic across probes: {'yes' if rc.get('monotonic') else 'no'}")
        probes = rc.get("probes") or []
        if probes:
            lines.append("")
            lines.append("| requested | returned |")
            lines.append("|---|---|")
            for p in probes:
                lines.append(f"| {p.get('requested')} | {p.get('returned')} |")
    lines.append("")
    lines.append(
        "Method: `read_room(room, since=0, limit=L)` for L in 50, 100, 200, "
        "500, 1000; `observed cap` is the largest returned count across "
        "probes — a description of what came back, not by itself a claim "
        "about a server-side limit. A cap is only reported as demonstrated "
        "when the probe trace is monotonic, requests exceeded returns, AND "
        "the service's own `/openapi.json` declares a `limit` parameter "
        "maximum that exactly matches the observed cap — an unfetchable or "
        "unparsable OpenAPI document is reported distinctly from a "
        "genuinely examined absence of a declared maximum, never collapsed "
        "into the same claim. `room last_seq` (from `/rooms`) is NOT used "
        "as cap evidence: it is a high-water mark on sequence numbers ever "
        "assigned, not a record count, and cannot by itself establish how "
        "many records are retained — a room can report a large `last_seq` "
        "while holding far fewer live records than that."
    )
    lines.append("")

    # ---- sequence continuity ---------------------------------------------
    lines.append("## Sequence continuity")
    lines.append("")
    if "error" in seq:
        lines.append(f"- error: {seq['error']}")
    elif seq.get("note"):
        lines.append(f"- note: {seq['note']}")
    else:
        lines.append(f"- room: {seq.get('room')}")
        lines.append(
            f"- visible range: {seq.get('first_visible_seq')}–{seq.get('last_visible_seq')} "
            f"({seq.get('visible_count')} records)"
        )
        lines.append(f"- span: {seq.get('span')}, missing in span: {seq.get('missing_in_span')}")
        lines.append(f"- room last_seq (from /rooms): {seq.get('room_last_seq')}")
        lines.append(f"- history before visible window: {seq.get('history_before_window')} sequence numbers")
        gaps = seq.get("gaps") or []
        if gaps:
            lines.append("")
            lines.append("| after | before | missing |")
            lines.append("|---|---|---|")
            for g in gaps:
                lines.append(f"| {g.get('after')} | {g.get('before')} | {g.get('missing')} |")
    lines.append("")
    lines.append(
        "Method: `read_room(room, since=0, limit=<observed cap>)`, sorted by "
        "sequence number; span/gaps computed from first to last visible "
        "sequence. `room_last_seq` is the room's reported `last_seq` from "
        "`/rooms`, independent of the read above. Note on interpretation: "
        "`since=0` returns the most recent window, not the oldest, so "
        "`history before visible window` counts sequence numbers not "
        "returned by this read — it is NOT a measurement of retention or reaping, "
        "and must not be read as one. Only `missing in span` and the gap "
        "table describe discontinuity within what was actually returned."
    )
    lines.append("")

    # ---- signature retention -----------------------------------------------
    lines.append("## Signature retention")
    lines.append("")
    if "error" in sig:
        lines.append(f"- error: {sig['error']}")
    else:
        top_keys = sig.get("observed_top_level_keys") or []
        lines.append(f"- room: {sig.get('room')}, sample: {sig.get('sample')}")
        lines.append(
            f"- signed-lane records: {sig.get('signed_lane_records')} "
            f"(with a recognized signature field: {sig.get('signed_lane_with_signature')}), "
            f"unsigned-lane records: {sig.get('unsigned_lane_records')}"
        )
        lines.append(
            f"- observed top-level keys across the sample: "
            f"{', '.join(top_keys) if top_keys else '(none)'}"
        )
        lines.append(
            f"- search truncated by the depth/node bound on at least one "
            f"record: {'yes' if sig.get('search_truncated') else 'no'}"
        )
        lines.append(f"- signature field/path found: {sig.get('signature_path') or '(none)'}")
        lines.append(
            f"- signatures exposed: {sig.get('signatures_exposed')} "
            f"(empty/falsey candidate fields seen: {sig.get('empty_signature_fields')})"
        )
        lines.append(
            f"- did-lane offline verified: {sig.get('offline_verified')}, "
            f"did-lane offline failed: {sig.get('offline_failed')}, "
            f"did-lane could not be checked: {sig.get('offline_unverifiable')} "
            f"(these three counters are scoped to did-lane records only — an "
            f"unsigned-lane record with a sig-shaped field never contributes "
            f"to them or to the verdict below)"
        )
        reasons = sig.get("unverifiable_reasons") or []
        if reasons:
            lines.append(f"- reasons some signatures could not be checked: {', '.join(reasons)}")
        lines.append(f"- verdict: {sig.get('verdict')}")
    lines.append("")
    lines.append(
        "Method: read a room sample, classify each record's author as "
        "did:key (signed lane) or plain nick (unsigned lane), then search "
        "each record recursively — into both nested objects and arrays, "
        "bounded depth and size (see `search truncated` above; a truncated "
        "search cannot license a claim that no field exists anywhere) — for "
        "a signature under an exact known-name set: sig, signature, "
        "sig_b64, signature_b64, jws, or any of those nested under a proof "
        "envelope, with no substring/heuristic matching. A verdict of no "
        "recognized field covers exactly the observed top-level keys listed "
        "above (and, when the search was not truncated, everything reached "
        "within the depth/node bound), not every conceivable field name. "
        "The did-lane offline-verification counters and the verdict are "
        "computed from DID-LANE (signed-lane) records only: an unsigned-lane "
        "(plain-nick) record with a recognized sig-shaped field is still "
        "counted in `signatures exposed` above, but there is no did:key to "
        "check it against, so it is excluded from these counters and cannot "
        "move the verdict either way. NOT every exposed did-lane signature "
        "is checked offline: a `jws`-named field is a compact JWS with its "
        "own serialization this checker does not implement, so it is "
        "counted as exposed-but-unverifiable rather than run through the "
        "verifier. Where a genuinely verifiable signature (sig/signature/"
        "sig_b64/signature_b64 on a did:key author) is found, it IS checked "
        "OFFLINE — without trusting the server's own claim that a message "
        "was signed — by decoding it (rejecting anything that is not "
        "exactly 86 strict base64url characters decoding to exactly 64 "
        "bytes) and verifying it against `room|nonce|text` with the public "
        "key recovered from the did:key itself. A did-lane record that "
        "exposes such a signature but is missing an input needed to check "
        "it (nonce, text, or a decodable did) is reported as unable to be "
        "checked, never silently counted as verified. If the search over "
        "this sample was truncated (see above), no signature-related figure "
        "on this page is published in the digest — a truncated search "
        "cannot license a completeness claim."
    )
    lines.append("")

    # ---- method -------------------------------------------------------
    lines.append("## Method")
    lines.append("")
    lines.append(
        "All numbers above come from public, unauthenticated GET endpoints "
        "(`/rooms`, `/r/lobby`, `/openapi.json`, `/llms.txt`, `/healthz`) on "
        "technocore.chat, fetched via the `technocore-mcp` client. The "
        "collection and rendering code lives in this repository — there is no "
        "LLM anywhere in this loop. Numbers are as-of the run that produced "
        "this file."
    )
    lines.append("")

    return "\n".join(lines)


def _is_plain_int(value: object) -> bool:
    """True for a real int that isn't secretly a bool (`isinstance(True,
    int)` is True in Python) -- used throughout the clause builders below so
    a numeric field is only ever rendered when it's genuinely numeric."""
    return isinstance(value, int) and not isinstance(value, bool)


def _rooms_clause(census: dict) -> str | None:
    """FIX 2: `rooms-shown=N (limit L)` -- N returned records at request
    limit L can never be told apart from "at least N" without the limit
    alongside it, so the limit is always rendered. `rooms-total=T` is added
    only when the service's own `/rooms` `total` field was present and
    numeric; no total is ever inferred or guessed."""
    if "error" in census:
        return None
    rooms = census.get("rooms_shown")
    limit = census.get("rooms_shown_limit")
    if not _is_plain_int(rooms) or not _is_plain_int(limit):
        return None
    clause = f"rooms-shown={rooms} (limit {limit})"
    total = census.get("rooms_total")
    if _is_plain_int(total):
        clause += f", rooms-total={total}"
    return clause


def _dup_clause(dup: dict) -> str | None:
    if "error" in dup:
        return None
    dup_share = dup.get("duplicate_share")
    sample = dup.get("sample")
    authors = dup.get("distinct_authors")
    if isinstance(dup_share, bool) or not isinstance(dup_share, (int, float)):
        return None
    if not _is_plain_int(sample) or not _is_plain_int(authors):
        return None
    return f"dup-share={round(dup_share * 100, 1)}% ({sample}-msg lobby sample, {authors} authors)"


def _api_clause(api: dict) -> str | None:
    if "error" in api:
        return None
    paths_total = api.get("paths_total")
    if not _is_plain_int(paths_total):
        return None
    added = api.get("added") or []
    removed = api.get("removed") or []
    tripwire = api.get("tripwire") or []
    delta = "baseline" if api.get("baseline_created") else f"+{len(added)}/-{len(removed)}"
    tripwire_note = f", new-path keyword match: {', '.join(tripwire)}" if tripwire else ""
    return f"api-paths={paths_total} ({delta}{tripwire_note})"


def _health_clause(health: dict) -> str | None:
    """FIX 3: latency is only ever rendered under a genuine 2xx `healthz`
    status. A non-2xx status still renders (as the status code itself, not
    a latency figure) so a failing probe is visible in the digest rather
    than silently omitted."""
    if "error" in health and health.get("healthz_ms") is None and health.get("read_ms") is None:
        return None
    status = health.get("healthz_status")
    healthz_ms = health.get("healthz_ms")
    if _is_plain_int(status) and 200 <= status < 300 and _is_plain_int(healthz_ms):
        return f"healthz={healthz_ms}ms"
    if _is_plain_int(status):
        return f"healthz={status}"
    return None


def _recompute_observed_cap(rc: dict) -> int | None:
    """Re-derive the observed cap straight from the raw probe trace (FIX D),
    rather than trusting the stored `observed_cap` field. A renderer that
    only ever echoes a number computed elsewhere could publish a cap that
    disagrees with the probe table sitting right next to it (a stale value,
    a hand-edited summary, a future collector bug that stores one thing and
    a table that shows another). Returns None -- "refuse to print a cap" --
    when `probes` is missing, empty, or contains anything that isn't a
    plain int `returned` count."""
    probes = rc.get("probes")
    if not isinstance(probes, list) or not probes:
        return None
    returned: list[object] = []
    for p in probes:
        if not isinstance(p, dict):
            return None
        returned.append(p.get("returned"))
    if not all(_is_plain_int(x) for x in returned):
        return None
    return max(returned)


def _recompute_cap_demonstrated(rc: dict) -> bool:
    """Re-derive whether a cap was demonstrated straight from the raw probe
    trace and the OpenAPI probe status (FIX 4c), rather than trusting the
    stored `cap_demonstrated` boolean. A renderer that only ever echoes a
    boolean computed elsewhere can end up publishing a stale or hand-edited
    claim; recomputing here means the published sentence is only ever as
    true as the data sitting right next to it in the same dict."""
    probes = rc.get("probes")
    if not isinstance(probes, list) or not probes:
        return False
    requested: list[object] = []
    returned: list[object] = []
    for p in probes:
        if not isinstance(p, dict):
            return False
        requested.append(p.get("requested"))
        returned.append(p.get("returned"))
    if not all(_is_plain_int(x) for x in requested) or not all(_is_plain_int(x) for x in returned):
        return False
    monotonic = all(returned[i] <= returned[i + 1] for i in range(len(returned) - 1))
    requests_exceeded_returns = any(r < q for q, r in zip(requested, returned))
    observed_cap = max(returned)
    declared_max = rc.get("openapi_declared_max")
    return (
        monotonic
        and requests_exceeded_returns
        and rc.get("openapi_probe_status") == OPENAPI_STATUS_DECLARED
        and _is_plain_int(declared_max)
        and observed_cap == declared_max
    )


def _cap_clause(rc: dict) -> str | None:
    """Fail-closed per FINDING 1: only rendered when read_cap succeeded and
    there is a probe trace to derive a cap FROM. FIX D: the printed cap is
    always `_recompute_observed_cap(rc)` -- derived from the raw `probes`
    table right here, never the stored `observed_cap` field, which could in
    principle disagree with the trace it's supposed to summarize. No probe
    trace to derive from means no cap clause at all, even if a stale
    `observed_cap` is sitting in the dict."""
    if "error" in rc:
        return None
    observed_cap = _recompute_observed_cap(rc)
    if observed_cap is None:
        return None
    if _recompute_cap_demonstrated(rc):
        return f"read-cap={observed_cap} (declared+confirmed)"
    return f"read-cap={observed_cap} (undemonstrated)"


def _continuity_clause(seq: dict) -> str | None:
    """Fail-closed per FINDING 1: omitted on error, on a `note` (any of the
    tolerant-degradation paths in `sequence_continuity` -- non-integer/
    duplicate/absent sequence values), or if any of the four numbers this
    clause reports isn't a genuine (non-bool) int in range."""
    if "error" in seq or seq.get("note"):
        return None
    visible_count = seq.get("visible_count")
    missing = seq.get("missing_in_span")
    first = seq.get("first_visible_seq")
    last = seq.get("last_visible_seq")
    if not _is_plain_int(visible_count) or visible_count <= 0:
        return None
    if not _is_plain_int(missing) or missing < 0:
        return None
    if not _is_plain_int(first) or not _is_plain_int(last):
        return None
    return f"seq-gaps={missing} in {visible_count} visible (range {first}-{last})"


def _signature_clause(sig: dict) -> str | None:
    """Fail-closed per FINDING 1: omitted on error, or unless a real
    did-lane sample was actually taken (`sample` and `signed_lane_records`
    both genuinely > 0). Also omitted entirely when the signature search was
    truncated by the depth/node bound (FIX 5a): a truncated search cannot
    support a "no field found" claim, so a "did-lane records exposed a
    recognized sig field" count built on it must not be published either."""
    if "error" in sig:
        return None
    if sig.get("search_truncated"):
        return None
    sample = sig.get("sample")
    signed_lane_records = sig.get("signed_lane_records")
    if not _is_plain_int(sample) or sample <= 0:
        return None
    if not _is_plain_int(signed_lane_records) or signed_lane_records <= 0:
        return None
    signed_lane_with_signature = sig.get("signed_lane_with_signature")
    # FIX 5c: state what was actually searched (a count of did-lane records
    # exposing a recognized field), not the ambiguous "w/sig" shorthand.
    if _is_plain_int(signed_lane_with_signature):
        clause = f"sig-check={signed_lane_with_signature}/{signed_lane_records} did-lane records exposed a recognized sig field"
    else:
        clause = f"sig-check: {signed_lane_records} did-lane records sampled"
    offline_verified = sig.get("offline_verified")
    if _is_plain_int(offline_verified):
        clause += f", {offline_verified} verified offline"
    return clause


def render_digest(summary: dict, sha: str) -> str:
    """`sha` is the commit that produced `reports/<date>.md` -- REQUIRED,
    not optional, so this can never be called with a mutable `blob/master`
    link (FIX 1). The only production caller, `observatory.cli.publish`,
    resolves and verifies `sha` before ever calling this."""
    date = summary.get("date", "unknown")
    census = summary.get("census") or {}
    dup = summary.get("duplicates") or {}
    api = summary.get("api") or {}
    health = summary.get("health") or {}
    rc = summary.get("read_cap") or {}
    seq = summary.get("sequence_continuity") or {}
    sig = summary.get("signature_retention") or {}

    # Every clause below is built independently and omitted entirely (never
    # rendered with "?" or a guessed value) when its collector failed or its
    # own preconditions don't hold -- see the FINDING 1 fail-closed
    # requirement. If every clause is omitted the digest still renders (old
    # fields only, or the explicit "no measurements available" fallback)
    # and never implies a measurement that wasn't actually made.
    clauses = [
        c
        for c in (
            _rooms_clause(census),
            _dup_clause(dup),
            _api_clause(api),
            _health_clause(health),
            _cap_clause(rc),
            _continuity_clause(seq),
            _signature_clause(sig),
        )
        if c is not None
    ]

    body = " ".join(clauses) if clauses else "no measurements available"
    digest = (
        f"Technocore observatory {date}: {body}. "
        f"Methods+data: {_report_url(date, sha)} — deterministic method, African Proofs"
    )

    if len(digest) > DIGEST_MAX_CHARS:
        raise PublicationTooLongError(
            f"digest is {len(digest)} chars, over the {DIGEST_MAX_CHARS} cap -- "
            "truncating would risk cutting the permalink or attribution "
            "footer, so this refuses to render a shortened digest instead"
        )
    return digest


def render_note(summary: dict, sha: str) -> str:
    """`sha` is REQUIRED for the same reason as in `render_digest` -- see
    its docstring."""
    date = summary.get("date", "unknown")
    # The kv note THIS REPO WRITES is unsigned and world-overwritable,
    # because this client only ever calls the plain
    # `/kv/{ns}/{key}/set/{value}` endpoint. Technocore.chat itself DOES
    # expose a signed kv-note lane
    # (`/kv/{ns}/{key}/set-signed/{did}/{sig}/{nonce}/{value}` -- see
    # state/api-baseline.json, and technocore_mcp.identity.sign_set, which
    # already implements that lane's canonical string) -- this client simply
    # doesn't call it yet. That is a gap in THIS repo, not something the
    # service lacks; do not claim otherwise. Separately: the room post is
    # signed at write time and attributable to SIGNER_DID, but calling it
    # unconditionally "tamper-evident" overclaims -- this repo's own
    # signature-retention measurement shows technocore.chat does not
    # reliably expose message signatures on read, so a reader often cannot
    # re-verify that post's signature offline (see the Signature retention
    # section of the report this note points to).
    note = (
        f"{render_digest(summary, sha)} | report: {_report_url(date, sha)} | "
        f"signed record (signed at write time, attributable to {SIGNER_DID}): "
        f"room african-proofs. Not independently re-verifiable by a reader "
        f"unless technocore.chat exposes the signature on read -- see the "
        f"report's Signature retention section. This kv note itself is "
        f"UNSIGNED and world-overwritable."
    )
    if len(note) > NOTE_MAX_CHARS:
        raise PublicationTooLongError(
            f"kv note is {len(note)} chars, over the {NOTE_MAX_CHARS} cap -- "
            "truncating would risk cutting the report permalink or "
            "attribution footer, so this refuses to render a shortened note "
            "instead"
        )
    return note
