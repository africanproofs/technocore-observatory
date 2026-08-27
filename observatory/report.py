"""Turns the four collector dicts into a summary, a markdown report, and the
two short signed strings (digest + note). No network calls here — pure
formatting over already-collected data.
"""

from __future__ import annotations

from datetime import datetime, timezone

REPO_URL = "https://github.com/africanproofs/technocore-observatory"
SIGNER_DID = "did:key:z6MksYze47qWaCvBK92UNzjuis5eqRdfX4C8SfaD8ynKWyNp"
DIGEST_MAX_CHARS = 900
NOTE_MAX_CHARS = 2000


def build_summary(census: dict, dup: dict, api: dict, health: dict) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "date": now.strftime("%Y-%m-%d"),
        "generated_at": now.isoformat(),
        "census": census,
        "duplicates": dup,
        "api": api,
        "health": health,
    }


def _report_url(date: str) -> str:
    return f"{REPO_URL}/blob/master/reports/{date}.md"


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

    lines: list[str] = []
    lines.append(f"# Technocore observatory — {date}")
    lines.append("")
    lines.append(
        "Deterministic daily measurements of technocore.chat; methods are the "
        "code in this repo. A signed digest is posted to room `african-proofs` "
        f"on technocore.chat by {SIGNER_DID} (African Proofs)."
    )
    lines.append("")

    # ---- census ---------------------------------------------------------
    lines.append("## Network census")
    lines.append("")
    if "error" in census:
        lines.append(f"- error: {census['error']}")
    else:
        lines.append(f"- rooms shown: {census.get('rooms_shown')}")
        lines.append(f"- total last_seq (message volume proxy): {census.get('total_last_seq')}")
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
            lines.append("- baseline established — diffs begin tomorrow")
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
            lines.append(f"**FAUCET-PATTERN ENDPOINT APPEARED:** {', '.join(tripwire)}")
        lines.append(f"- llms.txt changed: {'yes' if api.get('llms_changed') else 'no'}")
    lines.append("")

    # ---- health -------------------------------------------------------
    lines.append("## Health")
    lines.append("")
    if "error" in health and health.get("healthz_ms") is None and health.get("read_ms") is None:
        lines.append(f"- error: {health['error']}")
    else:
        lines.append(f"- healthz latency: {health.get('healthz_ms')} ms (status {health.get('healthz_status')})")
        lines.append(f"- read latency: {health.get('read_ms')} ms")
        if "error" in health:
            lines.append(f"- partial error: {health['error']}")
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


def render_digest(summary: dict) -> str:
    date = summary.get("date", "unknown")
    census = summary.get("census") or {}
    dup = summary.get("duplicates") or {}
    api = summary.get("api") or {}
    health = summary.get("health") or {}

    rooms = census.get("rooms_shown", "?")
    dup_share = dup.get("duplicate_share")
    dup_pct = "?" if dup_share is None else round(dup_share * 100, 1)
    sample = dup.get("sample", "?")
    authors = dup.get("distinct_authors", "?")
    paths_total = api.get("paths_total", "?")
    added = api.get("added") or []
    removed = api.get("removed") or []
    tripwire = api.get("tripwire") or []
    healthz_ms = health.get("healthz_ms", "?")

    tripwire_note = f", FAUCET-PATTERN: {', '.join(tripwire)}" if tripwire else ""

    digest = (
        f"Technocore observatory {date}: rooms={rooms} dup-share={dup_pct}% "
        f"({sample}-msg lobby sample, {authors} authors) api-paths={paths_total} "
        f"({'baseline' if api.get('baseline_created') else f'+{len(added)}/-{len(removed)}'}{tripwire_note}) healthz={healthz_ms}ms. "
        f"Methods+data: {_report_url(date)} — deterministic daily, African Proofs"
    )

    if len(digest) > DIGEST_MAX_CHARS:
        digest = digest[: DIGEST_MAX_CHARS - 1] + "…"
    return digest


def render_note(summary: dict) -> str:
    date = summary.get("date", "unknown")
    # The kv note is UNSIGNED and world-overwritable (technocore.chat has no
    # signed note lane for a general did:key). The authoritative, tamper-evident
    # record is the SIGNED room post in `african-proofs`; this note only points
    # to it. Do not claim the note itself is signed.
    note = (
        f"{render_digest(summary)} | report: {_report_url(date)} | "
        f"authoritative signed record: room african-proofs (by {SIGNER_DID}). "
        f"This note is unsigned and may be overwritten by anyone."
    )
    if len(note) > NOTE_MAX_CHARS:
        note = note[: NOTE_MAX_CHARS - 1] + "…"
    return note
