"""Collectors: each takes a `TechnocoreClient` and returns a plain dict.

Every collector is tolerant of shape drift in technocore.chat's JSON — the
service is a live, evolving third-party API and these functions must not
raise on an unexpected (but plausible) payload shape. They raise only
`TechnocoreError` (network/HTTP failures), which callers in `cli.py` catch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from technocore_mcp import identity
from technocore_mcp.client import TechnocoreClient, TechnocoreError

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

# read_cap: limits probed, smallest to largest, and the pause between them —
# polite pacing against a small third-party service.
READ_CAP_PROBE_LIMITS = (50, 100, 200, 500, 1000)
READ_CAP_SLEEP_S = 0.7

# signature_retention: exact known field names for an embedded signature.
# No substring/heuristic matching (e.g. "any key containing 'sig'") -- that
# false-positives on "signal", "design", "assigned" and overclaims what was
# actually examined. Searched recursively into both dicts and lists (see
# _find_signature) but bounded, so a hostile/huge payload can't make the
# search pathological.
#
# `jws` is detected (so its presence is reported) but deliberately NOT in
# VERIFIABLE_SIG_FIELD_NAMES: compact JWS has its own serialization and
# signing-input construction, which this checker does not implement. A
# found `jws` field is counted as exposed-but-unverifiable, never run
# through the raw-Ed25519-signature verifier below.
SIG_FIELD_NAMES = ("sig", "signature", "sig_b64", "signature_b64", "jws")
VERIFIABLE_SIG_FIELD_NAMES = ("sig", "signature", "sig_b64", "signature_b64")
JWS_UNVERIFIABLE_REASON = "jws serialization not supported by this checker"
SIG_SEARCH_MAX_DEPTH = 3
SIG_SEARCH_MAX_NODES = 200
NONCE_FIELD_CANDIDATES = ("nonce", "seq_nonce")
# did:key for an Ed25519 key always starts "did:key:z6Mk" (multicodec 0xed01
# base58btc-encoded then multibase-prefixed) — see technocore_mcp.identity.
DID_KEY_ED25519_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$")

# fail-closed signature decode: a real Ed25519 signature is exactly 64 bytes,
# which unpadded base64url always renders as exactly 86 characters. Both
# ends are checked before ever calling verify() -- base64.urlsafe_b64decode
# is permissive about alphabet and length otherwise, so a malformed value
# must never be allowed to fall through to a "pass".
B64URL_STRICT_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
ED25519_SIG_B64_LEN = 86
ED25519_SIG_BYTES = 64

# sequence_continuity: candidate sequence-number field names, and how many of
# the largest gaps to report.
SEQ_FIELD_CANDIDATES = ("seq", "sequence", "n")
MAX_GAPS_REPORTED = 5


def _plain_int(value: object) -> int | None:
    """`value` as a genuine (non-bool) int, or None -- used wherever a
    service-reported number is trusted only if it is actually numeric."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def census(client: TechnocoreClient) -> dict:
    """Room census + engagement rollup from `/rooms`.

    `rooms_shown` is exactly `len(rooms)` for THIS response -- it must never
    be read as "the total room count" (FIX 2): a `limit` of 100 returning
    100 rooms is indistinguishable from "at least 100" unless the service's
    own total is known. `/rooms` does publish a `total` field (see its
    OpenAPI response schema), so it is surfaced here as `rooms_total` when
    present and numeric; when it is absent or of the wrong shape,
    `rooms_total` is None and no total is claimed.
    """
    data = client.rooms_overview(limit=DEFAULT_CENSUS_LIMIT)

    if isinstance(data, dict):
        rooms = data.get("rooms") or []
        engagement = data.get("engagement")
        rooms_total = _plain_int(data.get("total"))
    elif isinstance(data, list):
        rooms = data
        engagement = None
        rooms_total = None
    else:
        rooms = []
        engagement = None
        rooms_total = None

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
        "rooms_shown_limit": DEFAULT_CENSUS_LIMIT,
        "rooms_total": rooms_total,
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
    committed baseline file.

    This function only READS `baseline_path`; it never writes it (FIX 6).
    The new state to persist is returned under `new_baseline` for the
    caller to hand to `write_api_baseline` -- but only once the caller knows
    the whole run succeeded. Writing the baseline mid-collection, before
    later collectors have even run, would silently advance the comparison
    point even when the run overall later turns out to have failed, and a
    same-day re-run after that partial failure would then diff against
    itself and erase a real delta.

    FIX B (fail closed): an unparseable/malformed `/openapi.json` body used
    to silently become an EMPTY path set (`openapi = {}` on a JSON error,
    then `paths = []`). Diffed against a real baseline, an empty path set
    presents as a mass "removal" of every previously-seen path -- the
    opposite of "nothing could be measured". Any of the following is now a
    collector FAILURE (`{"error": ...}`, per the module's `TechnocoreError`
    convention -- `cli.run` then omits the API clause and does not advance
    the baseline) instead of a silent empty surface:
      - `/openapi.json`'s body is not valid JSON;
      - it parses to something other than a JSON object;
      - its `paths` key is present but isn't a JSON object.
    A missing `paths` key alone is tolerated as "zero paths" (the doc was
    at least a well-formed object; some minimal/degenerate OpenAPI docs
    have no `paths` block), matching the deliberately narrow scope of this
    fix: fail on evidence of a broken fetch/parse, not on an unusual-but-
    coherent shape.

    The same fail-closed treatment applies to a corrupt/unreadable EXISTING
    baseline file: read or parse failure there is also a collector failure,
    never a silent "treat it as no baseline" -- because "no baseline" mints
    a brand-new one built from a `{}` that isn't the real prior state, and
    would misreport `added`/`llms_changed` against a state that never
    actually held. `cli.run` only ever writes a new baseline after a fully
    successful run, so a failure here also means the last-known-good
    baseline on disk is never overwritten with one derived from thin air.
    """
    openapi_text = client.fetch_doc("openapi.json")
    try:
        openapi = json.loads(openapi_text)
    except ValueError as e:
        return {"error": f"/openapi.json is not valid JSON: {e}"}
    if not isinstance(openapi, dict):
        return {
            "error": f"/openapi.json parsed to a {type(openapi).__name__}, not a JSON object"
        }
    raw_paths = openapi.get("paths")
    if raw_paths is None:
        raw_paths = {}
    if not isinstance(raw_paths, dict):
        return {
            "error": f"/openapi.json 'paths' is a {type(raw_paths).__name__}, not a JSON object"
        }
    paths = sorted(raw_paths.keys())

    llms = client.fetch_doc("llms.txt")
    llms_sha256 = hashlib.sha256(llms.encode("utf-8")).hexdigest()

    baseline_created = not baseline_path.exists()
    baseline: dict = {}
    if not baseline_created:
        try:
            baseline_text = baseline_path.read_text()
        except OSError as e:
            return {"error": f"could not read existing baseline {baseline_path}: {e}"}
        try:
            baseline = json.loads(baseline_text)
        except ValueError as e:
            return {"error": f"existing baseline {baseline_path} is not valid JSON: {e}"}
        if not isinstance(baseline, dict):
            return {
                "error": (
                    f"existing baseline {baseline_path} parsed to a "
                    f"{type(baseline).__name__}, not a JSON object"
                )
            }

    baseline_paths_raw = baseline.get("paths")
    if baseline_paths_raw is None:
        baseline_paths_raw = []
    if not isinstance(baseline_paths_raw, list):
        return {
            "error": (
                f"existing baseline {baseline_path} 'paths' is a "
                f"{type(baseline_paths_raw).__name__}, not a list"
            )
        }
    baseline_paths = set(baseline_paths_raw)
    added = sorted(p for p in paths if p not in baseline_paths)
    removed = sorted(p for p in baseline_paths if p not in paths)
    tripwire = [p for p in added if TRIPWIRE_RE.search(p)]
    llms_changed = False if baseline_created else (baseline.get("llms_sha256") != llms_sha256)

    return {
        "paths_total": len(paths),
        "added": added,
        "removed": removed,
        "tripwire": tripwire,
        "llms_changed": llms_changed,
        "baseline_created": baseline_created,
        "new_baseline": {
            "paths": paths,
            "llms_sha256": llms_sha256,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def write_api_baseline(baseline_path: Path, new_baseline: dict) -> None:
    """Persist `new_baseline` (the `new_baseline` key of an `api_surface`
    result) to `baseline_path`. Split out from `api_surface` so the CALLER
    controls when this happens -- only after a fully successful run (FIX 6;
    see `observatory.cli.run`), and only after the report + summary for
    that run have already been written to disk (FIX E) -- so a failure
    anywhere before this point leaves the previous baseline intact and
    nothing is ever advanced ahead of the artifacts that justify it.

    FIX E: written atomically -- a temp file in the same directory
    (`os.replace` only guarantees atomicity within one filesystem) followed
    by `os.replace`, never a direct `write_text` on the target path. A
    crash or kill mid-write to the real path would otherwise leave a
    truncated/corrupt baseline on disk; `os.replace` is a single atomic
    rename, so `baseline_path` is always either the old complete file or
    the new complete file, never a partial one.
    """
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(baseline_path.parent), prefix=f".{baseline_path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(new_baseline, indent=1))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, baseline_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


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


def _room_last_seq(client: TechnocoreClient, room: str) -> int | None:
    """Look up `room`'s reported `last_seq` from `/rooms`.

    This is a high-water mark on sequence numbers ever assigned, NOT a
    record count and NOT evidence of how many records the room currently
    holds -- it cannot by itself establish how many records are retained
    (this measurement has observed rooms whose visible history is far
    shorter than their `last_seq` would suggest, consistent with retention
    or reaping upstream, but this repo does not have and does not claim a
    citable, precise account of that upstream mechanism). It is surfaced as
    context only; `read_cap` below does not use it as cap evidence.

    Tolerant of `/rooms` shape drift (a non-list `rooms` value such as
    `{"rooms": 7}`, non-dict room entries, a missing/non-numeric `last_seq`)
    by returning None. A `TechnocoreError` (network/HTTP) is NOT caught here
    and propagates to the caller.
    """
    overview = client.rooms_overview(limit=100)
    if isinstance(overview, dict):
        rooms_list = overview.get("rooms")
    elif isinstance(overview, list):
        rooms_list = overview
    else:
        rooms_list = None
    if not isinstance(rooms_list, list):
        return None
    for r in rooms_list:
        if not isinstance(r, dict):
            continue
        if r.get("room") == room or r.get("name") == room:
            try:
                return int(r.get("last_seq"))
            except (TypeError, ValueError):
                return None
    return None


# openapi_probe_status: the three DISTINCT facts a `/openapi.json` probe can
# come back with (FIX 4) -- these must never collapse into a single "None"
# the way an earlier version did, because "the service publishes no limit
# maximum" (an examined, affirmative absence) and "the probe itself failed"
# (fetch error, bad JSON, or a doc shape too foreign to examine) are
# different claims and must be reported differently.
OPENAPI_STATUS_DECLARED = "declared"
OPENAPI_STATUS_NO_MAXIMUM = "no_maximum_declared"
OPENAPI_STATUS_UNAVAILABLE = "openapi_unavailable"


def _openapi_declared_read_limit_max(client: TechnocoreClient) -> tuple[str, int | None]:
    """Fetch `/openapi.json` and pull out the declared maximum for `/r/{room}`
    GET's `limit` query parameter -- the service's own authoritative claim
    about its read cap, independent of anything a probe trace can infer.

    Returns `(status, maximum)`:
      - `OPENAPI_STATUS_DECLARED`: the doc was fetched and parsed, the
        `/r/{room}` GET `limit` parameter was found, and its schema declares
        a `maximum` -- `maximum` holds that value.
      - `OPENAPI_STATUS_NO_MAXIMUM`: the doc was fetched and parsed, and the
        `limit` parameter's schema (or the parameter itself) was examined
        and simply has no `maximum` -- an affirmative, examined absence.
        `maximum` is None.
      - `OPENAPI_STATUS_UNAVAILABLE`: the `/openapi.json` GET failed, the
        body wasn't valid JSON, or the document's shape didn't contain a
        recognizable `/r/{room}` GET `limit` parameter to examine at all --
        this is NOT evidence that no maximum exists, only that this probe
        could not check. `maximum` is None.

    Never raises -- a `TechnocoreError` (network/HTTP failure) degrades to
    `OPENAPI_STATUS_UNAVAILABLE`, not a collector failure.
    """
    try:
        text = client.fetch_doc("openapi.json")
    except TechnocoreError:
        return OPENAPI_STATUS_UNAVAILABLE, None
    try:
        spec = json.loads(text)
    except ValueError:
        return OPENAPI_STATUS_UNAVAILABLE, None
    if not isinstance(spec, dict):
        return OPENAPI_STATUS_UNAVAILABLE, None
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return OPENAPI_STATUS_UNAVAILABLE, None
    path_item = paths.get("/r/{room}")
    if not isinstance(path_item, dict):
        return OPENAPI_STATUS_UNAVAILABLE, None
    get_op = path_item.get("get")
    if not isinstance(get_op, dict):
        return OPENAPI_STATUS_UNAVAILABLE, None
    parameters = get_op.get("parameters")
    if not isinstance(parameters, list):
        return OPENAPI_STATUS_UNAVAILABLE, None
    for p in parameters:
        if not isinstance(p, dict) or p.get("name") != "limit":
            continue
        schema = p.get("schema")
        if not isinstance(schema, dict):
            return OPENAPI_STATUS_UNAVAILABLE, None
        if "maximum" not in schema:
            return OPENAPI_STATUS_NO_MAXIMUM, None
        maximum = schema.get("maximum")
        if isinstance(maximum, bool):
            return OPENAPI_STATUS_UNAVAILABLE, None
        if isinstance(maximum, int):
            return OPENAPI_STATUS_DECLARED, maximum
        if isinstance(maximum, float) and maximum.is_integer():
            return OPENAPI_STATUS_DECLARED, int(maximum)
        return OPENAPI_STATUS_UNAVAILABLE, None
    # The parameter list was examined and simply has no `limit` entry.
    return OPENAPI_STATUS_NO_MAXIMUM, None


def read_cap(client: TechnocoreClient, room: str = DEFAULT_DUP_ROOM) -> dict:
    """Probe a room's read cap by asking for successively larger limits, then
    check the result against the service's OWN published limit maximum in
    `/openapi.json` -- the only evidence strong enough to claim a
    server-side cap is demonstrated.

    `room_last_seq` (from `/rooms`) is NOT used as cap evidence: it is a
    high-water mark on sequence numbers ever assigned, not a record count,
    and cannot by itself establish how many records are retained -- a room
    can report a large `last_seq` while holding far fewer live records than
    that. A
    200-message room capped at 200 and an uncapped room that happens to
    hold exactly 200 messages produce an IDENTICAL probe trace
    ([50, 100, 200, 200, 200]); only the OpenAPI-declared maximum, not
    `last_seq`, can tell them apart.
    """
    probes: list[dict] = []
    for i, limit in enumerate(READ_CAP_PROBE_LIMITS):
        if i > 0:
            time.sleep(READ_CAP_SLEEP_S)
        messages = client.read_room(room, since=0, limit=limit)
        if not isinstance(messages, list):
            messages = []
        probes.append({"requested": limit, "returned": len(messages)})

    returned_counts = [p["returned"] for p in probes]
    # observed_cap: max records returned by any probe. This is a description
    # of what came back, NOT a claim about a server-side limit -- that claim
    # is `cap_demonstrated` below, gated on the OpenAPI-declared maximum.
    observed_cap = max(returned_counts) if returned_counts else 0
    monotonic = all(
        returned_counts[i] <= returned_counts[i + 1] for i in range(len(returned_counts) - 1)
    )

    try:
        room_last_seq = _room_last_seq(client, room)
    except TechnocoreError:
        room_last_seq = None

    openapi_probe_status, openapi_declared_max = _openapi_declared_read_limit_max(client)

    # requests_exceeded_returns: a PER-PROBE comparison (FIX 4) -- whether ANY
    # single probe got back fewer records than it asked for. The old
    # `observed_cap < max(requested)` comparison could compare the LARGEST
    # returned count (from any probe) against the LARGEST requested count
    # (from any probe), which are not necessarily the same probe: a trace
    # like [(50, 0), (100, 100), (200, 200), (500, 500), (1000, 1000)] has
    # observed_cap == max(requested) == 1000, so the old check said "no probe
    # requested more than was returned" -- false, since the FIRST probe
    # (50 requested, 0 returned) manifestly did.
    requests_exceeded_returns = any(p["returned"] < p["requested"] for p in probes)

    cap_demonstrated = (
        monotonic
        and requests_exceeded_returns
        and openapi_probe_status == OPENAPI_STATUS_DECLARED
        and observed_cap == openapi_declared_max
    )

    if cap_demonstrated:
        evidence = "cap declared in the service's OpenAPI (limit maximum) and confirmed by probes"
    elif not requests_exceeded_returns:
        evidence = "cap not demonstrated: no probe requested more than was returned"
    elif not monotonic:
        evidence = "cap not demonstrated: returned counts were not monotonic across probes"
    elif openapi_probe_status == OPENAPI_STATUS_UNAVAILABLE:
        evidence = (
            f"cap not demonstrated: probes returned at most {observed_cap} records, "
            "but the service's OpenAPI document could not be fetched or parsed "
            "to check for a declared maximum -- this is NOT the same as the "
            "service publishing no maximum"
        )
    elif openapi_probe_status == OPENAPI_STATUS_NO_MAXIMUM:
        evidence = f"probes returned at most {observed_cap} records but the service publishes no limit maximum"
    else:
        # openapi_probe_status == OPENAPI_STATUS_DECLARED, but it doesn't
        # match what the probes actually observed.
        evidence = (
            f"cap not demonstrated: probes returned at most {observed_cap} records, "
            f"which does not match the published limit maximum ({openapi_declared_max})"
        )

    return {
        "room": room,
        "probes": probes,
        "observed_cap": observed_cap,
        "room_last_seq": room_last_seq,
        "openapi_declared_max": openapi_declared_max,
        "openapi_probe_status": openapi_probe_status,
        "cap_demonstrated": cap_demonstrated,
        "evidence": evidence,
        "monotonic": monotonic,
    }


def _find_signature(record: dict) -> tuple[str | None, object, bool, bool]:
    """Search `record` recursively for a field under the exact SIG_FIELD_NAMES
    set, e.g. a top-level `sig`, or `signature` nested inside a `proof`
    envelope (path "proof.signature"), or inside a list of proof envelopes
    (path "proofs[0].signature"). Recurses into both dicts and lists. No
    substring/heuristic matching.

    Bounded to SIG_SEARCH_MAX_DEPTH levels of nesting and SIG_SEARCH_MAX_NODES
    visited entries total, so a hostile/huge payload can't make this
    pathological -- but a bound that is actually hit means the search did
    NOT exhaustively cover the record, which the caller must be able to
    state (see `truncated` below); a truncated search can never license a
    "no field found anywhere" claim.

    Returns (path, value, saw_empty, truncated):
      - path/value: the first TRUTHY match found (dotted/indexed path,
        depth-first, in the record's own key/list order), or (None, None,
        ...) if none.
      - saw_empty: True if a candidate-named field was present but falsey
        (e.g. `"sig": ""`) -- that is NOT a signature, but it is worth
        recording separately from "field absent entirely".
      - truncated: True if the depth bound or the node budget cut the
        search short anywhere in this record (before a match, if any, was
        found).
    """
    visited = 0
    saw_empty = False
    found: tuple[str, object] | None = None
    truncated = False

    def _walk(node: object, path: str, depth: int) -> None:
        nonlocal visited, saw_empty, found, truncated
        if found is not None:
            return
        if isinstance(node, dict):
            items = list(node.items())
        elif isinstance(node, list):
            items = list(enumerate(node))
        else:
            return
        for k, v in items:
            if found is not None:
                return
            if visited >= SIG_SEARCH_MAX_NODES:
                truncated = True
                return
            visited += 1
            if isinstance(node, dict):
                if not isinstance(k, str):
                    continue
                dotted = f"{path}.{k}" if path else k
                if k in SIG_FIELD_NAMES:
                    if v:
                        found = (dotted, v)
                        return
                    saw_empty = True
                    continue
            else:
                dotted = f"{path}[{k}]"
            if isinstance(v, (dict, list)):
                if depth < SIG_SEARCH_MAX_DEPTH:
                    _walk(v, dotted, depth + 1)
                else:
                    truncated = True

    _walk(record, "", 0)
    if found is None:
        return None, None, saw_empty, truncated
    return found[0], found[1], saw_empty, truncated


def _verify_ed25519_b64(pubkey_bytes: bytes, sig_b64: str, canonical: str) -> bool:
    """Fail-closed Ed25519 verification over a base64url-encoded signature.

    Rejects anything that isn't exactly ED25519_SIG_B64_LEN characters of
    strict unpadded base64url, or that doesn't decode to exactly
    ED25519_SIG_BYTES bytes, before ever calling verify() -- see the
    B64URL_STRICT_RE/ED25519_SIG_B64_LEN/ED25519_SIG_BYTES module comment.
    """
    if len(sig_b64) != ED25519_SIG_B64_LEN or not B64URL_STRICT_RE.match(sig_b64):
        return False
    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        sig_bytes = base64.urlsafe_b64decode(padded)
    except ValueError:
        return False
    if len(sig_bytes) != ED25519_SIG_BYTES:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(sig_bytes, canonical.encode("utf-8"))
    except InvalidSignature:
        return False
    return True


def _find_nonce_value(record: dict) -> object:
    """Return the nonce value, if any, checking known names then any
    integer-valued key whose name contains "nonce"."""
    for k in NONCE_FIELD_CANDIDATES:
        if k in record and record[k] is not None:
            return record[k]
    for k, v in record.items():
        if isinstance(k, str) and "nonce" in k.lower() and isinstance(v, int):
            return v
    return None


def _b58decode(s: str) -> bytes:
    """Decode a base58btc string (the alphabet in `technocore_mcp.identity`)
    back to bytes. Inverse of that module's `_b58` encoder, needed here to go
    from a did:key back to raw public-key bytes for offline verification."""
    n = 0
    for ch in s:
        idx = identity.B58.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == identity.B58[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def _decode_did_key_ed25519(did: str) -> bytes | None:
    """Recover the 32-byte raw Ed25519 public key from a did:key, or None if
    it isn't a well-formed Ed25519 did:key."""
    if not did.startswith("did:key:z"):
        return None
    try:
        raw = _b58decode(did[len("did:key:z") :])
    except ValueError:
        return None
    if not raw.startswith(identity.MULTICODEC_ED25519):
        return None
    key_bytes = raw[len(identity.MULTICODEC_ED25519) :]
    return key_bytes if len(key_bytes) == 32 else None


def signature_retention(client: TechnocoreClient, room: str = DEFAULT_DUP_ROOM, sample: int = 50) -> dict:
    """Determine, from the outside, whether message signatures are exposed on
    read and whether an exposed signature verifies OFFLINE — i.e. without
    trusting the server's own say-so that a message was signed.

    Detection only ever claims what was actually looked for: an exact
    known-name set (SIG_FIELD_NAMES), searched recursively into dicts and
    lists but bounded (see `_find_signature`). `observed_top_level_keys`
    records the real top-level shape seen in the sample, so a "not found"
    verdict can be stated against the fields that were actually there, not
    against every conceivable name; `search_truncated` records whether the
    depth/node bound cut any record's search short, so that verdict never
    silently overclaims completeness.

    Not every exposed signature is checked: a `jws`-named field is a
    compact JWS, which has its own serialization and signing-input
    construction that this checker does not implement, so it is counted as
    exposed-but-unverifiable rather than run through the raw-Ed25519
    verifier below. A record that exposes a genuinely verifiable signature
    but is missing an input needed to check it (nonce, text, or a decodable
    did) is also counted as `offline_unverifiable`, never silently skipped
    into an "all verified" verdict.

    `offline_verified`/`offline_failed`/`offline_unverifiable` (and the
    `verdict` they drive) are scoped to did-lane (signed-lane) records ONLY
    (FIX 5b). A recognized signature-shaped field found on an UNSIGNED-lane
    (plain-nick) record is still counted in `signatures_exposed` above (it
    is real data about the sample), but it is never fed into the did-lane
    offline-verification counters or the verdict -- there is no did:key to
    check it against, and a verdict that is supposed to describe the
    did-lane must never be able to flip on the strength of an unsigned-lane
    record. Earlier logic mixed the two lanes into these counters, which
    could make an all-verified did-lane sample report "some could not be
    checked" purely because of an unrelated plain-nick message.

    NOTE: verification is over the text exactly as returned by the server. If
    the server has already applied its single-line "sweep" to stored text
    (per the canonical-string protocol in `technocore_mcp.identity`), that is
    also what was actually signed, so this is the correct text to verify
    against — we deliberately do not re-sweep here.
    """
    messages = client.read_room(room, since=0, limit=sample)
    if not isinstance(messages, list):
        messages = []

    signed_lane = 0
    unsigned_lane = 0
    signed_lane_with_signature = 0
    signed_lane_empty_signature_fields = 0
    signature_path_counts: Counter = Counter()
    signatures_exposed = 0
    empty_signature_fields = 0
    offline_verified = 0
    offline_failed = 0
    offline_unverifiable = 0
    unverifiable_reasons: set[str] = set()
    top_level_keys_seen: set[str] = set()
    search_truncated = False

    for m in messages:
        if not isinstance(m, dict):
            continue
        top_level_keys_seen.update(k for k in m if isinstance(k, str))

        frm = m.get("from")
        is_did = isinstance(frm, str) and DID_KEY_ED25519_RE.match(frm) is not None
        if is_did:
            signed_lane += 1
        else:
            unsigned_lane += 1

        sig_path, sig_value, saw_empty, truncated = _find_signature(m)
        if truncated:
            search_truncated = True
        if sig_path is not None:
            signatures_exposed += 1
            signature_path_counts[sig_path] += 1
            if is_did:
                signed_lane_with_signature += 1
        elif saw_empty:
            empty_signature_fields += 1
            if is_did:
                signed_lane_empty_signature_fields += 1

        if sig_path is None:
            continue

        # Everything below classifies did-lane records ONLY into the
        # offline-verification counters (FIX 5b). An unsigned-lane record
        # with a recognized sig-shaped field is real data -- already
        # reflected in `signatures_exposed` above -- but there is no did:key
        # to check it against, and it must never feed a verdict that is
        # supposed to describe the did-lane.
        if not is_did:
            continue

        sig_field_name = sig_path.rsplit(".", 1)[-1]

        if sig_field_name not in VERIFIABLE_SIG_FIELD_NAMES:
            # jws (or any other detected-but-unverifiable field name).
            offline_unverifiable += 1
            unverifiable_reasons.add(JWS_UNVERIFIABLE_REASON)
            continue

        nonce_value = _find_nonce_value(m)
        text = m.get("text")
        pubkey_bytes = _decode_did_key_ed25519(frm)

        reasons: list[str] = []
        if nonce_value is None or isinstance(nonce_value, bool) or not isinstance(nonce_value, (int, str)):
            reasons.append("missing or invalid nonce")
        if text is None:
            reasons.append("missing text")
        if pubkey_bytes is None:
            reasons.append("undecodable did")
        if reasons:
            offline_unverifiable += 1
            unverifiable_reasons.update(reasons)
            continue

        if not isinstance(sig_value, str):
            offline_failed += 1
            continue

        canonical = f"{room}|{nonce_value}|{text}"
        if _verify_ed25519_b64(pubkey_bytes, sig_value, canonical):
            offline_verified += 1
        else:
            offline_failed += 1

    signature_path = signature_path_counts.most_common(1)[0][0] if signature_path_counts else None
    signature_field = signature_path.rsplit(".", 1)[-1] if signature_path else None

    # The verdict is a claim about the DID-LANE only, so every count feeding
    # it must itself be did-lane-scoped (FIX 5b): signed_lane,
    # signed_lane_with_signature, signed_lane_empty_signature_fields, and
    # offline_verified/offline_failed/offline_unverifiable (the latter three
    # can now only ever be incremented for is_did records -- see above).
    if signed_lane == 0:
        verdict = "no signed-lane records in sample"
    elif signed_lane_empty_signature_fields > 0 and signed_lane_with_signature == 0:
        verdict = "recognized signature field present but empty in did-lane records"
    elif signed_lane_with_signature == 0:
        verdict = "no recognized signature field in did-lane records"
    elif offline_failed > 0:
        verdict = "signatures exposed; some failed offline verification"
    elif offline_unverifiable > 0:
        verdict = "signatures exposed; some could not be checked"
    else:
        verdict = "signatures exposed; all fully checked signatures verified offline"

    return {
        "room": room,
        "sample": len(messages),
        "signed_lane_records": signed_lane,
        "unsigned_lane_records": unsigned_lane,
        "observed_top_level_keys": sorted(top_level_keys_seen),
        "search_truncated": search_truncated,
        "signature_field": signature_field,
        "signature_path": signature_path,
        "signatures_exposed": signatures_exposed,
        "signed_lane_with_signature": signed_lane_with_signature,
        "empty_signature_fields": empty_signature_fields,
        "offline_verified": offline_verified,
        "offline_failed": offline_failed,
        "offline_unverifiable": offline_unverifiable,
        "unverifiable_reasons": sorted(unverifiable_reasons),
        "verdict": verdict,
    }


def _coerce_seq(val: object) -> int | None:
    """Return `val` as a clean integral sequence number, or None if it isn't
    one. Rejects bool (`isinstance(True, int)` is True in Python -- a bool
    must never pass as a sequence number) and any value with a fractional
    part (e.g. 1.9) rather than silently truncating it: a truncated float
    must never masquerade as a continuous integer sequence."""
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val) if val.is_integer() else None
    if isinstance(val, str) and re.fullmatch(r"-?\d+", val):
        return int(val)
    return None


def sequence_continuity(client: TechnocoreClient, room: str = DEFAULT_DUP_ROOM, at_limit: int = 200) -> dict:
    """Characterise whether a room's visible sequence is continuous, and how
    much history precedes the visible window (rooms are subject to upstream
    retention/reaping)."""
    result: dict = {
        "room": room,
        "first_visible_seq": None,
        "last_visible_seq": None,
        "visible_count": None,
        "span": None,
        "missing_in_span": None,
        "gaps": [],
        "room_last_seq": None,
        "history_before_window": None,
    }

    messages = client.read_room(room, since=0, limit=at_limit)
    if not isinstance(messages, list):
        messages = []
    result["visible_count"] = len(messages)

    seqs: list[int] = []
    saw_invalid = False
    for m in messages:
        if not isinstance(m, dict):
            continue
        val = None
        for k in SEQ_FIELD_CANDIDATES:
            if k in m and m[k] is not None:
                val = m[k]
                break
        if val is None:
            continue
        coerced = _coerce_seq(val)
        if coerced is None:
            saw_invalid = True
            continue
        seqs.append(coerced)

    if not messages or len(seqs) != len(messages):
        result["note"] = (
            "non-integer sequence values"
            if saw_invalid
            else "sequence field absent on one or more visible records"
        )
        return result

    if len(set(seqs)) != len(seqs):
        result["note"] = "duplicate sequence values"
        return result

    seqs.sort()
    first, last = seqs[0], seqs[-1]
    span = last - first + 1
    missing = span - len(seqs)

    gaps = []
    for i in range(len(seqs) - 1):
        a, b = seqs[i], seqs[i + 1]
        if b - a > 1:
            gaps.append({"after": a, "before": b, "missing": b - a - 1})
    gaps.sort(key=lambda g: g["missing"], reverse=True)

    result.update(
        {
            "first_visible_seq": first,
            "last_visible_seq": last,
            "span": span,
            "missing_in_span": missing,
            "gaps": gaps[:MAX_GAPS_REPORTED],
        }
    )

    try:
        result["room_last_seq"] = _room_last_seq(client, room)
    except TechnocoreError:
        result["room_last_seq"] = None

    result["history_before_window"] = max(0, first - 1)

    return result
