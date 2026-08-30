"""Offline tests for observatory.collect.read_cap, signature_retention, and
sequence_continuity.

No network, no technocore-mcp client instantiation — everything here is
plain dicts and tiny stub client objects, same pattern as test_report.py.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from technocore_mcp import identity
from technocore_mcp.client import TechnocoreError

from observatory import collect


def _openapi_doc(declared_max: int | None) -> str:
    """The `/openapi.json` shape `_openapi_declared_read_limit_max` reads:
    `paths["/r/{room}"].get.parameters[].schema.maximum` for the `limit`
    parameter. `declared_max=None` renders a doc with no such parameter at
    all (the "service publishes no limit maximum" case)."""
    if declared_max is None:
        return json.dumps({"paths": {"/r/{room}": {"get": {"parameters": []}}}})
    return json.dumps(
        {
            "paths": {
                "/r/{room}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "limit",
                                "schema": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": declared_max,
                                    "default": 50,
                                },
                            }
                        ]
                    }
                }
            }
        }
    )


class _CapClient:
    """Returns up to `available` messages regardless of the requested limit
    (optionally further capped at `cap`) — a stand-in for a server that
    either has a cap or simply runs out. `room_last_seq`, if given, is
    reported via `rooms_overview` (context only — no longer cap evidence).
    `openapi_declared_max`, if given, is served from `/openapi.json`'s
    `/r/{room}` GET `limit` parameter maximum, the same way the real
    service's OpenAPI doc would."""

    def __init__(
        self,
        available: int,
        cap: int | None = None,
        room_last_seq: int | None = None,
        openapi_declared_max: int | None = None,
    ):
        self.available = available
        self.cap = cap
        self.room_last_seq = room_last_seq
        self.openapi_declared_max = openapi_declared_max
        self.calls: list[int] = []

    def read_room(self, room: str, since: int = 0, limit: int = 50) -> list[dict]:
        self.calls.append(limit)
        n = min(limit, self.available)
        if self.cap is not None:
            n = min(n, self.cap)
        return [{"seq": i} for i in range(n)]

    def rooms_overview(self, limit: int = 100) -> dict:
        if self.room_last_seq is None:
            return {"rooms": []}
        return {"rooms": [{"room": "lobby", "last_seq": self.room_last_seq}]}

    def fetch_doc(self, name: str) -> str:
        assert name == "openapi.json"
        return _openapi_doc(self.openapi_declared_max)


def test_read_cap_declared_max_confirmed_by_probe_demonstrates_cap() -> None:
    # The service's own OpenAPI declares a limit maximum of 200, and a
    # probe asking for more than 200 gets back exactly 200 -- this is the
    # only evidence strong enough to call a cap demonstrated.
    client = _CapClient(available=9_000_000, cap=200, room_last_seq=9_000_000, openapi_declared_max=200)
    result = collect.read_cap(client, room="lobby")

    assert [p["requested"] for p in result["probes"]] == [50, 100, 200, 500, 1000]
    assert [p["returned"] for p in result["probes"]] == [50, 100, 200, 200, 200]
    assert result["observed_cap"] == 200
    assert result["room_last_seq"] == 9_000_000
    assert result["openapi_declared_max"] == 200
    assert result["cap_demonstrated"] is True
    assert result["evidence"] == (
        "cap declared in the service's OpenAPI (limit maximum) and confirmed by probes"
    )
    assert result["monotonic"] is True
    assert "room_message_count_lower_bound" not in result


def test_read_cap_demonstrated_even_without_room_last_seq_evidence() -> None:
    # room_last_seq is context only now: a cap can be demonstrated purely
    # from the OpenAPI-declared maximum plus a confirming probe, with no
    # /rooms size evidence at all -- the reverse of the old (removed)
    # dependency on room_last_seq.
    client = _CapClient(available=9_000_000, cap=200, room_last_seq=None, openapi_declared_max=200)
    result = collect.read_cap(client, room="lobby")

    assert result["room_last_seq"] is None
    assert result["cap_demonstrated"] is True


def test_read_cap_no_declared_max_not_demonstrated_even_with_room_size_symptom() -> None:
    # Requests exceeded returns and the room is far larger than the
    # returned window -- exactly the symptom the OLD, removed heuristic
    # treated as proof of a cap -- but the service publishes no OpenAPI
    # limit maximum, so no cap may be claimed on room_last_seq alone
    # (upstream reaps rooms; last_seq is not a record count).
    client = _CapClient(available=9_000_000, cap=200, room_last_seq=9_000_000, openapi_declared_max=None)
    result = collect.read_cap(client, room="lobby")

    assert result["observed_cap"] == 200
    assert result["openapi_declared_max"] is None
    assert result["cap_demonstrated"] is False
    assert result["evidence"] == (
        "probes returned at most 200 records but the service publishes no limit maximum"
    )


def test_read_cap_no_probe_exceeded_returns_is_not_demonstrated() -> None:
    # An uncapped room big enough that even the largest probe (1000) still
    # gets back everything it asked for -- no probe ever requested more
    # than it received, so nothing resembling a cap was even observed.
    client = _CapClient(available=2_000, room_last_seq=2_000, openapi_declared_max=200)
    result = collect.read_cap(client, room="lobby")

    assert [p["returned"] for p in result["probes"]] == [50, 100, 200, 500, 1000]
    assert result["observed_cap"] == 1000
    assert result["cap_demonstrated"] is False
    assert result["evidence"] == "cap not demonstrated: no probe requested more than was returned"


class _NonMonotonicClient:
    """A pathological, non-monotonic probe trace -- a genuine server-side
    cap can never produce this, so it must never be reported as
    demonstrated regardless of what OpenAPI declares or whether requests
    exceeded returns."""

    def __init__(self, returns: list[int], openapi_declared_max: int | None):
        self._returns = list(returns)
        self.openapi_declared_max = openapi_declared_max

    def read_room(self, room: str, since: int = 0, limit: int = 50) -> list[dict]:
        n = self._returns.pop(0)
        return [{"seq": i} for i in range(n)]

    def rooms_overview(self, limit: int = 100) -> dict:
        return {"rooms": []}

    def fetch_doc(self, name: str) -> str:
        assert name == "openapi.json"
        return _openapi_doc(self.openapi_declared_max)


def test_read_cap_non_monotonic_trace_never_demonstrates_a_cap() -> None:
    # [50, 100, 200, 500, 0] -- even though observed_cap (500) exactly
    # matches a declared max of 500 and requests exceeded returns, the
    # trace itself is impossible for a real cap to produce.
    client = _NonMonotonicClient(returns=[50, 100, 200, 500, 0], openapi_declared_max=500)
    result = collect.read_cap(client, room="lobby")

    assert result["monotonic"] is False
    assert result["observed_cap"] == 500
    assert result["openapi_declared_max"] == 500
    assert result["cap_demonstrated"] is False


def test_read_cap_rooms_shape_drift_does_not_raise() -> None:
    # {"rooms": 7} instead of a list -- must degrade room_last_seq to None,
    # not raise, and must not affect the (OpenAPI-based) cap verdict.
    class _DriftClient(_CapClient):
        def rooms_overview(self, limit: int = 100) -> dict:
            return {"rooms": 7}

    client = _DriftClient(available=10_000, cap=200, openapi_declared_max=200)
    result = collect.read_cap(client, room="lobby")

    assert result["room_last_seq"] is None
    assert result["cap_demonstrated"] is True


def test_read_cap_openapi_doc_shape_drift_degrades_to_none() -> None:
    # Malformed/unparsable OpenAPI JSON must degrade to no declared-max
    # evidence, never raise.
    class _BadOpenApiClient(_CapClient):
        def fetch_doc(self, name: str) -> str:
            return "not json"

    client = _BadOpenApiClient(available=9_000_000, cap=200, room_last_seq=9_000_000)
    result = collect.read_cap(client, room="lobby")

    assert result["openapi_declared_max"] is None
    assert result["cap_demonstrated"] is False


def test_read_cap_openapi_fetch_error_degrades_to_none() -> None:
    # A failed /openapi.json fetch (network/HTTP) must degrade to no
    # declared-max evidence, never raise or abort the whole collector.
    class _ErrorOpenApiClient(_CapClient):
        def fetch_doc(self, name: str) -> str:
            raise TechnocoreError(500, "boom")

    client = _ErrorOpenApiClient(available=9_000_000, cap=200)
    result = collect.read_cap(client, room="lobby")

    assert result["openapi_declared_max"] is None
    assert result["cap_demonstrated"] is False


# ---- FIX 4 regressions ------------------------------------------------


class _EarlyZeroThenUncappedClient:
    """The FIRST probe returns 0 records regardless of what it asks for;
    every later probe returns exactly what it asked for (fully uncapped
    otherwise). This is the exact shape FIX 4 targets: the OLD
    `observed_cap < max(requested)` comparison saw observed_cap (1000, from
    the LAST probe) equal to max(requested) (1000) and concluded "no probe
    requested more than was returned" -- false, since the FIRST probe (50
    requested, 0 returned) manifestly did. A per-probe comparison must catch
    this regardless of trace position."""

    def __init__(self, openapi_declared_max: int | None = None):
        self.calls: list[int] = []
        self.openapi_declared_max = openapi_declared_max

    def read_room(self, room: str, since: int = 0, limit: int = 50) -> list[dict]:
        self.calls.append(limit)
        if len(self.calls) == 1:
            return []
        return [{"seq": i} for i in range(limit)]

    def rooms_overview(self, limit: int = 100) -> dict:
        return {"rooms": []}

    def fetch_doc(self, name: str) -> str:
        assert name == "openapi.json"
        return _openapi_doc(self.openapi_declared_max)


def test_read_cap_per_probe_comparison_catches_early_shortfall() -> None:
    client = _EarlyZeroThenUncappedClient()
    result = collect.read_cap(client, room="lobby")

    assert [p["requested"] for p in result["probes"]] == [50, 100, 200, 500, 1000]
    assert [p["returned"] for p in result["probes"]] == [0, 100, 200, 500, 1000]
    assert result["observed_cap"] == 1000
    # The old bug: observed_cap (1000) == max(requested) (1000) was read as
    # "no probe requested more than was returned". The first probe alone
    # (50 requested, 0 returned) refutes that -- the fixed evidence string
    # must not claim it.
    assert result["evidence"] != "cap not demonstrated: no probe requested more than was returned"
    assert result["cap_demonstrated"] is False  # no declared max in this doc


def test_read_cap_openapi_unavailable_evidence_distinct_from_no_maximum_declared() -> None:
    # FIX 4: a fetch/parse FAILURE must never be reported with the same
    # "publishes no limit maximum" sentence as a genuinely examined
    # absence -- these are different facts about what was actually checked.
    class _BadOpenApiClient(_CapClient):
        def fetch_doc(self, name: str) -> str:
            return "not json"

    client = _BadOpenApiClient(available=9_000_000, cap=200, room_last_seq=9_000_000)
    result = collect.read_cap(client, room="lobby")

    assert result["openapi_probe_status"] == collect.OPENAPI_STATUS_UNAVAILABLE
    assert result["openapi_declared_max"] is None
    assert "could not be fetched or parsed" in result["evidence"]
    assert "publishes no limit maximum" not in result["evidence"]


def test_read_cap_no_maximum_declared_status_is_distinct_and_labeled() -> None:
    client = _CapClient(available=9_000_000, cap=200, openapi_declared_max=None)
    result = collect.read_cap(client, room="lobby")

    assert result["openapi_probe_status"] == collect.OPENAPI_STATUS_NO_MAXIMUM
    assert result["evidence"] == (
        "probes returned at most 200 records but the service publishes no limit maximum"
    )


def test_read_cap_declared_status_recorded_alongside_max() -> None:
    client = _CapClient(available=9_000_000, cap=200, openapi_declared_max=200)
    result = collect.read_cap(client, room="lobby")

    assert result["openapi_probe_status"] == collect.OPENAPI_STATUS_DECLARED
    assert result["openapi_declared_max"] == 200


class _RoomClient:
    """Minimal stand-in exposing read_room + rooms_overview."""

    def __init__(self, messages: list[dict], rooms_overview: object | None = None):
        self._messages = messages
        self._rooms_overview = rooms_overview if rooms_overview is not None else {"rooms": []}

    def read_room(self, room: str, since: int = 0, limit: int = 200) -> list[dict]:
        return self._messages

    def rooms_overview(self, limit: int = 100) -> object:
        return self._rooms_overview


def _signed_message(room: str, text: str, nonce: str = "1700000000000") -> dict:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    did = identity.did_of(key)
    sig = identity.sign_canonical(key, f"{room}|{nonce}|{text}")
    return {"from": did, "text": text, "nonce": nonce, "sig": sig}


def test_signature_retention_no_signed_records() -> None:
    messages = [{"from": "some_nick", "text": "gm"} for _ in range(3)]
    client = _RoomClient(messages)
    result = collect.signature_retention(client, room="lobby", sample=50)

    assert result["signed_lane_records"] == 0
    assert result["unsigned_lane_records"] == 3
    assert result["verdict"] == "no signed-lane records in sample"


def test_signature_retention_no_recognized_field() -> None:
    # did-lane authors, but no field carrying a signature.
    messages = [
        {"from": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "text": "hi"},
    ]
    client = _RoomClient(messages)
    result = collect.signature_retention(client, room="lobby", sample=50)

    assert result["signed_lane_records"] == 1
    assert result["signature_path"] is None
    assert result["signature_field"] is None
    assert result["signatures_exposed"] == 0
    assert result["observed_top_level_keys"] == ["from", "text"]
    assert result["verdict"] == "no recognized signature field in did-lane records"


def test_signature_retention_valid_signature_verifies_offline() -> None:
    room = "lobby"
    msg = _signed_message(room, "a genuinely signed message")
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signed_lane_records"] == 1
    assert result["signed_lane_with_signature"] == 1
    assert result["signature_field"] == "sig"
    assert result["signature_path"] == "sig"
    assert result["signatures_exposed"] == 1
    assert result["offline_verified"] == 1
    assert result["offline_failed"] == 0
    assert result["offline_unverifiable"] == 0
    assert result["search_truncated"] is False
    assert result["verdict"] == "signatures exposed; all fully checked signatures verified offline"


def test_signature_retention_invalid_signature_fails_offline() -> None:
    room = "lobby"
    msg = _signed_message(room, "a genuinely signed message")
    # Tamper with the stored text after signing -- the signature no longer
    # covers what's stored, so offline verification must fail.
    msg["text"] = "a genuinely signed message, but edited after the fact"
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signatures_exposed"] == 1
    assert result["offline_verified"] == 0
    assert result["offline_failed"] == 1
    assert result["verdict"] == "signatures exposed; some failed offline verification"


def test_signature_retention_finds_nested_proof_signature() -> None:
    room = "lobby"
    msg = _signed_message(room, "nested proof carries the signature")
    msg["proof"] = {"signature": msg.pop("sig")}
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signature_path"] == "proof.signature"
    assert result["signature_field"] == "signature"
    assert result["signatures_exposed"] == 1
    assert result["offline_verified"] == 1
    assert result["verdict"] == "signatures exposed; all fully checked signatures verified offline"


def test_signature_retention_finds_jws_field_but_does_not_verify_it() -> None:
    # jws is a compact JWS, not a raw Ed25519 signature -- it must be
    # counted as exposed (the field is genuinely there) but NOT run through
    # the raw-signature verifier, and reported as unverifiable with a
    # specific reason.
    room = "lobby"
    msg = _signed_message(room, "jws-named signature field")
    msg["jws"] = msg.pop("sig")
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signature_path"] == "jws"
    assert result["signatures_exposed"] == 1
    assert result["signed_lane_with_signature"] == 1
    assert result["offline_verified"] == 0
    assert result["offline_failed"] == 0
    assert result["offline_unverifiable"] == 1
    assert result["unverifiable_reasons"] == ["jws serialization not supported by this checker"]
    assert result["verdict"] == "signatures exposed; some could not be checked"


def test_signature_retention_falsey_field_yields_present_but_empty_verdict() -> None:
    # "sig": "" is a recognized field that IS present, just empty -- the
    # verdict must say so, not claim no recognized field exists.
    messages = [
        {
            "from": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "text": "hi",
            "sig": "",
            "signal": "green",
        }
    ]
    client = _RoomClient(messages)
    result = collect.signature_retention(client, room="lobby", sample=50)

    assert result["signatures_exposed"] == 0
    assert result["empty_signature_fields"] == 1
    assert result["signature_path"] is None
    assert result["observed_top_level_keys"] == ["from", "sig", "signal", "text"]
    assert result["verdict"] == "recognized signature field present but empty in did-lane records"


def test_signature_retention_finds_signature_nested_in_a_list() -> None:
    # {"proofs": [{...}, {"signature": ...}]} -- recursion must enter lists,
    # not just dicts.
    room = "lobby"
    msg = _signed_message(room, "signature nested inside a list of proofs")
    msg["proofs"] = [{"type": "ed25519"}, {"signature": msg.pop("sig")}]
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signature_path"] == "proofs[1].signature"
    assert result["signature_field"] == "signature"
    assert result["signatures_exposed"] == 1
    assert result["offline_verified"] == 1
    assert result["verdict"] == "signatures exposed; all fully checked signatures verified offline"


def test_signature_retention_search_truncated_by_depth_bound() -> None:
    # A genuine signature nested deeper than SIG_SEARCH_MAX_DEPTH must not
    # be found, AND the result must say the search was truncated -- it must
    # never license a bare "no recognized field" claim without that caveat.
    room = "lobby"
    msg = _signed_message(room, "buried too deep to find")
    sig = msg.pop("sig")
    msg["a"] = {"b": {"c": {"d": {"signature": sig}}}}
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signature_path"] is None
    assert result["search_truncated"] is True
    assert result["verdict"] == "no recognized signature field in did-lane records"


def test_signature_retention_non_did_author_with_signature_is_out_of_scope_for_did_lane() -> None:
    # FIX 5b: a recognized signature field on a record whose author is a
    # plain nick (not a did:key) is real data -- it IS counted in
    # `signatures_exposed` (a sample-wide, lane-agnostic count) -- but it
    # must NEVER be counted into the did-lane offline-verification counters
    # (offline_verified/offline_failed/offline_unverifiable) or feed the
    # verdict, which are both scoped to the did-lane only. Earlier logic
    # mixed the two lanes together here, which could make an all-verified
    # did-lane sample report "some could not be checked" purely because of
    # an unrelated unsigned-lane message.
    room = "lobby"
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    sig = identity.sign_canonical(key, f"{room}|1|hello")
    msg = {"from": "some_nick", "text": "hello", "nonce": "1", "sig": sig}
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signed_lane_records"] == 0
    assert result["unsigned_lane_records"] == 1
    assert result["signatures_exposed"] == 1
    assert result["signed_lane_with_signature"] == 0
    assert result["offline_verified"] == 0
    assert result["offline_failed"] == 0
    assert result["offline_unverifiable"] == 0
    assert result["unverifiable_reasons"] == []
    # No did-lane records at all -> that verdict wins, unaffected by the
    # unsigned-lane record's signature-shaped field.
    assert result["verdict"] == "no signed-lane records in sample"


def test_signature_retention_unsigned_lane_garbage_sig_never_pollutes_did_lane_verdict() -> None:
    # Regression for FIX 5b: a fully-formed did-lane sample (verifies clean)
    # PLUS an unrelated unsigned-lane record carrying a garbage-but-present
    # sig field must still report the did-lane as fully verified -- the
    # unsigned-lane record must not be able to flip the verdict to "some
    # could not be checked" or "some failed".
    room = "lobby"
    good = _signed_message(room, "a genuinely signed message")
    noise = {"from": "some_nick", "text": "unrelated", "sig": "not-a-real-signature"}
    client = _RoomClient([good, noise])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signed_lane_records"] == 1
    assert result["unsigned_lane_records"] == 1
    assert result["signatures_exposed"] == 2  # both records counted, lane-agnostic
    assert result["offline_verified"] == 1
    assert result["offline_failed"] == 0
    assert result["offline_unverifiable"] == 0
    assert result["verdict"] == "signatures exposed; all fully checked signatures verified offline"


def test_signature_retention_tampered_signature_string_fails_closed() -> None:
    # A genuinely valid signature with garbage appended must count as
    # FAILED, never as verified -- base64.urlsafe_b64decode is permissive
    # enough to still decode this.
    room = "lobby"
    msg = _signed_message(room, "a genuinely signed message")
    msg["sig"] = msg["sig"] + "!!!!"
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["offline_verified"] == 0
    assert result["offline_failed"] == 1
    assert result["verdict"] == "signatures exposed; some failed offline verification"


def test_signature_retention_wrong_length_signature_fails() -> None:
    room = "lobby"
    msg = _signed_message(room, "short")
    msg["sig"] = msg["sig"][:-1]  # 85 chars -- still a valid alphabet, wrong length
    client = _RoomClient([msg])
    result = collect.signature_retention(client, room=room, sample=50)

    assert len(msg["sig"]) == 85
    assert result["offline_failed"] == 1
    assert result["offline_verified"] == 0


def test_verify_ed25519_b64_rejects_wrong_decoded_length() -> None:
    # A correct-length (86 chars), strictly-valid-alphabet base64url string
    # always decodes to exactly 64 bytes by construction, so this path is
    # unreachable through signature_retention() once the length-86
    # precondition holds. Exercised directly as defense in depth for the
    # decoded-byte-count guard.
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pubkey_bytes = key.public_key().public_bytes_raw()
    short_but_valid_alphabet = "A" * 43  # decodes to 32 bytes, not 64
    assert collect._verify_ed25519_b64(pubkey_bytes, short_but_valid_alphabet, "x") is False


def test_signature_retention_missing_nonce_is_unverifiable_not_failed() -> None:
    room = "lobby"
    good = _signed_message(room, "a genuinely signed message")
    incomplete = _signed_message(room, "another signed message")
    del incomplete["nonce"]
    client = _RoomClient([good, incomplete])
    result = collect.signature_retention(client, room=room, sample=50)

    assert result["signatures_exposed"] == 2
    assert result["offline_verified"] == 1
    assert result["offline_failed"] == 0
    assert result["offline_unverifiable"] == 1
    assert result["unverifiable_reasons"] == ["missing or invalid nonce"]
    assert result["verdict"] == "signatures exposed; some could not be checked"


def test_sequence_continuity_continuous() -> None:
    messages = [{"seq": i} for i in range(1, 11)]
    client = _RoomClient(messages, rooms_overview={"rooms": [{"room": "lobby", "last_seq": 10}]})
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["first_visible_seq"] == 1
    assert result["last_visible_seq"] == 10
    assert result["span"] == 10
    assert result["missing_in_span"] == 0
    assert result["gaps"] == []
    assert result["room_last_seq"] == 10
    assert result["history_before_window"] == 0


def test_sequence_continuity_with_gaps() -> None:
    seqs = [5, 6, 7, 10, 11, 20]
    messages = [{"seq": s} for s in seqs]
    client = _RoomClient(messages, rooms_overview={"rooms": [{"room": "lobby", "last_seq": 20}]})
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["first_visible_seq"] == 5
    assert result["last_visible_seq"] == 20
    assert result["span"] == 16
    assert result["visible_count"] == 6
    assert result["missing_in_span"] == 10
    assert result["gaps"][0] == {"after": 11, "before": 20, "missing": 8}
    assert result["history_before_window"] == 4


def test_sequence_continuity_missing_seq_field_is_tolerant() -> None:
    messages = [{"text": "no seq here"}, {"seq": 3}]
    client = _RoomClient(messages)
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["first_visible_seq"] is None
    assert result["note"] == "sequence field absent on one or more visible records"


def test_sequence_continuity_garbage_seq_field_is_tolerant() -> None:
    messages = [{"seq": "not-a-number"}, {"seq": 3}]
    client = _RoomClient(messages)
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["first_visible_seq"] is None
    assert result["note"] == "non-integer sequence values"


def test_sequence_continuity_rejects_non_integral_floats() -> None:
    # Must NOT be silently truncated to a fake-continuous [1, 2].
    messages = [{"seq": 1.9}, {"seq": 2.9}]
    client = _RoomClient(messages)
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["first_visible_seq"] is None
    assert result["missing_in_span"] is None
    assert result["note"] == "non-integer sequence values"


def test_sequence_continuity_rejects_boolean_seq() -> None:
    # A Python bool is an int -- must be excluded explicitly.
    messages = [{"seq": True}, {"seq": 2}]
    client = _RoomClient(messages)
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["first_visible_seq"] is None
    assert result["note"] == "non-integer sequence values"


def test_sequence_continuity_rejects_duplicate_seqs() -> None:
    # [1, 1, 2] must not be treated as continuous, and must never produce a
    # negative missing_in_span.
    messages = [{"seq": 1}, {"seq": 1}, {"seq": 2}]
    client = _RoomClient(messages)
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["note"] == "duplicate sequence values"
    assert result["missing_in_span"] is None


def test_sequence_continuity_rooms_shape_drift_does_not_raise() -> None:
    # {"rooms": 7} instead of a list must not raise -- must degrade to None.
    messages = [{"seq": i} for i in range(1, 6)]
    client = _RoomClient(messages, rooms_overview={"rooms": 7})
    result = collect.sequence_continuity(client, room="lobby", at_limit=200)

    assert result["room_last_seq"] is None
    assert result["first_visible_seq"] == 1


# ---- FIX 2 regressions (census rooms_shown vs rooms_total) ---------------


class _CensusClient:
    def __init__(self, rooms: list[dict], total: object = "OMIT", engagement: dict | None = None):
        self._rooms = rooms
        self._total = total
        self._engagement = engagement

    def rooms_overview(self, limit: int = 100) -> dict:
        data: dict = {"rooms": self._rooms, "engagement": self._engagement}
        if self._total != "OMIT":
            data["total"] = self._total
        return data


def test_census_reports_limit_alongside_shown_count() -> None:
    rooms = [{"room": f"r{i}", "last_seq": i} for i in range(5)]
    client = _CensusClient(rooms, total=37_320)
    result = collect.census(client)

    assert result["rooms_shown"] == 5
    assert result["rooms_shown_limit"] == collect.DEFAULT_CENSUS_LIMIT
    assert result["rooms_total"] == 37_320


def test_census_rooms_total_none_when_field_absent() -> None:
    rooms = [{"room": "r0", "last_seq": 1}]
    client = _CensusClient(rooms, total="OMIT")
    result = collect.census(client)

    assert result["rooms_total"] is None


def test_census_rooms_total_none_when_field_is_wrong_type() -> None:
    # A drifted /rooms response with a non-integer "total" must never be
    # rendered as a real total (FIX 2: never guess or coerce).
    rooms = [{"room": "r0", "last_seq": 1}]
    client = _CensusClient(rooms, total="a lot")
    result = collect.census(client)

    assert result["rooms_total"] is None


def test_census_rooms_total_none_when_data_is_a_list() -> None:
    # The tolerant `list` shape (no wrapping object) has no `total` field to
    # read at all.
    class _ListClient:
        def rooms_overview(self, limit: int = 100) -> list:
            return [{"room": "r0", "last_seq": 1}]

    result = collect.census(_ListClient())
    assert result["rooms_total"] is None
    assert result["rooms_shown"] == 1
