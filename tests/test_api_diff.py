"""Offline test for observatory.collect.api_surface against a stub client.

FIX 6 regression coverage: api_surface() must never write baseline_path
itself -- it only READS the existing baseline and returns a `new_baseline`
payload for the caller to persist via `write_api_baseline`, and only the
caller decides WHEN that happens (see observatory.cli.run).
"""

from __future__ import annotations

import json
import os

import pytest

from observatory import collect

_OPENAPI = json.dumps(
    {
        "paths": {
            "/r/{room}": {},
            "/faucet/claim": {},
        }
    }
)
_LLMS = "This is the llms.txt content for technocore.chat.\n"


class _StubClient:
    def fetch_doc(self, name: str) -> str:
        if name == "openapi.json":
            return _OPENAPI
        if name == "llms.txt":
            return _LLMS
        raise AssertionError(f"unexpected doc requested: {name}")


def test_api_surface_detects_added_and_tripwire(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text(json.dumps({"paths": ["/r/{room}"], "llms_sha256": "0" * 64}))

    client = _StubClient()
    result = collect.api_surface(client, baseline_path)

    assert "/faucet/claim" in result["added"]
    assert "/faucet/claim" in result["tripwire"]
    assert result["removed"] == []
    assert result["baseline_created"] is False
    assert result["llms_changed"] is True  # baseline hash was a dummy value

    # api_surface() itself never writes baseline_path (FIX 6) -- the
    # baseline on disk is untouched by the call above.
    on_disk = json.loads(baseline_path.read_text())
    assert on_disk["paths"] == ["/r/{room}"]

    # The caller decides when to persist the new state.
    collect.write_api_baseline(baseline_path, result["new_baseline"])
    written = json.loads(baseline_path.read_text())
    assert sorted(written["paths"]) == ["/faucet/claim", "/r/{room}"]


def test_api_surface_never_writes_the_baseline_file_itself(tmp_path) -> None:
    # Regression for FIX 6: a caller that never calls write_api_baseline
    # must see the baseline file completely unaffected, even across
    # multiple api_surface() calls.
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text(json.dumps({"paths": ["/r/{room}"], "llms_sha256": "0" * 64}))
    before = baseline_path.read_text()

    client = _StubClient()
    collect.api_surface(client, baseline_path)
    collect.api_surface(client, baseline_path)

    assert baseline_path.read_text() == before


def test_api_surface_second_call_is_stable_once_baseline_is_written(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text(json.dumps({"paths": ["/r/{room}"], "llms_sha256": "0" * 64}))

    client = _StubClient()
    first = collect.api_surface(client, baseline_path)
    collect.write_api_baseline(baseline_path, first["new_baseline"])  # caller persists it

    result = collect.api_surface(client, baseline_path)  # second call: same live data

    assert result["added"] == []
    assert result["removed"] == []
    assert result["tripwire"] == []
    assert result["baseline_created"] is False
    assert result["llms_changed"] is False


def test_api_surface_baseline_created_when_no_file_exists(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    assert not baseline_path.exists()

    client = _StubClient()
    result = collect.api_surface(client, baseline_path)

    assert result["baseline_created"] is True
    assert not baseline_path.exists()  # still not written -- FIX 6

    collect.write_api_baseline(baseline_path, result["new_baseline"])
    assert baseline_path.exists()
    on_disk = json.loads(baseline_path.read_text())
    assert sorted(on_disk["paths"]) == ["/faucet/claim", "/r/{room}"]


# ---- FIX B: invalid/unparseable OpenAPI must fail closed -------------------


class _FixedDocClient:
    """Serves a fixed `openapi.json` body (whatever the test wants to probe)
    and the normal `_LLMS` for `llms.txt`."""

    def __init__(self, openapi_text: str):
        self.openapi_text = openapi_text

    def fetch_doc(self, name: str) -> str:
        if name == "openapi.json":
            return self.openapi_text
        if name == "llms.txt":
            return _LLMS
        raise AssertionError(f"unexpected doc requested: {name}")


def test_api_surface_invalid_json_fails_closed_no_mass_removal(tmp_path) -> None:
    # A real baseline with real paths already on disk.
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text(
        json.dumps({"paths": ["/r/{room}", "/rooms", "/healthz"], "llms_sha256": "0" * 64})
    )
    before = baseline_path.read_text()

    client = _FixedDocClient("{not valid json")
    result = collect.api_surface(client, baseline_path)

    # A collector failure, per the module's `TechnocoreError`-dict
    # convention -- never a diff, and never an empty "removed everything"
    # result.
    assert "error" in result
    assert "added" not in result
    assert "removed" not in result
    assert "new_baseline" not in result

    # The existing baseline file on disk is completely untouched.
    assert baseline_path.read_text() == before


def test_api_surface_non_object_openapi_fails_closed(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    client = _FixedDocClient(json.dumps(["not", "an", "object"]))
    result = collect.api_surface(client, baseline_path)
    assert "error" in result
    assert "not a JSON object" in result["error"]


def test_api_surface_non_object_paths_fails_closed(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    client = _FixedDocClient(json.dumps({"paths": "not-a-dict"}))
    result = collect.api_surface(client, baseline_path)
    assert "error" in result
    assert "'paths'" in result["error"]


def test_api_surface_missing_paths_key_is_tolerated_as_zero_paths(tmp_path) -> None:
    # A well-formed-but-degenerate doc (no `paths` key at all) is NOT the
    # same failure mode as broken JSON -- it's tolerated as "zero paths",
    # matching the deliberately narrow scope of FIX B.
    baseline_path = tmp_path / "api-baseline.json"
    client = _FixedDocClient(json.dumps({"info": {}}))
    result = collect.api_surface(client, baseline_path)
    assert "error" not in result
    assert result["paths_total"] == 0


# ---- FIX B: corrupt/unreadable existing baseline must also fail closed ----


def test_api_surface_corrupt_existing_baseline_fails_closed(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text("{not valid json either")
    before = baseline_path.read_text()

    client = _StubClient()
    result = collect.api_surface(client, baseline_path)

    assert "error" in result
    assert "new_baseline" not in result
    # The corrupt file is left exactly as it was -- api_surface() never
    # writes baseline_path itself (FIX 6), and a failure here must not
    # tempt a caller into treating this as "no baseline, start fresh".
    assert baseline_path.read_text() == before


def test_api_surface_unreadable_existing_baseline_fails_closed(tmp_path) -> None:
    # A directory where a file was expected triggers an OSError on read,
    # not a ValueError -- exercises the separate read-failure branch.
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.mkdir()

    client = _StubClient()
    result = collect.api_surface(client, baseline_path)

    assert "error" in result
    assert "new_baseline" not in result


def test_api_surface_baseline_paths_wrong_type_fails_closed(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text(json.dumps({"paths": "not-a-list", "llms_sha256": "0" * 64}))

    client = _StubClient()
    result = collect.api_surface(client, baseline_path)

    assert "error" in result
    assert "'paths'" in result["error"]


# ---- FIX E: write_api_baseline is atomic (temp file + os.replace) ---------


def test_write_api_baseline_leaves_the_old_file_intact_on_replace_failure(
    tmp_path, monkeypatch
) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    original = json.dumps({"paths": ["/old"], "llms_sha256": "a" * 64})
    baseline_path.write_text(original)

    def _boom(_src, _dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", _boom)

    with pytest.raises(OSError):
        collect.write_api_baseline(baseline_path, {"paths": ["/new"], "llms_sha256": "b" * 64})

    # The previous baseline is untouched -- os.replace never completed.
    assert baseline_path.read_text() == original
    # No stray temp file left behind in the directory.
    leftovers = [p for p in tmp_path.iterdir() if p != baseline_path]
    assert leftovers == []


def test_write_api_baseline_writes_the_new_content_on_success(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    collect.write_api_baseline(baseline_path, {"paths": ["/a", "/b"], "llms_sha256": "c" * 64})

    on_disk = json.loads(baseline_path.read_text())
    assert on_disk["paths"] == ["/a", "/b"]
    # No stray temp file left behind after a successful replace.
    leftovers = [p for p in tmp_path.iterdir() if p != baseline_path]
    assert leftovers == []
