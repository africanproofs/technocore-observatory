"""Offline test for observatory.collect.api_surface against a stub client."""

from __future__ import annotations

import json

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

    # baseline_path was rewritten to the current state
    written = json.loads(baseline_path.read_text())
    assert sorted(written["paths"]) == ["/faucet/claim", "/r/{room}"]


def test_api_surface_second_call_is_stable(tmp_path) -> None:
    baseline_path = tmp_path / "api-baseline.json"
    baseline_path.write_text(json.dumps({"paths": ["/r/{room}"], "llms_sha256": "0" * 64}))

    client = _StubClient()
    collect.api_surface(client, baseline_path)  # first call: writes current state as baseline

    result = collect.api_surface(client, baseline_path)  # second call: same live data

    assert result["added"] == []
    assert result["removed"] == []
    assert result["tripwire"] == []
    assert result["baseline_created"] is False
    assert result["llms_changed"] is False
