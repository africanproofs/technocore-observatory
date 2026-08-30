"""Offline tests for observatory.cli's publication-safety logic: collector
failure gating, the signer preflight, the git evidence check that gates
`publish` (FIX 1), the api-surface baseline transactionality (FIX 6), and
the signer key-binding fix (FIX 8 / FIX A -- now a real `key=` parameter on
`say_signed`, not a monkeypatch of `identity.load_key`).

No network — every `observatory.collect` function is monkeypatched to a
canned dict, `TechnocoreClient` is monkeypatched to a small fake, and
report/state file paths are redirected under `tmp_path` so a test run never
touches this repo's real `reports/` or `state/` directories. The git
preconditions in `resolve_pushed_commit`/`publish` DO shell out to a real
`git` binary, but only ever against a throwaway repo built fresh under
`tmp_path` for that test -- never this repo, never the network (no `git
fetch`/`push`/`clone` anywhere in these tests).

Gotcha worth flagging: `cli.publish`'s `date` parameter is declared with a
`typer.Option(...)` default for CLI parsing. Calling `cli.publish()` as a
plain Python function (as these tests do) bypasses Typer's runtime
substitution for the DEFAULT, but passing `date=...` explicitly works fine
-- these tests always pass it explicitly except where the "use
latest-summary.json's date" behavior is itself under test.
"""

from __future__ import annotations

import json
import subprocess

import pytest
from technocore_mcp.client import TechnocoreError
from technocore_mcp.identity import IdentityError

from observatory import cli, collect, report


def _canned() -> dict:
    return {
        "census": {
            "rooms_shown": 1,
            "rooms_shown_limit": 100,
            "rooms_total": 5,
            "engagement": None,
            "total_last_seq": 1,
            "top_rooms": [],
        },
        "duplicates": {
            "room": "lobby",
            "sample": 1,
            "distinct_texts": 1,
            "duplicate_share": 0.0,
            "distinct_sender_ids": 1,
            "top_templates": [],
        },
        "api": {
            "paths_total": 1,
            "added": [],
            "removed": [],
            "tripwire": [],
            "llms_changed": False,
            "baseline_created": True,
            "new_baseline": {"paths": ["/a"], "llms_sha256": "0" * 64, "updated_at": "2026-08-29T00:00:00+00:00"},
        },
        "health": {"healthz_ms": 1, "healthz_status": 200, "read_ms": 1},
        "read_cap": {
            "room": "lobby",
            "probes": [{"requested": 50, "returned": 1}],
            "observed_cap": 1,
            "room_last_seq": 1,
            "openapi_declared_max": None,
            "openapi_probe_status": collect.OPENAPI_STATUS_NO_MAXIMUM,
            "cap_demonstrated": False,
            "evidence": "cap not demonstrated: no probe requested more than was returned",
            "monotonic": True,
        },
        "sequence_continuity": {
            "room": "lobby",
            "first_visible_seq": 1,
            "last_visible_seq": 1,
            "visible_count": 1,
            "span": 1,
            "missing_in_span": 0,
            "gaps": [],
            "room_last_seq": 1,
            "history_before_window": 0,
        },
        "signature_retention": {
            "room": "lobby",
            "sample": 1,
            "signed_lane_records": 0,
            "unsigned_lane_records": 1,
            "observed_top_level_keys": ["from", "text"],
            "search_truncated": False,
            "signature_field": None,
            "signature_path": None,
            "signatures_exposed": 0,
            "signed_lane_with_signature": 0,
            "empty_signature_fields": 0,
            "offline_verified": 0,
            "offline_failed": 0,
            "offline_unverifiable": 0,
            "unverifiable_reasons": [],
            "verdict": "no signed-lane records in sample",
        },
    }


class _FakeClient:
    """Stand-in for TechnocoreClient. Once collect.* is monkeypatched, only
    close()/say_signed()/kv_set() are ever exercised by cli.run()/publish()."""

    def __init__(self):
        self.closed = False
        self.said: list[tuple[str, str]] = []
        self.said_keys: list[object] = []
        self.kv_sets: list[tuple[str, str, str]] = []
        self.say_signed_result: object = {
            "status": 200,
            "did": "did:key:test",
            "nonce": "1",
            "response": "ok",
        }

    def close(self) -> None:
        self.closed = True

    def say_signed(self, room: str, text: str, key: object = None) -> dict:
        # Mirrors the real `TechnocoreClient.say_signed(room, text, key=...)`
        # signature (FIX A) -- `key`, when given, is recorded so a test can
        # assert it was the EXACT verified key object, never re-resolved.
        self.said.append((room, text))
        self.said_keys.append(key)
        if isinstance(self.say_signed_result, Exception):
            raise self.say_signed_result
        return self.say_signed_result

    def kv_set(self, ns: str, key: str, value: str) -> str:
        self.kv_sets.append((ns, key, value))
        return "ok"


@pytest.fixture()
def fake_client(monkeypatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(cli, "TechnocoreClient", lambda: client)
    return client


@pytest.fixture(autouse=True)
def _isolate_filesystem_and_collectors(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(cli, "SUMMARY_PATH", tmp_path / "reports" / "latest-summary.json")
    monkeypatch.setattr(cli, "STATE_PATH", tmp_path / "state" / "api-baseline.json")

    results = _canned()
    monkeypatch.setattr(collect, "census", lambda client: dict(results["census"]))
    monkeypatch.setattr(collect, "duplicates", lambda client: dict(results["duplicates"]))
    monkeypatch.setattr(collect, "api_surface", lambda client, path: json.loads(json.dumps(results["api"])))
    monkeypatch.setattr(collect, "health", lambda client: dict(results["health"]))
    monkeypatch.setattr(collect, "read_cap", lambda client: dict(results["read_cap"]))
    monkeypatch.setattr(
        collect,
        "sequence_continuity",
        lambda client, at_limit=None: dict(results["sequence_continuity"]),
    )
    monkeypatch.setattr(
        collect, "signature_retention", lambda client: dict(results["signature_retention"])
    )
    return results


def _run_git(args: list[str], cwd) -> None:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"


@pytest.fixture()
def git_repo(tmp_path, monkeypatch):
    """A throwaway git repo under tmp_path, wired up as `cli.REPO_ROOT` (and
    `REPORTS_DIR`/`SUMMARY_PATH`/`STATE_PATH` inside it), for exercising
    `resolve_pushed_commit`/`publish`'s git-evidence checks without ever
    touching this actual repo or the network."""
    root = tmp_path / "repo"
    root.mkdir()
    _run_git(["init", "-q"], root)
    _run_git(["config", "user.email", "test@example.com"], root)
    _run_git(["config", "user.name", "test"], root)
    # FIX C: "pushed" now means pushed to the actual
    # africanproofs/technocore-observatory repo (`_verify_origin_remote`),
    # not just any remote-tracking ref -- so the throwaway repo needs a
    # real `origin` remote configured pointing there. No network access
    # happens against this URL (only `git remote get-url` is ever run).
    _run_git(["remote", "add", "origin", "https://github.com/africanproofs/technocore-observatory.git"], root)
    (root / "reports").mkdir()

    monkeypatch.setattr(cli, "REPO_ROOT", root)
    monkeypatch.setattr(cli, "REPORTS_DIR", root / "reports")
    monkeypatch.setattr(cli, "SUMMARY_PATH", root / "reports" / "latest-summary.json")
    monkeypatch.setattr(cli, "STATE_PATH", root / "state" / "api-baseline.json")
    return root


def _commit_and_push(root, *rel_paths: str) -> str:
    """Commit `rel_paths` (one or more) and mark the commit as pushed to
    `origin` (a local `refs/remotes/origin/master` ref pointing at HEAD --
    no actual network push happens)."""
    _run_git(["add", *rel_paths], root)
    _run_git(["commit", "-q", "-m", "test"], root)
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    sha = proc.stdout.strip()
    _run_git(["update-ref", "refs/remotes/origin/master", sha], root)
    return sha


def _commit_valid_report_and_summary(root, date: str, results: dict | None = None) -> tuple[dict, str]:
    """Write + commit + push a report/summary pair that satisfies FIX C's
    byte-for-byte binding check: the committed `reports/<date>.md` is
    exactly `report.render_report()` of the committed
    `reports/latest-summary.json`, both in the SAME commit. Use this for
    any test that needs `publish` to get PAST the evidence/consistency
    checks (to exercise the collector-gate, signer preflight, or posting
    logic further down)."""
    summary = _write_summary(root, date, results if results is not None else _canned())
    report_path = root / "reports" / f"{date}.md"
    report_path.write_text(report.render_report(summary))
    sha = _commit_and_push(root, f"reports/{date}.md", "reports/latest-summary.json")
    return summary, sha


# ---- pure helper functions -------------------------------------------------


def test_collector_failed_true_on_error_key() -> None:
    assert cli.collector_failed({"census": {"error": "boom"}}, "census") is True


def test_collector_failed_false_without_error_key() -> None:
    assert cli.collector_failed({"census": {"rooms_shown": 1}}, "census") is False


def test_collector_failed_health_requires_both_probes_none() -> None:
    # A partial health failure (one probe succeeded) is NOT a collector
    # failure -- only carries a benign "error" key alongside real data.
    partial = {"health": {"healthz_ms": 42, "read_ms": None, "error": "read timed out"}}
    assert cli.collector_failed(partial, "health") is False

    total = {"health": {"healthz_ms": None, "read_ms": None, "error": "all probes failed"}}
    assert cli.collector_failed(total, "health") is True


def test_failed_collectors_lists_only_the_failing_ones() -> None:
    results = _canned()
    results["read_cap"] = {"error": "boom"}
    assert cli.failed_collectors(results) == ["read_cap"]


def test_resolve_configured_signer_key_none_when_no_identity(monkeypatch) -> None:
    def _raise():
        raise IdentityError("no identity")

    monkeypatch.setattr(cli.identity, "load_key", _raise)
    assert cli.resolve_configured_signer_key() is None


def test_resolve_configured_signer_did_none_when_no_identity(monkeypatch) -> None:
    def _raise():
        raise IdentityError("no identity")

    monkeypatch.setattr(cli.identity, "load_key", _raise)
    assert cli.resolve_configured_signer_did() is None


def test_resolve_configured_signer_did_returns_the_actual_did(monkeypatch) -> None:
    monkeypatch.setattr(cli.identity, "load_key", lambda: "fake-key")
    monkeypatch.setattr(cli.identity, "did_of", lambda key: f"did:key:from-{key}")
    assert cli.resolve_configured_signer_did() == "did:key:from-fake-key"


@pytest.mark.parametrize(
    "result,expected",
    [
        ({"status": 200}, True),
        ({"status": 299}, True),
        ({"status": 404}, False),
        ({"status": 200, "note": "first attempt may have landed"}, False),
        ({"status": True}, False),  # bool is not a real status code
        ({}, False),
        ("not a dict", False),
        (None, False),
    ],
)
def test_post_confirmed_success(result, expected) -> None:
    assert cli.post_confirmed_success(result) is expected


# ---- resolve_pushed_commit (FIX 1 git evidence) -----------------------------


def test_resolve_pushed_commit_missing_file(git_repo) -> None:
    ok, sha, reason = cli.resolve_pushed_commit(git_repo / "reports" / "2026-08-29.md", git_repo)
    assert ok is False
    assert sha is None
    assert "does not exist" in reason


def test_resolve_pushed_commit_never_committed(git_repo) -> None:
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is False
    assert sha is None
    assert "never been committed" in reason


def test_resolve_pushed_commit_dirty_working_tree(git_repo) -> None:
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    _commit_and_push(git_repo, "reports/2026-08-29.md")
    report_path.write_text("hello, but edited after committing")

    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is False
    assert sha is None
    assert "uncommitted changes" in reason


def test_resolve_pushed_commit_committed_but_not_pushed(git_repo) -> None:
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    _run_git(["add", "reports/2026-08-29.md"], git_repo)
    _run_git(["commit", "-q", "-m", "test"], git_repo)
    # No refs/remotes/origin/* ref created -- simulates "committed, never pushed".

    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is False
    assert sha is None
    assert "not on any remote-tracking branch" in reason


def test_resolve_pushed_commit_committed_and_pushed_succeeds(git_repo) -> None:
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    expected_sha = _commit_and_push(git_repo, "reports/2026-08-29.md")

    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is True
    assert sha == expected_sha
    assert "origin/master" in reason


# ---- FIX C: "pushed" must mean pushed to the REAL origin repo -------------


def test_resolve_pushed_commit_refuses_when_origin_points_elsewhere(git_repo) -> None:
    _run_git(
        ["remote", "set-url", "origin", "https://github.com/someone-else/not-this-repo.git"],
        git_repo,
    )
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    _commit_and_push(git_repo, "reports/2026-08-29.md")

    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is False
    assert sha is None
    assert "africanproofs/technocore-observatory" in reason


def test_resolve_pushed_commit_refuses_when_no_origin_remote_configured(git_repo) -> None:
    _run_git(["remote", "remove", "origin"], git_repo)
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    _run_git(["add", "reports/2026-08-29.md"], git_repo)
    _run_git(["commit", "-q", "-m", "test"], git_repo)

    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is False
    assert sha is None
    assert "no 'origin' remote" in reason


def test_resolve_pushed_commit_accepts_ssh_style_origin_url(git_repo) -> None:
    _run_git(
        ["remote", "set-url", "origin", "git@github.com:africanproofs/technocore-observatory.git"],
        git_repo,
    )
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text("hello")
    expected_sha = _commit_and_push(git_repo, "reports/2026-08-29.md")

    ok, sha, reason = cli.resolve_pushed_commit(report_path, git_repo)
    assert ok is True
    assert sha == expected_sha


# ---- run() (fakes only, no network, no posting -- `run` never posts) -------


def test_run_writes_report_and_summary_and_never_touches_say_signed_or_kv(
    monkeypatch, fake_client
) -> None:
    cli.run()

    assert fake_client.said == []
    assert fake_client.kv_sets == []
    assert fake_client.closed is True
    assert cli.SUMMARY_PATH.exists()
    summary = json.loads(cli.SUMMARY_PATH.read_text())
    report_path = cli.REPORTS_DIR / f"{summary['date']}.md"
    assert report_path.exists()


def test_run_has_no_post_parameter() -> None:
    # FIX 1: `--post` was removed from `run` entirely rather than kept
    # (publish is the only posting path) -- `run` must be callable with no
    # arguments at all.
    import inspect

    sig = inspect.signature(cli.run)
    assert "post" not in sig.parameters


def test_all_collectors_failing_exits_nonzero_and_writes_no_report(monkeypatch, fake_client) -> None:
    import typer

    for name in ("census", "duplicates", "health", "read_cap", "sequence_continuity", "signature_retention"):
        monkeypatch.setattr(collect, name, lambda client, _n=name, **_k: {"error": "boom"})
    monkeypatch.setattr(collect, "api_surface", lambda client, path: {"error": "boom"})

    with pytest.raises(typer.Exit):
        cli.run()

    assert fake_client.said == []
    assert fake_client.kv_sets == []
    assert fake_client.closed is True
    assert not cli.SUMMARY_PATH.exists()


# ---- FIX 6: api-surface baseline transactionality --------------------------


def test_run_advances_baseline_when_the_whole_run_succeeds(monkeypatch, fake_client) -> None:
    cli.run()
    assert cli.STATE_PATH.exists()
    on_disk = json.loads(cli.STATE_PATH.read_text())
    assert on_disk["paths"] == ["/a"]


def test_run_does_not_advance_baseline_when_another_collector_fails(monkeypatch, fake_client) -> None:
    # api_surface itself succeeds (has a new_baseline to offer), but a
    # DIFFERENT collector fails this run -- the baseline must not advance,
    # so a same-day retry after the fix doesn't diff against itself and
    # erase a real delta.
    monkeypatch.setattr(collect, "health", lambda client: {"error": "boom"})

    cli.run()

    assert not cli.STATE_PATH.exists()


def test_run_does_not_advance_baseline_when_api_surface_itself_fails(monkeypatch, fake_client) -> None:
    monkeypatch.setattr(collect, "api_surface", lambda client, path: {"error": "boom"})

    cli.run()

    assert not cli.STATE_PATH.exists()


# ---- publish() ---------------------------------------------------------


def _write_summary(root, date: str, results: dict) -> None:
    summary = report.build_summary(
        results["census"],
        results["duplicates"],
        results["api"],
        results["health"],
        results["read_cap"],
        results["sequence_continuity"],
        results["signature_retention"],
    )
    summary["date"] = date
    (root / "reports").mkdir(exist_ok=True)
    (root / "reports" / "latest-summary.json").write_text(json.dumps(summary))
    return summary


def test_publish_refuses_when_report_not_committed(git_repo, fake_client) -> None:
    import typer

    results = _canned()
    _write_summary(git_repo, "2026-08-29", results)
    (git_repo / "reports" / "2026-08-29.md").write_text("hello")  # never committed

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []
    assert fake_client.kv_sets == []


def test_publish_refuses_when_a_collector_failed_in_the_saved_summary(git_repo, fake_client) -> None:
    import typer

    results = _canned()
    results["read_cap"] = {"error": "boom"}
    _commit_valid_report_and_summary(git_repo, "2026-08-29", results)

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []
    assert fake_client.kv_sets == []


def test_publish_refuses_when_a_collector_key_is_missing_from_the_committed_summary(
    git_repo, fake_client
) -> None:
    """FIX C: a MISSING collector key in the committed summary is a
    publication failure, not something that silently reads as "no error
    present"."""
    import typer

    summary, _sha = _commit_valid_report_and_summary(git_repo, "2026-08-29")
    # Overwrite the committed summary (in a NEW commit) with one that's
    # missing "read_cap" entirely, and DON'T update the report to match --
    # the missing-key check must fire before the byte-match check even runs.
    broken = dict(summary)
    del broken["read_cap"]
    (git_repo / "reports" / "latest-summary.json").write_text(json.dumps(broken))
    _commit_and_push(git_repo, "reports/latest-summary.json")

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []


def test_publish_refuses_when_summary_is_for_a_different_date(git_repo, fake_client) -> None:
    import typer

    results = _canned()
    summary = _write_summary(git_repo, "2026-08-28", results)  # wrong date
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text(report.render_report(summary))
    _commit_and_push(git_repo, "reports/2026-08-29.md", "reports/latest-summary.json")

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []


def test_publish_refuses_on_invalid_date_format(git_repo, fake_client) -> None:
    import typer

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-8-29")  # not zero-padded

    with pytest.raises(typer.Exit):
        cli.publish(date="../../etc/passwd")

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29\nrm -rf /")

    assert fake_client.said == []


def test_publish_refuses_on_symlinked_report_path(git_repo, fake_client) -> None:
    import typer

    summary, _sha = _commit_valid_report_and_summary(git_repo, "2026-08-29")
    report_path = git_repo / "reports" / "2026-08-29.md"
    outside = git_repo.parent / "outside-target.md"
    outside.write_text(report.render_report(summary))
    report_path.unlink()
    report_path.symlink_to(outside)

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []


def test_publish_refuses_when_no_identity_configured(monkeypatch, git_repo, fake_client) -> None:
    import typer

    _commit_valid_report_and_summary(git_repo, "2026-08-29")
    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: None)

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []


def test_publish_refuses_on_signer_did_mismatch(monkeypatch, git_repo, fake_client) -> None:
    import typer

    _commit_valid_report_and_summary(git_repo, "2026-08-29")
    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: object())
    monkeypatch.setattr(cli.identity, "did_of", lambda key: "did:key:z6Mksomeoneelsesidentity")

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []
    assert fake_client.kv_sets == []


def test_publish_refuses_when_committed_report_does_not_match_rendered_summary(
    git_repo, fake_client
) -> None:
    """FIX C: the permalink must bind to exactly what was measured -- a
    committed report that has drifted from what `render_report` recomputes
    off the committed summary (hand-edited, stale, wrong code version) must
    refuse publication."""
    import typer

    summary = _write_summary(git_repo, "2026-08-29", _canned())
    report_path = git_repo / "reports" / "2026-08-29.md"
    report_path.write_text(report.render_report(summary) + "\nhand-added sentence")
    _commit_and_push(git_repo, "reports/2026-08-29.md", "reports/latest-summary.json")

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []


def test_publish_posts_immutable_link_and_writes_kv_note_on_success(monkeypatch, git_repo, fake_client) -> None:
    _summary, sha = _commit_valid_report_and_summary(git_repo, "2026-08-29")
    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: object())
    monkeypatch.setattr(cli.identity, "did_of", lambda key: report.SIGNER_DID)

    cli.publish(date="2026-08-29")

    assert len(fake_client.said) == 1
    assert fake_client.said[0][0] == "african-proofs"
    posted_digest = fake_client.said[0][1]
    assert f"/blob/{sha}/reports/2026-08-29.md" in posted_digest
    assert "/blob/master/" not in posted_digest
    assert len(fake_client.kv_sets) == 2  # dated key + "latest"
    assert fake_client.closed is True


def test_publish_kv_note_not_written_when_post_raises(monkeypatch, git_repo, fake_client) -> None:
    import typer

    _commit_valid_report_and_summary(git_repo, "2026-08-29")
    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: object())
    monkeypatch.setattr(cli.identity, "did_of", lambda key: report.SIGNER_DID)
    fake_client.say_signed_result = TechnocoreError(500, "boom")

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert len(fake_client.said) == 1  # the post was attempted
    assert fake_client.kv_sets == []  # but never confirmed, so no kv note


def test_publish_kv_note_not_written_when_post_result_is_ambiguous(monkeypatch, git_repo, fake_client) -> None:
    import typer

    _commit_valid_report_and_summary(git_repo, "2026-08-29")
    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: object())
    monkeypatch.setattr(cli.identity, "did_of", lambda key: report.SIGNER_DID)
    fake_client.say_signed_result = {
        "status": 404,
        "did": "did:key:test",
        "nonce": "1",
        "response": "not found",
        "note": "first attempt may have landed; verify with read_room",
    }

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert len(fake_client.said) == 1
    assert fake_client.kv_sets == []


def test_publish_refuses_when_digest_would_exceed_char_cap(git_repo, fake_client) -> None:
    """FIX C: a would-be-truncated permalink/attribution footer fails
    publication rather than posting a shortened link."""
    import typer

    results = _canned()
    results["api"] = dict(results["api"])
    huge_tripwire = [f"/faucet/claim/very-long-suspicious-path-segment-{i:04d}" for i in range(40)]
    results["api"]["added"] = huge_tripwire
    results["api"]["tripwire"] = huge_tripwire
    _commit_valid_report_and_summary(git_repo, "2026-08-29", results)

    with pytest.raises(typer.Exit):
        cli.publish(date="2026-08-29")

    assert fake_client.said == []
    assert fake_client.kv_sets == []


def test_publish_defaults_date_from_latest_summary(monkeypatch, git_repo, fake_client) -> None:
    _commit_valid_report_and_summary(git_repo, "2026-08-29")
    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: object())
    monkeypatch.setattr(cli.identity, "did_of", lambda key: report.SIGNER_DID)

    cli.publish(date=None)  # no --date given

    assert len(fake_client.said) == 1


# ---- FIX A / FIX 8: signer key binding via a real parameter (no monkeypatch) ---
#
# `publish` used to close the TOCTOU window (a second, independent
# `load_key()` call between the DID check and the actual sign could return a
# different key if the seed file was rotated/replaced/removed in between) by
# rebinding the process-global `identity.load_key` for the duration of one
# call. An external review ruled that a publication blocker: monkeypatching a
# process-global secret-key loader in a security-sensitive public posting
# path. `TechnocoreClient.say_signed` now takes an explicit `key` parameter
# instead (technocore-mcp), and `publish` just passes the exact key object it
# verified straight through -- no rebinding, nothing global.
#
# This repo's poetry.lock pins technocore-mcp by git SHA, so the new `key`
# parameter is not actually installed in THIS checkout yet -- these tests
# exercise the call shape through `_FakeClient` (which mirrors the new
# signature), not the real installed package. Publishing for real requires:
# push technocore-mcp -> `poetry update technocore-mcp` here -> commit -> only
# then can `observatory publish` run against the real dependency.


def test_publish_passes_the_exact_verified_key_to_say_signed(
    monkeypatch, git_repo, fake_client
) -> None:
    _commit_valid_report_and_summary(git_repo, "2026-08-29")

    verified_key = object()
    rotated_key = object()  # what a SECOND, independent load_key() call would return
    load_calls: list[object] = []

    def _load_key():
        obj = verified_key if not load_calls else rotated_key
        load_calls.append(obj)
        return obj

    def _did_of(key):
        return report.SIGNER_DID if key is verified_key else "did:key:z6MkWRONGKEYUSED"

    monkeypatch.setattr(cli.identity, "load_key", _load_key)
    monkeypatch.setattr(cli.identity, "did_of", _did_of)

    cli.publish(date="2026-08-29")

    # `publish`'s own preflight load_key() call is call #1 (verified_key). If
    # signing re-resolved via a second, independent load_key() call instead
    # of using the passed `key=`, it would get rotated_key -- proving the
    # TOCTOU window is still open. It must not: the key passed to
    # `say_signed` must be the exact object verified in preflight.
    assert fake_client.said_keys == [verified_key]
    assert len(fake_client.kv_sets) == 2


def test_publish_does_not_monkeypatch_identity_load_key(
    monkeypatch, git_repo, fake_client
) -> None:
    """Regression guard for FIX A: `publish` must never reassign
    `identity.load_key` (module-global) as a side channel for binding the
    signing key -- that pattern is exactly what got ruled a publication
    blocker. The real object identity of `cli.identity.load_key` must be
    unchanged before and after a successful `publish` call."""
    _commit_valid_report_and_summary(git_repo, "2026-08-29")

    monkeypatch.setattr(cli, "resolve_configured_signer_key", lambda: object())
    monkeypatch.setattr(cli.identity, "did_of", lambda key: report.SIGNER_DID)
    original_load_key = cli.identity.load_key

    cli.publish(date="2026-08-29")

    assert cli.identity.load_key is original_load_key
