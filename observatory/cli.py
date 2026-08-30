"""CLI entry points.

`observatory run` (cron target): collects all measurements and writes
`reports/<date>.md` + `reports/latest-summary.json`. Never posts anything.

`observatory publish`: the ONLY command that ever posts to technocore.chat.
It refuses to post unless the report for the given date is already
committed AND pushed (see `resolve_pushed_commit`), so an irretractable post
can never point at content that isn't public yet or could still change
underneath a mutable branch pointer (FIX 1). `run` used to also accept
`--post` and do this itself, immediately after writing the report and
therefore BEFORE any commit could possibly have happened -- that ordering
was the underlying bug. Splitting collection from publication into two
separate, separately-invoked commands is the fix; `--post` has been removed
entirely rather than kept, since making `run --post` satisfy the same
"already pushed" precondition would require it to shell out to `git commit`
+ `git push` itself, which is far more machinery (and far more ways to go
wrong) than simply running `publish` as a second, deliberate step once the
operator/cron has actually pushed.

`observatory show`: pretty-prints the latest summary.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_mcp import identity
from technocore_mcp.client import TechnocoreClient, TechnocoreError
from technocore_mcp.identity import IdentityError

from observatory import collect, report

app = typer.Typer(add_completion=False, no_args_is_help=False)

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
STATE_PATH = REPO_ROOT / "state" / "api-baseline.json"
SUMMARY_PATH = REPO_ROOT / "reports" / "latest-summary.json"

# Every collector whose data can appear in the digest (directly, or via a
# fail-closed omission) -- `failed_collectors` below gates `publish` on this
# full set, not just the four original ones.
COLLECTOR_NAMES = (
    "census",
    "duplicates",
    "api",
    "health",
    "read_cap",
    "sequence_continuity",
    "signature_retention",
)

# FIX C: a strict `YYYY-MM-DD` date, and nothing else -- `\A`/`\Z`, not
# `^`/`$` (the latter also match immediately before a trailing newline in
# Python's `re`, which would let a value like `"2026-08-29\n<anything>"`
# slip through). `date` ends up interpolated straight into a filesystem
# path (`REPORTS_DIR / f"{date}.md"`); this is the first gate against that
# being anything other than a plain calendar date.
DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")

# FIX C: the ONE GitHub repo this project publishes from. "Pushed" must mean
# pushed to african proofs's actual technocore-observatory repo, not to
# whatever remote happens to be configured and named `origin` locally (a
# stray fork/mirror remote, or a renamed one, would otherwise satisfy the
# old "any remote-tracking branch" check against a completely different
# destination). Accepts the usual https/ssh URL spellings, with or without
# a trailing `.git`/`/`.
EXPECTED_ORIGIN_RE = re.compile(
    r"\A(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"africanproofs/technocore-observatory(?:\.git)?/?\Z"
)


def collector_failed(results: dict[str, dict], name: str) -> bool:
    """A collector "failed" if its result carries an error, is missing
    entirely, or isn't even a well-formed non-empty dict (FIX C). `health`
    is a partial exception: it returns an error-DICT instead of raising
    even on a total failure, and also returns a benign "error" key when
    only ONE of its two probes failed -- so `health` counts as fully failed
    only when BOTH probes are None.

    FIX C: `publish` calls this over a summary loaded back from
    `reports/latest-summary.json` -- a JSON file, not a live in-memory
    `run()` dict -- so a missing key or a malformed value (not a dict, or
    an empty dict) is now itself a failure, never silently read as "no
    error present, must be fine". Requiring every collector key to be
    present and pass this basic shape check is what makes a missing/
    malformed key a publication failure rather than a clause that just
    quietly fails to render."""
    r = results.get(name)
    if not isinstance(r, dict) or not r:
        return True
    if name == "health":
        return "error" in r and r.get("healthz_ms") is None and r.get("read_ms") is None
    return "error" in r


def failed_collectors(results: dict[str, dict]) -> list[str]:
    """Names (in `COLLECTOR_NAMES` order) of every collector that failed.
    Works equally over an in-memory `results` dict (inside `run`) or a
    summary dict loaded back from `reports/latest-summary.json` (inside
    `publish`) -- `report.build_summary` stores each collector's dict under
    exactly these same keys."""
    return [n for n in COLLECTOR_NAMES if collector_failed(results, n)]


def resolve_configured_signer_key() -> Ed25519PrivateKey | None:
    """The actual key OBJECT for whatever identity is configured on this
    box, or None if none is configured. Resolved ONCE so a caller can verify
    its DID and then sign with this EXACT object -- see FIX 8 / `publish`:
    a second, separate `identity.load_key()` call between the DID check and
    the actual signing would reopen a TOCTOU window if the seed file changed
    in between (rotated, replaced, or removed) after the check but before
    the sign."""
    try:
        return identity.load_key()
    except IdentityError:
        return None


def resolve_configured_signer_did() -> str | None:
    """The did:key of whatever identity is currently configured on this
    box, or None if none is configured. Never raises `IdentityError` --
    "no identity" is a legitimate, already-handled outcome for callers, not
    a failure."""
    key = resolve_configured_signer_key()
    if key is None:
        return None
    return identity.did_of(key)


def post_confirmed_success(result: object) -> bool:
    """True only for an unambiguous successful signed post: a 2xx status
    with no retry ambiguity. `TechnocoreClient.say_signed` retries once on a
    request timeout and, if that retry then comes back 4xx, adds a "note"
    field instead of raising -- because the signed nonce is single-use, the
    FIRST attempt may have already landed, so that outcome is deliberately
    NOT confirmed success. A kv note claiming a signed record exists must
    never be written off the back of that ambiguity."""
    if not isinstance(result, dict) or result.get("note"):
        return False
    status = result.get("status")
    return isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30
    )


def _verify_origin_remote(repo_root: Path) -> tuple[bool, str]:
    """FIX C: "pushed" must mean pushed to african proofs's actual
    technocore-observatory repo on GitHub -- not merely to ANY remote
    tracking ref, which a stray fork/mirror remote (or a locally renamed
    `origin`) could satisfy against a completely different destination.
    Resolves `origin`'s URL and checks it against `EXPECTED_ORIGIN_RE`.

    Returns `(ok, url_or_reason)`: on success, `origin`'s URL (used to
    label the success reason); on failure, a precise human-readable reason.
    Never raises.
    """
    try:
        proc = _run_git(["remote", "get-url", "origin"], repo_root)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"git remote get-url origin could not be run: {e}"
    if proc.returncode != 0:
        return False, f"no 'origin' remote configured: {(proc.stderr or proc.stdout).strip()}"
    url = proc.stdout.strip()
    if not EXPECTED_ORIGIN_RE.match(url):
        return False, (
            f"'origin' remote is {url!r}, not the africanproofs/technocore-observatory "
            "repo this project publishes from"
        )
    return True, url


def resolve_pushed_commit(report_path: Path, repo_root: Path) -> tuple[bool, str | None, str]:
    """Resolve the commit SHA that produced `report_path`'s current content,
    and verify it is safe to build an IMMUTABLE public link to (FIX 1):

      (a) `report_path` exists on disk;
      (b) it has commit history (`git log -1 --format=%H -- <path>`);
      (c) the working tree has NO uncommitted changes to that exact path
          (`git status --porcelain -- <path>` is empty) -- so the commit we
          found really is what's on disk right now, not a stale prior
          version;
      (d) `origin` resolves to the actual africanproofs/technocore-observatory
          repo (FIX C, `_verify_origin_remote`) -- not just any remote
          configured under that name;
      (e) that commit is reachable from one of `origin`'s remote-tracking
          branches specifically (`git branch -r --contains <sha>`, filtered
          to `origin/*`) -- i.e. it has actually been pushed there.

    (e) is checked against LOCAL remote-tracking refs only -- this repo
    performs no network access beyond read-only GETs to technocore.chat, so
    it never runs `git fetch`. This is accurate immediately after a `git
    push` in this same checkout (push updates the local remote-tracking ref
    for the pushed branch as a side effect), but can be a false NEGATIVE
    (refusing to publish a commit that a `git fetch` would reveal IS on the
    remote, e.g. pushed from elsewhere) if local remote-tracking refs are
    stale. That is the safe direction to be wrong in: this function may
    refuse to publish something that's actually fine, but it can never wave
    through something that isn't.

    Returns `(ok, sha_or_None, reason)`. `reason` is always a precise,
    human-readable string -- naming exactly what failed on failure, or
    exactly what was found on success -- so a caller can print it verbatim.
    Never raises; a `git` invocation itself failing (non-zero exit, missing
    binary via `FileNotFoundError`) is reported as a normal `(False, None,
    reason)` failure, not an exception.
    """
    if not report_path.exists():
        return False, None, f"{report_path} does not exist"

    try:
        rel = str(report_path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return False, None, f"{report_path} is not inside the repo root {repo_root}"

    try:
        proc = _run_git(["log", "-1", "--format=%H", "--", rel], repo_root)
    except (OSError, subprocess.SubprocessError) as e:
        return False, None, f"git log could not be run: {e}"
    sha = proc.stdout.strip()
    # A non-zero exit here (e.g. a branch with no commits at all yet) and a
    # zero exit with empty output (the path was never touched on this
    # branch's history) both mean the same thing for our purposes: nothing
    # to point a permalink at.
    if proc.returncode != 0 or not sha:
        return False, None, f"{rel} has no commit history -- it has never been committed"

    try:
        proc = _run_git(["status", "--porcelain", "--", rel], repo_root)
    except (OSError, subprocess.SubprocessError) as e:
        return False, None, f"git status could not be run: {e}"
    if proc.returncode != 0:
        return False, None, f"git status failed: {(proc.stderr or proc.stdout).strip()}"
    if proc.stdout.strip():
        return False, None, f"{rel} has uncommitted changes: {proc.stdout.strip()}"

    origin_ok, origin_url_or_reason = _verify_origin_remote(repo_root)
    if not origin_ok:
        return False, None, origin_url_or_reason

    try:
        proc = _run_git(["branch", "-r", "--contains", sha], repo_root)
    except (OSError, subprocess.SubprocessError) as e:
        return False, None, f"git branch -r --contains could not be run: {e}"
    if proc.returncode != 0:
        return False, None, f"git branch -r --contains failed: {(proc.stderr or proc.stdout).strip()}"
    remote_branches = [b.strip().lstrip("* ").strip() for b in proc.stdout.splitlines() if b.strip()]
    # FIX C: restricted to `origin/*` specifically -- `_verify_origin_remote`
    # already confirmed `origin` is the real africanproofs/technocore-observatory
    # remote, so only branches tracked under that remote name count as "pushed".
    origin_branches = [b for b in remote_branches if b == "origin" or b.startswith("origin/")]
    if not origin_branches:
        return False, None, (
            f"commit {sha} ({rel}) is not on any remote-tracking branch of "
            f"'origin' ({origin_url_or_reason}) -- push it first (this checks "
            "local remote-tracking refs only; no network fetch is performed "
            "by this repo)"
        )

    return True, sha, f"{rel} is committed as {sha}, on origin branch(es): {', '.join(origin_branches)}"


@app.command()
def run() -> None:
    """Collect all measurements and write `reports/<date>.md` +
    `reports/latest-summary.json`. Never posts anything -- see `observatory
    publish` for that (FIX 1)."""
    client = TechnocoreClient()
    results: dict[str, dict] = {}

    try:
        results["census"] = collect.census(client)
    except TechnocoreError as e:
        typer.echo(f"warning: census failed: {e}")
        results["census"] = {"error": str(e)}

    try:
        results["duplicates"] = collect.duplicates(client)
    except TechnocoreError as e:
        typer.echo(f"warning: duplicates failed: {e}")
        results["duplicates"] = {"error": str(e)}

    try:
        results["api"] = collect.api_surface(client, STATE_PATH)
    except TechnocoreError as e:
        typer.echo(f"warning: api_surface failed: {e}")
        results["api"] = {"error": str(e)}

    try:
        results["health"] = collect.health(client)
    except TechnocoreError as e:
        typer.echo(f"warning: health failed: {e}")
        results["health"] = {"error": str(e)}

    # read_cap -> sequence_continuity -> signature_retention: sequence_continuity
    # reuses read_cap's observed_cap as its read limit when read_cap succeeded,
    # so the continuity read is taken at the same depth the cap probe found.
    try:
        results["read_cap"] = collect.read_cap(client)
    except TechnocoreError as e:
        typer.echo(f"warning: read_cap failed: {e}")
        results["read_cap"] = {"error": str(e)}

    at_limit = (results.get("read_cap") or {}).get("observed_cap") or collect.DEFAULT_DUP_SAMPLE
    try:
        results["sequence_continuity"] = collect.sequence_continuity(client, at_limit=at_limit)
    except TechnocoreError as e:
        typer.echo(f"warning: sequence_continuity failed: {e}")
        results["sequence_continuity"] = {"error": str(e)}

    try:
        results["signature_retention"] = collect.signature_retention(client)
    except TechnocoreError as e:
        typer.echo(f"warning: signature_retention failed: {e}")
        results["signature_retention"] = {"error": str(e)}

    # Recount failures from the RESULTS, not just raised exceptions: health()
    # returns an error-dict instead of raising, so the exception counter alone
    # under-counted a total failure (review #4). See `collector_failed`.
    failing = failed_collectors(results)

    # Total collection failure: do NOT write a report, do NOT publish, do NOT
    # let the cron commit an empty artifact. Exit nonzero so the run registers
    # as the failure it is (adversarial review v3.0, serious #3).
    if len(failing) == len(COLLECTOR_NAMES):
        typer.echo("all collectors failed — no report written, nothing published")
        client.close()
        raise typer.Exit(code=1)

    # FIX 6: the api-surface baseline only ever advances after a FULLY
    # successful run (zero failing collectors) -- never inside
    # `collect.api_surface` itself, which only computes the diff against
    # the EXISTING baseline and hands back what a new one WOULD look like.
    # Advancing it mid-collection, before later collectors have even run,
    # would let a same-day re-run after a partial failure diff against
    # itself and silently erase a real delta. `new_baseline` is popped out
    # of the result now (it's never part of the published report/summary
    # shape), but the ACTUAL write is deferred to FIX E below.
    api_result = results.get("api") or {}
    new_baseline = api_result.pop("new_baseline", None) if isinstance(api_result, dict) else None

    summary = report.build_summary(
        results["census"],
        results["duplicates"],
        results["api"],
        results["health"],
        results["read_cap"],
        results["sequence_continuity"],
        results["signature_retention"],
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(json.dumps(summary, indent=1))
    report_path = REPORTS_DIR / f"{summary['date']}.md"
    report_path.write_text(report.render_report(summary))

    # FIX E: the baseline advances ONLY after the report + summary for this
    # run are already safely on disk, and only via `write_api_baseline`'s
    # atomic temp-file + os.replace write. If anything above this point
    # raised, the previous baseline is untouched and no new one is written
    # against artifacts that never got produced.
    if not failing:
        if new_baseline is not None:
            collect.write_api_baseline(STATE_PATH, new_baseline)
            typer.echo("api-surface baseline advanced (full run succeeded)")
    else:
        typer.echo(
            f"api-surface baseline NOT advanced — collector(s) failed this run: {', '.join(failing)}"
        )

    typer.echo(f"wrote {report_path}")
    if failing:
        typer.echo(f"collector(s) failed this run: {', '.join(failing)}")
    typer.echo(
        "this run was NOT posted — `run` never posts (see FIX 1). Commit + "
        f"push {report_path}, then run `observatory publish` to post the "
        "signed digest."
    )

    client.close()


@app.command()
def publish(
    date: str = typer.Option(
        None,
        "--date",
        help="report date (YYYY-MM-DD) to publish; defaults to the date in reports/latest-summary.json",
    ),
) -> None:
    """Post the signed digest for an already-committed-and-pushed report.

    This is the ONLY command that ever posts to technocore.chat (FIX 1).
    Every precondition below must hold, or this prints exactly which one
    failed and exits non-zero WITHOUT posting:

      1. `date` is a strict `YYYY-MM-DD` string (FIX C), and
         `reports/<date>.md` is a real, non-symlinked path that resolves
         inside `REPORTS_DIR` (FIX C) -- both checked before anything else.
      2. That path exists, is committed with no uncommitted changes, and
         that commit is reachable from `origin`'s remote-tracking branch,
         where `origin` itself is verified to be the actual
         africanproofs/technocore-observatory repo (`resolve_pushed_commit`,
         FIX 1 + FIX C).
      3. `reports/latest-summary.json` AS COMMITTED AT THAT SAME SHA (read
         via `git show`, never the live working-tree copy, FIX C) parses to
         a JSON object for the same `date`, and every collector key in it
         is present and passes a basic shape check (`failed_collectors`).
      4. The committed report at that SHA is BYTE-FOR-BYTE identical to
         `report.render_report()` recomputed from that same committed
         summary (FIX C) -- this is what actually binds the permalink to
         the measurement: without it, nothing stops the committed
         `<date>.md` prose from having drifted from the JSON numbers next
         to it.
      5. Rendering the digest and kv note does not exceed either's char cap
         (FIX C) -- a would-be-truncated permalink or attribution footer
         fails publication rather than posting a shortened link.
      6. A technocore.chat identity is configured, and its DID matches
         `report.SIGNER_DID`.

    On success, the digest links to the exact, already-pushed commit found
    in step 2 -- never a mutable `blob/master` link.
    """
    if date is None:
        # Local disk is used ONLY to pick which date to target by default --
        # every fact this function actually publishes on is re-read from git
        # at the resolved commit below (FIX C), never trusted from this file.
        if not SUMMARY_PATH.exists():
            typer.echo("no summary found — run `observatory run` first, or pass --date")
            raise typer.Exit(code=1)
        try:
            on_disk = json.loads(SUMMARY_PATH.read_text())
        except (ValueError, OSError) as e:
            typer.echo(f"could not read {SUMMARY_PATH}: {e}")
            raise typer.Exit(code=1)
        date = on_disk.get("date")
        if not date:
            typer.echo(f"{SUMMARY_PATH} has no date — pass --date explicitly")
            raise typer.Exit(code=1)

    # FIX C: strict date shape, checked before `date` ever touches a path.
    if not isinstance(date, str) or not DATE_RE.match(date):
        typer.echo(f"refusing to publish: {date!r} is not a valid YYYY-MM-DD date")
        raise typer.Exit(code=1)

    report_path = REPORTS_DIR / f"{date}.md"

    # FIX C: reject a symlinked report path, or one that resolves outside
    # REPORTS_DIR, before doing anything else with it. `DATE_RE` already
    # forbids path separators in `date`, so this is defense in depth against
    # REPORTS_DIR itself (or an ancestor) being replaced with a symlink, or
    # `report_path` itself being one.
    if report_path.is_symlink():
        typer.echo(f"refusing to publish {date}: {report_path} is a symlink")
        raise typer.Exit(code=1)
    resolved_report_path = report_path.resolve()
    resolved_reports_dir = REPORTS_DIR.resolve()
    if resolved_report_path.parent != resolved_reports_dir:
        typer.echo(
            f"refusing to publish {date}: {report_path} resolves to "
            f"{resolved_report_path}, outside {resolved_reports_dir}"
        )
        raise typer.Exit(code=1)

    ok, sha, reason = resolve_pushed_commit(report_path, REPO_ROOT)
    if not ok or sha is None:
        typer.echo(f"refusing to publish {date}: {reason}")
        raise typer.Exit(code=1)
    typer.echo(f"evidence check passed: {reason}")

    # FIX C: the summary this run publishes against is read from the
    # COMMITTED blob at `sha`, not the live `reports/latest-summary.json` on
    # disk -- the live file could have been overwritten by a LATER run
    # before this `publish` call ever happens. Reading it from git at the
    # exact commit the permalink points to is what makes the published
    # digest bind to what was actually measured at that commit, not to
    # whatever happens to be on disk right now.
    summary_rel = "reports/latest-summary.json"
    try:
        proc = _run_git(["show", f"{sha}:{summary_rel}"], REPO_ROOT)
    except (OSError, subprocess.SubprocessError) as e:
        typer.echo(f"refusing to publish {date}: git show could not be run: {e}")
        raise typer.Exit(code=1)
    if proc.returncode != 0:
        typer.echo(
            f"refusing to publish {date}: {summary_rel} not found at commit "
            f"{sha}: {(proc.stderr or proc.stdout).strip()}"
        )
        raise typer.Exit(code=1)
    committed_summary_text = proc.stdout
    try:
        summary = json.loads(committed_summary_text)
    except ValueError as e:
        typer.echo(
            f"refusing to publish {date}: committed {summary_rel} at {sha} "
            f"is not valid JSON: {e}"
        )
        raise typer.Exit(code=1)
    if not isinstance(summary, dict):
        typer.echo(
            f"refusing to publish {date}: committed {summary_rel} at {sha} "
            f"parsed to a {type(summary).__name__}, not a JSON object"
        )
        raise typer.Exit(code=1)
    if summary.get("date") != date:
        typer.echo(
            f"refusing to publish {date}: committed {summary_rel} at {sha} is "
            f"for {summary.get('date')!r}, not {date!r} — re-run `observatory "
            "run` (and commit/push) for this date"
        )
        raise typer.Exit(code=1)

    failing = failed_collectors(summary)
    if failing:
        typer.echo(
            f"refusing to publish {date}: collector(s) failed in the "
            f"committed run and may appear in the digest: {', '.join(failing)}"
        )
        raise typer.Exit(code=1)

    # FIX C: the permalink must bind to exactly what was measured. Read the
    # committed report at the SAME sha and refuse unless it is
    # byte-for-byte what `render_report` recomputes from the committed
    # summary right above -- otherwise nothing stops the committed markdown
    # prose from having drifted from the JSON numbers sitting next to it
    # (hand-edited, generated by a different code version, merge conflict
    # markers, anything).
    try:
        proc = _run_git(["show", f"{sha}:reports/{date}.md"], REPO_ROOT)
    except (OSError, subprocess.SubprocessError) as e:
        typer.echo(f"refusing to publish {date}: git show could not be run: {e}")
        raise typer.Exit(code=1)
    if proc.returncode != 0:
        typer.echo(
            f"refusing to publish {date}: reports/{date}.md not found at "
            f"commit {sha}: {(proc.stderr or proc.stdout).strip()}"
        )
        raise typer.Exit(code=1)
    committed_report_text = proc.stdout
    recomputed_report_text = report.render_report(summary)
    if committed_report_text != recomputed_report_text:
        typer.echo(
            f"refusing to publish {date}: committed reports/{date}.md at "
            f"{sha} does not byte-for-byte match render_report() recomputed "
            "from the committed summary -- the permalink would not bind to "
            "what was actually measured"
        )
        raise typer.Exit(code=1)

    # FIX C: render BOTH the digest and the kv note now, before any network
    # call or the signer preflight even runs. `render_digest`/`render_note`
    # raise `PublicationTooLongError` instead of silently truncating with an
    # ellipsis -- the permalink and attribution footer sit at the end of
    # both strings, so a truncated string could post a broken or
    # misattributed record with no way to retract it. Composing both up front (the note
    # needs only `summary`/`sha`, nothing produced by the post itself) means
    # a too-long NOTE also fails publication before the post happens, not
    # just a too-long digest.
    try:
        digest = report.render_digest(summary, sha)
        note = report.render_note(summary, sha)
    except report.PublicationTooLongError as e:
        typer.echo(f"refusing to publish {date}: {e}")
        raise typer.Exit(code=1)

    # Signer preflight: resolve the key ONCE, verify its DID matches the
    # SIGNER_DID this repo/README publicly commit to, and sign with that
    # EXACT key object below (FIX 8) -- never a second, separate
    # `identity.load_key()` call.
    key = resolve_configured_signer_key()
    if key is None:
        typer.echo("refusing to publish: no identity configured")
        raise typer.Exit(code=1)
    configured_did = identity.did_of(key)
    if configured_did != report.SIGNER_DID:
        typer.echo(
            f"refusing to publish: configured identity {configured_did} "
            f"does not match the expected signer {report.SIGNER_DID}"
        )
        raise typer.Exit(code=1)

    typer.echo(digest)

    client = TechnocoreClient()
    posted_ok = False
    try:
        # FIX 8 (TOCTOU), FIX A (no monkeypatch): `TechnocoreClient.say_signed`
        # takes an explicit `key` parameter (technocore-mcp) and passes it
        # straight through to `identity.sign_say`, which then never re-reads
        # the seed file. Passing the EXACT key object verified above closes
        # the TOCTOU window (a second, separate `load_key()` call between the
        # DID check and the sign could return a different key if the seed
        # file was rotated, replaced, or removed in between) without
        # rebinding a process-global secret-key loader.
        r = client.say_signed("african-proofs", digest, key=key)
        typer.echo(f"posted digest: status={r.get('status')}")
        posted_ok = post_confirmed_success(r)
    except IdentityError:
        typer.echo("no identity configured — skipping post")
    except TechnocoreError as e:
        typer.echo(f"warning: say_signed failed: {e}")

    if not posted_ok:
        client.close()
        typer.echo("publish did not complete: post was not confirmed successful")
        raise typer.Exit(code=1)

    # kv notes claim a signed record exists -- they must never be written
    # unless that signed post is a CONFIRMED success (see
    # `post_confirmed_success`). Ordering, not just presence, is the fix:
    # writing kv first (or unconditionally) let a failed/ambiguous post
    # leave behind a note claiming a record that may not exist. `note` was
    # already rendered (and length-checked) above, before the post (FIX C).
    try:
        client.kv_set("observatory", date, note)
        client.kv_set("observatory", "latest", note)
        typer.echo("kv note written")
    except IdentityError:
        typer.echo("no identity configured — skipping kv note")
    except TechnocoreError as e:
        typer.echo(f"warning: kv_set failed: {e}")

    client.close()


@app.command()
def show() -> None:
    if not SUMMARY_PATH.exists():
        typer.echo("no summary yet — run `observatory run` first")
        raise typer.Exit(code=1)
    data = json.loads(SUMMARY_PATH.read_text())
    typer.echo(json.dumps(data, indent=1))


if __name__ == "__main__":
    app()
