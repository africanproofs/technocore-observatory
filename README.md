# technocore-observatory

A no-LLM daily observatory of [technocore.chat](https://technocore.chat)
network health: room census, duplicate-share sampling of a room's visible
tail, an API-surface diff watch, basic health probes, a read-cap probe
cross-checked against the service's own published OpenAPI limit, a
sequence-continuity check over a room's visible window, and an offline
signature-retention check over signed-lane messages. Every number in every
report comes from a fixed, small set of public, unauthenticated GET
requests, and the code that computes each one is in this repository — the
METHOD is deterministic and auditable, not a black box. The measurements
themselves are point-in-time (health latency, a room's live tail, and
similar live state change from run to run by nature), and this repo does
not archive the raw responses each run's numbers were computed from, so
re-running the method later reproduces the METHOD, not necessarily the same
day's NUMBERS.

**Not affiliated with Flop Labs.** Technocore.chat is built and operated by
[flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat).
This is an independent, third-party observer of their public HTTP API.

## Why

Technocore.chat has no registration step — anyone can post as a plain nick
or a self-issued `did:key` — and a sampled tail of one room (`lobby`) has
shown a lot of templated, repetitive content. This repo measures that
directly: how much of that sampled tail is duplicate template text, how many
distinct `from` identifiers appear in it (a count of distinct sender
identifiers, not necessarily distinct actors — nothing stops one person or
bot from posting under several), whether the service's own API surface
changed, and (as of this build) whether its read cap is a demonstrated
server-side limit, whether a room's visible sequence is continuous, and
whether signed messages expose a signature that verifies offline. It commits
its raw baseline and its daily reports to git, so every day's diff is
publicly auditable after the fact — the methods are the code in this
repository, not a claim to take on trust.

The API-surface watch exists for a specific reason: a `$FLOP` testnet faucet
is officially expected to appear on technocore.chat at some point. The day a
path containing one of the tripwire keywords (`faucet`, `claim`, `mint`,
`airdrop`, `token`, `wallet`, `testnet`) first appears in `/openapi.json`,
this repo's diff shows it as an observed keyword match on a newly seen
path — compared against the previous SUCCESSFUL run's committed baseline
(not necessarily yesterday's: the baseline only advances after a run in
which every collector succeeded, so a failed or skipped run leaves it
unchanged — see `state/api-baseline.json` below), not a claim anyone has to
take on trust.

## Reports

- `reports/YYYY-MM-DD.md` — one markdown report per day.
- `reports/latest-summary.json` — the same run's data as machine-readable JSON.
- `state/api-baseline.json` — the API-surface diff baseline. It's committed
  (not gitignored) so every change to it is a reviewable git diff. It is
  overwritten only after a run in which every collector succeeded — never
  mid-run, and never after a partial failure — so a same-day re-run after a
  failure can't silently erase a real delta. The comparison point for any
  given report is therefore "the previous successful run", which is usually
  yesterday but is not guaranteed to be.

## Signed digests

Publication is a separate, later step from collection (`observatory
publish`, not `observatory run` — see "Run your own" below). When it runs,
it posts a one-line **signed** digest to room `african-proofs` on
technocore.chat — Ed25519, attributable to the
`did:key:z6MksYze47qWaCvBK92UNzjuis5eqRdfX4C8SfaD8ynKWyNp` identity (African
Proofs), the signature scheme documented in
[technocore-mcp](https://github.com/africanproofs/technocore-mcp). The
digest links to the exact, immutable commit of that day's report
(`/blob/<sha>/reports/<date>.md`, never the mutable `blob/master`), and
`observatory publish` refuses to post at all unless that commit is already
pushed. That room post is signed at write time and attributable to that
identity. It is **not independently re-verifiable by a reader**: this
repo's own signature-retention measurement (see the daily reports) checks
whether technocore.chat exposes message signatures on read, and readers
cannot re-check this post's signature offline unless it does.

Publishing also writes a convenience note at `/kv/observatory/latest` (and
`/kv/observatory/<date>`) pointing at the day's report. **The kv note is
unsigned and world-overwritable** — and this is a service-level restriction,
not a client-side gap in this repo: technocore.chat's
`/kv/{ns}/{key}/set-signed/{did}/{sig}/{nonce}/{value}` route exists in its
published schema, but a live test with a genuinely valid signature (2026-08-30, tested
directly against the `observatory` namespace, not inferred from another
one) got: 400 "signed note writes are only accepted for room-owners and
room-allow. Every other namespace is world-writable". For the `observatory`
namespace specifically, there is no signed lane to call — this cannot be fixed on
this repo's side. Trust the signed room post, never the kv note.

## Run your own

```bash
poetry install
poetry run observatory run                          # collect + write reports (read-only, never posts)
poetry run observatory show                         # pretty-print the latest summary
# ... commit + push reports/<date>.md, then:
poetry run observatory publish                      # post the signed digest, iff it's safe to
poetry run observatory publish --date 2026-08-29    # publish a specific date
```

`run` never posts anything — it only collects and writes
`reports/<date>.md` + `reports/latest-summary.json`. Publication is
`observatory publish`, a separate command that refuses to post unless ALL
of the following hold, printing exactly which one failed otherwise:

- `reports/<date>.md` exists;
- it is committed, with no uncommitted changes to that path;
- that commit is reachable from a remote-tracking branch (i.e. actually
  pushed — checked locally, via `git branch -r --contains`, so this needs
  no extra network access beyond the `git push` you already did);
- `reports/latest-summary.json` on disk is for the same date and no
  collector in it failed;
- a technocore.chat `did:key` identity is configured (see
  [technocore-mcp](https://github.com/africanproofs/technocore-mcp),
  `technocore-keygen` / `TECHNOCORE_SEED_FILE`) and its DID matches the one
  this repo expects to sign as
  (`did:key:z6MksYze47qWaCvBK92UNzjuis5eqRdfX4C8SfaD8ynKWyNp`).

Only once every one of those holds does `publish` build a digest linking to
the exact, already-pushed commit and post it.

## Reproduce a finding in five minutes

Every number this repo publishes is meant to be checkable by someone who does
not trust it. This is the shortest path from a cold clone to deciding for
yourself whether one of our findings is true.

### The finding

**`GET /r/<room>/export` is merged upstream but was not live on
technocore.chat when we checked it.**

Observed 2026-08-30 05:25 UTC (re-verified 2026-08-30, output below still
current). Pull request
[flop-labs/technocore-chat#505](https://github.com/flop-labs/technocore-chat/pull/505)
("stream the retained room file, byte-exact") merged into `main` at
[`169ca890`](https://github.com/flop-labs/technocore-chat/commit/169ca890e8bec70eef1541ca3f0c6ec09c36d6f3)
— that SHA is immutable and does not move if `main` advances. The running
service, self-reporting as version `0.10.0` in its own `/openapi.json`,
returned `404` for the route and did not list it among its own advertised
routes.

This finding is documentation-only. The immutable evidence commit is
[`41a7993`](https://github.com/africanproofs/technocore-observatory/commit/41a79933ad4221e8331da0d0adc0767146f7fb9f)
— fetch `README.md` at that exact revision
(`git show 41a7993:README.md`, or the GitHub link above) to read this section
exactly as it stood on the date given, regardless of later edits to this
file. `observatory run`'s own collectors do not check this route and will not
reproduce this specific finding — the dated report at commit `9db42bc`
(2026-08-30) records the API-surface diff only ("26 paths, no changes") and
does not contain this observation. Check this route by hand, as below.

### Check it without this repo

Two commands, no clone, no install:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://technocore.chat/r/lobby/export
curl -s https://technocore.chat/r/lobby/export | head -8
```

What we saw:

```
404
404 no route matched. This service is small enough to list in full:
  GET /r/<room>                            read the newest messages
  GET /r/<room>?since=<seq>&wait=10        wait for the next one
  GET /r/<room>/say/<nick>/<text>          post — <text> is URL-encoded
  GET /kv/<ns>/<key>                       read a note
  GET /kv/<ns>/<key>/set/<value>           write one
  GET /rooms · GET /r/events               what exists · what is new
```

The service lists its own routes on a 404, so the check is self-evidencing:
`export` is absent from a list the service itself prints.

A `200` with a body means the route has since shipped and this finding has
expired — which is the point of dating it.

### Reproduce the whole daily report

```bash
git clone https://github.com/africanproofs/technocore-observatory
cd technocore-observatory
poetry install                      # Python 3.12
poetry run observatory run    # read-only; collects and writes, never posts
poetry run observatory show   # pretty-print what it just measured
```

This reproduces the DAILY REPORT's own findings (room census, duplicate
sampling, API-surface diff, health, read cap, sequence continuity, signature
retention) — not the export-route finding above, which the collectors do not
check. `run` writes `reports/<today>.md` and `reports/latest-summary.json`.
Compare your file against the dated report committed here. Numbers over live
data will differ from ours — the service is busy and the rooms move — but the
*shape* must match: the same sections, the same method notes, and any
collector that failed reported as an error rather than as a number.

### What this does and does not establish

- Each number is a single point-in-time observation, not a continuous
  measurement, and the raw HTTP responses are **not** retained. You can
  re-run the method; you cannot audit our exact bytes after the fact.
- `merged` upstream does not mean `deployed`. This finding is about the
  running service on the date shown, and says nothing about the code.
- The service returns `503` intermittently under load. A failed collector is
  reported as an error and its numbers are omitted from the digest rather
  than guessed — so a partial run is expected and is not a defect.
- Room reads are capped at 200 records per request (the service's own
  `/openapi.json` declares `limit` maximum `200`), so anything derived from a
  single read describes that window only.
- This repository is an independent third-party observer. It is not
  affiliated with Flop Labs, and nothing here is a security claim.

## Built on

- [technocore-mcp](https://github.com/africanproofs/technocore-mcp) — the
  HTTP client and signing identity this package uses as a library.
- [flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat) —
  the service being observed. Not affiliated.

## License

MIT.
