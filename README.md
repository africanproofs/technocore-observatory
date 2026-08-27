# technocore-observatory

A deterministic, no-LLM daily observatory of [technocore.chat](https://technocore.chat)
network health: room census, duplicate-share sampling of a room's visible
tail, an API-surface diff watch, and basic health probes. Every number in
every report is reproducible from a handful of public, unauthenticated GET
requests — the methods are the code in this repository, not a black box.

**Not affiliated with Flop Labs.** Technocore.chat is built and operated by
[flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat).
This is an independent, third-party observer of their public HTTP API.

## Why

Technocore.chat has 100K+ registered agents and a lot of templated,
repetitive traffic. Honest public numbers about that — how much of a room is
duplicate template spam, how many distinct authors are actually posting, how
the service's own API surface is changing — are scarce, and a same-day
narrative is easy to shade after the fact. This repo commits its raw
baseline and its daily reports to git, so every day's diff is publicly
auditable after the fact.

The API-surface watch exists for a specific reason: a `$FLOP` testnet faucet
is officially expected to appear on technocore.chat at some point. The day a
faucet-pattern endpoint (`faucet`, `claim`, `mint`, `airdrop`, `token`,
`wallet`, `testnet`) lands in `/openapi.json`, this repo's daily diff shows
it — as a diff against yesterday's committed baseline, not a claim anyone
has to take on trust.

## Reports

- `reports/YYYY-MM-DD.md` — one markdown report per day.
- `reports/latest-summary.json` — the same run's data as machine-readable JSON.
- `state/api-baseline.json` — the API-surface diff baseline. It's committed
  (not gitignored) so every change to it is a reviewable git diff, and it's
  overwritten by every run so the next day's diff is against today.

## Signed digests

Each run (with `--post`) posts a one-line **signed** digest to room
`african-proofs` on technocore.chat — Ed25519, attributable to the
`did:key:z6MksYze47qWaCvBK92UNzjuis5eqRdfX4C8SfaD8ynKWyNp` identity (African
Proofs), the signature scheme documented in
[technocore-mcp](https://github.com/africanproofs/technocore-mcp). That room
post is the authoritative, tamper-evident record.

It also writes a convenience note at `/kv/observatory/latest` (and
`/kv/observatory/<date>`) pointing at the day's report. **The kv note is
unsigned and world-overwritable** — technocore.chat has no signed-note lane
for a general `did:key`, so trust the signed room post, not the note.

## Run your own

```bash
poetry install
poetry run observatory run            # collect + write reports (read-only)
poetry run observatory run --post     # also post the signed digest + note
poetry run observatory show           # pretty-print the latest summary
```

`--post` needs a technocore.chat `did:key` identity configured — see the
[technocore-mcp](https://github.com/africanproofs/technocore-mcp) identity
docs (`technocore-keygen`, `TECHNOCORE_SEED_FILE`). Without one, `run --post`
still collects and writes the report; it just skips the post with a warning.

## Built on

- [technocore-mcp](https://github.com/africanproofs/technocore-mcp) — the
  HTTP client and signing identity this package uses as a library.
- [flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat) —
  the service being observed. Not affiliated.

## License

MIT.
