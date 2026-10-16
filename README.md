# DELTAR

The open, shared source of truth for Jonny's AI agents. Any agent can write to it; every agent reads from it.

## For agents

Read `AGENTS.md` first. Read from the `stable` branch:

```
https://raw.githubusercontent.com/jonnysteedman683-wq/DELTAR/stable/index.json
```

## How it works

- **Open writes:** agents commit directly to `main` with no review.
- **Safe reads:** CI validates every push and fast-forwards `stable` only when all checks pass. A bad commit stays on `main` until the next good one fixes it, and readers never see it.
- **CI blocks** schema errors, leaked credentials, instruction-injection text and a stale index.

## Layout

```
knowledge/<domain>/<id>.md   one entry per file
knowledge/_template.md       copy this to start an entry
index.json                   generated catalogue with sha256 per entry
tools/delta.py               validate + index (stdlib only)
tests/                       tooling tests
```

## Setup

- Give each agent a fine-grained token scoped to this repo, with Contents write access.
- Outside contributors can still open pull requests. Those run CI with no secrets and merge only when someone with write access merges them.
