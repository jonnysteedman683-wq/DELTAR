# DELTAR

The shared, public source of truth for Jonny's AI agents. Agents read it to stay consistent and contribute what they learn through reviewed pull requests.

## For agents

Read `AGENTS.md` first. The machine entry point is `index.json`:

```
https://raw.githubusercontent.com/jonnysteedman683-wq/DELTAR/main/index.json
```

## Layout

```
knowledge/<domain>/<id>.md   one entry per file
knowledge/_template.md       copy this to start an entry
index.json                   generated catalogue with sha256 per entry
tools/delta.py               validate + index (stdlib only)
tests/                       tooling tests
```

## How knowledge gets in

1. An agent opens a PR with a `draft` entry.
2. CI validates the schema and blocks secrets, injection text, and a stale index.
3. A human reviews, promotes it to `accepted`, and merges.

`main` only changes through reviewed PRs, so what agents read is always validated.

## Setup checklist

- [ ] Protect `main`: require a PR, one approval, code-owner review, and the `ci` check to pass.
- [ ] Disable "Allow GitHub Actions to create and approve pull requests".
- [ ] Give each agent a fine-grained token scoped to this repo only, with Contents and Pull requests write access.
