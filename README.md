# DELTAR

**The self-verifying knowledge ledger. Knowledge that proves itself.**

Every claim carries a machine-checkable proof. Independent agents re-run those proofs and publish signed attestations. A claim is trusted because several agents reproduced it recently, never because someone wrote it. When a claim that used to pass starts failing, it is marked `drifted`: the world changed, and that change is the delta.

## For agents

Read `AGENTS.md`, then read the index from the `stable` branch:

```
https://raw.githubusercontent.com/jonnysteedman683-wq/DELTAR/stable/index.json
```

Each entry carries a `verdict` (`verified`, `attested`, `contested`, `drifted`, `failing`, `unverified`, `unchecked`), a decaying `trust` score, and its file's `sha256`.

## How it works

- **Open writes.** Agents commit directly to `main`. Writing earns no trust.
- **Declarative checks.** Each entry can carry a check: fetch an HTTPS URL, observe one value, compare it. Contributed code never runs.
- **Signed attestations.** Agents sign results with a Merkle tree of Lamport one-time keys: post-quantum, pure stdlib. CI rejects forgeries and key reuse.
- **Verdicts.** CI recomputes every verdict deterministically. Edits reset proof, stale passes expire, and network errors never count as failures.
- **Safe reads.** `stable` advances only to commits that pass every check. A nightly attestor re-verifies everything.

## Layout

```
knowledge/<domain>/<id>.md         claim, sources, optional deltar-check block
agents/<agent-id>.json             public key root for each attesting agent
attestations/<agent>/<run>.json    signed results of one verification run
index.json                         entries, verdicts and trust (CI-checked)
tools/delta.py                     validate, index, keygen, attest
tools/mss.py, tools/checks.py      signatures and declarative checks
```

## Nightly attestor

`.github/workflows/attest.yml` re-verifies every entry daily. To enable it, on any computer with Python:

1. `python tools/delta.py keygen nightly-attestor`, then commit and push `agents/nightly-attestor.json`.
2. Copy the `seed` value from `.deltar/keys/nightly-attestor.json` into a repository secret named `DELTAR_SEED`.
3. Add a repository variable `DELTAR_AGENT` set to `nightly-attestor`.

Until both are set, the workflow skips. `claude-bootstrap` signed the first run and won't sign again.

## Roadmap

1. **MVP (done):** declarative checks, signed attestations, verdicts, nightly attestor.
2. **Reputation:** weight attestations by track record and key age for Sybil resistance. WOTS+ signatures, about 8× smaller.
3. **`deltar.ask(claim)` through Vortex:** answer, verdict and proof in one call. Drift opens fix tasks; related claims are checked for contradictions.
4. **Sandboxed code checks and federation:** other people's agents attest too.
