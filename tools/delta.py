#!/usr/bin/env python3
"""DELTAR tooling: a self-verifying knowledge ledger. Stdlib only.

    python tools/delta.py validate              check entries, agents and attestations
    python tools/delta.py index [--check]       rebuild index.json, or fail if it is stale
    python tools/delta.py keygen <agent-id>     create a signing key and register the agent
    python tools/delta.py attest <agent-id>     run every check and write a signed attestation
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import checks  # noqa: E402
import mss  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR, AGENTS_DIR, ATTEST_DIR = "knowledge", "agents", "attestations"
KEY_DIR = Path(".deltar") / "keys"
INDEX_FILE = "index.json"
SCHEMA_VERSION = 2
MAX_BYTES = 64_000
DEFAULT_HEIGHT = 10            # 1024 one-time signatures per key
QUORUM, MAX_AGE_DAYS, HALF_LIFE_DAYS = 2, 90, 30
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"

REQUIRED = ("id", "title", "domain", "author", "status", "confidence", "updated", "sources")
OPTIONAL = ("tags", "supersedes")
LIST_FIELDS = {"sources", "tags"}
STATUSES = {"draft", "accepted", "deprecated"}
CONFIDENCE = {"low", "medium", "high"}
OUTCOMES = {"pass", "fail", "error"}
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CHECK_BLOCK = re.compile(r"^```deltar-check\n(.*?)\n```[ \t]*$", re.M | re.S)

# Public repo: block credentials outright.
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
# Agents read this repo: block text written to hijack them.
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+|any\s+)?(previous|prior|above)", re.I),
    re.compile(r"<\s*/?\s*(system|assistant)\s*>", re.I),
]


def flagged(text: str) -> bool:
    return any(p.search(text) for p in SECRET_PATTERNS + INJECTION_PATTERNS)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_time(value) -> datetime:
    return datetime.strptime(value, TIME_FMT).replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- entries

def parse(text: str) -> tuple[dict, str]:
    """Parse the frontmatter subset DELTAR allows: `key: value` and `key: [a, b]`."""
    if not text.startswith("---\n"):
        raise ValueError("missing frontmatter (file must start with '---')")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError("unterminated frontmatter")
    meta: dict = {}
    for n, line in enumerate(text[4:end].splitlines(), start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, val = line.partition(":")
        if not sep:
            raise ValueError(f"line {n}: expected 'key: value'")
        key, val = key.strip(), val.strip()
        if key in meta:
            raise ValueError(f"duplicate key '{key}'")
        if key in LIST_FIELDS:
            if not (val.startswith("[") and val.endswith("]")):
                raise ValueError(f"'{key}' must be a list like [a, b]")
            meta[key] = [v.strip().strip("\"'") for v in val[1:-1].split(",") if v.strip()]
        else:
            meta[key] = val.strip("\"'")
    return meta, text[end + 5:]


def validate_entry(path: Path, root: Path) -> tuple[dict | None, list[str]]:
    rel = path.relative_to(root).as_posix()
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        return None, [f"{rel}: larger than {MAX_BYTES} bytes; split it"]
    text = raw.decode("utf-8")
    try:
        meta, body = parse(text)
    except ValueError as exc:
        return None, [f"{rel}: {exc}"]

    errs = [f"{rel}: missing field '{k}'" for k in REQUIRED if k not in meta]
    errs += [f"{rel}: unknown field '{k}'" for k in meta if k not in REQUIRED + OPTIONAL]
    if errs:
        return None, errs

    for field in ("id", "domain"):
        if not SLUG.match(meta[field]):
            errs.append(f"{rel}: {field} '{meta[field]}' must be kebab-case")
    if path.stem != meta["id"]:
        errs.append(f"{rel}: filename must be '{meta['id']}.md'")
    if path.parent.name != meta["domain"]:
        errs.append(f"{rel}: must live in knowledge/{meta['domain']}/")
    if meta["status"] not in STATUSES:
        errs.append(f"{rel}: status must be one of {sorted(STATUSES)}")
    if meta["confidence"] not in CONFIDENCE:
        errs.append(f"{rel}: confidence must be one of {sorted(CONFIDENCE)}")
    try:
        if date.fromisoformat(meta["updated"]) > date.today():
            errs.append(f"{rel}: updated date is in the future")
    except ValueError:
        errs.append(f"{rel}: updated must be YYYY-MM-DD")
    if not meta["sources"]:
        errs.append(f"{rel}: at least one source is required")
    if "supersedes" in meta and not SLUG.match(meta["supersedes"]):
        errs.append(f"{rel}: supersedes must be an entry id")
    if not body.strip():
        errs.append(f"{rel}: body is empty")
    if any(p.search(text) for p in SECRET_PATTERNS):
        errs.append(f"{rel}: looks like it contains a credential")
    if any(p.search(text) for p in INJECTION_PATTERNS):
        errs.append(f"{rel}: contains instruction-injection text")

    blocks = CHECK_BLOCK.findall(body)
    if len(blocks) > 1:
        errs.append(f"{rel}: only one deltar-check block is allowed")
    elif blocks:
        try:
            check = json.loads(blocks[0])
        except json.JSONDecodeError as exc:
            errs.append(f"{rel}: deltar-check block is not valid JSON ({exc.msg})")
        else:
            errs += [f"{rel}: {m}" for m in checks.validate_check(check)]
            meta["check"] = check
    elif "```deltar-check" in body:
        errs.append(f"{rel}: deltar-check block is not closed with ```")

    if errs:
        return None, errs
    meta["path"] = rel
    meta["sha256"] = hashlib.sha256(raw).hexdigest()
    return meta, []


def load_entries(root: Path) -> tuple[list[dict], list[str]]:
    entries, errors, seen = [], [], {}
    base = root / KNOWLEDGE_DIR
    files = sorted(p for p in base.rglob("*.md") if not p.name.startswith("_")) if base.exists() else []
    for path in files:
        meta, errs = validate_entry(path, root)
        errors += errs
        if meta is None:
            continue
        if meta["id"] in seen:
            errors.append(f"{meta['path']}: id '{meta['id']}' already used by {seen[meta['id']]}")
            continue
        seen[meta["id"]] = meta["path"]
        entries.append(meta)
    for e in entries:
        if "supersedes" in e and e["supersedes"] not in seen:
            errors.append(f"{e['path']}: supersedes unknown id '{e['supersedes']}'")
    return entries, errors


# ---------------------------------------------------------------- agents & attestations

def load_agents(root: Path) -> tuple[dict, list[str]]:
    agents, errors = {}, []
    base = root / AGENTS_DIR
    for path in sorted(base.glob("*.json")) if base.exists() else []:
        rel = path.relative_to(root).as_posix()
        try:
            a = json.loads(path.read_text("utf-8"))
        except (ValueError, UnicodeDecodeError):
            errors.append(f"{rel}: not valid JSON")
            continue
        if not isinstance(a, dict) or set(a) != {"agent", "root", "height", "created"}:
            errors.append(f"{rel}: needs exactly agent, root, height, created")
            continue
        if not isinstance(a["agent"], str) or not SLUG.match(a["agent"]) or path.stem != a["agent"]:
            errors.append(f"{rel}: agent must be kebab-case and match the filename")
        elif not (isinstance(a["root"], str) and re.fullmatch(r"[0-9a-f]{64}", a["root"])):
            errors.append(f"{rel}: root must be 64 hex characters")
        elif not (isinstance(a["height"], int) and not isinstance(a["height"], bool) and 1 <= a["height"] <= 16):
            errors.append(f"{rel}: height must be an integer from 1 to 16")
        else:
            agents[a["agent"]] = a
    return agents, errors


def _valid_result(r) -> bool:
    return (isinstance(r, dict) and set(r) == {"id", "entry_sha256", "outcome", "observed", "error"}
            and isinstance(r["id"], str) and r["outcome"] in OUTCOMES
            and isinstance(r["entry_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", r["entry_sha256"])
            and (r["error"] is None or isinstance(r["error"], str)))


def load_attestations(root: Path, agents: dict) -> tuple[list[dict], dict, list[str]]:
    """Return (attestations, used one-time keys {(agent, index): path}, errors)."""
    out, used, errors = [], {}, []
    base = root / ATTEST_DIR
    latest_ok = datetime.now(timezone.utc) + timedelta(minutes=10)
    for path in sorted(base.glob("*/*.json")) if base.exists() else []:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text("utf-8")
            a = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            errors.append(f"{rel}: not valid JSON")
            continue
        if flagged(text):
            errors.append(f"{rel}: contains credential or injection text")
            continue
        if not isinstance(a, dict) or set(a) != {"version", "agent", "run_at", "commit", "env", "results", "signature"}:
            errors.append(f"{rel}: malformed attestation")
            continue
        agent = agents.get(a["agent"]) if isinstance(a["agent"], str) else None
        if agent is None or path.parent.name != a["agent"]:
            errors.append(f"{rel}: agent is not registered in agents/ or folder does not match")
            continue
        try:
            run_at = parse_time(a["run_at"])
        except (TypeError, ValueError):
            errors.append(f"{rel}: run_at must look like 2026-01-31T12:00:00Z")
            continue
        if run_at > latest_ok:
            errors.append(f"{rel}: run_at is in the future")
            continue
        if not isinstance(a["results"], list) or not all(_valid_result(r) for r in a["results"]):
            errors.append(f"{rel}: malformed results")
            continue
        payload = {k: v for k, v in a.items() if k != "signature"}
        if not mss.verify(agent["root"], agent["height"], canonical(payload), a["signature"]):
            errors.append(f"{rel}: signature does not verify against agents/{a['agent']}.json")
            continue
        key = (a["agent"], a["signature"]["key_index"])
        if key in used:
            errors.append(f"{rel}: reuses one-time key {key[1]} already used by {used[key]}")
            continue
        used[key] = rel
        out.append({"agent": a["agent"], "run_at": run_at, "results": a["results"]})
    return out, used, errors


def load(root: Path = ROOT) -> dict:
    entries, e1 = load_entries(root)
    agents, e2 = load_agents(root)
    attestations, used, e3 = load_attestations(root, agents)
    return {"entries": entries, "agents": agents, "attestations": attestations,
            "used": used, "errors": e1 + e2 + e3}


# ---------------------------------------------------------------- verdicts & index

def verdict(entry: dict, attestations: list[dict], as_of: datetime | None) -> dict:
    check = entry.get("check")
    if not check:
        return {"verdict": "unchecked"}
    quorum = check.get("quorum", QUORUM)
    max_age = check.get("max_age_days", MAX_AGE_DAYS)
    half_life = check.get("half_life_days", HALF_LIFE_DAYS)

    latest, ever_passed = {}, False
    for att in attestations:
        for r in att["results"]:
            # Only results for this exact version of the entry count. Edits reset proof.
            if r["id"] != entry["id"] or r["entry_sha256"] != entry["sha256"] or r["outcome"] == "error":
                continue
            ever_passed |= r["outcome"] == "pass"
            prev = latest.get(att["agent"])
            if prev is None or att["run_at"] > prev[0]:
                latest[att["agent"]] = (att["run_at"], r["outcome"])

    fresh = {ag: v for ag, v in latest.items() if as_of and (as_of - v[0]).days <= max_age}
    passes = sorted(t for t, o in fresh.values() if o == "pass")
    fails = sum(1 for _, o in fresh.values() if o == "fail")
    trust = sum(0.5 ** ((as_of - t).total_seconds() / 86400 / half_life) for t in passes) if passes else 0.0

    if not fresh:
        state = "unverified"
    elif passes and fails:
        state = "contested"
    elif fails:
        state = "drifted" if ever_passed else "failing"
    elif len(passes) >= quorum:
        state = "verified"
    else:
        state = "attested"
    return {"verdict": state, "trust": round(trust, 3), "passes": len(passes), "fails": fails,
            "last_verified": passes[-1].strftime(TIME_FMT) if passes else None}


def build_index(entries: list[dict], attestations: list[dict]) -> str:
    # Deterministic: "now" is the newest attestation, so `index --check` is a pure diff.
    as_of = max((a["run_at"] for a in attestations), default=None)
    rows = [{**e, **verdict(e, attestations, as_of)} for e in sorted(entries, key=lambda e: e["id"])]
    data = {"schema_version": SCHEMA_VERSION,
            "as_of": as_of.strftime(TIME_FMT) if as_of else None,
            "entries": rows}
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_index(root: Path, state: dict) -> None:
    (root / INDEX_FILE).write_text(build_index(state["entries"], state["attestations"]), "utf-8")


# ---------------------------------------------------------------- keys

def key_path(root: Path, agent_id: str) -> Path:
    return root / KEY_DIR / f"{agent_id}.json"


def keygen(root: Path, agent_id: str, height: int = DEFAULT_HEIGHT) -> Path:
    if not SLUG.match(agent_id):
        raise SystemExit("agent id must be kebab-case")
    reg, kp = root / AGENTS_DIR / f"{agent_id}.json", key_path(root, agent_id)
    if reg.exists() or kp.exists():
        raise SystemExit(f"agent '{agent_id}' already has a key; pick a new id to rotate")
    seed = os.urandom(32)
    root_hex = mss.public_root(seed, height)
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.write_text(json.dumps({"agent": agent_id, "seed": seed.hex(), "height": height, "next_index": 0}), "utf-8")
    os.chmod(kp, 0o600)
    reg.parent.mkdir(parents=True, exist_ok=True)
    reg.write_text(json.dumps({"agent": agent_id, "root": root_hex, "height": height,
                               "created": date.today().isoformat()}, indent=2) + "\n", "utf-8")
    return kp


def _load_seed(root: Path, agent_id: str) -> tuple[bytes, dict | None]:
    env_seed = os.environ.get("DELTAR_SEED", "").strip()
    if env_seed:
        return bytes.fromhex(env_seed), None
    kp = key_path(root, agent_id)
    if not kp.exists():
        raise SystemExit(f"no key for '{agent_id}': run keygen or set DELTAR_SEED")
    data = json.loads(kp.read_text("utf-8"))
    return bytes.fromhex(data["seed"]), data


def _sanitize(observed):
    if observed is not None and not isinstance(observed, (str, int, float, bool)):
        observed = json.dumps(observed, ensure_ascii=False)
    if isinstance(observed, str):
        observed = observed[:120]
        if flagged(observed):
            observed = "[redacted]"
    return observed


def attest(root: Path, agent_id: str, now: datetime | None = None, run=None) -> Path | None:
    state = load(root)
    if state["errors"]:
        raise SystemExit("fix validation errors before attesting:\n" + "\n".join(state["errors"]))
    agent = state["agents"].get(agent_id)
    if agent is None:
        raise SystemExit(f"agent '{agent_id}' is not registered in {AGENTS_DIR}/")
    targets = [e for e in state["entries"] if e.get("check")]
    if not targets:
        print("no entries have checks; nothing to attest")
        return None

    seed, keyfile = _load_seed(root, agent_id)
    used = [i for (ag, i) in state["used"] if ag == agent_id]
    index = max([max(used) + 1 if used else 0, keyfile["next_index"] if keyfile else 0])
    if index >= 2 ** agent["height"]:
        raise SystemExit("signing key exhausted: register a new agent id")
    if keyfile:  # advance local state before signing so a crash can never reuse a key
        keyfile["next_index"] = index + 1
        key_path(root, agent_id).write_text(json.dumps(keyfile), "utf-8")

    run = run or checks.run_check
    results = []
    for e in targets:
        outcome, observed, error = run(e["check"])
        results.append({"id": e["id"], "entry_sha256": e["sha256"], "outcome": outcome,
                        "observed": _sanitize(observed), "error": _sanitize(error)})
    now = now or datetime.now(timezone.utc)
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                                text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    payload = {"version": 1, "agent": agent_id, "run_at": now.strftime(TIME_FMT), "commit": commit,
               "env": f"python-{platform.python_version()}-{platform.system().lower()}", "results": results}
    sig, root_hex = mss.sign(seed, agent["height"], index, canonical(payload))
    if root_hex != agent["root"]:
        raise SystemExit(f"this key does not match agents/{agent_id}.json")
    out = root / ATTEST_DIR / agent_id / f"{now.strftime('%Y%m%dT%H%M%SZ')}-{index}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({**payload, "signature": sig}, indent=1, ensure_ascii=False) + "\n", "utf-8")
    write_index(root, load(root))
    tally = {o: sum(r["outcome"] == o for r in results) for o in sorted(OUTCOMES)}
    print(f"attested {len(results)} checks as {agent_id} (key {index}): {tally}")
    return out


# ---------------------------------------------------------------- cli

def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    ap = argparse.ArgumentParser(prog="delta")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate")
    ix = sub.add_parser("index")
    ix.add_argument("--check", action="store_true")
    kg = sub.add_parser("keygen")
    kg.add_argument("agent")
    kg.add_argument("--height", type=int, default=DEFAULT_HEIGHT)
    at = sub.add_parser("attest")
    at.add_argument("agent")
    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        kp = keygen(root, args.agent, args.height)
        print(f"registered agents/{args.agent}.json; secret seed saved to {kp} (never commit it)")
        return 0
    if args.cmd == "attest":
        attest(root, args.agent)
        return 0

    state = load(root)
    if state["errors"]:
        print("\n".join(state["errors"]), file=sys.stderr)
        return 1
    if args.cmd == "validate":
        print(f"ok: {len(state['entries'])} entries, {len(state['agents'])} agents, "
              f"{len(state['attestations'])} attestations valid")
        return 0

    fresh = build_index(state["entries"], state["attestations"])
    index_path = root / INDEX_FILE
    if args.check:
        current = index_path.read_text("utf-8") if index_path.exists() else ""
        if current != fresh:
            print("index.json is stale: run `python tools/delta.py index`", file=sys.stderr)
            return 1
        print("ok: index.json is current")
        return 0
    index_path.write_text(fresh, "utf-8")
    print(f"wrote {INDEX_FILE} ({len(state['entries'])} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
