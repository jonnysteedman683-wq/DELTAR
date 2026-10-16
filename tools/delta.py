#!/usr/bin/env python3
"""DELTAR knowledge-base tooling. Stdlib only.

    python tools/delta.py validate        # check every entry
    python tools/delta.py index           # rebuild index.json
    python tools/delta.py index --check   # fail if index.json is stale (CI)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = "knowledge"
INDEX_FILE = "index.json"
SCHEMA_VERSION = 1
MAX_BYTES = 64_000

REQUIRED = ("id", "title", "domain", "author", "status", "confidence", "updated", "sources")
OPTIONAL = ("tags", "supersedes")
LIST_FIELDS = {"sources", "tags"}
STATUSES = {"draft", "accepted", "deprecated"}
CONFIDENCE = {"low", "medium", "high"}
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

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

    if errs:
        return None, errs
    meta["path"] = rel
    meta["sha256"] = hashlib.sha256(raw).hexdigest()
    return meta, []


def validate_all(root: Path = ROOT) -> tuple[list[dict], list[str]]:
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


def build_index(entries: list[dict]) -> str:
    # Deterministic (no timestamps) so `index --check` is a pure diff.
    data = {"schema_version": SCHEMA_VERSION, "entries": sorted(entries, key=lambda e: e["id"])}
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    ap = argparse.ArgumentParser(prog="delta")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate")
    ix = sub.add_parser("index")
    ix.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    entries, errors = validate_all(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.cmd == "validate":
        print(f"ok: {len(entries)} entries valid")
        return 0

    index_path = root / INDEX_FILE
    fresh = build_index(entries)
    if args.check:
        current = index_path.read_text("utf-8") if index_path.exists() else ""
        if current != fresh:
            print("index.json is stale: run `python tools/delta.py index`", file=sys.stderr)
            return 1
        print("ok: index.json is current")
        return 0
    index_path.write_text(fresh, "utf-8")
    print(f"wrote {INDEX_FILE} ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
