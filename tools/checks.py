"""Declarative checks: fetch a URL, observe one thing, compare it. No contributed code runs."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlparse

TYPES = {"http_json", "http_status", "http_text", "url_sha256"}
NUMERIC = {"gt", "gte", "lt", "lte"}
TYPE_OPS = {
    "http_json": {"eq", "ne", "contains", "matches", "exists"} | NUMERIC,
    "http_status": {"eq", "ne"} | NUMERIC,
    "http_text": {"contains", "matches"},
    "url_sha256": {"eq"},
}
ALLOWED_KEYS = {"type", "url", "path", "op", "value", "quorum", "max_age_days", "half_life_days"}
MAX_BODY = 2_000_000
TIMEOUT = 15
MAX_PATTERN = 200


def validate_check(check) -> list[str]:
    if not isinstance(check, dict):
        return ["check must be a JSON object"]
    errs = []
    unknown = set(check) - ALLOWED_KEYS
    if unknown:
        errs.append(f"unknown check keys {sorted(unknown)}")
    kind = check.get("type")
    if kind not in TYPES:
        return errs + [f"check type must be one of {sorted(TYPES)}"]
    url = check.get("url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme != "https" or not parsed.netloc:
        errs.append("check url must be an https URL")
    op = check.get("op")
    if op not in TYPE_OPS[kind]:
        errs.append(f"op for {kind} must be one of {sorted(TYPE_OPS[kind])}")
    if kind == "http_json" and not isinstance(check.get("path"), str):
        errs.append("http_json needs a path such as info.version")
    if kind != "http_json" and "path" in check:
        errs.append("path is only valid for http_json")
    if op != "exists" and "value" not in check:
        errs.append("check needs a value")
    if op == "matches":
        value = check.get("value")
        if not isinstance(value, str) or len(value) > MAX_PATTERN:
            errs.append(f"matches value must be a regex under {MAX_PATTERN} chars")
        else:
            try:
                re.compile(value)
            except re.error as exc:
                errs.append(f"invalid regex: {exc}")
    for key, lo, hi in (("quorum", 1, 9), ("max_age_days", 1, 365), ("half_life_days", 1, 365)):
        val = check.get(key)
        if key in check and not (isinstance(val, int) and not isinstance(val, bool) and lo <= val <= hi):
            errs.append(f"{key} must be an integer from {lo} to {hi}")
    return errs


def dig(data, path: str):
    for part in path.split("."):
        if isinstance(data, dict) and part in data:
            data = data[part]
        elif isinstance(data, list) and part.isdigit() and int(part) < len(data):
            data = data[int(part)]
        else:
            return None
    return data


def compare(observed, op: str, value) -> bool:
    if op == "exists":
        return observed is not None
    if op == "eq":
        return observed == value
    if op == "ne":
        return observed != value
    if op in NUMERIC:
        nums = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (observed, value))
        if not nums:
            return False
        return {"gt": observed > value, "gte": observed >= value,
                "lt": observed < value, "lte": observed <= value}[op]
    if op == "contains":
        if isinstance(observed, str) and isinstance(value, str):
            return value in observed
        return isinstance(observed, list) and value in observed
    if op == "matches":
        return isinstance(observed, str) and re.search(value, observed) is not None
    raise ValueError(f"unknown op {op}")


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != "https":
            raise urllib.error.URLError("redirect to non-https URL blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(_HttpsOnlyRedirects())
    req = urllib.request.Request(url, headers={"User-Agent": "deltar-attestor/1"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            status, body = resp.status, resp.read(MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("response larger than 2 MB")
    return status, body


def run_check(check: dict) -> tuple[str, object, str | None]:
    """Return (outcome, observed, error). outcome is pass, fail or error.

    Errors (network, parsing) never count as fail, so an outage can't fake drift.
    """
    if urlparse(check["url"]).scheme != "https":
        return "error", None, "url must be https"
    try:
        status, body = fetch(check["url"])
        kind = check["type"]
        if kind == "http_status":
            observed = status
        elif kind == "url_sha256":
            if not 200 <= status < 300:
                return "error", status, f"http {status}"
            observed = hashlib.sha256(body).hexdigest()
        else:
            if not 200 <= status < 300:
                return "error", status, f"http {status}"
            text = body.decode("utf-8", "replace")
            observed = dig(json.loads(text), check["path"]) if kind == "http_json" else text
        passed = compare(observed, check["op"], check.get("value"))
        if kind == "http_text":
            observed = "matched" if passed else "not matched"
        return ("pass" if passed else "fail"), observed, None
    except Exception as exc:  # noqa: BLE001 - every failure mode becomes an "error" outcome
        return "error", None, f"{type(exc).__name__}: {exc}"[:200]
