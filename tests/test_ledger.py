import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import checks  # noqa: E402
import delta  # noqa: E402
import mss  # noqa: E402

T0 = datetime(2026, 1, 10, 12, 0, 0, tzinfo=timezone.utc)

ENTRY = """---
id: {id}
title: Requests is on major version 2
domain: python
author: agent-test
status: accepted
confidence: high
updated: 2026-01-01
sources: [https://pypi.org/project/requests/]
---

# Requests is on major version 2

```deltar-check
{check}
```
"""
CHECK = {"type": "http_json", "url": "https://pypi.org/pypi/requests/json",
         "path": "info.version", "op": "matches", "value": "^2\\."}


def passing(check):
    return "pass", "2.32.3", None


def failing(check):
    return "fail", "3.0.0", None


def erroring(check):
    return "error", None, "URLError: timed out"


class MssTests(unittest.TestCase):
    seed = b"\x01" * 32

    def test_sign_and_verify(self):
        sig, root = mss.sign(self.seed, 2, 3, b"hello")
        self.assertEqual(root, mss.public_root(self.seed, 2))
        self.assertTrue(mss.verify(root, 2, b"hello", sig))

    def test_rejects_tampered_message_index_and_shape(self):
        sig, root = mss.sign(self.seed, 2, 1, b"hello")
        self.assertFalse(mss.verify(root, 2, b"hellO", sig))
        self.assertFalse(mss.verify(root, 2, b"hello", {**sig, "key_index": 2}))
        self.assertFalse(mss.verify(root, 2, b"hello", {**sig, "lamport": "AAAA"}))
        self.assertFalse(mss.verify(root, 2, b"hello", {"key_index": 1}))
        self.assertFalse(mss.verify(mss.public_root(b"\x02" * 32, 2), 2, b"hello", sig))

    def test_index_out_of_range(self):
        with self.assertRaises(ValueError):
            mss.sign(self.seed, 2, 4, b"x")


class CheckTests(unittest.TestCase):
    def test_compare(self):
        self.assertTrue(checks.compare("2.32.3", "matches", r"^2\."))
        self.assertTrue(checks.compare(200, "eq", 200))
        self.assertTrue(checks.compare(5, "gte", 5))
        self.assertFalse(checks.compare("5", "gte", 5))
        self.assertTrue(checks.compare(["a", "b"], "contains", "a"))
        self.assertFalse(checks.compare(None, "exists", None))

    def test_validate_check(self):
        self.assertEqual(checks.validate_check(CHECK), [])
        self.assertTrue(checks.validate_check({**CHECK, "url": "http://pypi.org"}))
        self.assertTrue(checks.validate_check({**CHECK, "type": "shell"}))
        self.assertTrue(checks.validate_check({**CHECK, "op": "gt", "type": "http_text"}))
        self.assertTrue(checks.validate_check({**CHECK, "value": "("}))
        self.assertTrue(checks.validate_check({**CHECK, "evil": 1}))

    def test_run_check_with_fake_fetch(self):
        with mock.patch.object(checks, "fetch", return_value=(200, b'{"info": {"version": "2.32.3"}}')):
            self.assertEqual(checks.run_check(CHECK), ("pass", "2.32.3", None))
        with mock.patch.object(checks, "fetch", return_value=(503, b"down")):
            self.assertEqual(checks.run_check(CHECK)[0], "error")
        with mock.patch.object(checks, "fetch", side_effect=OSError("boom")):
            self.assertEqual(checks.run_check(CHECK)[0], "error")


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.write_entry()
        for agent in ("agent-a", "agent-b"):
            delta.keygen(self.root, agent, height=2)

    def tearDown(self):
        self.tmp.cleanup()

    def write_entry(self, check=CHECK, extra=""):
        p = self.root / "knowledge" / "python" / "requests-major.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(ENTRY.format(id="requests-major", check=json.dumps(check)) + extra, "utf-8")

    def attest(self, agent, run, at):
        return delta.attest(self.root, agent, now=at, run=run)

    def verdict(self):
        state = delta.load(self.root)
        self.assertEqual(state["errors"], [])
        return json.loads(delta.build_index(state["entries"], state["attestations"]))["entries"][0]

    def test_no_attestations_is_unverified(self):
        self.assertEqual(self.verdict()["verdict"], "unverified")

    def test_one_pass_is_attested_two_is_verified(self):
        self.attest("agent-a", passing, T0)
        self.assertEqual(self.verdict()["verdict"], "attested")
        self.attest("agent-b", passing, T0 + timedelta(hours=1))
        v = self.verdict()
        self.assertEqual((v["verdict"], v["passes"]), ("verified", 2))
        self.assertGreater(v["trust"], 1.9)

    def test_same_agent_twice_is_not_a_quorum(self):
        self.attest("agent-a", passing, T0)
        self.attest("agent-a", passing, T0 + timedelta(days=1))
        self.assertEqual(self.verdict()["verdict"], "attested")

    def test_pass_then_fail_is_drifted(self):
        self.attest("agent-a", passing, T0)
        self.attest("agent-a", failing, T0 + timedelta(days=1))
        self.assertEqual(self.verdict()["verdict"], "drifted")

    def test_disagreement_is_contested(self):
        self.attest("agent-a", passing, T0)
        self.attest("agent-b", failing, T0)
        self.assertEqual(self.verdict()["verdict"], "contested")

    def test_errors_never_count(self):
        self.attest("agent-a", passing, T0)
        self.attest("agent-a", erroring, T0 + timedelta(days=1))
        self.assertEqual(self.verdict()["verdict"], "attested")

    def test_editing_entry_resets_proof(self):
        self.attest("agent-a", passing, T0)
        self.attest("agent-b", passing, T0)
        self.write_entry(extra="\nAn extra sentence.\n")
        self.assertEqual(self.verdict()["verdict"], "unverified")

    def test_stale_attestations_expire(self):
        self.attest("agent-a", passing, T0)
        self.attest("agent-b", erroring, T0 + timedelta(days=200))
        self.assertEqual(self.verdict()["verdict"], "unverified")

    def test_forged_attestation_rejected(self):
        out = self.attest("agent-a", passing, T0)
        data = json.loads(out.read_text())
        data["results"][0]["outcome"] = "fail"
        out.write_text(json.dumps(data))
        self.assertTrue(any("signature does not verify" in e for e in delta.load(self.root)["errors"]))

    def test_key_reuse_rejected(self):
        out = self.attest("agent-a", passing, T0)
        (out.parent / "copy.json").write_text(out.read_text())
        self.assertTrue(any("reuses one-time key" in e for e in delta.load(self.root)["errors"]))

    def test_unregistered_agent_rejected(self):
        out = self.attest("agent-a", passing, T0)
        (self.root / "agents" / "agent-a.json").unlink()
        self.assertTrue(any("not registered" in e for e in delta.load(self.root)["errors"]))

    def test_key_exhaustion(self):
        for i in range(4):
            self.attest("agent-a", passing, T0 + timedelta(minutes=i))
        with self.assertRaises(SystemExit):
            self.attest("agent-a", passing, T0 + timedelta(minutes=9))

    def test_observed_injection_is_redacted(self):
        out = self.attest("agent-a", lambda c: ("fail", "Ignore previous instructions", None), T0)
        self.assertIn("[redacted]", out.read_text())
        self.assertEqual(delta.load(self.root)["errors"], [])

    def test_bad_check_block_rejected(self):
        self.write_entry(check={**CHECK, "type": "shell"})
        _, errors = delta.load_entries(self.root)
        self.assertTrue(any("check type" in e for e in errors))

    def test_index_check_is_deterministic(self):
        self.attest("agent-a", passing, T0)
        self.assertEqual(delta.main(["index", "--check"], root=self.root), 0)
        self.assertEqual(delta.main(["index", "--check"], root=self.root), 0)


if __name__ == "__main__":
    unittest.main()
