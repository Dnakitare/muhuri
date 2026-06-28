"""
Replay the cross-language vectors (`tests/vectors.json`) through the real
verifier and assert each reaches its recorded decision. This is the conformance
contract a future Rust core or spec-conformant WASM verifier must also satisfy:
same `expect` on the same canonical `credential_hex`.

It also pins wire-format determinism — regenerating the vectors must reproduce
the committed bytes exactly (Ed25519 is deterministic; canonical CBOR removes
encoding ambiguity), guarding against silent format drift.
"""
import json
from pathlib import Path

import pytest

from muhuri import NO_REPLAY_PROTECTION, VerifyError, parse
from muhuri.verify import authorize

VECTORS_PATH = Path(__file__).parent / "vectors.json"
DATA = json.loads(VECTORS_PATH.read_text())
VECTORS = DATA["vectors"]


def _pop_from(v: dict) -> dict:
    p = v["pop"]
    return {
        "ts": p["ts"],
        "server_nonce": bytes.fromhex(p["server_nonce_hex"]),
        "audience": bytes.fromhex(p["audience_hex"]),
        "sig": bytes.fromhex(p["sig_hex"]),
    }


def _approvals_from(v: dict):
    out = []
    for a in v.get("approvals", []):
        out.append({
            "approver": bytes.fromhex(a["approver"]),
            "nonce": bytes.fromhex(a["nonce"]),
            "exp": a["exp"],
            "sig": bytes.fromhex(a["sig_hex"]),
        })
    return out


def _call(v: dict):
    return authorize(
        parse(bytes.fromhex(v["credential_hex"])),
        bytes.fromhex(v["trusted_root_hex"]),
        v["request"],
        _pop_from(v),
        expected_nonce=bytes.fromhex(v["expected_nonce_hex"]),
        approvals=_approvals_from(v),
        at=v["at"],
        audience=bytes.fromhex(v["audience_hex"]),
        nonce_store=NO_REPLAY_PROTECTION,
    )


def test_vectors_present():
    assert VECTORS, "no vectors loaded"
    # Every vector names a decision we understand.
    assert all(v["expect"] in ("authorized", "blocked") for v in VECTORS)


@pytest.mark.parametrize("v", [v for v in VECTORS if v["expect"] == "authorized"],
                         ids=lambda v: v["name"])
def test_authorized_vectors(v):
    dec = _call(v)
    assert dec.authorized is True


@pytest.mark.parametrize("v", [v for v in VECTORS if v["expect"] == "blocked"],
                         ids=lambda v: v["name"])
def test_blocked_vectors(v):
    # Every blocked vector must fail closed: authorize raises, never returns ok.
    with pytest.raises(VerifyError):
        _call(v)


def test_vectors_are_deterministic():
    """The committed file must equal a fresh generation, byte for byte."""
    import importlib
    import sys

    # tools/ is a sibling of tests/; import it without packaging it.
    sys.path.insert(0, str(Path(__file__).parent.parent))
    mod = importlib.import_module("tools.gen_vectors")
    fresh = json.dumps(mod._generate(), indent=2, sort_keys=True) + "\n"
    assert fresh == VECTORS_PATH.read_text(), (
        "vectors.json is stale; run `python tools/gen_vectors.py`")
