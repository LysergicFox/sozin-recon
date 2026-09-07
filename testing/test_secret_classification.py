"""
Mocked-tier tests for E4 — OFFLINE secret classification. Uses only PLANTED FAKE
secrets (documented example / structurally-valid but non-real values); makes zero
network calls by construction. Location-independent.
"""
import json
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p
        break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))

import secret_classification as e4
from state import RunState, Secret, secret_fingerprint


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# planted FAKE values (safe: AWS's own documented example key + structural fakes)
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_GH = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"  # ghp_ + 36 chars (real PAT length)
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijKLMNOP"
FAKE_STRIPE = "sk_live_1234567890abcdefghijklmn"
FAKE_GOOGLE = "AIza" + "B" * 35  # AIza + 35 chars (real key length), structural fake
FAKE_PK = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"


def test_classify_secret_detectors():
    assert e4.classify_secret(FAKE_AWS) == ("aws_access_key_id", "aws")
    assert e4.classify_secret(FAKE_GH) == ("github_pat", "github")
    assert e4.classify_secret(FAKE_JWT) == ("jwt", "generic")
    assert e4.classify_secret(FAKE_STRIPE) == ("stripe_key", "stripe")
    assert e4.classify_secret(FAKE_GOOGLE) == ("google_api_key", "google")
    assert e4.classify_secret(FAKE_PK) == ("private_key", "generic")
    # a non-secret string is left unclassified (no guessing)
    assert e4.classify_secret("just some ordinary text here") == (None, None)
    assert e4.classify_secret("") == (None, None)
    print("PASS: classify_secret detects aws/github/jwt/stripe/google/private-key; unknown→(None,None)")


def _seed_secret_with_archive(st, value):
    """Add a Secret whose raw_log_ref points at a real jsluice-secrets archive
    file containing `value` (fingerprint links the two, as in the real pipeline)."""
    fp = secret_fingerprint(value)
    ref = "raw/stage7_jsluice_secrets_planted.json"
    (st.run_dir / ref).write_text(json.dumps({"kind": "generic", "value": value}) + "\n")
    st.add_secrets([Secret(kind="unknown", fingerprint=fp, raw_log_ref=ref,
                           discovered_by="jsluice", discovered_at_stage=7)])
    return fp


def test_run_secret_classification_reads_archive_and_updates():
    st = fresh_state()
    _seed_secret_with_archive(st, FAKE_AWS)
    summary = e4.run_secret_classification(st)
    assert summary == {"classified": 1, "total": 1}
    s = st.load_secrets()[0]
    assert s.kind == "aws_access_key_id" and s.provider == "aws"
    assert s.validated is None, "E4 must NEVER set validated (primitive's field)"
    print("PASS: run_secret_classification recovers value from raw archive (fingerprint match) → kind/provider")


def test_run_secret_classification_failsafe_missing_archive():
    st = fresh_state()
    # a secret whose raw_log_ref file does not exist → skipped, no crash, no change
    st.add_secrets([Secret(kind="unknown", fingerprint=secret_fingerprint(FAKE_GH),
                           raw_log_ref="raw/does_not_exist.json", discovered_by="jsluice")])
    summary = e4.run_secret_classification(st)
    assert summary == {"classified": 0, "total": 1}
    assert st.load_secrets()[0].kind == "unknown"
    print("PASS: missing raw archive is fail-safe (skipped, no crash, kind unchanged)")


def test_run_secret_classification_idempotent():
    st = fresh_state()
    _seed_secret_with_archive(st, FAKE_STRIPE)
    a = e4.run_secret_classification(st)
    b = e4.run_secret_classification(st)
    assert a == b == {"classified": 1, "total": 1}
    print("PASS: E4 is idempotent")


if __name__ == "__main__":
    test_classify_secret_detectors()
    test_run_secret_classification_reads_archive_and_updates()
    test_run_secret_classification_failsafe_missing_archive()
    test_run_secret_classification_idempotent()
    print("\nAll checks passed.")
