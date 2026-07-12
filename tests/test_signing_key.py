"""The build-time GPG gate, exercised with real gpg-generated keys and signatures.

A hand-entered fingerprint is only as good as the data entry, so the refresh proves
the chain before publishing the pin. These tests generate a throwaway keypair, sign
with it, and drive `verify_signing_key` through both strengths and every failure
mode -- including the two the live feed actually hit (a key not at the URL, and a
signature from a key we did not pin).
"""

from __future__ import annotations

import os
import subprocess
import tempfile

import pytest

from conftest import FakeClient
from distro_iso_feed import gpgverify
from distro_iso_feed.config import ConfigError, _validate_signing_key
from distro_iso_feed.models import Release
from distro_iso_feed.strategies._common import BAD, DEFERRED, VERIFIED, verify_signing_key

pytestmark = pytest.mark.skipif(not gpgverify.gpg_available(), reason="needs gpg + gpgv")


def _gen(home: str, uid: str) -> str:
    env = {**os.environ, "GNUPGHOME": home}
    subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-gen-key", uid, "default", "default", "0"],
        env=env, capture_output=True, check=True,
    )  # fmt: skip
    out = subprocess.run(
        ["gpg", "--with-colons", "--list-keys", uid], env=env, capture_output=True, text=True
    ).stdout
    return next(ln.split(":")[9] for ln in out.splitlines() if ln.startswith("fpr"))


def _export(home: str, fpr: str) -> bytes:
    env = {**os.environ, "GNUPGHOME": home}
    return subprocess.run(["gpg", "--export", fpr], env=env, capture_output=True).stdout


def _sign(home: str, fpr: str, data: bytes) -> bytes:
    env = {**os.environ, "GNUPGHOME": home}
    return subprocess.run(
        ["gpg", "--batch", "--detach-sign", "--local-user", fpr, "-o", "-"],
        env=env, input=data, capture_output=True, check=True,
    ).stdout  # fmt: skip


def _clearsign(home: str, fpr: str, data: bytes) -> bytes:
    """An inline-clearsigned document (the AlmaLinux CHECKSUM shape)."""
    env = {**os.environ, "GNUPGHOME": home}
    return subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--clearsign", "--local-user", fpr, "-o", "-"],
        env=env, input=data, capture_output=True, check=True,
    ).stdout  # fmt: skip


ISO = "distro-9.0-amd64.iso"
CKSUM = "a" * 64
SUMS = f"{CKSUM}  {ISO}\n".encode()


@pytest.fixture(scope="module")
def keys():
    """One trusted keypair (signs the fixtures) and one unrelated key (the impostor)."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        fpr = _gen(home, "Distro Signing <sign@distro.example>")
        pub = _export(home, fpr)
        sums_sig = _sign(home, fpr, SUMS)
        sums_clear = _clearsign(home, fpr, SUMS)  # AlmaLinux: inline-signed CHECKSUM
        iso_sig = _sign(home, fpr, b"pretend ISO bytes")  # image mode never fetches the ISO
        other_home = tempfile.mkdtemp()
        os.chmod(other_home, 0o700)
        other_fpr = _gen(other_home, "Impostor <no@distro.example>")
        other_pub = _export(other_home, other_fpr)
        other_iso_sig = _sign(other_home, other_fpr, b"pretend ISO bytes")
        other_sums_clear = _clearsign(other_home, other_fpr, SUMS)
        yield {
            "fpr": fpr, "pub": pub, "sums_sig": sums_sig, "sums_clear": sums_clear,
            "iso_sig": iso_sig, "other_fpr": other_fpr, "other_pub": other_pub,
            "other_iso_sig": other_iso_sig, "other_sums_clear": other_sums_clear,
        }  # fmt: skip


KEY_URL = "https://keys.example/key"
SIG_URL = "https://dl.example/SHA256SUMS.gpg"
SUMS_URL = "https://dl.example/SHA256SUMS"


def _release(**kw) -> Release:
    base = dict(
        distro="distro", variant="main", version="9.0", title="t", filename=ISO,
        download_url="https://dl.example/" + ISO, checksum=CKSUM, checksum_algo="sha256",
        signature_url=SIG_URL,
    )  # fmt: skip
    return Release(**{**base, **kw})


def _params(keys, covers, *, fpr=None):
    return {"signing_key": {"url": KEY_URL, "fingerprint": fpr or keys["fpr"], "covers": covers}}


# ------------------------------------------------------------------ checksums mode


def test_checksums_verified_publishes_the_pin(keys):
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == VERIFIED
    assert r.signing_key_fingerprint == keys["fpr"]
    assert r.signing_key_url == KEY_URL
    assert r.signature_target == "checksums"  # published, not left for the client to infer
    assert r.verify == "gpg"


def test_checksums_tampered_sums_drops_the_claim(keys):
    tampered = SUMS.replace(b"a" * 64, b"b" * 64)  # sig no longer matches the bytes
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"], SUMS_URL: tampered})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == BAD
    assert r.signature_url is None and r.signing_key_fingerprint is None
    assert r.signature_target is None  # no signature -> no target
    assert r.verify == "checksum"  # degraded, not gpg


def test_checksums_good_sig_but_our_checksum_absent_drops(keys):
    """A valid signature over a SUMS that does not list our checksum is not evidence
    for our artifact."""
    other = f"{'c' * 64}  {ISO}\n".encode()
    sig = None  # need a sig over `other`; reuse the fixture home is gone, so re-sign inline
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        fpr = _gen(home, "X <x@e>")
        client = FakeClient({KEY_URL: _export(home, fpr), SIG_URL: _sign(home, fpr, other), SUMS_URL: other})
        r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums", fpr=fpr))
    assert outcome == BAD  # checksum "aaaa..." is not in the verified `other`
    assert sig is None


# ---------------------------------------------------------------------- image mode


def test_image_issuer_matches_pin(keys):
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["iso_sig"]})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "image"))
    assert outcome == VERIFIED
    assert r.signing_key_fingerprint == keys["fpr"]
    assert r.signature_target == "image"


def test_image_sig_from_a_different_key_drops(keys):
    """The MX case: the artifact is signed, but by a key we did not pin."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["other_iso_sig"]})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "image"))
    assert outcome == BAD
    assert r.signature_url is None and r.verify == "checksum"


# ----------------------------------------------------------------- clearsigned mode


def test_clearsigned_verified_publishes_the_pin(keys):
    """AlmaLinux: the CHECKSUM is its own inline signature. `sig` points at that file, so
    verify it under only the pin and confirm the checksum sits inside the verified body."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_clear"]})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    assert outcome == VERIFIED
    assert r.signing_key_fingerprint == keys["fpr"]
    assert r.signature_target == "checksums"  # clearsigned maps to checksums for the client
    assert r.verify == "gpg"


def test_clearsigned_tampered_body_drops(keys):
    tampered = keys["sums_clear"].replace(b"a" * 64, b"b" * 64)  # breaks both sig and checksum
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: tampered})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    assert outcome == BAD
    assert r.signature_url is None and r.signature_target is None and r.verify == "checksum"


def test_clearsigned_from_a_different_key_drops(keys):
    """Signed inline, but by a key we did not pin -- `gpg --verify` fails under the pin."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["other_sums_clear"]})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    assert outcome == BAD


# ------------------------------------------------------------- guards & degrade


def test_url_serving_the_wrong_key_drops(keys):
    """The primary-fpr guard: the URL serves a key whose primary is not the pin."""
    client = FakeClient({KEY_URL: keys["other_pub"], SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == BAD


def test_key_fetch_failure_defers_without_flapping(keys):
    """The Tails case: key not at the URL (a blip, or wrong host) must NOT drop the
    claim -- keep signature_url, add no pin, try again next run."""
    client = FakeClient({SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})  # KEY_URL unmapped -> 404
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == DEFERRED
    assert r.signature_url == SIG_URL and r.signing_key_fingerprint is None  # unchanged


def test_gpg_absent_defers(keys, monkeypatch):
    monkeypatch.setattr(gpgverify, "gpg_available", lambda: False)
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == DEFERRED and r.signature_url == SIG_URL
    # signature_target is config, not a verification result -> emitted even without gpg,
    # while the pin waits. The client gets the target regardless of the build's toolchain.
    assert r.signature_target == "checksums" and r.signing_key_fingerprint is None


def test_no_signing_key_or_no_sig_is_a_noop(keys):
    client = FakeClient({})
    # No signing_key (the MX case): no target either -> the client infers from the URL.
    r, outcome = verify_signing_key(client, _release(), {})
    assert outcome == DEFERRED and r.signature_target is None
    r = _release(signature_url=None)
    assert verify_signing_key(client, r, _params(keys, "image"))[1] == DEFERRED  # no sig


# ----------------------------------------------------------------- config guard


def test_config_rejects_bad_fingerprint_and_covers():
    with pytest.raises(ConfigError, match="40 hex"):
        _validate_signing_key("d", {"url": "u", "fingerprint": "nothex", "covers": "image"})
    with pytest.raises(ConfigError, match="covers"):
        _validate_signing_key("d", {"url": "u", "fingerprint": "A" * 40, "covers": "iso"})
    with pytest.raises(ConfigError, match="needs a `url`"):
        _validate_signing_key("d", {"fingerprint": "A" * 40, "covers": "image"})
    _validate_signing_key("d", {"url": "u", "fingerprint": "a" * 40, "covers": "checksums"})  # ok
    _validate_signing_key("d", None)  # optional
