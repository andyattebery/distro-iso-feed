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
from distro_iso_feed.signing import DEFERRED, REJECTED, VERIFIED, verify_signing_key

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


def _sign(home: str, fpr: str, data: bytes, *, armor: bool = False) -> bytes:
    env = {**os.environ, "GNUPGHOME": home}
    return subprocess.run(
        ["gpg", "--batch", *(["--armor"] if armor else []), "--detach-sign", "--local-user", fpr, "-o", "-"],
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


def _export_secret(home: str, fpr: str) -> bytes:
    env = {**os.environ, "GNUPGHOME": home}
    return subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--export-secret-keys", fpr],
        env=env, capture_output=True, check=True,
    ).stdout  # fmt: skip


def _dual_sign(home: str, fprs: list[str], data: bytes, *, clear: bool = False) -> bytes:
    """One artifact signed by every key in `fprs` -- the Proxmox dual-signature shape. `home`
    must hold every secret key. Detached by default; `clear` for an inline-clearsigned doc."""
    env = {**os.environ, "GNUPGHOME": home}
    users = [a for f in fprs for a in ("--local-user", f)]
    mode = "--clearsign" if clear else "--detach-sign"
    return subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", mode, *users, "-o", "-"],
        env=env, input=data, capture_output=True, check=True,
    ).stdout  # fmt: skip


ISO = "distro-9.0-amd64.iso"
CKSUM = "a" * 64
SUMS = f"{CKSUM}  {ISO}\n".encode()
DECOY_SUMS = f"{'d' * 64}  {ISO}\n".encode()  # a body that does NOT carry the feed's CKSUM
IMAGE_BYTES = b"pretend ISO bytes"  # image mode never fetches the ISO, so any bytes stand in


@pytest.fixture(scope="module")
def keys():
    """One trusted keypair (signs the fixtures) and one unrelated key (the impostor)."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        fpr = _gen(home, "Distro Signing <sign@distro.example>")
        pub = _export(home, fpr)
        sums_sig = _sign(home, fpr, SUMS)
        sums_sig_asc = _sign(home, fpr, SUMS, armor=True)  # armored, for armor damage
        sums_clear = _clearsign(home, fpr, SUMS)  # AlmaLinux: inline-signed CHECKSUM
        iso_sig = _sign(home, fpr, b"pretend ISO bytes")  # image mode never fetches the ISO
        other_home = tempfile.mkdtemp()
        os.chmod(other_home, 0o700)
        other_fpr = _gen(other_home, "Impostor <no@distro.example>")
        other_pub = _export(other_home, other_fpr)
        other_iso_sig = _sign(other_home, other_fpr, IMAGE_BYTES)
        other_sums_clear = _clearsign(other_home, other_fpr, SUMS)
        other_sums_sig = _sign(other_home, other_fpr, SUMS)  # SUMS detached-signed by B alone

        # A home holding BOTH secret keys, so one artifact can be signed by A *and* B -- the
        # Proxmox dual-signature that a plain gpgv exit-code check hard-fails.
        both_home = tempfile.mkdtemp()
        os.chmod(both_home, 0o700)
        for h, f in ((home, fpr), (other_home, other_fpr)):
            subprocess.run(
                ["gpg", "--batch", "--import"], env={**os.environ, "GNUPGHOME": both_home},
                input=_export_secret(h, f), capture_output=True, check=True,
            )  # fmt: skip
        dual_sums_sig = _dual_sign(both_home, [fpr, other_fpr], SUMS)
        dual_iso_sig = _dual_sign(both_home, [fpr, other_fpr], IMAGE_BYTES)
        dual_sums_clear = _dual_sign(both_home, [fpr, other_fpr], SUMS, clear=True)

        # The blob a compromised key URL might serve: the pinned key with an attacker key
        # appended. `primary_fingerprint` (first key only) never sees the second.
        two_key_blob = pub + other_pub

        # The clearsigned injection: A signs a DECOY body (no CKSUM), then a line carrying the
        # feed's CKSUM is appended AFTER the signature block. Inner sig stays Good; the raw file
        # contains CKSUM but gpg's extracted payload does not.
        clear_appended = _clearsign(home, fpr, DECOY_SUMS) + f"{CKSUM}  {ISO}\n".encode()

        yield {
            "fpr": fpr, "pub": pub, "sums_sig": sums_sig, "sums_clear": sums_clear,
            "sums_sig_asc": sums_sig_asc,
            "iso_sig": iso_sig, "other_fpr": other_fpr, "other_pub": other_pub,
            "other_iso_sig": other_iso_sig, "other_sums_clear": other_sums_clear,
            "other_sums_sig": other_sums_sig, "dual_sums_sig": dual_sums_sig,
            "dual_iso_sig": dual_iso_sig, "dual_sums_clear": dual_sums_clear,
            "two_key_blob": two_key_blob, "clear_appended": clear_appended,
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
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    r, outcome = out
    assert outcome == REJECTED
    # The PIN made this signature; the bytes changed under it (a mirror serving SUMS and its sig
    # out of sync, or tampering). Not a rotation -- there is no new key to go and verify.
    assert out.cause == "bad-signature"
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
        out = verify_signing_key(client, _release(), _params(keys, "checksums", fpr=fpr))
    assert out.verdict == REJECTED  # checksum "aaaa..." is not in the verified `other`
    assert out.cause == "checksum-absent"
    assert sig is None


def test_checksums_no_checksum_at_all_defers_without_stripping_the_pin(keys):
    """No checksum resolved => nothing to check the signature against. We can neither prove nor
    disprove the pin, so DEFERRED -- never REJECTED.

    This is the incident: a timed-out SUMS fetch left `checksum=None`, the signing re-fetch of
    the same file *succeeded*, and the None fell into the "absent from the signed file" branch.
    That reported a healthy, unrotated key as a rotation, stripped a valid pin, and failed the
    job. The signature here is genuinely good -- the only thing missing is our own checksum.
    """
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(checksum=None), _params(keys, "checksums"))
    assert outcome == DEFERRED
    assert r.signature_url == SIG_URL, "a transient miss must never strip the claim"
    assert r.signature_target == "checksums"
    assert r.signing_key_fingerprint is None  # no pin published this run; retried next run
    assert r.verify == "gpg"  # the level does not flap


# -------------------------------------------------- checksums mode, multiple signatures


def test_checksums_dual_signed_verifies_when_the_pin_is_a_cosigner(keys):
    """The Proxmox class: a SUMS signed by two keys. A plain gpgv exit-code check hard-fails
    (it can't verify the co-signer), but the pinned key's signature is good -- so we accept."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["dual_sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == VERIFIED and r.verify == "gpg"


def test_checksums_signed_only_by_another_key_drops(keys):
    """A good signature, but by a key we did not pin -- not evidence for our pin."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["other_sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == REJECTED


def test_rejected_names_the_actual_signer_for_the_rotation_lead(keys):
    """The escalation lead: SUMS signed by another key (a rotation), pinned to ours. REJECTED, and
    `signer` names the signing key from the signature packet -- which works precisely because the
    pin failed (gpg can't verify the new key, but the packet still says who signed)."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["other_sums_sig"], SUMS_URL: SUMS})
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "foreign-signer"
    assert out.signer == keys["other_fpr"] and "does not chain to the pinned key" in out.reason


def test_checksums_appended_attacker_key_in_the_blob_drops(keys):
    """The key URL serves `[pinned] ++ [attacker]` and the SUMS is the attacker's. The old
    first-key-only fpr guard passes, but the signature's primary fpr is not the pin, so the
    VALIDSIG set-gate rejects it -- the appended key never lends its signature to the pin."""
    client = FakeClient(
        {KEY_URL: keys["two_key_blob"], SIG_URL: keys["other_sums_sig"], SUMS_URL: SUMS}
    )
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED
    # The attacker key rode in on the blob, but it is not the PIN's -- so it is named as the
    # signer, never mistaken for one of the pin's own subkeys.
    assert out.cause == "foreign-signer" and out.signer == keys["other_fpr"]


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
    out = verify_signing_key(client, _release(), _params(keys, "image"))
    r, outcome = out
    assert outcome == REJECTED and out.cause == "foreign-signer"
    assert r.signature_url is None and r.verify == "checksum"


def test_image_dual_signed_verifies_for_either_pinned_cosigner(keys):
    """A dual-signed ISO `.asc` names two issuers, and the pinned one is not always first.
    Pinning A (listed first) or B (listed second) both verify -- order must not decide it."""
    a = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["dual_iso_sig"]})
    assert verify_signing_key(a, _release(), _params(keys, "image")).verdict == VERIFIED
    b = FakeClient({KEY_URL: keys["other_pub"], SIG_URL: keys["dual_iso_sig"]})
    assert verify_signing_key(b, _release(), _params(keys, "image", fpr=keys["other_fpr"])).verdict == VERIFIED


def test_image_appended_attacker_key_in_the_blob_drops(keys):
    """The bonus: the ISO sig is the attacker's and the key URL served `[pinned] ++ [attacker]`.
    The issuer is checked only against the PINNED key's own fingerprints, so the co-packaged
    attacker key cannot lend its issuer. (Checking every fpr in the blob would have accepted it.)"""
    client = FakeClient({KEY_URL: keys["two_key_blob"], SIG_URL: keys["other_iso_sig"]})
    out = verify_signing_key(client, _release(), _params(keys, "image"))
    r, outcome = out
    assert outcome == REJECTED and r.signature_url is None
    assert out.cause == "foreign-signer" and out.signer == keys["other_fpr"]


# A 200 that is not a signature: a CDN or SourceForge error page where the `.sig` should be.
HTML_200 = b"<html><body><h1>Not Found</h1></body></html>\n"


def test_image_sig_that_is_not_a_signature_is_rejected_as_unsigned(keys):
    """Was a silent DEFERRED ("could not parse the signature") -- and DEFERRED publishes, so the
    one covers mode where a stripped signature went unnoticed. gpg's NODATA is positive evidence
    that no signature is there."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: HTML_200})
    out = verify_signing_key(client, _release(), _params(keys, "image"))
    r, outcome = out
    assert outcome == REJECTED and out.cause == "unsigned" and out.signer is None
    assert r.signature_url is None and r.signing_key_fingerprint is None


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
    out = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    r, outcome = out
    assert outcome == REJECTED and out.cause == "bad-signature"
    assert r.signature_url is None and r.signature_target is None and r.verify == "checksum"


def test_clearsigned_from_a_different_key_drops(keys):
    """Signed inline, but by a key we did not pin -- `gpg --verify` fails under the pin.

    `signer` is the rotation lead. `gpg --list-packets` over a WHOLE clearsigned doc stops at its
    literal-data packet and never reaches the signature (0 signature packets on gnupg 2.4.4 and
    2.5.24), so for AlmaLinux/Gentoo/Parrot this was always None until the signature block was
    listed on its own."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["other_sums_clear"]})
    out = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    assert out.verdict == REJECTED
    assert out.cause == "foreign-signer" and out.signer == keys["other_fpr"]


def test_clearsigned_file_with_no_signature_is_rejected_as_unsigned(keys):
    """Parrot 7.4: `signed-hashes.txt` arrived as plain text -- md5 only, no PGP armor at all.
    Nothing signed it, so it is not a rotation; the escalation that read it as "likely a single
    upstream rotation" sent the reader after a key that does not exist."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: SUMS})
    out = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    r, outcome = out
    assert outcome == REJECTED and out.cause == "unsigned" and out.signer is None
    assert r.signature_url is None and r.verify == "checksum"


def test_clearsigned_no_checksum_at_all_defers_without_stripping_the_pin(keys):
    """The clearsigned twin of the checksums None-guard -- the same bug lived in both branches."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_clear"]})
    r, outcome = verify_signing_key(client, _release(checksum=None), _params(keys, "clearsigned"))
    assert outcome == DEFERRED
    assert r.signature_url == SIG_URL
    assert r.signature_target == "checksums"
    assert r.signing_key_fingerprint is None
    assert r.verify == "gpg"


def test_clearsigned_text_appended_after_the_signature_is_rejected(keys):
    """The injection this whole path is hardened against: the pinned key signs a DECOY body
    (no CKSUM), then a line carrying the feed's CKSUM is appended after `END PGP SIGNATURE`.
    The inner signature is still Good and the raw file DOES contain CKSUM -- a raw `in` check
    (the old behaviour) would pass. Checking against gpg's extracted payload rejects it."""
    assert CKSUM.encode() in keys["clear_appended"]  # the attack would fool a raw-bytes check
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["clear_appended"]})
    out = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    r, outcome = out
    assert outcome == REJECTED and r.verify == "checksum"
    assert out.cause == "checksum-absent"  # the pin's signature is good; its body lacks CKSUM


def test_clearsigned_dual_signed_with_unknown_cosigner_is_handled_safely(keys):
    """A clearsigned CHECKSUM co-signed by the pinned key AND an unknown key. gpg's `--output`
    policy for a *partially* verifiable doc is version-dependent: some builds withhold the payload
    (-> fail-closed REJECTED, drop to `checksum`), others extract the body the pinned key DID sign
    (-> VERIFIED against the real, pin-signed CHECKSUM). Both are safe -- the pin is attached only
    when gpg confirms the pinned key signed the extracted body, and injected-after-signature text is
    rejected on every gpg by `test_clearsigned_text_appended_after_the_signature_is_rejected`. What
    must never happen is a false GOOD, and neither branch produces one.

    This case once failed the daily refresh when a CI runner's gpg changed its `--output` policy,
    so the assertion no longer pins a single gpg version's behaviour. (No clearsigned source
    dual-signs today; AlmaLinux/Parrot/Gentoo are single-signed.)"""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["dual_sums_clear"]})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "clearsigned"))
    assert outcome in (REJECTED, VERIFIED)
    if outcome == VERIFIED:
        # rode through only because gpg extracted the body the pinned key signed, which carries the
        # real CKSUM -- so the published checksum is genuinely pin-signed, not injected.
        assert r.signing_key_fingerprint == keys["fpr"] and r.checksum == CKSUM and r.verify == "gpg"
    else:
        assert r.signature_url is None and r.verify == "checksum"  # dropped, degraded safely


# ------------------------------------------------------------- guards & degrade


def test_url_serving_the_wrong_key_drops(keys):
    """The primary-fpr guard: the URL serves a key whose primary is not the pin."""
    client = FakeClient({KEY_URL: keys["other_pub"], SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "key-url"


def test_key_fetch_failure_defers_without_flapping(keys):
    """A network failure fetching the key is couldn't-check, not evidence: keep signature_url,
    add no pin, try again next run."""
    client = FakeClient(
        {SIG_URL: keys["sums_sig"], SUMS_URL: SUMS}, fail={KEY_URL: "ConnectTimeout"}
    )
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == DEFERRED
    assert r.signature_url == SIG_URL and r.signing_key_fingerprint is None  # unchanged


def test_key_url_that_404s_is_rejected_as_key_url(keys):
    """A 404 is the host answering that the key is gone -- the same structural verdict a resolve
    failure gets. It used to defer forever, publishing every release unpinned in silence."""
    client = FakeClient({SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})  # KEY_URL unmapped -> 404
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "key-url"
    assert out.release.signature_url is None


def test_key_url_serving_an_empty_200_is_rejected_as_key_url(keys):
    """An empty 200 is the host answering with nothing -- structural, like a 404, not a blip."""
    client = FakeClient({KEY_URL: b"", SIG_URL: keys["sums_sig"], SUMS_URL: SUMS})
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "key-url"


def test_sig_that_404s_is_rejected_as_unsigned(keys):
    """A deleted signature is the cheapest way to strip one; it must not read as a blip."""
    client = FakeClient({KEY_URL: keys["pub"], SUMS_URL: SUMS})  # SIG_URL unmapped -> 404
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "unsigned"


def test_sig_fetch_failure_defers(keys):
    client = FakeClient({KEY_URL: keys["pub"], SUMS_URL: SUMS}, fail={SIG_URL: 503})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == DEFERRED and r.signature_url == SIG_URL


def test_detached_sig_that_is_not_a_signature_is_rejected_as_unsigned(keys):
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: HTML_200, SUMS_URL: SUMS})
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "unsigned" and out.signer is None


def test_signed_sums_that_404s_is_rejected_as_checksum_absent(keys):
    """The signature arrived but the file it signs is gone: nothing vouches for this artifact."""
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"]})  # SUMS_URL -> 404
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "checksum-absent"


def test_signed_sums_fetch_failure_defers(keys):
    client = FakeClient(
        {KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"]}, fail={SUMS_URL: "ReadTimeout"}
    )
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == DEFERRED and r.signature_url == SIG_URL


def test_a_failed_verify_that_gpg_cannot_explain_defers(keys, monkeypatch):
    """The pin did not verify, and gpg then reads nothing at all from the signature -- no packets
    AND no NODATA, i.e. it did not run. There is no evidence either way: couldn't-check is DEFERRED
    (spec 1a), never a REJECTED that escalates a gpg hiccup as a key event."""
    real_run = gpgverify._run

    def list_packets_dies(args, **kw):
        return None if "--list-packets" in args else real_run(args, **kw)

    monkeypatch.setattr(gpgverify, "_run", list_packets_dies)
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["other_sums_sig"], SUMS_URL: SUMS})
    r, outcome = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert outcome == DEFERRED and r.signature_url == SIG_URL


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
    assert verify_signing_key(client, r, _params(keys, "image")).verdict == DEFERRED  # no sig


def _bad_crc(armored: bytes) -> bytes:
    """The same armored signature with its `=XXXX` checksum line changed."""
    lines = armored.splitlines(keepends=True)
    i = next(i for i, ln in enumerate(lines) if ln.startswith(b"="))
    lines[i] = b"=AAAA\n" if lines[i].strip() != b"=AAAA" else b"=BBBB\n"
    return b"".join(lines)


def test_a_damaged_signature_by_the_pin_is_bad_not_deferred(keys):
    """A pin signature whose armor checksum is broken: gpg lists the packet (issuer = the pin) yet
    exits non-zero, with no NODATA. Read as "gpg could not read the signature" it DEFERRED -- which
    keeps a verified record silently forever and never opens the issue."""
    client = FakeClient(
        {KEY_URL: keys["pub"], SIG_URL: _bad_crc(keys["sums_sig_asc"]), SUMS_URL: SUMS}
    )
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "bad-signature"


# gnupg 2.4.4's `--list-packets` on an armored signature with its tail cut (the runner's version):
# exit 2, the signature packet listed with its issuer, and NODATA 1. Canned, because 2.5.24 lists
# no packet for the same bytes -- a dev box could not reproduce what the runner sees.
def _list_packets_answers(monkeypatch, rc: int, stdout: str, status: str) -> None:
    real_run = gpgverify._run

    def fake(args, **kw):
        if "--list-packets" in args:
            return subprocess.CompletedProcess(args, rc, stdout.encode(), status.encode())
        return real_run(args, **kw)

    monkeypatch.setattr(gpgverify, "_run", fake)


def _packet(fpr: str) -> str:
    return f":signature packet: algo 22, keyid {fpr[-16:]}\n\thashed subpkt 33 len 21 (issuer fpr v4 {fpr})\n"


def test_a_truncated_signature_by_the_pin_is_bad_not_unsigned(keys, monkeypatch):
    """Exit 2 + NODATA was read as "no signature at all" -- with the signer hidden -- though gpg
    listed the pin's signature packet. That is a damaged signature, not an absent one."""
    _list_packets_answers(
        monkeypatch, 2, _packet(keys["fpr"]), "[GNUPG:] NODATA 1\n[GNUPG:] FAILURE - 4294967295\n"
    )
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["sums_sig"][:-20], SUMS_URL: SUMS})
    out = verify_signing_key(client, _release(), _params(keys, "checksums"))
    assert out.verdict == REJECTED and out.cause == "bad-signature"


def test_a_damaged_image_signature_is_rejected_not_deferred(keys, monkeypatch):
    """Image mode only reads the issuer; a damaged packet must neither pass as VERIFIED nor hide
    behind a silent DEFERRED."""
    _list_packets_answers(monkeypatch, 2, _packet(keys["fpr"]), "[GNUPG:] FAILURE - 4294967295\n")
    client = FakeClient({KEY_URL: keys["pub"], SIG_URL: keys["iso_sig"]})
    out = verify_signing_key(client, _release(), _params(keys, "image"))
    assert out.verdict == REJECTED and out.cause == "bad-signature"


# ----------------------------------------------------------- gpgverify unit surface


def test_verify_detached_gates_on_the_pinned_signer(keys):
    """Directly: a dual-signed file verifies for the pinned signer and not for an unrelated one."""
    assert gpgverify.verify_detached(
        keys["pub"], keys["dual_sums_sig"], SUMS, pinned_fpr=keys["fpr"]
    )
    # B signed it too, but B is not imported (only A's pub) and is not the pin here anyway.
    assert not gpgverify.verify_detached(
        keys["pub"], keys["other_sums_sig"], SUMS, pinned_fpr=keys["fpr"]
    )


def test_signature_packets_returns_every_signer(keys):
    """A dual-signed sig names both issuers; a single-signed one names just its own."""
    issuers = gpgverify.signature_packets(keys["dual_iso_sig"]).issuers
    assert any(i.endswith(keys["fpr"][-16:]) for i in issuers)
    assert any(i.endswith(keys["other_fpr"][-16:]) for i in issuers)
    single = gpgverify.signature_packets(keys["iso_sig"]).issuers
    assert [keys["fpr"]] == [i for i in single if i.endswith(keys["fpr"][-16:])][:1]


def test_signature_packets_reads_the_signature_inside_a_clearsigned_doc(keys):
    """Listed whole, a clearsigned doc yields no signature packet at all; its armored signature
    block, listed on its own, names the signer."""
    packets = gpgverify.signature_packets(keys["sums_clear"])
    assert keys["fpr"] in packets.issuers and not packets.unsigned and not packets.damaged


def test_signature_packets_on_plain_text_reports_unsigned():
    """The Parrot 7.4 shape: a hashes file with no OpenPGP data in it at all."""
    parrot_74 = b"Parrot OS 7.4\n\n\nmd5\n" + b"6" * 32 + b"  Parrot-home-7.4_amd64.iso\n"
    packets = gpgverify.signature_packets(parrot_74)
    assert (packets.issuers, packets.unsigned, packets.damaged) == ([], True, False)


def test_fingerprints_for_primary_isolates_the_pinned_key(keys):
    """From a two-key blob, only the pinned key's own fingerprints come back -- never the other's."""
    own = gpgverify.fingerprints_for_primary(keys["two_key_blob"], keys["fpr"])
    assert keys["fpr"] in own and keys["other_fpr"] not in own
    assert gpgverify.fingerprints_for_primary(keys["two_key_blob"], "F" * 40) == set()


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
