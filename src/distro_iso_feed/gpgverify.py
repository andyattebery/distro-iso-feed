"""Thin wrappers over `gpg`/`gpgv`, so the build can prove a signature chains to a
pinned key before publishing that key's fingerprint.

Everything here operates on **bytes** the caller already fetched, in a throwaway
`GNUPGHOME` -- the user's real keyring is never touched, and nothing is trusted into
it. Every function fails closed: a missing binary, a malformed key, a bad signature
all return ``None``/``False``/``[]`` rather than raising, because a resolver must
never take the run down (`resolve()`'s contract).

Two verification strengths, because the two sig shapes differ:

* `verify_detached` -- full cryptographic check that a signature is Good under only
  the pinned key. Used where the signed file is small (a `SHA*SUMS`/`.sha256`),
  which is fetchable at build time.
* `sig_issuer` -- the issuer (sub)key a signature names, without the signed data.
  Used where the signature covers the multi-GB ISO, which the build does not fetch;
  the caller checks the issuer is the pinned key or one of its subkeys.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# gpg verification needs no agent; `--no-autostart` stops 2.x spawning one per home.
_BASE = ("--batch", "--no-tty", "--no-autostart", "--with-colons")


def gpg_available() -> bool:
    """Is a usable `gpg` on PATH? Checked once so the build can skip the gate cleanly."""
    return shutil.which("gpg") is not None and shutil.which("gpgv") is not None


def _run(args: list[str], *, home: str | None = None, stdin: bytes | None = None):
    # Merge, never replace: a bare {"GNUPGHOME": home} would wipe PATH and gpg would
    # not be found at all -- a failure that looks exactly like "verification failed."
    env = {**os.environ, "GNUPGHOME": home} if home else None
    try:
        return subprocess.run(
            args, input=stdin, capture_output=True, env=env, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None


def key_fingerprints(key_bytes: bytes) -> list[str]:
    """Every fingerprint in a key blob (primary first, then subkeys), uppercase hex.

    Reads the key without importing it into any real keyring. Empty on any error.
    """
    with tempfile.TemporaryDirectory() as home:
        Path(home).chmod(0o700)
        r = _run(["gpg", *_BASE, "--show-keys"], home=home, stdin=key_bytes)
    if not r or r.returncode != 0:
        return []
    return re.findall(r"^fpr:*([0-9A-Fa-f]{40}):", r.stdout.decode("utf-8", "replace"), re.M)


def primary_fingerprint(key_bytes: bytes) -> str | None:
    """The primary key fingerprint -- the value projects publish and we pin against."""
    fprs = key_fingerprints(key_bytes)
    return fprs[0].upper() if fprs else None


def verify_detached(key_bytes: bytes, sig_bytes: bytes, data_bytes: bytes) -> bool:
    """Does `sig` cryptographically verify `data` under *only* this key? (`gpgv` Good.)

    Builds a keyring holding just the pinned key and runs `gpgv` -- no trust model,
    no other keys, just "is this signature valid by this key over these bytes."
    """
    with tempfile.TemporaryDirectory() as home:
        Path(home).chmod(0o700)
        keyring = str(Path(home) / "pinned.gpg")
        imp = _run(
            ["gpg", *_BASE, "--no-default-keyring", "--keyring", keyring, "--import"],
            home=home,
            stdin=key_bytes,
        )
        if not imp or imp.returncode != 0:
            return False
        sig = Path(home) / "artifact.sig"
        data = Path(home) / "artifact"
        sig.write_bytes(sig_bytes)
        data.write_bytes(data_bytes)
        r = _run(["gpgv", "--keyring", keyring, str(sig), str(data)], home=home)
    return bool(r and r.returncode == 0)


def verify_clearsigned(key_bytes: bytes, signed_bytes: bytes) -> bool:
    """Does this inline-clearsigned document verify under *only* this key? (`gpg --verify`.)

    AlmaLinux clearsigns its `CHECKSUM`: the signature and the checksum body are one file,
    so there is no detached sig to `gpgv`. Import just the pinned key and `gpg --verify` the
    whole document -- exit 0 means a good signature by a key in the (single-key) keyring; a
    signature from any other key returns non-zero. The caller then reads the checksum out of
    the same body it just verified.
    """
    with tempfile.TemporaryDirectory() as home:
        Path(home).chmod(0o700)
        keyring = str(Path(home) / "pinned.gpg")
        imp = _run(
            ["gpg", *_BASE, "--no-default-keyring", "--keyring", keyring, "--import"],
            home=home,
            stdin=key_bytes,
        )
        if not imp or imp.returncode != 0:
            return False
        doc = Path(home) / "clearsigned.asc"
        doc.write_bytes(signed_bytes)
        r = _run(
            ["gpg", *_BASE, "--no-default-keyring", "--keyring", keyring, "--verify", str(doc)],
            home=home,
        )
    return bool(r and r.returncode == 0)


def sig_issuer(sig_bytes: bytes) -> str | None:
    """The (sub)key a detached signature was issued by: full fpr if present, else a
    16-hex long key id. Needs no signed data, so it works for over-the-ISO sigs."""
    r = _run(["gpg", "--list-packets"], stdin=sig_bytes)
    if not r or r.returncode != 0:
        return None
    text = r.stdout.decode("utf-8", "replace")
    if m := re.search(r"issuer fpr v\d ([0-9A-Fa-f]{40})", text):
        return m.group(1).upper()
    if m := re.search(r"keyid ([0-9A-Fa-f]{16})", text):
        return m.group(1).upper()
    return None


def issuer_in_key(issuer: str, key_bytes: bytes) -> bool:
    """Was `issuer` (fpr or long key id) made by this key -- its primary or a subkey?

    Tails signs with a subkey of its published primary, so a match against the
    primary alone would wrongly reject it; this checks every fingerprint, by suffix
    when the issuer is only a 16-hex key id.
    """
    issuer = issuer.upper()
    for fpr in (f.upper() for f in key_fingerprints(key_bytes)):
        if fpr == issuer or fpr.endswith(issuer):
            return True
    return False
