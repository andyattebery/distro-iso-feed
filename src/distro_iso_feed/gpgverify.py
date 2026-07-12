"""Thin wrappers over `gpg`/`gpgv`, so the build can prove a signature chains to a
pinned key before publishing that key's fingerprint.

Everything here operates on **bytes** the caller already fetched, in a throwaway
`GNUPGHOME` -- the user's real keyring is never touched, and nothing is trusted into
it. Every function fails closed: a missing binary, a malformed key, a bad signature
all return ``None``/``False``/``[]`` rather than raising, because a resolver must
never take the run down (`resolve()`'s contract).

Two verification strengths, because the two sig shapes differ:

* `verify_detached`/`verify_clearsigned` -- a full cryptographic check, but the verdict
  is **"is the pinned key among the good signers?"**, never a `gpgv`/exit-code bool. gpg
  exits non-zero unless it can verify *every* signature in a file, so a Proxmox-style
  dual-signed file (current + previous release key) hard-fails a valid artifact under the
  exit-code test. `_valid_signers` asks gpg *who actually signed* (the VALIDSIG status
  lines) and the caller accepts iff the pin is in that set -- extra co-signers ignored, and
  a signature by a key appended to the fetched blob has a different primary fpr, so it is
  not the pin and is rejected. Used where the signed file is small (a `SHA*SUMS`/`.sha256`
  or a clearsigned `CHECKSUM`), which is fetchable at build time.
* `sig_issuers` -- the issuer (sub)keys a signature names, without the signed data. Used
  where the signature covers the multi-GB ISO, which the build does not fetch; the caller
  checks an issuer is the pinned key or one of its subkeys. Returns *all* issuers, because a
  dual-signed ISO `.asc` names two, and the pinned one is not always first.
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


def _import(home: str, key_bytes: bytes) -> bool:
    """Import a key blob into a throwaway keyring at `home/ring.gpg`. False on any error."""
    imp = _run(
        ["gpg", *_BASE, "--no-default-keyring", "--keyring", str(Path(home) / "ring.gpg"),
         "--import"],
        home=home,
        stdin=key_bytes,
    )  # fmt: skip
    return bool(imp and imp.returncode == 0)


# VALIDSIG <signing-fpr> <date> <ts> <exp-ts> <ver> <reserved> <pk-algo> <hash-algo>
#          <sig-class> <PRIMARY-fpr>
# The last field is the PRIMARY key's fingerprint even when a subkey made the signature
# (Tails signs that way), which is exactly what we want to compare against the pin.
_VALIDSIG = re.compile(r"^\[GNUPG:\] VALIDSIG (?:\S+ ){9}([0-9A-Fa-f]{40})\s*$", re.M)


def _valid_signers(args: list[str], home: str, stdin: bytes | None = None) -> set[str]:
    """Primary fingerprints that produced a *good* signature, from gpg's status output.

    Deliberately NOT gated on returncode: gpg exits non-zero when *any* signature in a
    multi-sig file is unverifiable, even though the pinned one verified fine. The VALIDSIG
    status lines are the source of truth, not the exit code.
    """
    r = _run(
        ["gpg", *_BASE, "--no-default-keyring", "--keyring", str(Path(home) / "ring.gpg"),
         "--status-fd", "1", *args],
        home=home,
        stdin=stdin,
    )  # fmt: skip
    if r is None:
        return set()
    text = r.stdout.decode("utf-8", "replace")
    return {m.group(1).upper() for m in _VALIDSIG.finditer(text)}


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


def key_fingerprint_groups(key_bytes: bytes) -> list[list[str]]:
    """Fingerprints grouped per key in the blob: `[[primary, sub, sub], [primary2, ...]]`.

    A `--show-keys` listing concatenates every key in the blob; `key_fingerprints` flattens
    them, which loses *which primary owns which subkey*. That distinction is the whole point
    when the blob might be `[pinned key] ++ [attacker key]` -- the pinned key's own set is what
    an issuer must belong to, not any fingerprint that happens to ride along. Each `pub:` record
    starts a new group; the `fpr:` records that follow it (primary, then subkeys) are its own.
    """
    with tempfile.TemporaryDirectory() as home:
        Path(home).chmod(0o700)
        r = _run(["gpg", *_BASE, "--show-keys"], home=home, stdin=key_bytes)
    if not r or r.returncode != 0:
        return []
    groups: list[list[str]] = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("pub:"):
            groups.append([])
        elif (m := re.match(r"fpr:*([0-9A-Fa-f]{40}):", line)) and groups:
            groups[-1].append(m.group(1).upper())
    return groups


def fingerprints_for_primary(key_bytes: bytes, primary_fpr: str) -> set[str]:
    """The one key's own fingerprints (its primary + subkeys) whose primary is `primary_fpr`.

    Empty if that primary is not in the blob. Used to scope the image-path issuer check to the
    *pinned* key alone, so a signature from a co-packaged attacker key is not mistaken for it.
    """
    primary_fpr = primary_fpr.upper()
    for group in key_fingerprint_groups(key_bytes):
        if group and group[0] == primary_fpr:
            return set(group)
    return set()


def verify_detached(
    key_bytes: bytes, sig_bytes: bytes, data_bytes: bytes, *, pinned_fpr: str
) -> bool:
    """Did the pinned key make a good detached signature over `data_bytes`?

    Builds a keyring of the fetched blob, asks gpg who validly signed the data, and returns
    whether the pin is among them. Not a `gpgv` exit-code test: a dual-signed file (one signer
    the build doesn't know) exits non-zero yet the pinned signature is perfectly good.
    """
    with tempfile.TemporaryDirectory() as home:
        Path(home).chmod(0o700)
        if not _import(home, key_bytes):
            return False
        sig = Path(home) / "artifact.sig"
        data = Path(home) / "artifact"
        sig.write_bytes(sig_bytes)
        data.write_bytes(data_bytes)
        signers = _valid_signers(["--verify", str(sig), str(data)], home)
    return pinned_fpr.upper() in signers


def verify_clearsigned(key_bytes: bytes, signed_bytes: bytes, *, pinned_fpr: str) -> str | None:
    """The signed payload of a clearsigned document, iff the pinned key signed it (else None).

    AlmaLinux clearsigns its `CHECKSUM`: the signature and the checksum body are one file, so
    there is no detached sig. Safe by construction: the payload comes back *only* when the pin
    is among the good signers, and it is gpg's own extraction of the signed region (`--output`)
    -- never the raw input. That closes an append-after-`END PGP SIGNATURE` injection: text a
    caller would otherwise `in`-match sits outside the signed region and never reaches `--output`.

    One constraint, fail-closed: gpg withholds `--output` unless it can verify *every* signature
    in the document, so a (hypothetical) dual-signed clearsigned with an unknown co-signer returns
    None even though the pin's own signature is good. No clearsigned source dual-signs today; if
    one ever does, this drops the gpg claim to `checksum` rather than ever accepting bad text.
    """
    with tempfile.TemporaryDirectory() as home:
        Path(home).chmod(0o700)
        if not _import(home, key_bytes):
            return None
        doc = Path(home) / "clearsigned.asc"
        out = Path(home) / "payload"
        doc.write_bytes(signed_bytes)
        signers = _valid_signers(["--output", str(out), "--yes", "--verify", str(doc)], home)
        if pinned_fpr.upper() not in signers:
            return None
        return out.read_text(encoding="utf-8", errors="replace") if out.exists() else None


def sig_issuers(sig_bytes: bytes) -> list[str]:
    """Every (sub)key a signature names: full fpr where present, else a 16-hex long key id.

    Needs no signed data, so it works for the over-the-ISO sigs the build never downloads. A
    dual-signed ISO `.asc` names two issuers and the pinned one is not always first, so the
    caller must see them all. A packet carries both an `issuer fpr` and a redundant `keyid`
    subpacket; the duplicate is harmless -- the keyid is a suffix of the same key's fpr.
    """
    r = _run(["gpg", "--list-packets"], stdin=sig_bytes)
    if not r or r.returncode != 0:
        return []
    text = r.stdout.decode("utf-8", "replace")
    issuers = re.findall(r"issuer fpr v\d ([0-9A-Fa-f]{40})", text)
    issuers += re.findall(r"keyid ([0-9A-Fa-f]{16})", text)
    return [i.upper() for i in issuers]


def issuer_in_fingerprints(issuer: str, fingerprints: set[str]) -> bool:
    """Was `issuer` (a full fpr or 16-hex long key id) made by one of these fingerprints?

    Suffix-matches so a 16-hex key id resolves against the full fpr it is the tail of (Tails
    signs with a subkey, so the caller passes the whole key's fingerprint set, not the primary).
    """
    issuer = issuer.upper()
    return any(fpr == issuer or fpr.endswith(issuer) for fpr in fingerprints)
