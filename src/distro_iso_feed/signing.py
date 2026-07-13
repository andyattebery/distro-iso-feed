"""The GPG **policy** layer: which `covers` mode dispatches to which `gpgverify` check, and the
build-time VERIFIED/BAD/DEFERRED verdict the runners act on.

Distinct from `gpgverify.py`, which holds the stateless gpg-subprocess *wrappers*. This module is
the policy that composes them against a resolved `Release` and its pinned-key config -- so "the GPG
gate" finally has a home of its own rather than squatting beside torrent plumbing.
"""

from __future__ import annotations

from dataclasses import replace

from . import gpgverify
from .client import Client
from .models import Release

_SIG_EXTS = (".sign", ".gpg", ".asc")

# The result of the build-time GPG gate, so the caller can log/act without re-deriving.
VERIFIED = "verified"  # signature chains to the pinned key -> publish the pin
BAD = "bad"  # a signature that fails its own key -> drop the gpg claim
DEFERRED = "deferred"  # transient/gpg-absent -> keep as resolved, add no pin

# The `covers` modes `verify_signing_key` dispatches on (see its if/elif). This is the single
# source of truth: `config.py` imports it to validate `signing_key.covers`, so the validator and
# the dispatch can no longer name different sets in two files coupled by a bare string. Adding a
# mode is now a single-file edit here -- add the name AND its dispatch branch below together (a
# name here with no branch would silently degrade to DEFERRED; a test pins config to this set).
COVERS = frozenset({"checksums", "clearsigned", "image"})


def _norm_fpr(value: str) -> str:
    return "".join(value.split()).upper()


def verify_signing_key(client: Client, release: Release, params: dict) -> tuple[Release, str]:
    """Prove the GPG chain before the feed publishes the pinned key.

    A hand-entered fingerprint is only as good as the data entry, so every build
    re-checks it against the *actual signature* on the current artifact:

      checksums -- the sig covers a small SHA*SUMS/.sha256 file, so `gpgv` the whole
                   thing under only the pinned key, then confirm the checksum the feed
                   ships is inside that verified file. Full authentication.
      image     -- the sig covers the multi-GB ISO we do not download, so confirm the
                   signature's issuer is the pinned key (primary or subkey). Proves
                   the signature is *from* the pinned key; the consumer does the rest.

    Returns `(release, outcome)`:
      VERIFIED -> the pin is attached;
      BAD      -> `signature_url` is cleared, so `verify` degrades to `checksum`
                  (a signed checksum that fails its signature is not forwardable);
      DEFERRED -> the entry is returned exactly as resolved (a network blip or a dev
                  box without gpg must never flap the claim), no pin this run.
    """
    key_conf = params.get("signing_key")
    if not key_conf or not release.signature_url:
        return release, DEFERRED

    # `signature_target` is a static fact -- what the sig signs -- known from config
    # regardless of whether gpg can verify the pin this run. Stage it now so it rides
    # every non-BAD path (a dev box without gpg still emits it); `_drop` clears it.
    covers = key_conf.get("covers")
    # `signature_target` names what the sig signs (checksums|image) for the client; a
    # clearsigned CHECKSUM is a checksums signature carried inline, so it maps to checksums.
    target = "checksums" if covers == "clearsigned" else covers
    staged = replace(release, signature_target=target)

    if not gpgverify.gpg_available():
        return staged, DEFERRED  # keep the claim; the environment, not the sig, is at fault

    key = client.get(key_conf["url"])
    if not key or not key.content:
        return staged, DEFERRED  # transient: don't drop over a key-server blip
    key_bytes = key.content

    pinned = _norm_fpr(str(key_conf["fingerprint"]))
    # A cheap sanity early-out: is the pinned key even in what the URL served? Set-based (not
    # "is it the first key") so a key directory that returns several keys, or lists the pin
    # second, is not a false BAD. It is no longer the security boundary -- each path below
    # proves the pin actually *signed*, so an appended attacker key cannot ride this through.
    primaries = {g[0] for g in gpgverify.key_fingerprint_groups(key_bytes) if g}
    if pinned not in primaries:
        return _drop(release), BAD  # the URL is not serving the key we pinned

    sig = client.get(release.signature_url)
    if not sig or not sig.content:
        return staged, DEFERRED
    sig_bytes = sig.content

    if covers == "checksums":
        signed_url = _strip_sig_ext(release.signature_url)
        signed = client.get(signed_url)
        if not signed or not signed.content:
            return staged, DEFERRED
        text = signed.content.decode("utf-8", "replace")
        good = gpgverify.verify_detached(key_bytes, sig_bytes, signed.content, pinned_fpr=pinned)
        # The checksum the feed publishes must be the one the signature vouches for. Reading it
        # from the raw SUMS is safe *here* because a detached sig covers the whole file -- any
        # appended line breaks `good`. (Clearsigned below cannot do this; see there.)
        if not (good and release.checksum and release.checksum.lower() in text.lower()):
            return _drop(release), BAD
    elif covers == "clearsigned":
        # AlmaLinux: `sig` IS the clearsigned CHECKSUM -- signature and body in one file, so
        # there is no separate SUMS to fetch. Check the feed's checksum against gpg's extracted
        # payload (the signed region only), NOT the raw file: text appended after the signature
        # block leaves the inner sig Good, so a raw `in` check would match injected lines.
        payload = gpgverify.verify_clearsigned(key_bytes, sig_bytes, pinned_fpr=pinned)
        if not (payload and release.checksum and release.checksum.lower() in payload.lower()):
            return _drop(release), BAD
    elif covers == "image":
        # The sig covers the ISO we never download, so we can only check who it *names*. A
        # dual-signed `.asc` names two issuers (Proxmox), so consider them all; and match only
        # against the pinned key's OWN fingerprints (primary + subkeys, the Tails case), never
        # every key in the blob -- an appended attacker key must not lend its issuer here.
        issuers = gpgverify.sig_issuers(sig_bytes)
        if not issuers:
            return staged, DEFERRED  # couldn't parse the sig -> don't punish the entry
        own = gpgverify.fingerprints_for_primary(key_bytes, pinned)
        if not any(gpgverify.issuer_in_fingerprints(iss, own) for iss in issuers):
            return _drop(release), BAD
    else:  # a config with signing_key but no/unknown `covers` verifies nothing
        return staged, DEFERRED

    return replace(
        staged, signing_key_url=key_conf["url"], signing_key_fingerprint=pinned
    ), VERIFIED


def _drop(release: Release) -> Release:
    """Strip the gpg claim so `verify` falls back to `checksum`."""
    return replace(
        release,
        signature_url=None,
        signing_key_url=None,
        signing_key_fingerprint=None,
        signature_target=None,
    )


def _strip_sig_ext(url: str) -> str:
    for ext in _SIG_EXTS:
        if url.endswith(ext):
            return url[: -len(ext)]
    return url
