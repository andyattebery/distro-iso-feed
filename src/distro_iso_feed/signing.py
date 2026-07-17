"""The GPG **policy** layer: which `covers` mode dispatches to which `gpgverify` check, and the
build-time VERIFIED/REJECTED/DEFERRED verdict the runners act on.

Distinct from `gpgverify.py`, which holds the stateless gpg-subprocess *wrappers*. This module is
the policy that composes them against a resolved `Release` and its pinned-key config -- so "the GPG
gate" finally has a home of its own rather than squatting beside torrent plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from . import gpgverify
from .client import Client
from .models import Release

_SIG_EXTS = (".sign", ".gpg", ".asc")

# The build-time GPG verdict -- proven / disproven / couldn't-check.
VERIFIED = "verified"  # signature chains to the pinned key -> publish the pin
REJECTED = "rejected"  # a signature that does NOT chain to the pin -> drop the gpg claim
DEFERRED = "deferred"  # couldn't verify (gpg-absent / transient fetch) -> keep as resolved, no pin

# The `covers` modes `verify_signing_key` dispatches on (see its if/elif). This is the single
# source of truth: `config.py` imports it to validate `signing_key.covers`, so the validator and
# the dispatch can no longer name different sets in two files coupled by a bare string. Adding a
# mode is now a single-file edit here -- add the name AND its dispatch branch below together (a
# name here with no branch would silently degrade to DEFERRED; a test pins config to this set).
COVERS = frozenset({"checksums", "clearsigned", "image"})

# No checksum resolved => nothing to check the signature against, so we cannot prove OR disprove
# the pin: DEFERRED, never REJECTED. This distinction is the whole bug behind the bogus
# "rotated signing key" tickets -- a timed-out sums fetch left `checksum=None`, which fell into
# the "absent from the signed file" branch and got reported as a key rotation.
_NO_CHECKSUM = "the feed has no checksum to check against (the sums fetch did not land)"


@dataclass(frozen=True, slots=True)
class SigningOutcome:
    """The GPG verdict plus the *why*, so a caller can log, report, or escalate without re-deriving.

    `reason` is the human cause for REJECTED/DEFERRED (None on VERIFIED). `signer` is the actual
    signing fingerprint when the pin was REJECTED -- read from the signature packet itself, so it
    names the key even though it isn't the pin: the rotation lead an escalation ticket needs.
    """

    release: Release
    verdict: str
    reason: str | None = None
    signer: str | None = None

    def __iter__(self):
        # A SigningOutcome is fundamentally the `(release, verdict)` this used to return; `reason`
        # and `signer` are added context. Unpacking as that pair stays supported for terse callers.
        return iter((self.release, self.verdict))


def _norm_fpr(value: str) -> str:
    return "".join(value.split()).upper()


def _first_issuer(sig_bytes: bytes) -> str | None:
    """The signature's own issuer fingerprint, read from the packet -- so it names the signer even
    when it isn't the pin (a rotated key gpg can't verify). None if the sig won't parse."""
    issuers = gpgverify.sig_issuers(sig_bytes)
    return issuers[0] if issuers else None


def verify_signing_key(client: Client, release: Release, params: dict) -> SigningOutcome:
    """Prove the GPG chain before the feed publishes the pinned key.

    A hand-entered fingerprint is only as good as the data entry, so every build
    re-checks it against the *actual signature* on the current artifact:

      checksums -- the sig covers a small SHA*SUMS/.sha256 file, so `gpgv` the whole
                   thing under only the pinned key, then confirm the checksum the feed
                   ships is inside that verified file. Full authentication.
      image     -- the sig covers the multi-GB ISO we do not download, so confirm the
                   signature's issuer is the pinned key (primary or subkey). Proves
                   the signature is *from* the pinned key; the consumer does the rest.

    Returns a `SigningOutcome` whose `verdict` is:
      VERIFIED -> the pin is attached;
      REJECTED -> `signature_url` is cleared, so `verify` degrades to `checksum` (a signed
                  checksum that fails its signature is not forwardable); `reason`/`signer` say why
                  and who signed instead -- the escalation lead;
      DEFERRED -> the entry is returned exactly as resolved (a network blip or a dev box without
                  gpg must never flap the claim), no pin this run; `reason` says what was missing.
    """
    key_conf = params.get("signing_key")
    if not key_conf or not release.signature_url:
        return SigningOutcome(release, DEFERRED)  # nothing to verify

    # `signature_target` is a static fact -- what the sig signs -- known from config
    # regardless of whether gpg can verify the pin this run. Stage it now so it rides
    # every non-REJECTED path (a dev box without gpg still emits it); `_drop` clears it.
    covers = key_conf.get("covers")
    # `signature_target` names what the sig signs (checksums|image) for the client; a
    # clearsigned CHECKSUM is a checksums signature carried inline, so it maps to checksums.
    target = "checksums" if covers == "clearsigned" else covers
    staged = replace(release, signature_target=target)

    if not gpgverify.gpg_available():
        return SigningOutcome(staged, DEFERRED, "gpg unavailable on this runner")

    # `get_cached`: one keyserver URL backs many variants (28 share the Ubuntu key), so this
    # collapses to a single fetch per key per run.
    key = client.get_cached(key_conf["url"])
    if not key or not key.content:
        return SigningOutcome(staged, DEFERRED, "key server unreachable")
    key_bytes = key.content

    pinned = _norm_fpr(str(key_conf["fingerprint"]))
    # A cheap sanity early-out: is the pinned key even in what the URL served? Set-based (not
    # "is it the first key") so a key directory that returns several keys, or lists the pin
    # second, is not a false reject. It is no longer the security boundary -- each path below
    # proves the pin actually *signed*, so an appended attacker key cannot ride this through.
    primaries = {g[0] for g in gpgverify.key_fingerprint_groups(key_bytes) if g}
    if pinned not in primaries:
        served = sorted(primaries)
        return SigningOutcome(
            _drop(release),
            REJECTED,
            f"the key URL no longer serves the pinned {pinned} "
            f"(it serves {', '.join(served) or 'no key'})",
            signer=served[0] if served else None,
        )

    sig = client.get_cached(release.signature_url)
    if not sig or not sig.content:
        return SigningOutcome(staged, DEFERRED, "signature file unreachable")
    sig_bytes = sig.content

    if covers == "checksums":
        signed_url = _strip_sig_ext(release.signature_url)
        # `get_cached`: the strategy already fetched this same SHA*SUMS to read the hash out of
        # it. One fetch for both closes a TOCTOU -- a second fetch can disagree with the first,
        # and only the first is published.
        signed = client.get_cached(signed_url)
        if not signed or not signed.content:
            return SigningOutcome(staged, DEFERRED, "checksum file unreachable")
        text = signed.content.decode("utf-8", "replace")
        good = gpgverify.verify_detached(key_bytes, sig_bytes, signed.content, pinned_fpr=pinned)
        if not good:
            return SigningOutcome(
                _drop(release), REJECTED,
                f"the SHA*SUMS signature does not chain to the pinned key {pinned}",
                signer=_first_issuer(sig_bytes),
            )  # fmt: skip
        if not release.checksum:
            return SigningOutcome(staged, DEFERRED, _NO_CHECKSUM)
        # The checksum the feed publishes must be the one the signature vouches for. Reading it
        # from the raw SUMS is safe *here* because a detached sig covers the whole file -- any
        # appended line breaks `good`. (Clearsigned below cannot do this; see there.)
        if release.checksum.lower() not in text.lower():
            return SigningOutcome(
                _drop(release), REJECTED,
                "the signature is valid but the feed's checksum is absent from the signed file",
                signer=pinned,
            )  # fmt: skip
    elif covers == "clearsigned":
        # AlmaLinux: `sig` IS the clearsigned CHECKSUM -- signature and body in one file, so
        # there is no separate SUMS to fetch. Check the feed's checksum against gpg's extracted
        # payload (the signed region only), NOT the raw file: text appended after the signature
        # block leaves the inner sig Good, so a raw `in` check would match injected lines.
        payload = gpgverify.verify_clearsigned(key_bytes, sig_bytes, pinned_fpr=pinned)
        if not payload:
            return SigningOutcome(
                _drop(release), REJECTED,
                f"the clearsigned CHECKSUM does not chain to the pinned key {pinned}",
                signer=_first_issuer(sig_bytes),
            )  # fmt: skip
        if not release.checksum:
            return SigningOutcome(staged, DEFERRED, _NO_CHECKSUM)
        if release.checksum.lower() not in payload.lower():
            return SigningOutcome(
                _drop(release), REJECTED,
                "the signature is valid but the feed's checksum is absent from the signed payload",
                signer=pinned,
            )  # fmt: skip
    elif covers == "image":
        # The sig covers the ISO we never download, so we can only check who it *names*. A
        # dual-signed `.asc` names two issuers (Proxmox), so consider them all; and match only
        # against the pinned key's OWN fingerprints (primary + subkeys, the Tails case), never
        # every key in the blob -- an appended attacker key must not lend its issuer here.
        issuers = gpgverify.sig_issuers(sig_bytes)
        if not issuers:
            return SigningOutcome(staged, DEFERRED, "could not parse the signature")
        own = gpgverify.fingerprints_for_primary(key_bytes, pinned)
        if not any(gpgverify.issuer_in_fingerprints(iss, own) for iss in issuers):
            return SigningOutcome(
                _drop(release), REJECTED,
                f"the image signature is from {issuers[0]}, not the pinned key or its subkeys",
                signer=issuers[0],
            )  # fmt: skip
    else:  # a config with signing_key but no/unknown `covers` verifies nothing
        return SigningOutcome(staged, DEFERRED, "no or unknown covers mode")

    return SigningOutcome(
        replace(staged, signing_key_url=key_conf["url"], signing_key_fingerprint=pinned), VERIFIED
    )


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
