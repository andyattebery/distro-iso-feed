"""Every checksum shape the seeded catalog actually contains.

A parser that knows only `<hash>  <name>` silently returns nothing for FreeBSD and
Batocera -- silently, which is why these are tests and not comments.
"""

from __future__ import annotations

from distro_iso_feed import checksums

SHA256 = "1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf"
SHA512 = "b" * 128
SHA1 = "c" * 40
MD5 = "0c365dc3c17b05a4b276c579168b01da"


def test_gnu_format():
    text = f"{SHA256}  Fedora-Workstation-Live-44-1.7.x86_64.iso"
    assert checksums.lookup(text, "Fedora-Workstation-Live-44-1.7.x86_64.iso") == ("sha256", SHA256)


def test_bsd_format_freebsd():
    """FreeBSD is NOT two-column. A GNU-only parser reads zero lines from this."""
    text = f"SHA256 (FreeBSD-15.1-RELEASE-amd64-disc1.iso) = {SHA256}"
    assert checksums.lookup(text, "FreeBSD-15.1-RELEASE-amd64-disc1.iso") == ("sha256", SHA256)


def test_bsd_format_is_not_parsed_as_gnu():
    text = f"SHA256 (x.iso) = {SHA256}"
    assert checksums.parse(text) == {"x.iso": ("sha256", SHA256)}


def test_bare_hash_batocera():
    """`.img.gz.md5` has no filename column at all; the caller supplies one."""
    assert checksums.lookup(MD5, "batocera-x86_64-43.1-20260529.img.gz") == ("md5", MD5)


def test_bare_hash_without_default_name_yields_nothing():
    assert checksums.parse(MD5) == {}


def test_algo_discriminated_by_exact_length():
    assert checksums.algo_for_hash(MD5) == "md5"
    assert checksums.algo_for_hash(SHA1) == "sha1"
    assert checksums.algo_for_hash(SHA256) == "sha256"
    assert checksums.algo_for_hash(SHA512) == "sha512"


def test_sha1_decoy_loses_to_sha256():
    """Garuda publishes `.iso.sha1` beside `.iso.sha256`. Strongest wins."""
    text = f"{SHA1}  garuda.iso\n{SHA256}  garuda.iso"
    assert checksums.lookup(text, "garuda.iso") == ("sha256", SHA256)


def test_sha512_line_not_mistaken_for_sha256():
    text = f"{SHA512}  debian-13.5.0-amd64-netinst.iso"
    algo, _ = checksums.lookup(text, "debian-13.5.0-amd64-netinst.iso")
    assert algo == "sha512"


def test_leading_dot_slash_is_normalized_nobara():
    """Nobara's sidecar reads `./Nobara-...iso`; without stripping, lookup misses."""
    text = f"{SHA256}  ./Nobara-43-GNOME-2026-04-19.iso"
    assert checksums.lookup(text, "Nobara-43-GNOME-2026-04-19.iso") == ("sha256", SHA256)


def test_aggregate_file_disambiguates_by_filename_q4os():
    """One md5sum.txt covers every release, i386 and older versions included.

    "The first hash" would attach an i386 checksum to an x64 ISO.
    """
    text = (
        "896f13da0b80d950237db0734159bb41  q4os-5.9-i386-instcd.r1.iso\n"
        "c2e21aa92380dd3e8c527b9767c13bf2  q4os-6.6-x64-instcd.r1.iso\n"
        f"{MD5}  q4os-6.7-x64.r1.iso\n"
    )
    assert checksums.lookup(text, "q4os-6.7-x64.r1.iso") == ("md5", MD5)


def test_sole_entry_ignores_name_mismatch_stable_symlink():
    """neon's sidecar names the dated ISO while we download `-current.iso`.

    Matching on name here would throw the checksum away; the mismatch IS the
    change-token mechanism.
    """
    text = f"{SHA256}  neon-desktop-20260707-0147.iso"
    assert checksums.sole(text, "neon-desktop-current.iso") == ("sha256", SHA256)


def test_sole_falls_back_to_name_lookup_when_many():
    text = f"{SHA256}  a.iso\n{SHA512}  b.iso"
    assert checksums.sole(text, "b.iso") == ("sha512", SHA512)
