"""Selection: decoys, prereleases, max-version, channels.

Every decoy below is real and co-located with the artifact we want. Each is one
unanchored regex away from being published as the current release.
"""

from __future__ import annotations

import pytest

from distro_iso_feed import select


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("manjaro-gnome-26.1.0-pre-260626-linux70.iso", True),
        ("MX-25.2_KDE_beta1_x64.iso", True),
        ("aurora-beta-webui-x86_64.iso", True),
        ("8.1.0-rc3", True),
        ("Zorin-OS-16-Core-Beta-64-bit.iso", True),
        ("MX-25.2_KDE_x64.iso", False),
        ("debian-13.5.0-amd64-netinst.iso", False),
    ],
)
def test_prerelease_detection(name, expected):
    assert select.is_prerelease(name) is expected


def test_prerelease_never_uses_github_flag():
    """elementary tags `8.1.0-rc3` with prerelease: false. The name is the truth."""
    assert select.is_prerelease("8.1.0-rc3")


def test_decoy_rejection_debian_edu():
    """With a loose `match`, `ignore` is the only thing standing between the feed
    and Debian Edu. The first assertion proves the decoy really is reachable."""
    names = ["debian-13.5.0-amd64-netinst.iso", "debian-edu-13.5.0-amd64-netinst.iso"]

    assert select.choose(names, match=r"netinst\.iso$") == "debian-edu-13.5.0-amd64-netinst.iso"
    assert (
        select.choose(names, match=r"netinst\.iso$", ignore=["debian-edu-"])
        == "debian-13.5.0-amd64-netinst.iso"
    )


def test_decoy_rejection_kali_arm64():
    names = ["kali-linux-2026.2-installer-amd64.iso", "kali-linux-2026.2-installer-arm64.iso"]
    assert select.excluding(names, ["arm64"]) == ["kali-linux-2026.2-installer-amd64.iso"]


def test_decoy_rejection_void_musl():
    names = ["void-live-x86_64-20250202-xfce.iso", "void-live-x86_64-musl-20250202-xfce.iso"]
    assert select.excluding(names, ["-musl-"]) == ["void-live-x86_64-20250202-xfce.iso"]


def test_decoy_rejection_antix_386():
    names = ["antiX-26_x64-full.iso", "antiX-26_386-full.iso"]
    assert select.excluding(names, ["_386-"]) == ["antiX-26_x64-full.iso"]


def test_dedupe_sourceforge_doubled_items():
    """A single ISO yields two identical <item> elements in SourceForge's RSS."""
    assert select.dedupe(["a.iso", "a.iso", "b.iso"]) == ["a.iso", "b.iso"]


def test_max_version_keys_on_token_not_name_endeavouros():
    """Codenames do not sort. Key on the embedded date, or publish Gemini forever."""
    names = [
        "EndeavourOS_Gemini-2024.04.20.iso",
        "EndeavourOS_Titan-2026.03.06.iso",
        "EndeavourOS_Titan-Neo-2026.04.27.iso",
        "EndeavourOS_Mercury-2025.02.08.iso",
    ]
    assert select.newest(names, r"(\d{4}\.\d{2}\.\d{2})") == "EndeavourOS_Titan-Neo-2026.04.27.iso"


def test_version_pattern_is_load_bearing_not_decoration():
    """A leading release number can outrank the date that actually orders builds.

    Bluestar's `7.10.0` sorts above `7.1.3`, so an unpatterned max-version picks the
    January image over the July one. The pattern anchors on the build date.
    """
    names = [
        "bslx-7.10.0-1-2026.01.01-x86_64.iso",  # higher semver, older build
        "bslx-7.1.3-3-2026.07.08-x86_64.iso",  # lower semver, newest build
    ]
    assert select.newest(names) == "bslx-7.10.0-1-2026.01.01-x86_64.iso"
    assert select.newest(names, r"(\d{4}\.\d{2}\.\d{2})") == "bslx-7.1.3-3-2026.07.08-x86_64.iso"


def test_ubuntu_lts_is_even_year_dot_04():
    assert select.is_lts("24.04")
    assert select.is_lts("26.04.1")
    assert not select.is_lts("25.04")  # interim, despite `.04`
    assert not select.is_lts("25.10")


def test_ubuntu_channels_split():
    versions = ["24.04.3", "24.04.4", "25.10", "26.04"]
    assert select.by_channel(versions, "lts") == ["24.04.3", "24.04.4", "26.04"]
    assert select.by_channel(versions, "interim") == ["25.10"]


def test_ubuntu_picks_newest_within_channel():
    lts = select.by_channel(["24.04.3", "24.04.4", "25.10", "26.04"], "lts")
    assert select.newest(lts) == "26.04"


def test_manjaro_all_prerelease_resolves_to_nothing():
    """Manjaro's SourceForge feed is entirely `-pre`. §8 says skip betas."""
    names = [
        "manjaro-gnome-26.1.0-pre-260626-linux70.iso",
        "manjaro-kde-26.1.0-pre-260626-linux70.iso",
    ]
    assert select.choose(names, match=r"\.iso$") is None


def test_sort_pattern_separates_ordering_from_identity_manjaro():
    """Kernel `linux70` is 7.0 and beats `linux618` (6.18). As integers it loses.

    The token must keep the kernel (different bytes -> different guid); the ordering
    must not use it as an integer.
    """
    names = [
        "manjaro-gnome-26.0.4-260327-linux618.iso",
        "manjaro-gnome-26.0.4-260327-linux70.iso",
    ]
    token = r"-([0-9.]+-\d{6}-linux\d+)\.iso$"
    order = r"-([0-9.]+-\d{6})-linux\d+\.iso$"

    # Ordering on the token alone gets it backwards: 618 > 70 numerically.
    assert select.choose(names, match=r"\.iso$", version_pattern=token).endswith("linux618.iso")

    # Sorting on release+date ties, and the name tie-break picks the 7.0 kernel.
    chosen = select.choose(names, match=r"\.iso$", version_pattern=token, sort_pattern=order)
    assert chosen.endswith("linux70.iso")


def test_newer_release_still_wins_regardless_of_kernel():
    names = [
        "manjaro-gnome-26.0.4-260327-linux70.iso",
        "manjaro-gnome-26.1.0-260626-linux612.iso",
    ]
    order = r"-([0-9.]+-\d{6})-linux\d+\.iso$"
    assert select.choose(names, match=r"\.iso$", sort_pattern=order).startswith(
        "manjaro-gnome-26.1.0"
    )
