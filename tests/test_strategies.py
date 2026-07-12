"""Strategy behaviour against captured upstream shapes.

The traps encoded here each produced a wrong conclusion during design, because a
transport-level signal (a 200, an item count) was mistaken for an artifact-level
one. Read the bytes the strategy would read.
"""

from __future__ import annotations

from conftest import FakeClient, atom_feed, autoindex_html, sf_rss
from distro_iso_feed.strategies import REGISTRY

SHA256 = "1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf"
MD5 = "0c365dc3c17b05a4b276c579168b01da"


# ------------------------------------------------------------------ directory_index


def test_directory_index_rejects_decoy_and_reads_gnu_sums():
    base = "https://cdimage.example/current/"
    client = FakeClient(
        {
            base: autoindex_html(
                ["debian-13.5.0-amd64-netinst.iso", "debian-edu-13.5.0-amd64-netinst.iso"]
            ),
            base + "SHA512SUMS": f"{'b' * 128}  debian-13.5.0-amd64-netinst.iso",
        }
    )
    rel = REGISTRY["directory_index"]().resolve(
        "debian",
        "netinst",
        {
            "index": base,
            "match": r"^debian-[0-9.]+-amd64-netinst\.iso$",
            "version_pattern": r"debian-([0-9.]+)-amd64",
            "sums": "SHA512SUMS",
            "ignore": ["debian-edu-"],
        },
        client,
    )
    assert rel.filename == "debian-13.5.0-amd64-netinst.iso"
    assert rel.version == "13.5.0"
    assert rel.checksum_algo == "sha512"
    assert rel.verify == "checksum"


def test_version_dir_picks_highest_that_contains_an_iso():
    """openSUSE lists 16.1 and 16.0, but only 15.6 has an `iso/` subdir today."""
    parent = "https://download.example/leap/"
    client = FakeClient(
        {
            parent: autoindex_html(["15.6/", "16.0/", "16.1/"]),
            parent + "16.1/iso/": "",  # exists but empty -> not a candidate
            parent + "16.0/iso/": "",
            parent + "15.6/iso/": autoindex_html(
                ["openSUSE-Leap-15.6-DVD-x86_64-Build710.3-Media.iso"]
            ),
            parent
            + "15.6/iso/openSUSE-Leap-15.6-DVD-x86_64-Build710.3-Media.iso.sha256": f"{SHA256}  openSUSE-Leap-15.6-DVD-x86_64-Build710.3-Media.iso",
        }
    )
    rel = REGISTRY["directory_index"]().resolve(
        "opensuse",
        "leap-dvd",
        {
            "version_dir": parent,
            "index": "{version}/iso/",
            "match": r"^openSUSE-Leap-[0-9.]+-DVD-x86_64-Build[0-9.]+-Media\.iso$",
            "version_pattern": r"Leap-([0-9.]+)-\w+-x86_64-Build([0-9.]+)-Media",
            "sums": "{filename}.sha256",
        },
        client,
    )
    assert rel.version == "15.6-710.3"


def test_freebsd_bsd_checksum_and_templated_sums():
    """`sums` must interpolate {version}; a literal cannot express this name."""
    parent = "https://download.freebsd.example/"
    idx = parent + "15.1/"
    client = FakeClient(
        {
            parent: autoindex_html(["14.4/", "15.1/"]),
            idx: autoindex_html(["FreeBSD-15.1-RELEASE-amd64-disc1.iso"]),
            idx
            + "CHECKSUM.SHA256-FreeBSD-15.1-RELEASE-amd64": f"SHA256 (FreeBSD-15.1-RELEASE-amd64-disc1.iso) = {SHA256}",
        }
    )
    rel = REGISTRY["directory_index"]().resolve(
        "freebsd",
        "disc1",
        {
            "version_dir": parent,
            "index": "{version}/",
            "match": r"^FreeBSD-[0-9.]+-RELEASE-amd64-disc1\.iso$",
            "version_pattern": r"FreeBSD-([0-9.]+)-RELEASE",
            "sums": "CHECKSUM.SHA256-FreeBSD-{version}-RELEASE-amd64",
        },
        client,
    )
    assert rel.version == "15.1"
    assert rel.checksum == SHA256


def test_batocera_bare_md5_and_non_iso_content_type():
    idx = "https://mirror.example/batocera/"
    name = "batocera-x86_64-43.1-20260529.img.gz"
    client = FakeClient({idx: autoindex_html([name]), idx + name + ".md5": MD5})
    rel = REGISTRY["directory_index"]().resolve(
        "batocera",
        "x86_64",
        {
            "index": idx,
            "match": r"^batocera-x86_64-[0-9.]+-\d{8}\.img\.gz$",
            "version_pattern": r"batocera-x86_64-([0-9.]+-\d{8})\.img\.gz",
            "sums": "{filename}.md5",
        },
        client,
    )
    assert rel.checksum_algo == "md5"
    assert rel.verify == "checksum"  # §16 says `none`; it publishes an md5
    assert rel.content_type == "application/gzip"


def test_directory_index_sums_from_filename_token_opnsense():
    """OPNsense's `26.7/` dir holds `OPNsense-26.7.r1-…`, and its checksums file is named from
    the FILENAME token. `sums_from_filename` must template `{version}` with `26.7.r1` (the
    file token), not `26.7` (the dir) -- without it the sums URL 404s."""
    parent = "https://mirror.example/opnsense/releases/"
    d = parent + "26.7/"
    iso = "OPNsense-26.7.r1-dvd-amd64.iso.bz2"
    client = FakeClient(
        {
            parent: autoindex_html(["25.7/", "26.7/"]),
            d: autoindex_html([iso, "OPNsense-26.7.r1-checksums-amd64.sha256"]),
            d + "OPNsense-26.7.r1-checksums-amd64.sha256": f"SHA256 ({iso}) = {SHA256}",
        }
    )
    params = {
        "version_dir": parent,
        "index": "{version}/",
        "sums": "OPNsense-{version}-checksums-amd64.sha256",
        "match": r"^OPNsense-[0-9.]+(?:\.r[0-9]+)?-dvd-amd64\.iso\.bz2$",
        "version_pattern": r"OPNsense-([0-9.]+(?:\.r[0-9]+)?)-dvd-amd64",
    }
    rel = REGISTRY["directory_index"]().resolve(
        "opnsense", "dvd", {**params, "sums_from_filename": True}, client
    )
    assert rel.filename == iso and rel.version == "26.7.r1"
    assert rel.checksum == SHA256  # sums URL built from 26.7.r1, not the dir 26.7
    assert rel.content_type == "application/x-bzip2"

    # Without the opt-in, {version} is the dir name `26.7` -> the sums URL 404s -> no checksum.
    miss = REGISTRY["directory_index"]().resolve("opnsense", "dvd", params, client)
    assert miss.filename == iso and miss.checksum is None


def test_tails_signature_without_checksum():
    """A signature does not imply a checksum. Tails publishes only `.iso.sig`."""
    idx = "https://download.tails.example/stable/tails-amd64-7.9.1/"
    client = FakeClient(
        {
            "https://download.tails.example/stable/": autoindex_html(["tails-amd64-7.9.1/"]),
            idx: autoindex_html(["tails-amd64-7.9.1.iso"]),
        }
    )
    rel = REGISTRY["directory_index"]().resolve(
        "tails",
        "iso",
        {
            "version_dir": "https://download.tails.example/stable/",
            "version_dir_match": r"^tails-amd64-[0-9.]+$",
            "index": "{version}/",
            "match": r"^tails-amd64-[0-9.]+\.iso$",
            "version_pattern": r"tails-amd64-([0-9.]+)\.iso",
            "sig": "{filename}.sig",
        },
        client,
    )
    assert rel.checksum is None
    assert rel.signature_url.endswith(".iso.sig")
    assert rel.verify == "gpg"


# ------------------------------------------------------------------- stable_symlink


def test_stable_symlink_token_from_sidecar_filename():
    """The URL is version-less; the sidecar names the dated artifact."""
    url = "https://files.example/neon/neon-desktop-current.iso"
    client = FakeClient(
        {
            "https://files.example/neon/neon-desktop-current.sha256sum": f"{SHA256}  neon-desktop-20260707-0147.iso"
        }
    )
    rel = REGISTRY["stable_symlink"]().resolve(
        "kde-neon",
        "desktop",
        {
            "url": url,
            "sums": "{stem}.sha256sum",
            "token": {"from": "sidecar_filename", "pattern": r"(\d{8}-\d{4})"},
        },
        client,
    )
    assert rel.version == "20260707-0147"
    assert rel.download_url == url  # still the version-less URL
    assert rel.checksum == SHA256  # name mismatch must not lose it


def test_stable_symlink_token_from_atom_tag_ublue():
    """ublue's `-CHECKSUM` names a version-less ISO, so GitHub supplies the token."""
    url = "https://download.bazzite.gg/bazzite-stable-amd64.iso"
    client = FakeClient(
        {
            "https://github.com/ublue-os/bazzite/releases.atom": atom_feed(
                ["stable-20260708: Stable"]
            ),
            url + "-CHECKSUM": f"{SHA256}  bazzite-stable-amd64.iso",
        }
    )
    rel = REGISTRY["stable_symlink"]().resolve(
        "bazzite",
        "desktop",
        {
            "url": url,
            "sums": "{filename}-CHECKSUM",
            "token": {"from": "atom_tag", "repo": "ublue-os/bazzite"},
        },
        client,
    )
    assert rel.version == "stable-20260708"


def test_atom_feed_with_zero_entries_yields_none():
    """Nobara's releases.atom is 200 with no <entry>. A 200 is not a release."""
    url = "https://example/x.iso"
    client = FakeClient(
        {
            "https://github.com/some/repo/releases.atom": atom_feed([]),
            url + "-CHECKSUM": f"{SHA256}  x.iso",
        }
    )
    rel = REGISTRY["stable_symlink"]().resolve(
        "x",
        "y",
        {
            "url": url,
            "sums": "{filename}-CHECKSUM",
            "token": {"from": "atom_tag", "repo": "some/repo"},
        },
        client,
    )
    assert rel is None


def test_atom_rc_tag_rejected_by_pattern_not_flag():
    url = "https://example/x.iso"
    client = FakeClient(
        {"https://github.com/elementary/os/releases.atom": atom_feed(["8.1.0-rc3: RC"])}
    )
    rel = REGISTRY["stable_symlink"]().resolve(
        "elementary",
        "default",
        {"url": url, "token": {"from": "atom_tag", "repo": "elementary/os"}},
        client,
    )
    assert rel is None


def test_nixos_candidate_probe_finds_highest_channel():
    """channels.nixos.org serves no index: candidates are generated and probed."""
    tmpl = "https://channels.example/nixos-{version}/latest-nixos-minimal-x86_64-linux.iso.sha256"
    sidecar = tmpl.format(version="25.05")
    client = FakeClient(
        {sidecar: f"{SHA256}  nixos-minimal-25.05.813814.ac62194c3917-x86_64-linux.iso"},
        existing={sidecar},
    )
    rel = REGISTRY["stable_symlink"]().resolve(
        "nixos",
        "minimal",
        {
            "url": "https://channels.example/nixos-{version}/latest-nixos-minimal-x86_64-linux.iso",
            "probe_versions": {"template": tmpl, "candidates": ["26.11", "25.05"]},
            "sums": "{filename}.sha256",
            "token": {"from": "sidecar_filename", "pattern": r"-([0-9.]+\.[0-9a-f]+)-x86_64"},
        },
        client,
    )
    assert rel.version == "25.05.813814.ac62194c3917"


# ----------------------------------------------------------------------- sourceforge


def test_sourceforge_dedupes_doubled_items_and_rejects_zsync():
    paths = ["/Final/Xfce/MX-25.2_Xfce_x64.iso", "/Final/Xfce/MX-25.2_Xfce_x64.iso.zsync"]
    feed = "https://sourceforge.net/projects/mx-linux/rss?path=/Final"
    sums = "https://sourceforge.net/projects/mx-linux/files/Final/Xfce/MX-25.2_Xfce_x64.iso.sha256/download"
    client = FakeClient({feed: sf_rss(paths), sums: f"{SHA256}  MX-25.2_Xfce_x64.iso"})
    rel = REGISTRY["sourceforge"]().resolve(
        "mx",
        "xfce",
        {
            "project": "mx-linux",
            "path": "/Final",
            "match": r"/Xfce/MX-[0-9.]+_Xfce_x64\.iso$",
            "version_pattern": r"MX-([0-9.]+)_",
            "sums": "{path}.sha256",
        },
        client,
    )
    assert rel.filename == "MX-25.2_Xfce_x64.iso"
    assert rel.checksum == SHA256


def test_sourceforge_absolute_foreign_sums_and_sig_url_clonezilla():
    """Clonezilla keeps its signed CHECKSUMS.TXT off SourceForge; an absolute `sums`/`sig`
    URL must be used verbatim, not wrapped in the SourceForge download template. The
    multi-section file resolves to its strongest hash."""
    iso_path = "/clonezilla_live_stable/3.3.2-31/clonezilla-live-3.3.2-31-amd64.iso"
    feed = "https://sourceforge.net/projects/clonezilla/rss?path=/clonezilla_live_stable"
    foreign = "https://clonezilla.org/downloads/stable/data/CHECKSUMS.TXT"
    client = FakeClient(
        {
            feed: sf_rss([iso_path]),
            foreign: f"### MD5SUMS:\n{MD5}  clonezilla-live-3.3.2-31-amd64.iso\n"
            f"### SHA256SUMS:\n{SHA256}  clonezilla-live-3.3.2-31-amd64.iso\n",
        }
    )
    rel = REGISTRY["sourceforge"]().resolve(
        "clonezilla",
        "default",
        {
            "project": "clonezilla",
            "path": "/clonezilla_live_stable",
            "match": r"/clonezilla-live-[0-9.-]+-amd64\.iso$",
            "version_pattern": r"clonezilla-live-([0-9.-]+)-amd64\.iso$",
            "sums": foreign,
            "sig": foreign + ".gpg",
        },
        client,
    )
    assert rel.version == "3.3.2-31"
    assert rel.checksum == SHA256  # off-host file fetched verbatim; sha256 beats the co-listed md5
    assert rel.signature_url == foreign + ".gpg"  # absolute, not SourceForge-wrapped


def test_sourceforge_token_from_filename_not_directory_cachyos():
    """dir says 250626, file says 260426. The filename is authoritative."""
    paths = ["/gui-installer/handheld/250626/cachyos-handheld-linux-260426.iso"]
    feed = "https://sourceforge.net/projects/cachyos-arch/rss?path=/gui-installer"
    client = FakeClient({feed: sf_rss(paths)})
    rel = REGISTRY["sourceforge"]().resolve(
        "cachyos",
        "handheld",
        {
            "project": "cachyos-arch",
            "path": "/gui-installer",
            "match": r"/handheld/\d+/cachyos-handheld-linux-\d+\.iso$",
            "version_pattern": r"-(\d{6})\.iso$",
        },
        client,
    )
    assert rel.version == "260426"


def test_sourceforge_stem_template_bluestar():
    """Bluestar's sidecar drops the `.iso`: `bslx-....md5`, not `....iso.md5`."""
    p = "/distro/bslx-7.1.3-3-2026.07.08-x86_64.iso"
    feed = "https://sourceforge.net/projects/bluestarlinux/rss?path=/distro"
    sums = "https://sourceforge.net/projects/bluestarlinux/files/distro/bslx-7.1.3-3-2026.07.08-x86_64.md5/download"
    client = FakeClient({feed: sf_rss([p]), sums: MD5})
    rel = REGISTRY["sourceforge"]().resolve(
        "bluestar",
        "default",
        {
            "project": "bluestarlinux",
            "path": "/distro",
            "match": r"/bslx-[0-9.-]+-\d{4}\.\d{2}\.\d{2}-x86_64\.iso$",
            "version_pattern": r"bslx-([0-9.-]+-\d{4}\.\d{2}\.\d{2})-x86_64",
            "sums": "{stem}.md5",
        },
        client,
    )
    assert rel.checksum_algo == "md5"


# ------------------------------------------------------------------------ page_index


def test_page_index_reads_data_attribute_and_sha256sum_suffix():
    """`<iso>.sha256` 404s for Nobara; the real suffix is `.sha256sum`."""
    page = "https://nobaraproject.org/download-nobara/"
    iso = "https://images.example/Nobara-43-GNOME-2026-04-19.iso"
    client = FakeClient(
        {
            page: f'<a data-url="{iso}">x</a>',
            iso + ".sha256sum": f"{SHA256}  ./Nobara-43-GNOME-2026-04-19.iso",
        }
    )
    rel = REGISTRY["page_index"]().resolve(
        "nobara",
        "gnome",
        {
            "url": page,
            "attr": "data-url",
            "match": r"^Nobara-\d+-GNOME-\d{4}-\d{2}-\d{2}\.iso$",
            "version_pattern": r"Nobara-(\d+)-[A-Za-z-]+-(\d{4}-\d{2}-\d{2})\.iso$",
            "sums": "{filename}.sha256sum",
        },
        client,
    )
    assert rel.version == "43-2026-04-19"  # release number AND date
    assert rel.checksum == SHA256  # `./` prefix normalized away


def test_page_index_resolves_relative_hrefs_against_the_page_url():
    """TrueNAS/Memtest link relatively, and the strategy derives the sidecar directory from
    the resolved URL -- so a relative href must become absolute or the deep-path sums 404s."""
    page = "https://dl.example/"
    iso_abs = "https://dl.example/Goldeye/25.10.4/TrueNAS-SCALE-25.10.4.iso"
    client = FakeClient(
        {
            page: (
                '<a href="Goldeye/25.10.4/TrueNAS-SCALE-25.10.4.iso">iso</a>'
                '<a href="Goldeye/25.10.4/TrueNAS-SCALE-25.10.4.iso.sha256">sum</a>'
            ),
            iso_abs + ".sha256": SHA256,  # bare hash, in the deep per-release directory
        }
    )
    rel = REGISTRY["page_index"]().resolve(
        "truenas",
        "scale",
        {
            "url": page,
            "attr": "href",
            "match": r"^TrueNAS-(?:SCALE-)?[0-9.]+\.iso$",
            "version_pattern": r"TrueNAS-(?:SCALE-)?([0-9.]+)\.iso$",
            "sums": "{filename}.sha256",
        },
        client,
    )
    assert rel.download_url == iso_abs  # relative href resolved to absolute
    assert rel.version == "25.10.4"
    assert rel.checksum == SHA256  # bare-hash sidecar found next to the ISO, not at the root


# -------------------------------------------------------------------- failure isolation


def test_resolver_returns_none_when_upstream_is_empty():
    client = FakeClient({})
    rel = REGISTRY["directory_index"]().resolve(
        "x", "y", {"index": "https://gone.example/", "match": r"\.iso$"}, client
    )
    assert rel is None
