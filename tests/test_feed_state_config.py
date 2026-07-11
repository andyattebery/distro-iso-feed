"""Feed rendering, state keying, config validation, and the generated catalog.

The determinism tests are the ones that keep `git diff` meaningful: if any
generated file embeds a clock, the daily commit is never empty and a diff stops
meaning "a distro released something".
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

import pytest

from conftest import NOT_ENUMERABLE
from distro_iso_feed import docs, feed
from distro_iso_feed.config import ConfigError, load
from distro_iso_feed.models import Release
from distro_iso_feed.state import State
from distro_iso_feed.strategies import REGISTRY

ATOM = {"a": "http://www.w3.org/2005/Atom"}
NOW = datetime(2026, 7, 9, 6, 17, tzinfo=UTC)
SHA256 = "1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf"


def make_release(**kw) -> Release:
    base = dict(
        distro="fedora",
        variant="workstation",
        version="44-1.7",
        title="Fedora Workstation 44-1.7 (x86_64)",
        download_url="https://example/Fedora-Workstation-Live-44-1.7.x86_64.iso",
        filename="Fedora-Workstation-Live-44-1.7.x86_64.iso",
        checksum=SHA256,
        checksum_algo="sha256",
    )
    base.update(kw)
    return Release(**base)


def state_with(*releases: Release) -> State:
    s = State()
    for r in releases:
        s.update(r, r.checksum or "h", now=NOW)
    return s


# ------------------------------------------------------------------------- identifiers


def test_guid_state_key_and_atom_id_are_distinct():
    r = make_release()
    assert r.guid() == "fedora:workstation:44-1.7"
    assert r.state_key == "fedora:workstation"  # the guid PREFIX
    assert feed.atom_id(r).startswith("https://github.com/")


def test_atom_id_is_an_absolute_iri_not_the_raw_url():
    r = make_release()
    aid = feed.atom_id(r)
    assert aid.startswith("https://github.com/andyattebery/distro-iso-feed/id/")
    assert "raw.githubusercontent.com" not in aid


def test_respin_changes_guid_even_though_upstream_version_is_identical():
    """Fedora reports version "44" for both; the filename and sha256 differ.

    Keyed on "44", the id would not move and no reader that dedups by id would
    ever see the respin.
    """
    a = make_release(version="44-1.7")
    b = make_release(version="44-1.8", checksum="f" * 64)
    assert a.guid() != b.guid()


# ------------------------------------------------------------------------------ state


def test_new_version_replaces_record_rather_than_adding_a_key():
    s = state_with(make_release(version="44-1.7"))
    s.update(make_release(version="44-1.8"), "other-hash", now=NOW)
    assert list(s.records) == ["fedora:workstation"]
    assert s.records["fedora:workstation"].version == "44-1.8"


def test_unchanged_release_is_not_rewritten():
    r = make_release()
    s = state_with(r)
    assert s.update(r, r.checksum, now=NOW) is False


def test_failed_resolve_leaves_state_byte_identical(tmp_path):
    """A None resolve must never remove an entry: stale, never empty."""
    s = state_with(make_release())
    p = tmp_path / "state.json"
    s.save(p)
    before = p.read_bytes()
    State.load(p).save(p)  # a run in which nothing resolved
    assert p.read_bytes() == before


def test_enrich_adds_metadata_without_moving_seen_or_version():
    """The migration: a torrent attached to a known ISO must rewrite the record while
    keeping `version`, `hash`, and `seen` -- so no feed timestamp moves and no reader
    re-notifies."""
    s = state_with(make_release())
    before = s.records["fedora:workstation"]
    seen_before, hash_before = before.seen, before.hash

    enriched = make_release(torrent_url="https://x/w.iso.torrent", info_hash="d" * 40)
    assert s.enrich(enriched) is True

    rec = s.records["fedora:workstation"]
    assert rec.seen == seen_before  # the re-notify guard
    assert rec.hash == hash_before
    assert rec.version == before.version
    assert rec.release.torrent_url == "https://x/w.iso.torrent"  # the new data landed


def test_enrich_is_a_noop_when_nothing_changed():
    s = state_with(make_release())
    assert s.enrich(make_release()) is False


def test_enrich_declines_a_version_move():
    """A real move is update()'s job, and carries a fresh `seen`. enrich must not
    quietly swallow it under the old timestamp."""
    s = state_with(make_release(version="44-1.7"))
    assert s.enrich(make_release(version="44-1.8", torrent_url="https://x/t")) is False


def test_enrich_declines_an_unknown_variant():
    assert State().enrich(make_release()) is False


# ------------------------------------------------------------------------------- feed


def test_every_entry_has_an_enclosure_with_type():
    s = state_with(make_release())
    root = ET.fromstring(feed._atom(s.entries(), title="t", self_url="u", feed_id="i"))
    links = root.findall(".//a:entry/a:link", ATOM)
    enclosure = [x for x in links if x.get("rel") == "enclosure"]
    assert len(enclosure) == 1
    assert enclosure[0].get("type") == "application/x-iso9660-image"


def test_img_gz_enclosure_type_is_gzip_not_iso():
    r = make_release(
        distro="batocera",
        variant="x86_64",
        filename="batocera-x86_64-43.1-20260529.img.gz",
        checksum="0c365dc3c17b05a4b276c579168b01da",
        checksum_algo="md5",
    )
    assert r.content_type == "application/gzip"


@pytest.mark.parametrize(
    ("checksum", "algo", "sig", "verify", "must_contain", "must_not_contain"),
    [
        (SHA256, "sha256", None, "checksum", "sha256: ", "Signature:"),
        (SHA256, "sha256", "https://s.sig", "gpg", "Signature:", "WARNING"),
        (None, None, "https://s.sig", "gpg", "Verify: gpg", "sha256:"),
        (None, None, None, "none", "WARNING: no published checksum", "sha256:"),
    ],
)
def test_four_verify_shapes(checksum, algo, sig, verify, must_contain, must_not_contain):
    """Checksum and signature vary independently: Tails signs without a checksum."""
    r = make_release(checksum=checksum, checksum_algo=algo, signature_url=sig)
    assert r.verify == verify
    summary = feed.summary_for(r)
    assert must_contain in summary
    assert must_not_contain not in summary


def test_md5_label_is_not_hardcoded_to_sha256():
    r = make_release(checksum="0c365dc3c17b05a4b276c579168b01da", checksum_algo="md5")
    assert "md5: " in feed.summary_for(r)


def test_render_is_byte_identical_across_runs(tmp_path):
    """No clock anywhere: the same state renders the same bytes forever."""
    s = state_with(
        make_release(), make_release(distro="debian", variant="netinst", version="13.5.0")
    )
    a, b = tmp_path / "a", tmp_path / "b"
    feed.render(s, a)
    feed.render(s, b)
    for name in ("feed.xml", "feed.rss", "latest.json", "README.md"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_feed_updated_is_newest_entry_not_now(tmp_path):
    s = state_with(make_release())
    feed.render(s, tmp_path)
    root = ET.parse(tmp_path / "feed.xml").getroot()
    assert root.findtext("a:updated", namespaces=ATOM) == NOW.isoformat()


def test_latest_json_carries_a_schema_version(tmp_path):
    s = state_with(make_release())
    feed.render(s, tmp_path)
    data = json.loads((tmp_path / "latest.json").read_text())
    assert data["schema"] == feed.SCHEMA_VERSION
    assert "fedora:workstation" in data["releases"]


def test_signing_key_fields_flow_to_latest_json_and_summary(tmp_path):
    fpr = "DF9B9C49EAA9298432589D76DA87E80D6294BE9B"
    url = "https://keys.example/key"
    s = state_with(make_release(signing_key_url=url, signing_key_fingerprint=fpr))
    feed.render(s, tmp_path)
    entry = json.loads((tmp_path / "latest.json").read_text())["releases"]["fedora:workstation"]
    assert entry["signing_key_url"] == url
    assert entry["signing_key_fingerprint"] == fpr

    summary = feed.summary_for(make_release(signing_key_url=url, signing_key_fingerprint=fpr))
    assert f"Key-fingerprint: {fpr}" in summary
    assert f"Signing-key: {url}" in summary

    # An entry without a pin carries neither field / line.
    plain = feed.summary_for(make_release())
    assert "Key-fingerprint:" not in plain


# ----------------------------------------------------------------------------- config


def write(tmp_path, body: str):
    p = tmp_path / "sources.yaml"
    p.write_text(body)
    return p


def test_variant_inherits_distro_strategy(tmp_path):
    p = write(
        tmp_path,
        "distros:\n  d:\n    strategy: json_api\n"
        + NOT_ENUMERABLE
        + "    variants:\n      v: {}\n",
    )
    _, sources = load(p, set(REGISTRY))
    assert sources[0].variants[0].strategy == "json_api"


def test_variant_may_override_strategy_opensuse(tmp_path):
    """The one reason §6 gained an override: Leap lists a dir, Tumbleweed is fixed."""
    p = write(
        tmp_path,
        "distros:\n  opensuse:\n    strategy: directory_index\n"
        + NOT_ENUMERABLE
        + "    variants:\n"
        "      leap-dvd: {}\n      tumbleweed-dvd: {strategy: stable_symlink}\n",
    )
    _, sources = load(p, set(REGISTRY))
    by_name = {v.name: v.strategy for v in sources[0].variants}
    assert by_name == {"leap-dvd": "directory_index", "tumbleweed-dvd": "stable_symlink"}


def test_missing_strategy_is_a_load_time_error(tmp_path):
    p = write(tmp_path, "distros:\n  d:\n" + NOT_ENUMERABLE + "    variants:\n      v: {}\n")
    with pytest.raises(ConfigError, match="no strategy"):
        load(p, set(REGISTRY))


def test_unknown_strategy_is_a_load_time_error(tmp_path):
    p = write(
        tmp_path,
        "distros:\n  d:\n    strategy: telepathy\n"
        + NOT_ENUMERABLE
        + "    variants:\n      v: {}\n",
    )
    with pytest.raises(ConfigError, match="unknown strategy"):
        load(p, set(REGISTRY))


# ---------------------------------------------------------------------------- catalog


def test_catalog_is_generated_from_config_and_state(tmp_path):
    p = write(
        tmp_path,
        "distros:\n  fedora:\n    strategy: json_api\n" + NOT_ENUMERABLE + "    variants:\n"
        "      workstation: {}\n      server: {}\n",
    )
    _, sources = load(p, set(REGISTRY))
    s = state_with(make_release())
    out = tmp_path / "catalog.md"
    docs.render(sources, s, out)
    body = out.read_text()
    assert "| fedora | workstation | json_api | checksum | — | 44-1.7 |" in body
    assert "| fedora | server | json_api | — | — | — |" in body  # configured, unresolved


def test_catalog_has_no_build_timestamp(tmp_path):
    p = write(
        tmp_path,
        "distros:\n  d:\n    strategy: json_api\n"
        + NOT_ENUMERABLE
        + "    variants:\n      v: {}\n",
    )
    _, sources = load(p, set(REGISTRY))
    out_a, out_b = tmp_path / "a.md", tmp_path / "b.md"
    docs.render(sources, State(), out_a)
    docs.render(sources, State(), out_b)
    assert out_a.read_bytes() == out_b.read_bytes()


# ------------------------------------------------------------------------ run summary


def test_diagnose_distinguishes_dead_endpoint_from_bad_regex():
    """The two causes have opposite fixes, so "unresolved" alone is not enough."""
    from conftest import FakeClient, autoindex_html
    from distro_iso_feed.models import Variant
    from distro_iso_feed.run_refresh import diagnose

    s = REGISTRY["directory_index"]()
    v = Variant(distro="x", name="y", strategy="directory_index", params={})
    idx = "https://live.example/"

    dead = diagnose(s, v, {"index": idx, "match": r"\.iso$"}, FakeClient({}))
    assert "unreachable" in dead and idx in dead

    listing = FakeClient({idx: autoindex_html(["debian-13.5.0-amd64-netinst.iso"])})
    bad_match = diagnose(s, v, {"index": idx, "match": r"^ubuntu-.*\.iso$"}, listing)
    assert "none matched" in bad_match
    assert "debian-13.5.0-amd64-netinst.iso" in bad_match  # shows what WAS there

    listing = FakeClient({idx: autoindex_html(["debian-13.5.0-amd64-netinst.iso"])})
    bad_token = diagnose(
        s, v, {"index": idx, "match": r"\.iso$", "version_pattern": r"ubuntu-(\d+)"}, listing
    )
    assert "extracted no token" in bad_token


def test_summary_reports_no_commit_when_nothing_moved(tmp_path):
    from distro_iso_feed.run_refresh import write_summary

    p = tmp_path / "s.md"
    write_summary(p, changed=[], failed=[], total=82)
    body = p.read_text()
    assert "82/82" in body
    assert "no commit" in body


def test_summary_makes_failures_actionable(tmp_path):
    from distro_iso_feed.run_refresh import write_summary

    p = tmp_path / "s.md"
    write_summary(
        p, changed=[], failed=[("tails:iso", "listing empty or unreachable: https://x/")], total=82
    )
    body = p.read_text()
    assert "tails:iso" in body
    assert "unreachable" in body
    assert "--dry-run --only tails:iso -v" in body  # copy-pasteable repro


def test_endpoint_of_prefers_the_parent_over_a_template():
    """`index` is `{version}/` for version-dir sources; printing that helps nobody."""
    from distro_iso_feed.run_refresh import endpoint_of

    assert (
        endpoint_of({"version_dir": "https://parent/", "index": "{version}/"}) == "https://parent/"
    )
    assert endpoint_of({"index": "https://flat/"}) == "https://flat/"
    assert endpoint_of({"url": "https://fixed/x.iso"}) == "https://fixed/x.iso"
