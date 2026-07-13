"""Synthesis, and the check that keeps a plausible synthesis from being written.

`match: TODO` made the discovery PR a to-do list. These tests cover what replaced
it: a config node diffed out of a sibling, then executed. The interesting cases are
all failures -- a proposal that resolves to the *sibling's* artifact is a silent
duplicate variant, and it is exactly what a plausible-but-wrong substitution yields.
"""

from __future__ import annotations

import re

from conftest import FakeClient
from distro_iso_feed.listers import Candidate
from distro_iso_feed.models import Release, Source, Variant, VariantSpec
from distro_iso_feed.propose_common import _confirms, pr_body
from distro_iso_feed.propose_variants import (
    _nodes_for,
    diff_tokens,
    generalize,
    propose_for,
    substitute,
)

# ------------------------------------------------------------------------ diff_tokens


def test_diff_is_token_granular_not_character_granular():
    """`standard` and `cinnamon` share an `n`, an `a` and an `n`. Diffing characters
    shatters one edition rename into sub-word fragments that substitute into
    gibberish; diffing tokens keeps it whole."""
    assert diff_tokens(
        "debian-live-13.5.0-amd64-standard.iso", "debian-live-13.5.0-amd64-cinnamon.iso"
    ) == [("standard", "cinnamon")]


def test_diff_ignores_a_pure_version_difference():
    """Two editions of one release share a version. A digit-only difference means
    these are different *releases* -- and substituting Nobara's `2026-04-25` into a
    sibling's date regex is how a superseded ISO becomes a config entry."""
    tokens = diff_tokens(
        "Nobara-43-Steam-Handheld-2026-04-25.iso", "Nobara-43-Steam-HTPC-2026-04-19.iso"
    )
    assert tokens == [("Handheld", "HTPC")]


def test_diff_declines_an_insertion():
    """Aurora inserts `nvidia-open-`. No substitution can bridge that, so the caller
    must fall back to the URL the server actually handed us."""
    assert (
        diff_tokens("aurora-stable-webui-x86_64.iso", "aurora-nvidia-open-stable-webui-x86_64.iso")
        == []
    )


def test_diff_ignores_a_one_character_change():
    assert diff_tokens("a-x.iso", "a-y.iso") == []


# ------------------------------------------------------------------------- substitute


def test_substitute_rewrites_every_occurrence_and_nests():
    """Garuda names its edition twice: once in a path, once in a filename."""
    node = {"label": "Garuda Xfce", "params": {"match": r"/xfce/\d+/garuda-xfce-\d+\.iso$"}}
    out = substitute(node, [("xfce", "mokka")])
    assert out["params"]["match"] == r"/mokka/\d+/garuda-mokka-\d+\.iso$"
    assert node["params"]["match"] == r"/xfce/\d+/garuda-xfce-\d+\.iso$"  # not mutated


# ---------------------------------------------------------------------------- _nodes_for


def test_nodes_for_offers_the_observed_url_when_substitution_declines():
    node = {"params": {"url": "https://dl.example/aurora-stable-webui-x86_64.iso"}}
    cand = Candidate(
        name="aurora-nvidia-open-stable-webui-x86_64.iso",
        url="https://dl.example/aurora-nvidia-open-stable-webui-x86_64.iso",
    )
    nodes = _nodes_for(node, "aurora-stable-webui-x86_64.iso", cand)
    assert [n["params"]["url"] for n in nodes] == [cand.url]


def test_nodes_for_never_copies_a_directory_url_into_an_artifact_url():
    """neon's rows are directories; its ISO is two segments below one. Copying the
    row's URL verbatim would point the variant at a listing. Substitution still
    applies -- that is how a real new neon edition gets proposed."""
    node = {"params": {"url": "https://files.example/images/desktop/current/neon-desktop.iso"}}
    cand = Candidate(name="bigscreen", url="https://files.example/images/bigscreen/")

    urls = [n["params"]["url"] for n in _nodes_for(node, "desktop", cand)]
    assert cand.url not in urls
    assert urls == ["https://files.example/images/bigscreen/current/neon-bigscreen.iso"]


def test_nodes_for_derives_a_match_when_the_edition_was_inserted():
    """Q4OS inserts `-tde`, and has no URL to copy. Substitution declines, so the last
    resort is a `match` generalized from the artifact's own name."""
    node = {"params": {"match": r"/q4os-[0-9.]+-x64\.r\d+\.iso$"}}
    cand = Candidate(name="/stable/q4os-6.7-x64-tde.r1.iso")

    matches = [n["params"]["match"] for n in _nodes_for(node, "/stable/q4os-6.7-x64.r1.iso", cand)]
    assert matches == [generalize(cand.name)]
    assert re.search(matches[0], cand.name)
    assert not re.search(matches[0], "/stable/q4os-6.7-x64.r1.iso")  # not the sibling


def test_nodes_for_marks_a_torrent_candidate_torrent_only():
    """Kali's siblings all `match` an `\\.iso$`. Appending `.torrent` is an insertion,
    so substitution declines -- and without this branch a new torrent-only edition is
    reported "could not synthesize" every week until a human notices."""
    node = {"params": {"match": r"^kali-linux-[0-9.]+-installer-amd64\.iso$"}}
    cand = Candidate(name="kali-linux-2026.2-live-amd64.iso.torrent", url="https://x/t")

    nodes = _nodes_for(node, "kali-linux-2026.2-installer-amd64.iso", cand)
    assert len(nodes) == 1
    params = nodes[0]["params"]
    # Beside `match`, not at the top level: a torrent-only sibling already carries it
    # in `params`, and writing both would commit a duplicated key.
    assert params["torrent_only"] is True
    assert "torrent_only" not in nodes[0]
    assert re.search(params["match"], cand.name)
    assert params["match"].endswith(r"\.torrent$")  # so config.py accepts it
    assert not re.search(params["match"], "kali-linux-2026.2-installer-amd64.iso")


def test_confirms_a_torrent_candidate_against_the_torrent_url():
    """`release.filename` is the ISO and `candidate.name` is the `.torrent`. Compared
    to each other they never match, and no torrent-only variant is ever proposed."""
    cand = Candidate(name="x.iso.torrent", url="https://x/x.iso.torrent")
    good = _release(filename="x.iso", download_url=None, torrent_url=cand.url, info_hash="a" * 40)
    bad = _release(filename="x.iso", download_url=None, torrent_url="https://x/other.torrent")
    assert _confirms(good, cand) is None
    assert "not the one behind this key" in _confirms(bad, cand)


# ------------------------------------------------------------------------- generalize


def test_generalize_loosens_versions_but_not_names():
    """`q4os` and `i3` are names; `6.7` and the `1` of `r1` are values. A regex reading
    `q[0-9.]+os` works and reads like a mistake -- and this one gets committed."""
    out = generalize("/stable/q4os-6.7-x64-tde.r1.iso")
    assert out == r"/stable/q4os\-[0-9.]+\-x[0-9.]+\-tde\.r[0-9.]+\.iso$"


def test_generalize_escapes_every_literal_dot():
    """An unescaped `.` would make `MX-25.2_Xfce_x64.iso` a wildcard for its siblings."""
    out = generalize("a.b-1.iso")
    assert r"\." in out
    assert re.search(out, "a.b-1.iso")
    assert not re.search(out, "axb-1.iso")


# --------------------------------------------------------------------------- _confirms

ISO = "Fedora-KDE-Live-44.iso"


def _release(**kw) -> Release:
    base = dict(
        distro="d",
        variant="v",
        version="1",
        title="t",
        download_url="https://x/" + ISO,
        filename=ISO,
        checksum="a" * 64,
    )
    return Release(**{**base, **kw})


def test_confirms_rejects_the_siblings_artifact():
    """The teeth: a node that resolves to the sibling's ISO is a duplicate variant."""
    cand = Candidate(name=ISO, url="https://x/" + ISO)
    problem = _confirms(_release(filename="Fedora-Workstation-Live-44.iso"), cand)
    assert problem and "not the artifact behind this key" in problem


def test_confirms_accepts_the_exact_artifact():
    assert _confirms(_release(), Candidate(name=ISO, url="https://x/" + ISO)) is None


def test_confirms_requires_integrity():
    cand = Candidate(name=ISO, url="https://x/" + ISO)
    problem = _confirms(_release(checksum=None), cand)
    assert problem and "no checksum, signature or infohash" in problem


def test_confirms_compares_the_basename_of_a_sourceforge_path():
    """SourceForge names a candidate by its full path; every other lister by filename.
    Compared whole, no SourceForge variant could ever be proposed."""
    cand = Candidate(name="/stable/q4os-6.7-x64-tde.r1.iso")
    good = _release(filename="q4os-6.7-x64-tde.r1.iso")
    bad = _release(filename="q4os-6.7-x64.r1.iso")  # the sibling
    assert _confirms(good, cand) is None
    assert "not the artifact behind this key" in _confirms(bad, cand)


def test_confirms_refuses_a_key_it_cannot_tie_to_anything():
    problem = _confirms(_release(), Candidate(name="desk"))  # no extension, no url
    assert problem and "no artifact or URL" in problem


def test_confirms_uses_containment_for_a_directory_row():
    """neon: the key came from a directory, so the test is that the resolved download
    lives under it. Comparing a filename to a directory name would reject every neon
    edition forever, on a technicality, in a message no reader could act on."""
    cand = Candidate(name="desk", url="https://files.example/images/desk/")
    inside = _release(download_url="https://files.example/images/desk/current/neon-desk.iso")
    outside = _release(download_url="https://files.example/images/desktop/current/neon.iso")
    assert _confirms(inside, cand) is None
    assert "outside" in _confirms(outside, cand)


# ----------------------------------------------------------------------- propose_for


class FakeStrategy:
    """Resolves whatever `match` names, so a wrong `match` produces a wrong Release."""

    def claims(self, candidate, params):
        return params.get("match") == candidate.name

    def resolve(self, distro, variant, params, client):
        name = params["match"]
        return _release(
            distro=distro, variant=variant, filename=name, download_url="https://x/" + name
        )


def _source(**discover) -> Source:
    return Source(
        name="d",
        variants=(
            Variant(distro="d", name="alpha", strategy="fake", params={"match": "pkg-alpha.iso"}),
        ),
        discover=discover or {"group": "(x)"},
    )


DOC = {"distros": {"d": {"variants": {"alpha": {"params": {"match": "pkg-alpha.iso"}}}}}}


def test_propose_writes_a_node_that_resolves_to_the_discovered_artifact(monkeypatch):
    import distro_iso_feed.propose_variants as mod

    monkeypatch.setitem(mod.REGISTRY, "fake", FakeStrategy)
    spec = VariantSpec(distro="d", variant="beta", params={"sample": "pkg-beta.iso", "row": {}})
    cands = [Candidate(name="pkg-alpha.iso"), Candidate(name="pkg-beta.iso")]

    good, bad = propose_for(_source(), [spec], cands, DOC, FakeClient())
    assert not bad
    assert good[0].node["params"]["match"] == "pkg-beta.iso"
    assert good[0].sibling == "alpha"
    assert good[0].release.filename == "pkg-beta.iso"


def test_propose_drops_a_node_that_resolves_to_the_siblings_artifact(monkeypatch):
    """A key whose artifact name cannot be diffed from the sibling's yields no node,
    and a node that would resolve elsewhere is never written."""
    import distro_iso_feed.propose_variants as mod

    class Sticky(FakeStrategy):
        def resolve(self, distro, variant, params, client):  # always the sibling's ISO
            return _release(filename="pkg-alpha.iso", download_url="https://x/pkg-alpha.iso")

    monkeypatch.setitem(mod.REGISTRY, "fake", Sticky)
    spec = VariantSpec(distro="d", variant="beta", params={"sample": "pkg-beta.iso", "row": {}})
    cands = [Candidate(name="pkg-alpha.iso"), Candidate(name="pkg-beta.iso")]

    good, bad = propose_for(_source(), [spec], cands, DOC, FakeClient())
    assert not good
    assert "not the artifact behind this key" in bad[0].reason


def test_propose_reports_when_there_is_no_sibling_to_copy(monkeypatch):
    import distro_iso_feed.propose_variants as mod

    monkeypatch.setitem(mod.REGISTRY, "fake", FakeStrategy)
    spec = VariantSpec(distro="d", variant="beta", params={"sample": "pkg-beta.iso", "row": {}})
    good, bad = propose_for(_source(), [spec], [], DOC, FakeClient())  # sibling claims nothing
    assert not good
    assert bad[0].reason == "no configured variant to copy from"


# --------------------------------------------------------------------------- pr_body


def test_pr_body_lists_rejections_so_they_are_not_silently_dropped():
    from distro_iso_feed.propose_common import Rejected

    text = pr_body([], [], [], [Rejected("kde-neon", "mobile", "mobile", "resolved to nothing")])
    assert "## Could not synthesize" in text
    assert "`kde-neon:mobile`" in text
    assert "resolved to nothing" in text
