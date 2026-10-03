"""The escalation surface: classification, the pure gate, and the report `run_refresh` writes.

The GPG signer lead is in test_signing_key; the diagnose classification is in test_feed_state_config.
Here: `classify_outcomes` + `plan_escalation` (pure, no gpg/network) and one end-to-end that drives
`run_refresh.main --dry-run --report` over a temp config so the report shape, regression flag, and
observed-candidates are exercised together.
"""

from __future__ import annotations

import json
from dataclasses import replace

from conftest import FakeClient, autoindex_html
from distro_iso_feed import run_refresh
from distro_iso_feed.escalate import (
    Failure,
    Pin,
    Report,
    SigningFailure,
    classify_outcomes,
    plan_escalation,
)
from distro_iso_feed.models import Release
from distro_iso_feed.signing import DEFERRED, REJECTED, SigningOutcome
from distro_iso_feed.state import State
from test_torrents import benc

# --------------------------------------------------------------------- classification


def test_classify_outcomes_transient_only_on_a_failed_request():
    assert classify_outcomes([200]) == "structural"  # reachable, wrong/absent content
    assert classify_outcomes([404]) == "structural"  # moved/removed, not a network problem
    assert classify_outcomes([200, 404]) == "structural"  # parent ok, subdir gone
    assert classify_outcomes(["ConnectTimeout"]) == "transient"  # network
    assert classify_outcomes([503]) == "transient"  # server error, exhausted retries
    assert classify_outcomes([200, "ReadTimeout"]) == "transient"  # any failed leg -> transient
    assert classify_outcomes([]) == "structural"  # nothing recorded -> don't swallow a break


# ------------------------------------------------------------------------- the gate


def _report(**kw) -> dict:
    return Report(**kw).to_json()


def test_gate_opens_only_structural_regressions_signing_and_pins():
    report = _report(
        total=5,
        failures=[
            Failure("nobara:kde", "none matched", "structural", "none-matched", regression=True),
            Failure("void:base", "timeout", "transient", "unreachable", regression=True),  # transient
            Failure("new:variant", "none matched", "structural", "none-matched", regression=False),  # never resolved
        ],
        signing_key_failures=[SigningFailure("qubes:iso", "signed by BBB now", "foreign-signer", actual_signer_fpr="BBB")],
        pins=[Pin("popos:intel:url", "literal `24.04` in `...`")],
    )
    plan = plan_escalation(report, open_issues=[])
    titles = {t["title"] for t in plan["to_open"]}
    assert titles == {
        "refresh failure: nobara:kde",   # structural + regression
        "refresh signing-key: qubes:iso",
        "refresh pin: popos:intel:url",
    }
    assert plan["exit_code"] == 1  # structural regression + signing failure are acute
    assert plan["to_close"] == [] and plan["mass_outage"] is False


def test_gate_pins_open_a_ticket_but_do_not_red_the_job():
    plan = plan_escalation(_report(total=1, pins=[Pin("d:v:url", "literal `1.0` in `...`")]), [])
    assert [t["title"] for t in plan["to_open"]] == ["refresh pin: d:v:url"]
    assert plan["exit_code"] == 0  # a standing config smell is a ticket, not a red job


def test_gate_transient_only_run_is_green_and_silent():
    report = _report(
        total=1,
        failures=[Failure("x:y", "timeout", "transient", "unreachable", regression=True)],
    )
    plan = plan_escalation(report, [])
    assert plan == {"exit_code": 0, "to_open": [], "to_close": [], "mass_outage": False}


def test_gate_closes_a_recovered_issue_on_a_clean_run():
    plan = plan_escalation(
        _report(total=5, resolved=5),
        open_issues=[
            {"number": 7, "title": "refresh failure: nobara:kde", "labels": [{"name": "refresh-failure"}]},
            {"number": 9, "title": "some unrelated issue", "labels": [{"name": "bug"}]},  # not ours
        ],
    )
    assert plan["exit_code"] == 0
    assert [c["number"] for c in plan["to_close"]] == [7]  # ours recovered; the unrelated one untouched


def test_gate_does_not_reopen_an_already_open_issue():
    report = _report(
        total=1,
        failures=[Failure("nobara:kde", "none matched", "structural", "none-matched", regression=True)],
    )
    open_issue = [{"number": 7, "title": "refresh failure: nobara:kde", "labels": [{"name": "refresh-failure"}]}]
    plan = plan_escalation(report, open_issue)
    assert plan["to_open"] == [] and plan["to_close"] == [] and plan["exit_code"] == 1  # still broken, no dupe


def test_gate_mass_outage_collapses_to_one_issue():
    fails = [
        Failure(f"d{i}:v", "none matched", "structural", "none-matched", regression=True)
        for i in range(8)
    ]
    plan = plan_escalation(_report(total=8, failures=fails), [])
    assert plan["mass_outage"] is True and plan["exit_code"] == 1
    assert len(plan["to_open"]) == 1  # one infra issue, not eight
    assert "8 sources regressed" in plan["to_open"][0]["title"]


def test_gate_mass_signing_failures_collapse_to_one_rotation_issue():
    """One key backs many variants -- 28 share Ubuntu's, 14 Debian's -- so a single rotation
    trips every one of them in the same run. That is one event, not N breaks."""
    sf = [
        SigningFailure(
            f"ubuntu-flavour-{i}:desktop", "signed by BBB now", "foreign-signer",
            actual_signer_fpr="BBB",
        )
        for i in range(8)
    ]
    plan = plan_escalation(_report(total=8, signing_key_failures=sf), [])
    assert plan["mass_outage"] is True and plan["exit_code"] == 1
    assert len(plan["to_open"]) == 1  # one rotation issue, not eight
    body = plan["to_open"][0]["body"]
    assert "8 pins stopped verifying" in plan["to_open"][0]["title"]
    assert "BBB" in body and "single key rotation" in body  # the shared signer is the lead
    assert "ubuntu-flavour-3:desktop" in body  # every affected key still named


def test_gate_mass_signing_with_different_signers_does_not_read_as_a_rotation():
    """N different new signers is not a simple rotation, and the body must not imply it is."""
    sf = [
        SigningFailure(
            f"d{i}:v", "signed by someone else", "foreign-signer", actual_signer_fpr=f"FPR{i}"
        )
        for i in range(8)
    ]
    plan = plan_escalation(_report(total=8, signing_key_failures=sf), [])
    body = plan["to_open"][0]["body"]
    assert "8 different" in body and "not" in body


def test_gate_signing_and_resolve_mass_outages_stay_separate_buckets():
    """Their bodies say different things; a merged ticket is unreadable. Counts must not sum."""
    fails = [
        Failure(f"d{i}:v", "none matched", "structural", "none-matched", regression=True)
        for i in range(8)
    ]
    sf = [
        SigningFailure(f"s{i}:v", "rotated", "foreign-signer", actual_signer_fpr="BBB")
        for i in range(8)
    ]
    plan = plan_escalation(_report(total=16, failures=fails, signing_key_failures=sf), [])
    titles = sorted(t["title"] for t in plan["to_open"])
    assert titles == [
        "refresh signing-key: 8 pins stopped verifying",
        "refresh: 8 sources regressed",
    ]


def test_gate_signing_below_the_threshold_still_opens_one_issue_each():
    sf = [
        SigningFailure(f"d{i}:v", "rotated", "foreign-signer", actual_signer_fpr="BBB")
        for i in range(3)
    ]
    plan = plan_escalation(_report(total=3, signing_key_failures=sf), [])
    assert sorted(t["title"] for t in plan["to_open"]) == [
        "refresh signing-key: d0:v",
        "refresh signing-key: d1:v",
        "refresh signing-key: d2:v",
    ]
    assert plan["mass_outage"] is False


def _body(*failures: SigningFailure) -> str:
    report = _report(total=len(failures), signing_key_failures=list(failures))
    return plan_escalation(report, [])["to_open"][0]["body"]


def test_gate_unsigned_issue_does_not_send_the_reader_after_a_new_key():
    """Parrot 7.4: nothing signed the file. The rotation copy -- confirm the new signer is the
    project's announced key, then update `signing_key.fingerprint` -- points at a key that does
    not exist."""
    body = _body(SigningFailure("parrot:home", "the file carries no signature", "unsigned"))
    assert "not a key rotation" in body
    assert "rotation is the usual cause" not in body
    assert "update `signing_key.fingerprint`" not in body


def test_gate_bad_signature_issue_is_not_a_rotation():
    """The pin's own signature stopped matching its file: skew or tampering, no new key."""
    body = _body(SigningFailure("debian:netinst", "pin sig mismatch", "bad-signature"))
    assert "not a key rotation" in body
    assert "update `signing_key.fingerprint`" not in body


def test_gate_mass_unsigned_failures_do_not_read_as_a_rotation():
    """Issue #17's body: six unsigned files, headlined "likely a single upstream rotation"."""
    body = _body(*(SigningFailure(f"parrot:e{i}", "no signature", "unsigned") for i in range(6)))
    assert "likely a single upstream rotation" not in body
    assert "not a key rotation" in body
    assert "parrot:e3" in body  # every affected key still named


def test_gate_mass_mixed_causes_judge_the_rotation_on_the_foreign_signers_alone():
    """Four unsigned + three re-signed by one new key: the one-signer verdict is about those three,
    and must not claim that all seven share a signer."""
    sf = [SigningFailure(f"u{i}:v", "no signature", "unsigned") for i in range(4)]
    sf += [
        SigningFailure(f"f{i}:v", "signed by BBB", "foreign-signer", actual_signer_fpr="BBB")
        for i in range(3)
    ]
    body = _body(*sf)
    assert "All 3 are now signed" in body and "All 7" not in body
    assert "u2:v" in body and "f1:v" in body


# --------------------------------------------------------- end-to-end report from a run


def test_report_captures_a_structural_regression_with_the_candidates_a_fix_needs(tmp_path, monkeypatch):
    """A tracked source whose regex stopped matching what upstream lists → the report marks it
    structural + regression and carries the filenames the endpoint serves now."""
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        "distros:\n  nobara:\n    strategy: directory_index\n"
        "    discover: {enumerable: false, reason: fixture}\n"
        "    params:\n"
        "      index: \"https://n/\"\n"
        "      match: '^ubuntu-[0-9.]+\\.iso$'\n"        # will not match what the index lists
        "      version_pattern: 'ubuntu-([0-9.]+)'\n"
        "    variants:\n      kde: {label: Nobara KDE}\n"
    )
    # state: nobara:kde WAS resolving (version 40) -> this is a regression, not a new/never-resolved key.
    state_path = tmp_path / "state.json"
    s = State()
    s.update(Release(distro="nobara", variant="kde", version="40", title="t", filename="x.iso", checksum="a"), "a")
    s.save(state_path)

    client = FakeClient({"https://n/": autoindex_html(["Nobara-41-KDE.iso", "Nobara-41-GNOME.iso"])})
    monkeypatch.setattr(run_refresh, "CONFIG", cfg)
    monkeypatch.setattr(run_refresh, "STATE", state_path)
    monkeypatch.setattr(run_refresh, "Client", lambda *a, **k: client)

    report = tmp_path / "report.json"
    run_refresh.main(["--dry-run", "--report", str(report), "--only", "nobara"])

    data = json.loads(report.read_text())
    assert data["total"] == 1 and data["resolved"] == 0
    f = data["failures"][0]
    assert f["key"] == "nobara:kde"
    assert f["failure_class"] == "structural" and f["cause"] == "none-matched"
    assert f["regression"] is True and f["last_good_version"] == "40"
    assert "Nobara-41-KDE.iso" in f["observed_candidates"]  # what upstream lists now, for the fix
    assert "--only nobara:kde" in f["repro"]

    # And the gate would escalate it: structural + regression -> exit 1, one issue.
    plan = plan_escalation(data, open_issues=[])
    assert plan["exit_code"] == 1
    assert [t["title"] for t in plan["to_open"]] == ["refresh failure: nobara:kde"]


def test_a_timed_out_sums_leaves_the_entry_untouched_and_the_gate_green(tmp_path, monkeypatch):
    """The incident, end to end.

    A mirror read-timed out on SHA512SUMS. The entry resolved anyway with `checksum=None`, the
    signing re-fetch of the same file happened to succeed, and the None was reported as a key
    rotation: bogus issue, valid pin stripped, job failed. A transient mirror blip must instead
    leave the entry exactly as it was and say nothing.
    """
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        "distros:\n  debian:\n    strategy: directory_index\n"
        "    discover: {enumerable: false, reason: fixture}\n"
        "    params:\n"
        '      index: "https://cdimage/"\n'
        "      match: '^debian-[0-9.]+-amd64-netinst\\.iso$'\n"
        "      version_pattern: 'debian-([0-9.]+)-amd64'\n"
        '      sums: "SHA512SUMS"\n'
        "    variants:\n      netinst: {label: Debian netinst}\n"
    )
    # The entry was resolving yesterday, with a real checksum -- so this is a regression candidate.
    state_path = tmp_path / "state.json"
    s = State()
    s.update(
        Release(
            distro="debian", variant="netinst", version="13.6.0", title="t",
            filename="debian-13.6.0-amd64-netinst.iso", checksum="b" * 128,
        ),  # fmt: skip
        "b" * 128,
    )
    s.save(state_path)

    client = FakeClient(
        {"https://cdimage/": autoindex_html(["debian-13.6.0-amd64-netinst.iso"])},
        fail={"https://cdimage/SHA512SUMS": "ReadTimeout"},
    )
    monkeypatch.setattr(run_refresh, "CONFIG", cfg)
    monkeypatch.setattr(run_refresh, "STATE", state_path)
    monkeypatch.setattr(run_refresh, "Client", lambda *a, **k: client)

    report = tmp_path / "report.json"
    run_refresh.main(["--dry-run", "--report", str(report), "--only", "debian"])

    data = json.loads(report.read_text())
    assert len(data["failures"]) == 1
    f = data["failures"][0]
    assert f["key"] == "debian:netinst"
    assert f["failure_class"] == "transient", "a mirror timeout is not a content regression"
    assert data["signing_key_failures"] == [], "and above all, not a key rotation"

    # The gate stays green and silent: nothing to fix, retry tomorrow.
    plan = plan_escalation(data, open_issues=[])
    assert plan == {"exit_code": 0, "to_open": [], "to_close": [], "mass_outage": False}

    # The entry keeps yesterday's good checksum rather than shipping `checksum: null`.
    kept = State.load(state_path).records["debian:netinst"]
    assert kept.release.checksum == "b" * 128


def test_a_listing_blip_that_heals_by_the_re_listing_opens_no_issue(tmp_path, monkeypatch):
    """The 2026-08-28 incident, end to end.

    `mirrors.edge.kernel.org` lost three tries to a handshake timeout and `Network is unreachable`,
    so `autoindex` returned `[]` and the resolver returned None. Three seconds later `diagnose`'s
    own re-listing served all 8 files -- and *that* fetch is what got classified, so a mirror blip
    opened `refresh failure: debian:netinst` and failed the nightly job. The failing fetch is the
    one that decides.
    """
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        "distros:\n  debian:\n    strategy: directory_index\n"
        "    discover: {enumerable: false, reason: fixture}\n"
        "    params:\n"
        '      index: "https://mirror/iso-cd/"\n'
        "      match: '^debian-[0-9.]+-amd64-netinst\\.iso$'\n"
        "      version_pattern: 'debian-([0-9.]+)-amd64'\n"
        "    variants:\n      netinst: {label: Debian netinst}\n"
    )
    iso = "debian-13.6.0-amd64-netinst.iso"
    # It was resolving yesterday, so a structural verdict here WOULD escalate.
    state_path = tmp_path / "state.json"
    s = State()
    s.update(
        Release(distro="debian", variant="netinst", version="13.6.0", title="t", filename=iso, checksum="b"),
        "b",
    )  # fmt: skip
    s.save(state_path)

    class BlipThenFine(FakeClient):
        """Fails the index once, then serves it -- resolve loses the wire, diagnose does not."""

        def get(self, url, headers=None):
            r = super().get(url, headers)
            self.fail.pop(url, None)  # the blip cleared before the next fetch
            return r

    client = BlipThenFine(
        {"https://mirror/iso-cd/": autoindex_html([iso])},
        fail={"https://mirror/iso-cd/": "ConnectTimeout"},
    )
    monkeypatch.setattr(run_refresh, "CONFIG", cfg)
    monkeypatch.setattr(run_refresh, "STATE", state_path)
    monkeypatch.setattr(run_refresh, "Client", lambda *a, **k: client)

    report = tmp_path / "report.json"
    run_refresh.main(["--dry-run", "--report", str(report), "--only", "debian"])

    data = json.loads(report.read_text())
    assert len(data["failures"]) == 1
    f = data["failures"][0]
    assert f["key"] == "debian:netinst"
    assert f["failure_class"] == "transient", "a mirror blip is not a content regression"
    assert f["cause"] == "attempt-transient"
    assert f["regression"] is True  # it WAS resolving -- classification is the only thing gating
    assert iso in f["observed_candidates"], "the re-listing's evidence is still carried"

    # The gate stays green and silent: nothing to fix, retry tomorrow.
    plan = plan_escalation(data, open_issues=[])
    assert plan == {"exit_code": 0, "to_open": [], "to_close": [], "mass_outage": False}


def test_a_transient_torrent_sums_failure_does_not_take_the_whole_run_down(tmp_path, monkeypatch):
    """`attach_torrent` is called outside the resolver try/except, so a `SumsUnavailable` escaping
    it would abort every remaining variant. The ISO resolves; only the torrent is dropped."""
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        "distros:\n  debian:\n    strategy: directory_index\n"
        "    discover: {enumerable: false, reason: fixture}\n"
        "    params:\n"
        '      index: "https://cdimage/iso-cd/"\n'
        "      match: '^debian-[0-9.]+-amd64-netinst\\.iso$'\n"
        "      version_pattern: 'debian-([0-9.]+)-amd64'\n"
        '      sums: "SHA512SUMS"\n'
        '      torrent: "../bt-cd/{filename}.torrent"\n'
        '      torrent_sums: "../bt-cd/SHA512SUMS"\n'
        "    variants:\n      netinst: {label: Debian netinst}\n"
    )
    iso = "debian-13.6.0-amd64-netinst.iso"
    client = FakeClient(
        {
            "https://cdimage/iso-cd/": autoindex_html([iso]),
            "https://cdimage/iso-cd/SHA512SUMS": f"{'b' * 128}  {iso}\n",
            "https://cdimage/bt-cd/" + iso + ".torrent": benc(
                {"info": {"name": iso, "length": 9, "piece length": 1, "pieces": b"\0" * 20}}
            ),
        },
        fail={"https://cdimage/bt-cd/SHA512SUMS": "ReadTimeout"},  # the torrent sidecar blips
    )
    monkeypatch.setattr(run_refresh, "CONFIG", cfg)
    monkeypatch.setattr(run_refresh, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(run_refresh, "Client", lambda *a, **k: client)

    report = tmp_path / "report.json"
    assert run_refresh.main(["--dry-run", "--report", str(report), "--only", "debian"]) == 0

    data = json.loads(report.read_text())
    assert data["resolved"] == 1 and data["failures"] == []  # the run survived; ISO still resolved


# ------------------------------------------- never replace a gpg-verified record with less
#
# The signing gate's verdict is stubbed (gpg is covered in test_signing_key); what is under test is
# the runner's rule. These run WITHOUT --dry-run: a dry run never saves state, so a hold could not
# be observed there.

PIN = "A" * 40
IDX = "https://iso.example/7.4/"
ISO_74 = "Parrot-home-7.4_amd64.iso"


def _parrot_cfg(tmp_path):
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(
        "distros:\n  parrot:\n    strategy: directory_index\n"
        "    discover: {enumerable: false, reason: fixture}\n"
        "    params:\n"
        f'      index: "{IDX}"\n'
        "      match: '^Parrot-home-[0-9.]+_amd64\\.iso$'\n"
        "      version_pattern: '-([0-9.]+)_amd64'\n"
        '      sums: "signed-hashes.txt"\n'
        '      sig: "signed-hashes.txt"\n'
        "      signing_key:\n"
        '        url: "https://keys.example/k"\n'
        f"        fingerprint: {PIN}\n"
        "        covers: clearsigned\n"
        "    variants:\n      home: {label: Parrot Home}\n"
    )
    return cfg


def _verified_73(state_path, *, pin=PIN, url="https://iso.example/7.3/Parrot-home-7.3_amd64.iso"):
    """Yesterday's record: 7.3, sha512, pinned -- what a VERIFIED run left behind."""
    s = State()
    s.update(
        Release(
            distro="parrot", variant="home", version="7.3", title="t",
            filename=url.rsplit("/", 1)[-1], download_url=url,
            checksum="c" * 128, checksum_algo="sha512",
            signature_url=url.rsplit("/", 1)[0] + "/signed-hashes.txt",
            signing_key_url="https://keys.example/k", signing_key_fingerprint=pin,
            signature_target="checksums",
        ),  # fmt: skip
        "c" * 128,
    )
    s.save(state_path)


def _run(tmp_path, monkeypatch, client, verdict, *, argv=(), cause="unsigned"):
    """Drive `main` over the parrot fixture with the signing verdict forced to `verdict`."""

    def gate(_client, release, _params):
        if verdict == REJECTED:
            dropped = replace(
                release, signature_url=None, signing_key_url=None,
                signing_key_fingerprint=None, signature_target=None,
            )  # fmt: skip
            return SigningOutcome(dropped, REJECTED, "no OpenPGP signature", cause=cause)
        return SigningOutcome(replace(release, signature_target="checksums"), DEFERRED, "blip")

    monkeypatch.setattr(run_refresh, "CONFIG", _parrot_cfg(tmp_path))
    monkeypatch.setattr(run_refresh, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(run_refresh, "FEED_DIR", tmp_path / "feed")
    monkeypatch.setattr(run_refresh, "CATALOG", tmp_path / "catalog.md")
    monkeypatch.setattr(run_refresh, "Client", lambda *a, **k: client)
    monkeypatch.setattr(run_refresh, "verify_signing_key", gate)
    report = tmp_path / "report.json"
    run_refresh.main(["--report", str(report), "--only", "parrot", *argv])
    return json.loads(report.read_text()), State.load(tmp_path / "state.json")


def _staged_74():
    """Parrot's staging dir: a 7.4 ISO and an md5-only hashes file."""
    return FakeClient(
        {
            IDX: autoindex_html([ISO_74, "signed-hashes.txt"]),
            IDX + "signed-hashes.txt": f"Parrot OS 7.4\n\nmd5\n{'6' * 32}  {ISO_74}\n",
        }
    )


def test_a_rejected_new_release_is_held_at_the_verified_one(tmp_path, monkeypatch):
    """Parrot 7.4: unsigned, md5-only. The feed must keep 7.3 (sha512 + pin) and say so in the
    issue, rather than publish 7.4 as md5 with the claim dropped."""
    _verified_73(tmp_path / "state.json")
    data, state = _run(tmp_path, monkeypatch, _staged_74(), REJECTED)
    kept = state.records["parrot:home"]
    assert (kept.version, kept.release.checksum_algo) == ("7.3", "sha512")
    assert kept.release.signing_key_fingerprint == PIN
    [sf] = data["signing_key_failures"]
    assert sf["cause"] == "unsigned" and sf["held_version"] == "7.3"


def test_a_rejected_same_release_keeps_its_pin(tmp_path, monkeypatch):
    """Same artifact, but its signature now fails: the issue opens, and the record keeps the pin
    it earned -- `enrich` must not rewrite it with the claim stripped."""
    _verified_73(tmp_path / "state.json", url=IDX + "Parrot-home-7.3_amd64.iso")
    iso = "Parrot-home-7.3_amd64.iso"
    client = FakeClient(
        {IDX: autoindex_html([iso]), IDX + "signed-hashes.txt": f"{'c' * 128}  {iso}\n"}
    )
    data, state = _run(tmp_path, monkeypatch, client, REJECTED)
    assert state.records["parrot:home"].release.signing_key_fingerprint == PIN
    assert data["signing_key_failures"][0]["held_version"] == "7.3"


def test_a_deferred_check_of_the_same_release_keeps_its_pin(tmp_path, monkeypatch):
    """2026-09-21: a keyserver blip made 118 variants DEFERRED, and `enrich` rewrote each record
    without its pin (142 pinned -> 24; back to 142 the next day). A hiccup must never strip a pin."""
    _verified_73(tmp_path / "state.json", url=IDX + "Parrot-home-7.3_amd64.iso")
    iso = "Parrot-home-7.3_amd64.iso"
    client = FakeClient(
        {IDX: autoindex_html([iso]), IDX + "signed-hashes.txt": f"{'c' * 128}  {iso}\n"}
    )
    data, state = _run(tmp_path, monkeypatch, client, DEFERRED)
    assert state.records["parrot:home"].release.signing_key_fingerprint == PIN
    assert data["signing_key_failures"] == []  # couldn't-check stays silent


def test_a_deferred_new_release_waits_silently(tmp_path, monkeypatch):
    """Couldn't check the new release (a blip): keep the verified one and retry next run -- no
    issue, and nothing unverified published in the meantime."""
    _verified_73(tmp_path / "state.json")
    data, state = _run(tmp_path, monkeypatch, _staged_74(), DEFERRED)
    assert state.records["parrot:home"].version == "7.3"
    assert data["signing_key_failures"] == []


def test_a_deferred_new_release_at_the_same_url_is_published(tmp_path, monkeypatch):
    """A fixed URL whose bytes moved (a stable symlink, a respin): holding would pair the old
    checksum with the new bytes and break every download, so a blip publishes as before."""
    iso = "Parrot-home-7.3_amd64.iso"
    _verified_73(tmp_path / "state.json", url=IDX + iso)
    client = FakeClient(
        {IDX: autoindex_html([iso]), IDX + "signed-hashes.txt": f"{'d' * 128}  {iso}\n"}
    )
    _, state = _run(tmp_path, monkeypatch, client, DEFERRED)
    assert state.records["parrot:home"].release.checksum == "d" * 128


def test_a_bumped_pin_does_not_hold_the_old_record(tmp_path, monkeypatch):
    """The config pin moved (a verified rotation): the record was vouched for by the OLD key, so
    there is nothing verified to protect and the new release flows as before."""
    _verified_73(tmp_path / "state.json", pin="B" * 40)
    data, state = _run(tmp_path, monkeypatch, _staged_74(), REJECTED)
    assert state.records["parrot:home"].version == "7.4"
    assert data["signing_key_failures"][0]["held_version"] is None


def test_with_no_verified_record_a_rejected_release_degrades(tmp_path, monkeypatch):
    data, state = _run(tmp_path, monkeypatch, _staged_74(), REJECTED)
    rec = state.records["parrot:home"]
    assert rec.version == "7.4" and rec.release.signature_url is None
    assert data["signing_key_failures"][0]["held_version"] is None


def test_a_hold_is_listed_in_the_run_summary(tmp_path, monkeypatch):
    """A hold keeps the feed stale on purpose; the run's receipt must say so, not "nothing moved"."""
    _verified_73(tmp_path / "state.json")
    summary = tmp_path / "summary.md"
    _run(tmp_path, monkeypatch, _staged_74(), DEFERRED, argv=("--summary", str(summary)))
    text = summary.read_text()
    assert "Held" in text and "`parrot:home`" in text and "7.4" in text
    assert "Nothing moved upstream" not in text


def test_a_dry_run_prints_the_held_row(tmp_path, monkeypatch, capsys):
    _verified_73(tmp_path / "state.json")
    _run(tmp_path, monkeypatch, _staged_74(), REJECTED, argv=("--dry-run",))
    row = next(ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("parrot:home"))
    assert "7.3" in row and "held" in row


def test_gate_names_the_release_the_feed_kept():
    body = _body(
        SigningFailure("parrot:home", "no signature", "unsigned", held_version="7.3")
    )
    assert "keeps `7.3`" in body


def test_a_rejected_respin_at_the_same_url_is_held(tmp_path, monkeypatch):
    """Same URL, new bytes, and the gate has evidence against them: fail closed. (Only a release
    the gate could not check is published at an unchanged URL.)"""
    iso = "Parrot-home-7.3_amd64.iso"
    _verified_73(tmp_path / "state.json", url=IDX + iso)
    client = FakeClient(
        {IDX: autoindex_html([iso]), IDX + "signed-hashes.txt": f"{'d' * 128}  {iso}\n"}
    )
    data, state = _run(tmp_path, monkeypatch, client, REJECTED)
    assert state.records["parrot:home"].release.checksum == "c" * 128
    assert data["signing_key_failures"][0]["held_version"] == "7.3"


def test_gate_a_refused_signature_url_is_not_read_as_an_unsigned_release():
    """clonezilla.org's CDN answers 403 to the feed's client (and 200 to curl, same UA): the
    signature exists, the host refuses us. The copy must not tell the reader nothing signed it."""
    body = _body(
        SigningFailure(
            "clonezilla:default",
            "no signature at https://clonezilla.org/downloads/stable/data/CHECKSUMS.TXT.gpg"
            " (it answered 403)",
            "unsigned",
        )
    )
    assert "refuses this client" in body


def test_a_held_respin_row_tells_the_two_releases_apart(tmp_path, monkeypatch):
    """A same-version respin that fails verification is held -- and its Held row read
    `| 7.3 | 7.3 |`, two identical cells. The unpublished release must be distinguishable."""
    iso = "Parrot-home-7.3_amd64.iso"
    _verified_73(tmp_path / "state.json", url=IDX + iso)
    client = FakeClient(
        {IDX: autoindex_html([iso]), IDX + "signed-hashes.txt": f"{'d' * 128}  {iso}\n"}
    )
    summary = tmp_path / "summary.md"
    _run(tmp_path, monkeypatch, client, REJECTED, argv=("--summary", str(summary)))
    row = next(ln for ln in summary.read_text().splitlines() if ln.startswith("| `parrot:home`"))
    kept, not_published = (cell.strip() for cell in row.split("|")[2:4])
    assert kept == "7.3" and not_published != kept and "7.3" in not_published
