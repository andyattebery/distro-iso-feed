"""The escalation surface: classification, the pure gate, and the report `run_refresh` writes.

The GPG signer lead is in test_signing_key; the diagnose classification is in test_feed_state_config.
Here: `classify_outcomes` + `plan_escalation` (pure, no gpg/network) and one end-to-end that drives
`run_refresh.main --dry-run --report` over a temp config so the report shape, regression flag, and
observed-candidates are exercised together.
"""

from __future__ import annotations

import json

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
from distro_iso_feed.state import State

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
        signing_key_failures=[SigningFailure("qubes:iso", "signed by BBB now", actual_signer_fpr="BBB")],
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
