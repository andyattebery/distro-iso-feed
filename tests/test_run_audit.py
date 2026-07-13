"""`run_audit.main` orchestration — the per-distro signing-key loop and the `--strict` exit.

The GPG policy itself is tested in test_signing_key.py; here `verify_signing_key` is monkeypatched
to a controlled outcome so the test pins the loop shape: only distros that pin a key are checked,
one representative variant per distro (the `break`), a BAD outcome lands in the failure list, and
`--strict` turns a failure into exit 1. It also guards the `verify_signing_key` import — when that
symbol moves to `signing.py`, a mis-updated import breaks `run_audit.verify_signing_key` and this
test goes red.
"""

from __future__ import annotations

import pytest

from conftest import FakeClient, autoindex_html
from distro_iso_feed import run_audit
from distro_iso_feed.signing import BAD, VERIFIED

FPR = "A" * 40
CKSUM = "d" * 64


def _signed_block(name: str, host: str) -> str:
    return (
        f"  {name}:\n"
        f"    strategy: directory_index\n"
        f"    params:\n"
        f"      index: \"{host}\"\n"
        f"      match: 'thing-[0-9.]+\\.iso$'\n"
        f"      version_pattern: 'thing-([0-9.]+)'\n"
        f"      sums: \"SHA256SUMS\"\n"
        f"      sig: \"SHA256SUMS.gpg\"\n"
        f"      signing_key: {{url: \"https://k/key\", fingerprint: {FPR}, covers: checksums}}\n"
        f"    variants:\n"
        f"      a: {{label: \"{name} A\"}}\n"
        f"      b: {{label: \"{name} B\"}}\n"
        f"    discover: {{enumerable: false, reason: fixture}}\n"
    )


CONFIG = (
    "distros:\n"
    + _signed_block("signed", "https://s/")
    + _signed_block("bad", "https://b/")
    + (
        "  unsigned:\n"
        "    strategy: directory_index\n"
        "    params: {index: \"https://u/\", match: 'thing-[0-9.]+\\.iso$', "
        "version_pattern: 'thing-([0-9.]+)', sums: \"SHA256SUMS\"}\n"
        "    variants:\n      a: {label: \"Unsigned A\"}\n"
        "    discover: {enumerable: false, reason: fixture}\n"
    )
)


def _pages() -> dict:
    pages = {}
    for host in ("https://s/", "https://b/", "https://u/"):
        pages[host] = autoindex_html(["thing-1.0.iso", "SHA256SUMS"])
        pages[host + "SHA256SUMS"] = f"{CKSUM}  thing-1.0.iso\n"
    return pages


@pytest.fixture
def audit_env(tmp_path, monkeypatch):
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(CONFIG)
    client = FakeClient(_pages())

    class OneShot(FakeClient):
        def __init__(self):
            super().__init__(client.pages)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_audit, "Client", lambda *a, **k: OneShot())

    # BAD only for the `bad` distro; the gate itself is exercised in test_signing_key.
    def fake_verify(_client, release, _params):
        return release, (BAD if release.distro == "bad" else VERIFIED)

    monkeypatch.setattr(run_audit, "verify_signing_key", fake_verify)
    return cfg


def test_audit_reports_the_bad_distro_and_strict_exits_one(audit_env, capsys):
    rc = run_audit.main(["--config", str(audit_env), "--strict"])
    assert rc == 1  # a signing-key failure under --strict
    out = capsys.readouterr().out
    assert "SIGNING-KEY FAIL: bad:a" in out  # the BAD distro, first (representative) variant
    assert "SIGNING-KEY FAIL: signed" not in out  # the signed distro verified, did not fail


def test_audit_non_strict_exits_zero_despite_failure(audit_env):
    assert run_audit.main(["--config", str(audit_env)]) == 0  # non-strict never exits 1


def test_audit_checks_one_representative_variant_per_distro(audit_env, monkeypatch):
    """The `break` after the first signed variant: `bad:a` fails, `bad:b` is never reached."""
    seen: list[str] = []

    def recording_verify(_client, release, _params):
        seen.append(f"{release.distro}:{release.variant}")
        return release, (BAD if release.distro == "bad" else VERIFIED)

    monkeypatch.setattr(run_audit, "verify_signing_key", recording_verify)
    run_audit.main(["--config", str(audit_env)])
    # signed + bad are checked once each (variant `a`); unsigned is skipped entirely.
    assert seen == ["signed:a", "bad:a"]
