"""
Tests for the Cisco config auditor.

Run them from the project folder with:

    .venv\\Scripts\\python.exe -m pytest -q      (Windows)
    .venv/bin/python -m pytest -q                (Linux / macOS)
"""

import sys
from pathlib import Path

import pytest

# Make sure "import auditor" works no matter where pytest is started from.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import auditor  # noqa: E402  (import after the sys.path change)


SAMPLES = PROJECT_ROOT / "sample_configs"


def audit_text(text: str) -> auditor.DeviceResult:
    """Small helper: audit a config string that lives inside the test."""
    return auditor.audit_config(text, name="test.cfg", path="test.cfg")


def status_of(device: auditor.DeviceResult, check_id: str) -> str:
    """Return 'pass', 'fail' or 'skip' for one check ID."""
    for result in device.results:
        if result.check.id == check_id:
            return result.status
    raise AssertionError(f"Unknown check ID: {check_id}")


# ---------------------------------------------------------------------------
# The catalogue itself
# ---------------------------------------------------------------------------

def test_check_catalogue_is_complete():
    assert len(auditor.CHECKS) >= 20, "We promised at least 20 checks"

    ids = [check.id for check in auditor.CHECKS]
    assert len(ids) == len(set(ids)), "Check IDs must be unique"

    for check in auditor.CHECKS:
        assert check.severity in auditor.SEVERITY_WEIGHTS
        assert check.category in auditor.CATEGORY_ORDER
        assert check.title.strip()
        assert check.explanation.strip()
        assert check.fix.strip()


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def test_enable_secret_check():
    good = audit_text("enable secret 9 $9$fake$hash\n")
    assert status_of(good, "MGMT-01") == "pass"

    weak = audit_text("enable password cisco\n")
    assert status_of(weak, "MGMT-01") == "fail"

    missing = audit_text("hostname Router\n")
    assert status_of(missing, "MGMT-01") == "fail"


def test_telnet_is_rejected_but_ssh_passes():
    telnet = audit_text(
        "hostname R1\n"
        "line vty 0 4\n"
        " transport input telnet\n"
    )
    assert status_of(telnet, "MGMT-02") == "fail"

    ssh = audit_text(
        "hostname R1\n"
        "ip ssh version 2\n"
        "line vty 0 4\n"
        " transport input ssh\n"
    )
    assert status_of(ssh, "MGMT-02") == "pass"


def test_snmp_public_rw_community_fails():
    device = audit_text("snmp-server community public RW\n")
    assert status_of(device, "SNMP-01") == "fail"   # default community name
    assert status_of(device, "SNMP-03") == "fail"   # read-write access

    safe = audit_text("snmp-server community MyLongString RO\n")
    assert status_of(safe, "SNMP-01") == "pass"
    assert status_of(safe, "SNMP-03") == "pass"


def test_http_server_check():
    assert status_of(audit_text("ip http server\n"), "SVC-01") == "fail"
    assert status_of(audit_text("no ip http server\n"), "SVC-01") == "pass"


def test_port_security_check_on_switch():
    unsafe = audit_text(
        "hostname SW1\n"
        "interface FastEthernet0/1\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        " no shutdown\n"
    )
    assert status_of(unsafe, "L2-01") == "fail"

    safe = unsafe.config_text + " switchport port-security\n"
    assert status_of(audit_text(safe), "L2-01") == "pass"


def test_layer2_checks_are_skipped_on_router():
    device = audit_text(
        "hostname R1\n"
        "interface GigabitEthernet0/0\n"
        " ip address 192.0.2.1 255.255.255.0\n"
    )
    for result in device.results:
        if result.check.layer2_only:
            assert result.status == "skip"
    # Skipped checks must not count towards the score.
    assert device.possible == sum(
        auditor.SEVERITY_WEIGHTS[r.check.severity]
        for r in device.results
        if r.status != "skip"
    )


def test_native_vlan_and_dhcp_snooping_checks():
    switch = audit_text(
        "hostname SW1\n"
        "interface GigabitEthernet0/1\n"
        " switchport mode trunk\n"
        " no shutdown\n"
    )
    assert status_of(switch, "L2-03") == "fail"   # native VLAN defaults to 1
    assert status_of(switch, "L2-05") == "fail"   # no DHCP snooping

    hardened = audit_text(
        "hostname SW1\n"
        "ip dhcp snooping\n"
        "ip dhcp snooping vlan 10\n"
        "interface GigabitEthernet0/1\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 99\n"
        " no shutdown\n"
    )
    assert status_of(hardened, "L2-03") == "pass"
    assert status_of(hardened, "L2-05") == "pass"


# ---------------------------------------------------------------------------
# Score targets from the project requirements
# ---------------------------------------------------------------------------

def test_good_router_scores_at_least_90_percent():
    device = auditor.audit_file(SAMPLES / "router_good.cfg")
    assert device.score >= 90.0, f"router_good.cfg only scored {device.score}%"


def test_bad_configs_score_below_50_percent():
    router_bad = auditor.audit_file(SAMPLES / "router_bad.cfg")
    switch_bad = auditor.audit_file(SAMPLES / "switch_bad.cfg")

    assert router_bad.score < 50.0, f"router_bad.cfg scored {router_bad.score}%"
    assert switch_bad.score < 50.0, f"switch_bad.cfg scored {switch_bad.score}%"


def test_bonus_good_switch_scores_at_least_90_percent():
    device = auditor.audit_file(SAMPLES / "switch_good.cfg")
    assert device.score >= 90.0, f"switch_good.cfg only scored {device.score}%"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def test_report_is_offline_and_escapes_config():
    tricky = (
        "hostname R1\n"
        "banner motd ^C\n"
        "<script>alert('xss')</script>\n"
        "^C\n"
    )
    device = audit_text(tricky)
    page = auditor.build_html([device], source="<test & demo>")

    # Config text must be escaped, never inserted as live HTML.
    assert "&lt;script&gt;" in page
    assert "<script>alert" not in page
    assert "&lt;test &amp; demo&gt;" in page

    # The report must not depend on anything from the internet.
    assert "http://" not in page
    assert "https://" not in page
    assert "<link" not in page.lower()
    assert "src=" not in page.lower()


def test_write_report_creates_a_file(tmp_path):
    device = auditor.audit_file(SAMPLES / "router_good.cfg")
    output = auditor.write_report([device], tmp_path / "report.html", "samples")
    assert output.exists()
    assert output.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
