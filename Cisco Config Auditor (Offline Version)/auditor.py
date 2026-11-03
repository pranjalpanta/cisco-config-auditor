#!/usr/bin/env python3
"""
cisco-config-auditor
====================
A small, completely offline auditor for Cisco IOS configuration files.

What it does
------------
1. Reads one .cfg file, or every .cfg file in a folder.
2. Runs 34 security checks on the text (plain regular expressions only).
3. Gives each device a weighted score between 0 % and 100 %.
4. Prints a short summary in the terminal.
5. Writes one self-contained report.html file (inline CSS, no internet).

Usage
-----
    python auditor.py sample_configs/
    python auditor.py sample_configs/router_bad.cfg
    python auditor.py sample_configs/ --output my_report.html

This file only uses the Python standard library. pytest is needed only to
run the tests in tests/test_auditor.py.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# 1. Settings / constants
# ---------------------------------------------------------------------------

# Points that a check is worth. A "high" problem costs 10 points, etc.
SEVERITY_WEIGHTS = {"high": 10, "medium": 5, "low": 2}

# The order in which categories appear in the report.
CATEGORY_ORDER = [
    "Management plane",
    "SNMP",
    "Services",
    "Logging & NTP",
    "Layer 2 security",
]

# File types we pick up when the user passes a folder.
CONFIG_SUFFIXES = {".cfg", ".conf", ".txt"}

# A check function receives the raw config text and returns:
#   (True,  "why it passed")   -> check passed
#   (False, "why it failed")   -> check failed
#   (None,  "why it is n/a")   -> check does not apply, not scored
CheckOutcome = Tuple[Optional[bool], str]


# ---------------------------------------------------------------------------
# 2. Small helpers used by the checks
# ---------------------------------------------------------------------------

def _re(pattern: str, text: str):
    """Run a case-insensitive, multi-line regular expression search."""
    return re.search(pattern, text, re.IGNORECASE | re.MULTILINE)


def _ok(detail: str) -> CheckOutcome:
    return (True, detail)


def _fail(detail: str) -> CheckOutcome:
    return (False, detail)


def _skip(detail: str) -> CheckOutcome:
    return (None, detail)


def get_blocks(config: str, prefix: str) -> List[Tuple[str, List[str]]]:
    """
    Split a Cisco config into blocks such as interface or line blocks.

    Returns a list of (header, body) pairs. For example:

        [("interface GigabitEthernet0/0",
          ["description WAN-LINK", "ip address 10.0.0.1 255.255.255.0"])]

    Cisco configs indent the child commands, and a "!" line ends a block.
    """
    prefix = prefix.lower()
    blocks: List[Tuple[str, List[str]]] = []
    header: Optional[str] = None
    body: List[str] = []

    for raw_line in config.splitlines():
        if not raw_line.strip():
            continue

        stripped = raw_line.strip()

        # A "!" line closes the current block.
        if stripped.startswith("!"):
            if header is not None:
                blocks.append((header, body))
                header, body = None, []
            continue

        indented = raw_line[0] in " \t"

        if not indented:
            # A new top-level command closes the previous block.
            if header is not None:
                blocks.append((header, body))
                header, body = None, []
            if stripped.lower().startswith(prefix):
                header, body = stripped, []
        elif header is not None:
            body.append(stripped)

    if header is not None:
        blocks.append((header, body))

    return blocks


def get_interfaces(config: str) -> List[Tuple[str, List[str]]]:
    """Every 'interface ...' block in the config."""
    return get_blocks(config, "interface")


def block_text(body: Sequence[str]) -> str:
    """Join a block body into one lower-case string for easy searching."""
    return "\n".join(body).lower()


def is_shutdown(body: Sequence[str]) -> bool:
    return any(line.lower() == "shutdown" for line in body)


def is_access_port(body: Sequence[str]) -> bool:
    """True if the interface looks like a Layer 2 access port."""
    text = block_text(body)
    return "switchport mode access" in text or "switchport access vlan" in text


def is_trunk_port(body: Sequence[str]) -> bool:
    """True if the interface looks like a Layer 2 trunk port."""
    text = block_text(body)
    return any(
        marker in text
        for marker in (
            "switchport mode trunk",
            "switchport trunk encapsulation",
            "switchport trunk allowed",
            "switchport trunk native",
        )
    )


def active_access_ports(config: str) -> List[Tuple[str, List[str]]]:
    """Access ports that are not shut down (shut ports need no protection)."""
    return [
        (header, body)
        for header, body in get_interfaces(config)
        if is_access_port(body) and not is_shutdown(body)
    ]


def exec_timeout_seconds(body: Sequence[str]) -> Optional[int]:
    """
    Return the 'exec-timeout' value of a block in seconds.
    None means the command is missing. 0 means "never time out".
    """
    for line in body:
        match = re.match(r"exec-timeout\s+(\d+)(?:\s+(\d+))?", line, re.IGNORECASE)
        if match:
            minutes = int(match.group(1))
            seconds = int(match.group(2) or 0)
            return minutes * 60 + seconds
    return None


# ---------------------------------------------------------------------------
# 3. Check definitions
#
# Each check has an ID, a title, a category, a severity, an explanation,
# a recommended Cisco CLI fix, and a function that tests the config.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Check:
    id: str
    title: str
    category: str
    severity: str
    explanation: str
    fix: str
    func: Callable[[str], CheckOutcome]
    layer2_only: bool = False


# --- Management plane checks ------------------------------------------------

def check_enable_secret(config: str) -> CheckOutcome:
    if _re(r"^enable secret\s+\S+", config):
        return _ok("A hashed enable secret is configured.")
    if _re(r"^enable password\s+\S+", config):
        return _fail("Only 'enable password' is set. It is weak and easy to reverse.")
    return _fail("No enable secret. Anyone who reaches privileged mode is unprotected.")


def check_ssh_only(config: str) -> CheckOutcome:
    blocks = get_blocks(config, "line vty")
    if not blocks:
        return _fail("No 'line vty' section found.")

    problems: List[str] = []
    for header, body in blocks:
        transport_lines = [
            line for line in body if line.lower().startswith("transport input")
        ]
        if not transport_lines:
            problems.append(header + " (no 'transport input', so all protocols are allowed)")
            continue
        for line in transport_lines:
            low = line.lower()
            if "telnet" in low or low.endswith(" all"):
                problems.append(header + " allows telnet or all protocols")
                break

    if not _re(r"^ip ssh version 2", config):
        problems.append("'ip ssh version 2' is missing")

    if problems:
        return _fail("; ".join(problems))
    return _ok("VTY lines accept SSH only, and SSH version 2 is forced.")


def check_vty_timeout(config: str) -> CheckOutcome:
    blocks = get_blocks(config, "line vty")
    if not blocks:
        return _fail("No 'line vty' section found.")

    bad: List[str] = []
    for header, body in blocks:
        seconds = exec_timeout_seconds(body)
        if seconds is None:
            bad.append(header + " (no exec-timeout)")
        elif seconds == 0:
            bad.append(header + " (exec-timeout 0 0 never logs out)")
    if bad:
        return _fail("Idle sessions are not timed out: " + ", ".join(bad))
    return _ok("Every VTY line logs out idle sessions.")


def check_console_timeout(config: str) -> CheckOutcome:
    blocks = get_blocks(config, "line con")
    if not blocks:
        return _fail("No 'line con 0' section found.")

    for header, body in blocks:
        seconds = exec_timeout_seconds(body)
        if seconds is None or seconds == 0:
            return _fail("The console line has no idle timeout.")
    return _ok("The console line logs out idle sessions.")


def check_banner(config: str) -> CheckOutcome:
    if _re(r"^banner\s+(motd|login|exec)\s+\S", config):
        return _ok("A login banner is configured.")
    return _fail("No login banner. Users are not warned that access is monitored.")


def check_aaa(config: str) -> CheckOutcome:
    has_new_model = _re(r"^aaa new-model", config) is not None
    has_login = _re(r"^aaa authentication login\s+\S+", config) is not None
    if has_new_model and has_login:
        return _ok("AAA new-model and a default login method are configured.")
    if has_new_model:
        return _fail("AAA is enabled but 'aaa authentication login' is missing.")
    return _fail("AAA is not enabled, so there is no central login policy.")


def check_named_user_secret(config: str) -> CheckOutcome:
    if _re(r"^username\s+\S+.*\bsecret\b", config):
        return _ok("A named admin account uses a hashed secret.")
    if _re(r"^username\s+\S+.*\bpassword\b", config):
        return _fail("A named account uses 'password' instead of 'secret'.")
    return _fail("No named admin account with a secret is configured.")


def check_password_encryption(config: str) -> CheckOutcome:
    if _re(r"^service password-encryption", config):
        return _ok("service password-encryption is enabled.")
    return _fail("service password-encryption is disabled, so some passwords may be plain text.")


def check_vty_acl(config: str) -> CheckOutcome:
    blocks = get_blocks(config, "line vty")
    if not blocks:
        return _fail("No 'line vty' section found.")

    missing: List[str] = []
    for header, body in blocks:
        allowed = any(
            line.lower().startswith("access-class") and line.lower().rstrip().endswith(" in")
            for line in body
        )
        if not allowed:
            missing.append(header)
    if missing:
        return _fail("No inbound ACL on: " + ", ".join(missing))
    return _ok("VTY lines are restricted by an inbound access-class.")


def check_ssh_limits(config: str) -> CheckOutcome:
    has_timeout = _re(r"^ip ssh time-out\s+\d+", config) is not None
    retries = _re(r"^ip ssh authentication-retries\s+(\d+)", config)
    if has_timeout and retries and int(retries.group(1)) <= 3:
        return _ok("SSH has a timeout and at most three authentication retries.")
    return _fail("SSH time-out or authentication-retries (<= 3) is not configured.")


# --- SNMP checks ------------------------------------------------------------

def check_snmp_communities(config: str) -> CheckOutcome:
    communities = re.findall(
        r"^snmp-server community\s+(\S+)", config, re.IGNORECASE | re.MULTILINE
    )
    weak = [name for name in communities if name.lower() in {"public", "private", "cisco"}]
    if weak:
        return _fail("Default community string(s) in use: " + ", ".join(sorted(set(weak))))
    return _ok("No default SNMP community strings are used.")


def check_snmp_v3(config: str) -> CheckOutcome:
    has_v3_group = _re(r"^snmp-server group\s+\S+.*\bv3\b", config) is not None
    has_v3_user = _re(r"^snmp-server user\s+\S+\s+\S+.*\bv3\b", config) is not None
    communities = re.findall(
        r"^snmp-server community\s+\S+", config, re.IGNORECASE | re.MULTILINE
    )
    if has_v3_group and has_v3_user:
        return _ok("SNMPv3 group and user are configured.")
    if not communities:
        return _ok("SNMPv1/v2c is not configured at all.")
    return _fail("SNMPv1/v2c community strings are used instead of SNMPv3.")


def check_snmp_rw(config: str) -> CheckOutcome:
    rw = re.findall(
        r"^snmp-server community\s+(\S+)\s+RW\b", config, re.IGNORECASE | re.MULTILINE
    )
    if rw:
        return _fail("Read-write community string(s): " + ", ".join(sorted(set(rw))))
    return _ok("No read-write SNMP community string is configured.")


# --- Service checks ---------------------------------------------------------

def check_http_server(config: str) -> CheckOutcome:
    if _re(r"^ip http server\b", config):
        return _fail("The plain HTTP server is enabled (unencrypted management).")
    return _ok("The plain HTTP server is disabled.")


def check_cdp(config: str) -> CheckOutcome:
    if _re(r"^no cdp run", config):
        return _ok("CDP is disabled globally.")
    interfaces = get_interfaces(config)
    if interfaces and all(
        any(line.lower() == "no cdp enable" for line in body) for _, body in interfaces
    ):
        return _ok("CDP is disabled on every interface.")
    return _fail("CDP is enabled and advertises device details to neighbours.")


def check_small_servers(config: str) -> CheckOutcome:
    missing = []
    if not _re(r"^no service tcp-small-servers", config):
        missing.append("no service tcp-small-servers")
    if not _re(r"^no service udp-small-servers", config):
        missing.append("no service udp-small-servers")
    if missing:
        return _fail("Small servers are not explicitly disabled: " + ", ".join(missing))
    return _ok("TCP and UDP small servers are disabled.")


def check_source_route(config: str) -> CheckOutcome:
    if _re(r"^no ip source-route", config):
        return _ok("IP source routing is disabled.")
    return _fail("IP source routing is enabled, which attackers can abuse.")


def check_directed_broadcast(config: str) -> CheckOutcome:
    l3_interfaces = [
        (header, body)
        for header, body in get_interfaces(config)
        if any(line.lower().startswith("ip address") for line in body)
    ]
    if not l3_interfaces:
        return _skip("No Layer 3 interfaces found.")
    missing = [
        header
        for header, body in l3_interfaces
        if not any(line.lower() == "no ip directed-broadcast" for line in body)
    ]
    if missing:
        return _fail("Directed broadcasts not disabled on: " + ", ".join(missing))
    return _ok("Directed broadcasts are disabled on all Layer 3 interfaces.")


def check_finger_bootp(config: str) -> CheckOutcome:
    missing = []
    if not _re(r"^no ip finger", config):
        missing.append("no ip finger")
    if not _re(r"^no ip bootp server", config):
        missing.append("no ip bootp server")
    if missing:
        return _fail("Not disabled: " + ", ".join(missing))
    return _ok("The finger service and the BOOTP server are disabled.")


# --- Logging and NTP checks -------------------------------------------------

def check_syslog(config: str) -> CheckOutcome:
    if _re(r"^logging host\s+\S+", config) or _re(r"^logging\s+\d+\.\d+\.\d+\.\d+", config):
        return _ok("Logs are sent to a remote syslog server.")
    return _fail("No remote syslog server. Logs are lost when the device reboots.")


def check_buffered_logging(config: str) -> CheckOutcome:
    missing = []
    if not _re(r"^logging buffered\b", config):
        missing.append("logging buffered")
    if not _re(r"^service timestamps log datetime", config):
        missing.append("service timestamps log datetime")
    if missing:
        return _fail("Missing: " + ", ".join(missing))
    return _ok("Logs are buffered locally and carry a real date/time.")


def check_logging_trap(config: str) -> CheckOutcome:
    if _re(r"^logging trap\s+\S+", config):
        return _ok("The syslog severity level is set explicitly.")
    return _fail("'logging trap' is missing, so the default level may be too quiet.")


def check_ntp(config: str) -> CheckOutcome:
    if _re(r"^ntp server\s+\S+", config):
        return _ok("At least one NTP server is configured.")
    return _fail("No NTP server. Timestamps in logs and certificates will drift.")


def check_ntp_auth(config: str) -> CheckOutcome:
    missing = []
    if not _re(r"^ntp authenticate", config):
        missing.append("ntp authenticate")
    if not _re(r"^ntp authentication-key\s+\d+", config):
        missing.append("ntp authentication-key")
    if not _re(r"^ntp trusted-key\s+\d+", config):
        missing.append("ntp trusted-key")
    if missing:
        return _fail("NTP authentication is incomplete: " + ", ".join(missing))
    return _ok("NTP authentication is enabled with a trusted key.")


# --- Layer 2 security checks ------------------------------------------------

def check_port_security(config: str) -> CheckOutcome:
    ports = active_access_ports(config)
    if not ports:
        return _skip("No active access switchports found.")
    missing = [
        header
        for header, body in ports
        if not any(line.lower().startswith("switchport port-security") for line in body)
    ]
    if missing:
        return _fail("Port security is missing on: " + ", ".join(missing))
    return _ok("All active access ports have port security.")


def check_port_security_tuning(config: str) -> CheckOutcome:
    ports = active_access_ports(config)
    if not ports:
        return _skip("No active access switchports found.")
    bad: List[str] = []
    for header, body in ports:
        text = block_text(body)
        has_max = "switchport port-security maximum" in text
        has_violation = (
            "switchport port-security violation restrict" in text
            or "switchport port-security violation shutdown" in text
        )
        if not (has_max and has_violation):
            bad.append(header)
    if bad:
        return _fail("Port security needs limits/violation mode on: " + ", ".join(bad))
    return _ok("Port security limits MAC addresses and restricts violations.")


def check_native_vlan(config: str) -> CheckOutcome:
    trunks = [(h, b) for h, b in get_interfaces(config) if is_trunk_port(b)]
    if not trunks:
        return _skip("No trunk ports found.")
    bad: List[str] = []
    for header, body in trunks:
        native = None
        for line in body:
            match = re.match(r"switchport trunk native vlan\s+(\d+)", line, re.IGNORECASE)
            if match:
                native = int(match.group(1))
        if native is None or native == 1:
            bad.append(header)
    if bad:
        return _fail("Trunks use VLAN 1 (or no explicit native VLAN): " + ", ".join(bad))
    return _ok("Every trunk uses a dedicated native VLAN instead of VLAN 1.")


def check_unused_ports(config: str) -> CheckOutcome:
    unused = []
    for header, body in get_interfaces(config):
        for line in body:
            if line.lower().startswith("description") and re.search(
                r"unused|spare|not in use|patch panel", line, re.IGNORECASE
            ):
                unused.append((header, body))
                break
    if not unused:
        return _skip("No ports described as unused/spare were found.")
    still_up = [header for header, body in unused if not is_shutdown(body)]
    if still_up:
        return _fail("Unused ports are still enabled: " + ", ".join(still_up))
    return _ok("All ports marked unused are administratively shut down.")


def check_dhcp_snooping(config: str) -> CheckOutcome:
    if _re(r"^ip dhcp snooping\b", config) and _re(r"^ip dhcp snooping vlan\s+\S+", config):
        return _ok("DHCP snooping is enabled for at least one VLAN.")
    return _fail("DHCP snooping is not enabled; rogue DHCP servers are possible.")


def check_dai(config: str) -> CheckOutcome:
    if _re(r"^ip arp inspection vlan\s+\S+", config):
        return _ok("Dynamic ARP Inspection is enabled for at least one VLAN.")
    return _fail("Dynamic ARP Inspection is not enabled; ARP spoofing is possible.")


def check_bpdu_guard(config: str) -> CheckOutcome:
    if _re(r"^spanning-tree portfast bpduguard default", config):
        return _ok("BPDU Guard is enabled globally for PortFast ports.")
    ports = active_access_ports(config)
    if ports and all(
        any(line.lower() == "spanning-tree bpduguard enable" for line in body)
        for _, body in ports
    ):
        return _ok("BPDU Guard is enabled on every active access port.")
    return _fail("BPDU Guard is not enabled; rogue switches can break the topology.")


def check_portfast(config: str) -> CheckOutcome:
    if _re(r"^spanning-tree portfast default", config):
        return _ok("PortFast is enabled globally.")
    ports = active_access_ports(config)
    if ports and all(
        any(line.lower().startswith("spanning-tree portfast") for line in body)
        for _, body in ports
    ):
        return _ok("PortFast is enabled on every active access port.")
    return _fail("PortFast is not enabled on access ports.")


def check_mgmt_svi(config: str) -> CheckOutcome:
    for header, body in get_interfaces(config):
        if re.fullmatch(r"interface\s+vlan1", header, re.IGNORECASE):
            if any(line.lower().startswith("ip address") for line in body):
                return _fail("The management IP address is on VLAN 1.")
    return _ok("Management is not addressed on VLAN 1.")


def check_trunk_allowed_vlans(config: str) -> CheckOutcome:
    trunks = [(h, b) for h, b in get_interfaces(config) if is_trunk_port(b)]
    if not trunks:
        return _skip("No trunk ports found.")
    bad: List[str] = []
    for header, body in trunks:
        allowed = None
        for line in body:
            match = re.match(
                r"switchport trunk allowed vlan\s+(.+)", line, re.IGNORECASE
            )
            if match:
                allowed = match.group(1).strip().lower()
        if not allowed or allowed == "all":
            bad.append(header)
    if bad:
        return _fail("Trunks allow every VLAN: " + ", ".join(bad))
    return _ok("Every trunk has an explicit allowed VLAN list.")


CHECKS: List[Check] = [
    # ---------------------- Management plane -------------------------------
    Check(
        id="MGMT-01",
        title="Enable secret is configured",
        category="Management plane",
        severity="high",
        explanation=(
            "The enable secret protects privileged mode. 'enable password' is stored "
            "weakly and can be reversed, so reading the config gives full control."
        ),
        fix=(
            "enable secret 9 <STRONG-HASH>\n"
            "! Create the hash on the device with:\n"
            "!   enable algorithm-type scrypt secret YourStrongPassword"
        ),
        func=check_enable_secret,
    ),
    Check(
        id="MGMT-02",
        title="SSHv2 only, Telnet disabled",
        category="Management plane",
        severity="high",
        explanation=(
            "Telnet sends every keystroke and password in clear text. SSH encrypts "
            "the session, and SSHv2 fixes weaknesses found in SSHv1."
        ),
        fix=(
            "ip ssh version 2\n"
            "line vty 0 15\n"
            " transport input ssh"
        ),
        func=check_ssh_only,
    ),
    Check(
        id="MGMT-03",
        title="VTY lines have an idle timeout",
        category="Management plane",
        severity="medium",
        explanation=(
            "An idle VTY session left open gives the next person full access. A "
            "5-15 minute timeout limits that window."
        ),
        fix=(
            "line vty 0 15\n"
            " exec-timeout 10 0"
        ),
        func=check_vty_timeout,
    ),
    Check(
        id="MGMT-04",
        title="Console line has an idle timeout",
        category="Management plane",
        severity="low",
        explanation=(
            "The console is powerful local access. A timeout stops a forgotten "
            "session from staying logged in."
        ),
        fix=(
            "line con 0\n"
            " exec-timeout 10 0"
        ),
        func=check_console_timeout,
    ),
    Check(
        id="MGMT-05",
        title="Login banner is configured",
        category="Management plane",
        severity="low",
        explanation=(
            "A banner warns users that only authorised access is allowed and that "
            "activity is monitored. Some countries also require a warning banner."
        ),
        fix=(
            "banner motd ^C\n"
            "Authorised access only. All activity is monitored and logged.\n"
            "^C"
        ),
        func=check_banner,
    ),
    Check(
        id="MGMT-06",
        title="AAA authentication is enabled",
        category="Management plane",
        severity="medium",
        explanation=(
            "AAA lets you use central RADIUS/TACACS+ accounts and accounting. "
            "Without it every device has separate local passwords."
        ),
        fix=(
            "aaa new-model\n"
            "aaa authentication login default group tacacs+ local\n"
            "aaa authorization exec default group tacacs+ local\n"
            "aaa accounting exec default start-stop group tacacs+"
        ),
        func=check_aaa,
    ),
    Check(
        id="MGMT-07",
        title="Named admin account uses a secret",
        category="Management plane",
        severity="medium",
        explanation=(
            "Named accounts give each admin their own login so actions can be "
            "traced. 'secret' stores a hash; 'password' does not."
        ),
        fix="username admin privilege 15 secret 9 <STRONG-HASH>",
        func=check_named_user_secret,
    ),
    Check(
        id="MGMT-08",
        title="Service password-encryption is enabled",
        category="Management plane",
        severity="medium",
        explanation=(
            "Some older commands store passwords in clear text. This service hides "
            "them with a weak (type 7) but better-than-nothing cipher."
        ),
        fix="service password-encryption",
        func=check_password_encryption,
    ),
    Check(
        id="MGMT-09",
        title="VTY access is restricted by an ACL",
        category="Management plane",
        severity="medium",
        explanation=(
            "If anyone on the network can reach the VTY lines, they can try "
            "passwords. An ACL limits management to trusted admin subnets."
        ),
        fix=(
            "ip access-list standard MGMT-ACCESS\n"
            " permit 192.0.2.0 0.0.0.255\n"
            "line vty 0 15\n"
            " access-class MGMT-ACCESS in"
        ),
        func=check_vty_acl,
    ),
    Check(
        id="MGMT-10",
        title="SSH timeouts and retries are limited",
        category="Management plane",
        severity="low",
        explanation=(
            "Limiting SSH retries and idle time slows down password guessing and "
            "frees abandoned sessions."
        ),
        fix=(
            "ip ssh time-out 60\n"
            "ip ssh authentication-retries 3"
        ),
        func=check_ssh_limits,
    ),
    # ---------------------------- SNMP -------------------------------------
    Check(
        id="SNMP-01",
        title="No default SNMP community strings",
        category="SNMP",
        severity="high",
        explanation=(
            "public/private are the default community strings and the first thing "
            "an attacker tries. SNMPv1/v2c sends them in clear text."
        ),
        fix=(
            "no snmp-server community public RO\n"
            "no snmp-server community private RW\n"
            "! Then configure SNMPv3 (see SNMP-02)"
        ),
        func=check_snmp_communities,
    ),
    Check(
        id="SNMP-02",
        title="SNMPv3 is used (or SNMP is off)",
        category="SNMP",
        severity="medium",
        explanation=(
            "SNMPv3 adds authentication and encryption. SNMPv1/v2c community "
            "strings work like plain-text passwords."
        ),
        fix=(
            "snmp-server group AUDIT v3 priv\n"
            "snmp-server user audit AUDIT v3 auth sha <AUTH-PASSWORD> priv aes 128 <PRIV-PASSWORD>"
        ),
        func=check_snmp_v3,
    ),
    Check(
        id="SNMP-03",
        title="No read-write SNMP community",
        category="SNMP",
        severity="high",
        explanation=(
            "A read-write community string lets an attacker change device "
            "settings, not just read them."
        ),
        fix="no snmp-server community <NAME> RW",
        func=check_snmp_rw,
    ),
    # --------------------------- Services ----------------------------------
    Check(
        id="SVC-01",
        title="Plain HTTP server is disabled",
        category="Services",
        severity="high",
        explanation=(
            "The HTTP server offers an unencrypted management page and has had "
            "many vulnerabilities. Disable it unless it is really needed."
        ),
        fix=(
            "no ip http server\n"
            "no ip http secure-server"
        ),
        func=check_http_server,
    ),
    Check(
        id="SVC-02",
        title="CDP is disabled",
        category="Services",
        severity="low",
        explanation=(
            "CDP tells neighbours the device model, IOS version and management "
            "address - useful reconnaissance for an attacker."
        ),
        fix=(
            "no cdp run\n"
            "! or per interface:\n"
            "interface GigabitEthernet0/1\n"
            " no cdp enable"
        ),
        func=check_cdp,
    ),
    Check(
        id="SVC-03",
        title="TCP/UDP small servers are disabled",
        category="Services",
        severity="medium",
        explanation=(
            "The small servers (echo, chargen, discard) are old debugging tools. "
            "They are rarely needed and can be abused for amplification attacks."
        ),
        fix=(
            "no service tcp-small-servers\n"
            "no service udp-small-servers"
        ),
        func=check_small_servers,
    ),
    Check(
        id="SVC-04",
        title="IP source routing is disabled",
        category="Services",
        severity="medium",
        explanation=(
            "Source routing lets the sender choose the path a packet takes. "
            "Attackers use it to bypass filters."
        ),
        fix="no ip source-route",
        func=check_source_route,
    ),
    Check(
        id="SVC-05",
        title="Directed broadcasts are disabled",
        category="Services",
        severity="low",
        explanation=(
            "A directed broadcast can be amplified into a flood against another "
            "network (Smurf-style attack)."
        ),
        fix=(
            "interface GigabitEthernet0/0\n"
            " no ip directed-broadcast"
        ),
        func=check_directed_broadcast,
    ),
    Check(
        id="SVC-06",
        title="Finger and BOOTP server are disabled",
        category="Services",
        severity="low",
        explanation=(
            "finger reveals who is logged in, and the BOOTP server can be tricked "
            "into serving configurations. Neither is normally needed."
        ),
        fix=(
            "no ip finger\n"
            "no ip bootp server"
        ),
        func=check_finger_bootp,
    ),
    # ------------------------ Logging & NTP --------------------------------
    Check(
        id="LOG-01",
        title="Remote syslog server is configured",
        category="Logging & NTP",
        severity="medium",
        explanation=(
            "Local logs disappear on reload and are easy to erase. A remote syslog "
            "server keeps evidence and helps with troubleshooting."
        ),
        fix=(
            "logging host 192.0.2.50\n"
            "logging source-interface GigabitEthernet0/0"
        ),
        func=check_syslog,
    ),
    Check(
        id="LOG-02",
        title="Buffered logging with timestamps",
        category="Logging & NTP",
        severity="low",
        explanation=(
            "Buffered logs survive a terminal disconnect, and timestamps let you "
            "correlate events between devices."
        ),
        fix=(
            "service timestamps log datetime msec localtime\n"
            "logging buffered 16384 informational"
        ),
        func=check_buffered_logging,
    ),
    Check(
        id="LOG-03",
        title="Syslog trap level is set",
        category="Logging & NTP",
        severity="low",
        explanation=(
            "If the trap level is not set, important messages may never be sent "
            "to the syslog server."
        ),
        fix="logging trap informational",
        func=check_logging_trap,
    ),
    Check(
        id="NTP-01",
        title="NTP server is configured",
        category="Logging & NTP",
        severity="medium",
        explanation=(
            "Accurate time is essential for log correlation, certificate checks "
            "and incident response."
        ),
        fix="ntp server 192.0.2.10",
        func=check_ntp,
    ),
    Check(
        id="NTP-02",
        title="NTP authentication is enabled",
        category="Logging & NTP",
        severity="low",
        explanation=(
            "Without authentication an attacker can feed the device a false time "
            "and confuse logs or certificate checks."
        ),
        fix=(
            "ntp authenticate\n"
            "ntp authentication-key 1 md5 <NTP-KEY>\n"
            "ntp trusted-key 1\n"
            "ntp server 192.0.2.10 key 1"
        ),
        func=check_ntp_auth,
    ),
    # ---------------------- Layer 2 security -------------------------------
    Check(
        id="L2-01",
        title="Port security on access ports",
        category="Layer 2 security",
        severity="high",
        explanation=(
            "Port security limits which MAC addresses may use a port. Without it, "
            "anyone can plug in a switch or spoof MAC addresses."
        ),
        fix=(
            "interface range FastEthernet0/1-8\n"
            " switchport port-security"
        ),
        func=check_port_security,
        layer2_only=True,
    ),
    Check(
        id="L2-02",
        title="Port security limits and violation mode",
        category="Layer 2 security",
        severity="medium",
        explanation=(
            "Without a maximum and a violation mode, port security may learn "
            "unlimited MACs or shut a port too aggressively."
        ),
        fix=(
            "interface range FastEthernet0/1-8\n"
            " switchport port-security maximum 3\n"
            " switchport port-security violation restrict\n"
            " switchport port-security mac-address sticky"
        ),
        func=check_port_security_tuning,
        layer2_only=True,
    ),
    Check(
        id="L2-03",
        title="Trunk native VLAN is not VLAN 1",
        category="Layer 2 security",
        severity="medium",
        explanation=(
            "VLAN 1 is the default native VLAN on every trunk. Its traffic is "
            "untagged, which enables VLAN-hopping attacks."
        ),
        fix=(
            "interface GigabitEthernet0/1\n"
            " switchport trunk native vlan 99\n"
            "! Use a dedicated, unused VLAN as the native VLAN."
        ),
        func=check_native_vlan,
        layer2_only=True,
    ),
    Check(
        id="L2-04",
        title="Unused ports are shut down",
        category="Layer 2 security",
        severity="high",
        explanation=(
            "An unused port that is up is an open door: anyone can plug in a "
            "laptop and get network access."
        ),
        fix=(
            "interface range FastEthernet0/10-24\n"
            " description UNUSED\n"
            " switchport mode access\n"
            " switchport access vlan 999\n"
            " shutdown"
        ),
        func=check_unused_ports,
        layer2_only=True,
    ),
    Check(
        id="L2-05",
        title="DHCP snooping is enabled",
        category="Layer 2 security",
        severity="high",
        explanation=(
            "DHCP snooping stops a rogue DHCP server from handing out fake "
            "gateways and DNS servers."
        ),
        fix=(
            "ip dhcp snooping\n"
            "ip dhcp snooping vlan 10,20,30\n"
            "no ip dhcp snooping information option\n"
            "interface GigabitEthernet0/1\n"
            " ip dhcp snooping trust"
        ),
        func=check_dhcp_snooping,
        layer2_only=True,
    ),
    Check(
        id="L2-06",
        title="Dynamic ARP Inspection is enabled",
        category="Layer 2 security",
        severity="high",
        explanation=(
            "DAI checks ARP packets against the DHCP snooping table, which blocks "
            "ARP spoofing and man-in-the-middle attacks."
        ),
        fix=(
            "ip arp inspection vlan 10,20,30\n"
            "ip arp inspection validate src-mac dst-mac ip\n"
            "interface GigabitEthernet0/1\n"
            " ip arp inspection trust"
        ),
        func=check_dai,
        layer2_only=True,
    ),
    Check(
        id="L2-07",
        title="BPDU Guard is enabled",
        category="Layer 2 security",
        severity="medium",
        explanation=(
            "A rogue switch on an access port can become root bridge and capture "
            "traffic. BPDU Guard shuts the port instead."
        ),
        fix=(
            "spanning-tree portfast bpduguard default\n"
            "! or per port: spanning-tree bpduguard enable"
        ),
        func=check_bpdu_guard,
        layer2_only=True,
    ),
    Check(
        id="L2-08",
        title="PortFast is enabled on access ports",
        category="Layer 2 security",
        severity="low",
        explanation=(
            "PortFast lets access ports forward traffic immediately instead of "
            "waiting through STP states. It is safe only with BPDU Guard."
        ),
        fix="spanning-tree portfast default",
        func=check_portfast,
        layer2_only=True,
    ),
    Check(
        id="L2-09",
        title="Management SVI is not on VLAN 1",
        category="Layer 2 security",
        severity="medium",
        explanation=(
            "VLAN 1 is the default and is often allowed everywhere. Putting "
            "management on a dedicated VLAN makes it harder to reach."
        ),
        fix=(
            "vlan 99\n"
            " name MGMT\n"
            "interface Vlan99\n"
            " ip address 192.0.2.20 255.255.255.0\n"
            " no ip directed-broadcast\n"
            "interface Vlan1\n"
            " no ip address\n"
            " shutdown"
        ),
        func=check_mgmt_svi,
        layer2_only=True,
    ),
    Check(
        id="L2-10",
        title="Trunk allowed VLAN list is restricted",
        category="Layer 2 security",
        severity="low",
        explanation=(
            "A trunk that allows every VLAN spreads broadcasts and attacks to the "
            "whole network. Allow only the VLANs you actually use."
        ),
        fix=(
            "interface GigabitEthernet0/1\n"
            " switchport trunk allowed vlan 10,20,30,99"
        ),
        func=check_trunk_allowed_vlans,
        layer2_only=True,
    ),
]


# ---------------------------------------------------------------------------
# 4. Running the checks and calculating the score
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """One check applied to one device."""

    check: Check
    status: str          # "pass", "fail" or "skip"
    detail: str


@dataclass
class DeviceResult:
    """Everything we know about one audited config file."""

    path: str
    name: str
    config_text: str
    results: List[CheckResult] = field(default_factory=list)
    earned: int = 0        # weight of the checks that passed
    possible: int = 0      # weight of all checks that were scored
    score: float = 0.0     # 0.0 - 100.0


def audit_config(config_text: str, name: str = "config", path: str = "") -> DeviceResult:
    """Run every check against one config and return the result."""
    device = DeviceResult(path=path, name=name, config_text=config_text)

    # Layer 2 checks only make sense on switches. If the config contains no
    # "switchport" command we assume it is a router and skip those checks.
    is_layer2 = _re(r"^\s*switchport\b", config_text) is not None

    for check in CHECKS:
        if check.layer2_only and not is_layer2:
            device.results.append(
                CheckResult(check, "skip", "Not a switch config (no switchport commands).")
            )
            continue

        try:
            passed, detail = check.func(config_text)
        except Exception as exc:  # a broken check must never stop the audit
            passed, detail = False, f"Check error: {exc}"

        if passed is None:
            status = "skip"
        elif passed:
            status = "pass"
        else:
            status = "fail"

        device.results.append(CheckResult(check, status, detail))

        # Skipped checks are not counted, so they cannot raise or lower a score.
        if status != "skip":
            weight = SEVERITY_WEIGHTS[check.severity]
            device.possible += weight
            if status == "pass":
                device.earned += weight

    if device.possible:
        device.score = round(100.0 * device.earned / device.possible, 1)
    else:
        device.score = 0.0

    return device


def audit_file(path: Path) -> DeviceResult:
    """Read a file (tolerating odd encodings) and audit it."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return audit_config(text, name=path.name, path=str(path))


def grade_for(score: float) -> str:
    if score >= 90:
        return "Good"
    if score >= 70:
        return "Needs work"
    if score >= 50:
        return "Poor"
    return "Critical"


def severity_counts(device: DeviceResult) -> dict:
    """How many failed checks of each severity the device has."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for result in device.results:
        if result.status == "fail":
            counts[result.check.severity] += 1
    return counts


def collect_config_files(target: Path) -> List[Path]:
    """Return one file, or every config file inside a folder."""
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(
            path
            for path in target.rglob("*")
            if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES
        )
    return []


# ---------------------------------------------------------------------------
# 5. HTML report
#
# The report is a single file: CSS is inline, there are no scripts, no fonts
# from the internet and no links to other files. All config text is escaped
# with html.escape() before it is placed in the page.
# ---------------------------------------------------------------------------

CSS = """
:root{
  --bg:#f4f6f8; --card:#ffffff; --ink:#1f2937; --muted:#6b7280;
  --line:#e2e8f0; --high:#b91c1c; --medium:#b45309; --low:#1d4ed8;
  --pass:#0f766e; --fail:#b91c1c; --skip:#6b7280;
}
*{box-sizing:border-box}
body{margin:0;padding:28px;background:var(--bg);color:var(--ink);
     font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
     line-height:1.55}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 6px}
.sub{color:var(--muted);margin:0 0 22px;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
      padding:18px 20px;margin-bottom:22px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.num{text-align:center}
.score{font-weight:700}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
.pill.good{background:#d1fae5;color:#065f46}
.pill.ok{background:#fef3c7;color:#92400e}
.pill.bad{background:#fee2e2;color:#991b1b}
.bar{height:7px;background:#e5e7eb;border-radius:4px;overflow:hidden;margin-top:4px;min-width:90px}
.bar span{display:block;height:100%;background:#0f766e}
.device-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.device-head h2{font-size:19px;margin:0}
.meta{color:var(--muted);font-size:13px;margin:8px 0 14px}
h3{font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:22px 0 10px}
.finding{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin-bottom:10px}
.finding.fail{border-left:4px solid var(--fail)}
.finding.pass{border-left:4px solid var(--pass)}
.finding.skip{border-left:4px solid var(--skip);opacity:.75}
.finding-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.finding-head .title{font-weight:600}
.cid{font-size:12px;color:var(--muted);background:#f1f5f9;padding:1px 6px;border-radius:4px}
.sev{font-size:11px;font-weight:700;padding:1px 7px;border-radius:999px;color:#fff}
.sev.high{background:var(--high)} .sev.medium{background:var(--medium)} .sev.low{background:var(--low)}
.result{margin-left:auto;font-size:12px;font-weight:700}
.result.pass{color:var(--pass)} .result.fail{color:var(--fail)} .result.skip{color:var(--skip)}
.detail{font-size:13.5px;margin:7px 0 0}
.why{font-size:13.5px;color:#374151;margin:6px 0 0}
.fix-title{display:block;font-size:12px;font-weight:700;text-transform:uppercase;
           letter-spacing:.04em;color:var(--muted);margin:10px 0 5px}
pre{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:6px;
    overflow-x:auto;font-size:12.5px;line-height:1.45;margin:0}
code{font-family:Consolas,"SF Mono",Menlo,monospace}
.pass .detail{color:var(--muted)}
details summary{cursor:pointer;font-size:13px;font-weight:600;color:#374151}
details pre{margin-top:10px;max-height:520px;overflow:auto}
.legend{font-size:12.5px;color:var(--muted)}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin:26px 0 6px}
@media print{body{padding:0;background:#fff}.card{box-shadow:none;break-inside:avoid}}
"""


def _esc(value: object) -> str:
    """Escape text so config contents can never break the HTML."""
    return html.escape(str(value), quote=True)


def _finding_html(result: CheckResult) -> str:
    check = result.check
    severity = check.severity
    head = (
        '<div class="finding-head">'
        f'<span class="sev {severity}">{severity.upper()}</span>'
        f'<code class="cid">{_esc(check.id)}</code>'
        f'<span class="title">{_esc(check.title)}</span>'
        f'<span class="result {result.status}">{result.status.upper()}</span>'
        "</div>"
    )

    if result.status == "fail":
        return (
            f'<article class="finding fail">{head}'
            f'<p class="detail">{_esc(result.detail)}</p>'
            f'<p class="why">{_esc(check.explanation)}</p>'
            '<div class="fix"><span class="fix-title">Recommended fix</span>'
            f"<pre><code>{_esc(check.fix)}</code></pre></div>"
            "</article>"
        )

    return (
        f'<article class="finding {result.status}">{head}'
        f'<p class="detail">{_esc(result.detail)}</p>'
        "</article>"
    )


def _device_html(device: DeviceResult) -> str:
    counts = severity_counts(device)
    passed = sum(1 for r in device.results if r.status == "pass")
    failed = sum(1 for r in device.results if r.status == "fail")
    skipped = sum(1 for r in device.results if r.status == "skip")
    grade = grade_for(device.score)
    pill_class = "good" if device.score >= 90 else ("ok" if device.score >= 50 else "bad")

    out = ['<div class="card">']
    out.append(
        '<div class="device-head">'
        f"<h2>{_esc(device.name)}</h2>"
        f'<span class="pill {pill_class}">{device.score:.1f}% &middot; {_esc(grade)}</span>'
        "</div>"
    )
    out.append(
        f'<p class="meta">File: <code>{_esc(device.path)}</code> &middot; '
        f"{passed} passed, {failed} failed, {skipped} skipped &middot; "
        f"score {device.earned}/{device.possible} points</p>"
    )
    out.append(
        "<details><summary>Show the analyzed configuration</summary>"
        f"<pre><code>{_esc(device.config_text)}</code></pre></details>"
    )

    for category in CATEGORY_ORDER:
        items = [r for r in device.results if r.check.category == category]
        if not items:
            continue
        # Failed findings first, then passed, then skipped.
        order = {"fail": 0, "pass": 1, "skip": 2}
        items.sort(key=lambda r: (order[r.status], r.check.id))
        out.append(f"<h3>{_esc(category)}</h3>")
        for item in items:
            out.append(_finding_html(item))

    out.append("</div>")
    return "".join(out)


def build_html(results: Sequence[DeviceResult], source: str) -> str:
    """Build the complete, self-contained HTML report as one string."""
    total = len(results)
    average = sum(device.score for device in results) / total if total else 0.0
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    out: List[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Cisco IOS Configuration Audit</title>",
        f"<style>{CSS}</style>",
        "</head><body><div class=\"wrap\">",
        "<h1>Cisco IOS Configuration Audit</h1>",
        (
            f'<p class="sub">Source <code>{_esc(source)}</code> &middot; '
            f"{total} device(s) &middot; average score {average:.1f}% &middot; "
            f"generated {generated}</p>"
        ),
        '<div class="card"><h2 style="font-size:16px;margin:0 0 10px">Summary</h2>',
        "<table><thead><tr><th>Device</th><th>Score</th><th>Grade</th>"
        '<th class="num">High</th><th class="num">Medium</th>'
        '<th class="num">Low</th></tr></thead><tbody>',
    ]

    for device in results:
        counts = severity_counts(device)
        grade = grade_for(device.score)
        pill_class = (
            "good" if device.score >= 90 else ("ok" if device.score >= 50 else "bad")
        )
        out.append(
            "<tr>"
            f"<td>{_esc(device.name)}</td>"
            f'<td><div class="score">{device.score:.1f}%</div>'
            f'<div class="bar"><span style="width:{device.score:.1f}%"></span></div></td>'
            f'<td><span class="pill {pill_class}">{_esc(grade)}</span></td>'
            f'<td class="num">{counts["high"]}</td>'
            f'<td class="num">{counts["medium"]}</td>'
            f'<td class="num">{counts["low"]}</td>'
            "</tr>"
        )

    out.append("</tbody></table>")
    out.append(
        '<p class="legend">Score = earned points / possible points. '
        "A high finding costs 10 points, medium 5, low 2. "
        "Checks that do not apply (for example Layer 2 checks on a router) "
        "are skipped and not counted.</p>"
    )
    out.append("</div>")

    for device in results:
        out.append(_device_html(device))

    out.append(
        "<footer>Generated offline by cisco-config-auditor. "
        "No data left this computer.</footer>"
    )
    out.append("</div></body></html>")
    return "\n".join(out)


def write_report(results: Sequence[DeviceResult], output: Path, source: str) -> Path:
    output = Path(output)
    output.write_text(build_html(results, source), encoding="utf-8")
    return output


# ---------------------------------------------------------------------------
# 6. Command line interface
# ---------------------------------------------------------------------------

def print_summary(results: Sequence[DeviceResult]) -> None:
    header = (
        f"{'Device':<32}{'Score':>7}  {'Grade':<11}"
        f"{'High':>5}{'Med':>5}{'Low':>5}"
    )
    print()
    print(header)
    print("-" * len(header))
    for device in results:
        counts = severity_counts(device)
        print(
            f"{device.name[:31]:<32}{device.score:>6.1f}%  "
            f"{grade_for(device.score):<11}"
            f"{counts['high']:>5}{counts['medium']:>5}{counts['low']:>5}"
        )
    print()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit Cisco IOS config files offline and write report.html."
    )
    parser.add_argument("path", help="a config file or a folder of config files")
    parser.add_argument(
        "-o",
        "--output",
        default="report.html",
        help="where to write the HTML report (default: report.html)",
    )
    args = parser.parse_args(argv)

    target = Path(args.path)
    files = collect_config_files(target)
    if not files:
        print(f"No config files found: {target}", file=sys.stderr)
        print("Pass a .cfg file, or a folder containing .cfg files.", file=sys.stderr)
        return 2

    print(f"Auditing {len(files)} config file(s) ...")
    results = [audit_file(path) for path in files]
    print_summary(results)

    report = write_report(results, Path(args.output), str(target))
    print(f"Report written to: {report.resolve()}")
    print("Open it in any web browser - it works completely offline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())


