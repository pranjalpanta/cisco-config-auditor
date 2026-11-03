# cisco-config-auditor

**Find the security settings that are missing from Cisco IOS configs — offline.**

`cisco-config-auditor` reads one Cisco router/switch config file (or a whole
folder), runs **34 security checks**, scores each device from **0–100 %**, and
writes a **self-contained HTML report** with the exact CLI commands to fix every
finding.

No SSH. No network. No Cisco device. Just Python and text files.

<p>
  <img alt="Python 3.8+" src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img alt="34 checks" src="https://img.shields.io/badge/checks-34-brightgreen">
  <img alt="13 tests passing" src="https://img.shields.io/badge/tests-13%20passing-brightgreen">
  <img alt="100% offline" src="https://img.shields.io/badge/network-100%25%20offline-informational">
</p>

### Why it is useful

- **Catches the easy misses** — Telnet, default SNMP strings, open HTTP, missing
  enable secret, unused ports left up, no logging or NTP.
- **Tells you how to fix it** — every finding includes the exact Cisco command.
- **Safe on production configs** — it only reads text files and never connects
  to a device.

## Contents

- [Why this project exists](#why-this-project-exists)
- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [The report](#the-report)
- [How the score works](#how-the-score-works)
- [All 34 checks](#all-34-checks)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Installation](#installation)
- [Tests](#tests)
- [What it is not](#what-it-is-not)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)
- [Safety notes](#safety-notes)
- [License](#license)

---

## Why this project exists

A real Cisco configuration is long. Most of it is ordinary: interfaces, VLANs,
routing, ACLs. The security settings are scattered through that file, and the
most dangerous ones are usually **commands that were never typed**:

- Telnet was left enabled years ago and nobody removed it.
- SNMP still uses `public` / `private`, maybe even read-write.
- A new switch was installed without port security or DHCP snooping.
- Unused wall ports were left enabled "just in case".
- Logging and NTP were never configured, so after an incident there are no
  useful logs.

None of these stop the network from working. That is exactly why they survive:
**the network works, so nobody notices.** An attacker notices.

Reviewing dozens of configs by hand is also slow, tiring, and inconsistent.
Different people miss different things, and the review is never repeated the
same way. This project turns that manual review into a fast, repeatable first
pass.

---

## What it does

| | |
|---|---|
| **Input** | One `.cfg` file, or a folder of `.cfg` / `.conf` / `.txt` files |
| **Checks** | 34 checks in 5 categories |
| **Output** | Terminal summary + one self-contained `report.html` |
| **Scoring** | Weighted by severity: high = 10, medium = 5, low = 2 |
| **Dependencies** | Python standard library only; pytest just for the tests |
| **Network** | None. No SSH, no HTTP, no cloud |
| **Platforms** | Windows, Linux, macOS |

The five categories:

1. **Management plane** — enable secret, SSH vs Telnet, AAA, timeouts, banner, VTY ACLs.
2. **SNMP** — default communities, read-write access, SNMPv3.
3. **Services** — HTTP server, CDP, small servers, source routing, finger/BOOTP.
4. **Logging & NTP** — remote syslog, buffered logs, timestamps, time sync.
5. **Layer 2 security** — port security, native VLAN, unused ports, DHCP snooping,
   Dynamic ARP Inspection, BPDU Guard.

---

## Quick start

```text
python auditor.py sample_configs
start report.html          # Windows
xdg-open report.html       # Linux
open report.html           # macOS
```

Sample output:

```text
Auditing 4 config file(s) ...

Device                            Score  Grade       High  Med  Low
-------------------------------------------------------------------
router_bad.cfg                     1.7%  Critical       5   10    8
router_good.cfg                  100.0%  Good           0    0    0
switch_bad.cfg                     4.9%  Critical       9   13    9
switch_good.cfg                  100.0%  Good           0    0    0

Report written to: ...\report.html
```

Run one file:

```text
python auditor.py sample_configs/router_bad.cfg
```

Choose the report name:

```text
python auditor.py sample_configs -o my_report.html
```

---

## The report

The report is one HTML file with no scripts, no CDN, and no internet access
needed. It contains:

- **A summary table** for all devices: score, grade, and counts of high/medium/low
  findings.
- **A section per device** with every check, grouped by category.
- **Failed findings first**, each with what is wrong, why it matters, and a
  copy-ready Cisco fix in a dark code block.
- **A collapsible copy of the analyzed config**, so you can check the evidence.
- **Escaped config text**, so a malicious banner cannot inject HTML or JavaScript.

Open it by double-clicking, or with `start` / `xdg-open` / `open`.

---

## How the score works

| Severity | Points if the check **fails** |
|----------|-------------------------------|
| high     | 10                            |
| medium   | 5                             |
| low      | 2                             |

```text
score % = points earned / points possible × 100
```

- A passing check earns its points.
- A failing check earns zero.
- A check that does not apply is **skipped** and removed from the calculation.
  For example, Layer 2 checks are skipped on a router because a router config
  has no `switchport` commands.

| Score    | Grade      |
|----------|------------|
| 90–100 % | Good       |
| 70–89 %  | Needs work |
| 50–69 %  | Poor       |
| 0–49 %   | Critical   |

---

## All 34 checks

<details>
<summary><strong>Management plane — 10 checks</strong></summary>

| ID | Check | What it looks for | Why it matters |
|----|-------|-------------------|----------------|
| MGMT-01 | Enable secret | `enable secret` exists (not just `enable password`) | `enable password` is easy to reverse. The secret protects privileged mode. |
| MGMT-02 | SSHv2 only | `ip ssh version 2` and `transport input ssh` on every VTY line | Telnet sends passwords in clear text. SSH encrypts the session. |
| MGMT-03 | VTY idle timeout | `exec-timeout` > 0 on every `line vty` block | A forgotten admin session is an open door. |
| MGMT-04 | Console timeout | `exec-timeout` > 0 on `line con 0` | Same risk, for someone standing at the device. |
| MGMT-05 | Login banner | `banner motd`, `banner login` or `banner exec` | Warns users that access is restricted and monitored (and is legally required in some places). |
| MGMT-06 | AAA | `aaa new-model` plus `aaa authentication login` | Central accounts, per-user logins and accounting instead of shared local passwords. |
| MGMT-07 | Named admin secret | `username ... secret` | Each admin gets their own account, stored as a hash. |
| MGMT-08 | Password encryption | `service password-encryption` | Hides older clear-text passwords in the config (weak, but better than nothing). |
| MGMT-09 | VTY ACL | `access-class ... in` on every VTY line | Only trusted admin networks should reach the login prompt. |
| MGMT-10 | SSH limits | `ip ssh time-out` and `ip ssh authentication-retries` ≤ 3 | Slows down password guessing and closes idle SSH sessions. |

</details>

<details>
<summary><strong>SNMP — 3 checks</strong></summary>

| ID | Check | What it looks for | Why it matters |
|----|-------|-------------------|----------------|
| SNMP-01 | No default communities | No `snmp-server community public/private/cisco` | These names are the first thing an attacker tries. |
| SNMP-02 | SNMPv3 or nothing | `snmp-server group ... v3` and `snmp-server user ...` (or no SNMP at all) | SNMPv3 encrypts and authenticates; v1/v2c uses plain-text community strings. |
| SNMP-03 | No RW community | No `snmp-server community <name> RW` | A read-write string lets an attacker change the device, not just read it. |

</details>

<details>
<summary><strong>Services — 6 checks</strong></summary>

| ID | Check | What it looks for | Why it matters |
|----|-------|-------------------|----------------|
| SVC-01 | HTTP server off | No `ip http server` | The plain HTTP management page is unencrypted and has a long history of bugs. |
| SVC-02 | CDP off | `no cdp run` (or `no cdp enable` everywhere) | CDP leaks the model, IOS version and management address to neighbours. |
| SVC-03 | Small servers off | `no service tcp-small-servers` and `no service udp-small-servers` | Old echo/chargen services can be abused for amplification attacks. |
| SVC-04 | Source routing off | `no ip source-route` | Attackers can use it to bypass packet filters. |
| SVC-05 | Directed broadcasts off | `no ip directed-broadcast` on every Layer 3 interface | Stops Smurf-style broadcast amplification. |
| SVC-06 | Finger/BOOTP off | `no ip finger` and `no ip bootp server` | finger leaks logged-in users; BOOTP can be abused to serve configs. |

</details>

<details>
<summary><strong>Logging &amp; NTP — 5 checks</strong></summary>

| ID | Check | What it looks for | Why it matters |
|----|-------|-------------------|----------------|
| LOG-01 | Remote syslog | `logging host <ip>` | Local logs are lost on reload; a syslog server keeps the evidence. |
| LOG-02 | Buffered + timestamps | `logging buffered` and `service timestamps log datetime` | Events stay readable and can be correlated with other devices. |
| LOG-03 | Trap level | `logging trap <level>` | Without it, important messages may never reach the syslog server. |
| NTP-01 | NTP server | `ntp server <ip>` | Correct time is required for logs, certificates and incident response. |
| NTP-02 | NTP authentication | `ntp authenticate`, `ntp authentication-key`, `ntp trusted-key` | Stops an attacker from feeding the device a false time. |

</details>

<details>
<summary><strong>Layer 2 security — 10 checks (switches only)</strong></summary>

| ID | Check | What it looks for | Why it matters |
|----|-------|-------------------|----------------|
| L2-01 | Port security | `switchport port-security` on every active access port | Stops MAC flooding and random devices on access ports. |
| L2-02 | Port security tuning | `port-security maximum` plus `violation restrict`/`shutdown` | Without limits, port security is easy to bypass or too aggressive. |
| L2-03 | Native VLAN | Trunk native VLAN is set and is not VLAN 1 | VLAN 1 is the default and enables VLAN-hopping attacks. |
| L2-04 | Unused ports down | Ports described as unused/spare are `shutdown` | An open port lets anyone plug in a laptop. |
| L2-05 | DHCP snooping | `ip dhcp snooping` and `ip dhcp snooping vlan ...` | Blocks rogue DHCP servers that hand out fake gateways. |
| L2-06 | Dynamic ARP Inspection | `ip arp inspection vlan ...` | Blocks ARP spoofing and man-in-the-middle attacks. |
| L2-07 | BPDU Guard | `spanning-tree portfast bpduguard default` (or per port) | Stops a rogue switch from becoming root bridge. |
| L2-08 | PortFast | `spanning-tree portfast default` (or per port) | Access ports start forwarding immediately; safe together with BPDU Guard. |
| L2-09 | Management VLAN | VLAN 1 has no IP address; management uses another VLAN | Keeps management traffic off the default VLAN. |
| L2-10 | Allowed VLANs | `switchport trunk allowed vlan ...` with an explicit list | A trunk allowing every VLAN spreads broadcasts and attacks everywhere. |

</details>

---

## How it works

```mermaid
flowchart LR
    A["Config file or folder"] --> B["Read text"]
    B --> C["Split into interface / line blocks"]
    C --> D["Run 34 regex checks"]
    D --> E["Weighted score"]
    E --> F["report.html"]
```

1. **Find the files.** A file is used directly; a folder is searched recursively
   for `.cfg`, `.conf` and `.txt`.
2. **Read the text.** No SSH and no device connection. Odd encodings are replaced
   instead of crashing.
3. **Split into blocks.** `get_blocks()` groups lines belonging to
   `interface ...`, `line vty ...` and `line con ...`. Cisco indents child
   commands, and a `!` line ends a block.
4. **Run the checks.** Each check is a small function using plain
   `re.search()`. It returns pass, fail, or "not applicable".
5. **Score.** Passed and failed checks are weighted 10 / 5 / 2; skipped checks
   are ignored.
6. **Build the report.** One HTML string with inline CSS and no scripts. All
   config text goes through `html.escape()`.
7. **Done.** Nothing is uploaded anywhere.

### Project structure

```text
cisco-config-auditor/
├── auditor.py               # the whole tool (standard library only)
├── requirements.txt         # pytest, for the tests only
├── README.md
├── report.html              # generated by the tool
├── docs/
│   └── report-preview.png   # screenshot used in this README
├── sample_configs/
│   ├── router_bad.cfg       # insecure router example
│   ├── router_good.cfg      # hardened router example
│   ├── switch_bad.cfg       # insecure switch example
│   └── switch_good.cfg      # bonus: hardened switch example
└── tests/
    └── test_auditor.py      # 13 pytest tests
```

---

## Installation

### Windows (PowerShell)

```powershell
cd "C:\path\to\cisco-config-auditor"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks the activate script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Or skip activation and call the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe auditor.py sample_configs
```

### Linux / macOS

```bash
cd ~/cisco-config-auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

> `pip install` is only needed for `pytest`. The auditor itself needs no
> third-party package.

---

## Tests

```text
python -m pytest -q
```

Expected:

```text
13 passed
```

The tests cover individual checks (enable secret, Telnet, SNMP, HTTP, port
security, native VLAN, DHCP snooping), the score targets, Layer 2 skipping,
HTML escaping, and report creation.

---

## What it is not

- **Not a vulnerability scanner.** It does not detect CVEs, IOS bugs, or missing
  patches. It checks configuration hygiene.
- **Does not log in to devices.** You export the config yourself. It cannot see
  live state such as the ARP table, routing neighbours, or actual port status.
- **Pattern matching, not a full Cisco parser.** Unusual formatting or generated
  configs can confuse it. False positives and misses are possible.
- **Not a replacement for an expert.** Use it as a fast first pass and a
  learning aid, then verify findings and test changes in a lab.
- **The sample hashes and IP addresses are fake.** Never copy them into
  production.

---

## FAQ

**Does it connect to my router or switch?**
No. It only reads a text file. It cannot change, reload, or lock a device.

**Do I need internet?**
No. The tool, the report, and the tests run fully offline.

**What file do I give it?**
The text output of `show running-config`, saved as `.cfg` or `.txt`.

**Can it find CVEs or missing patches?**
No. It checks configuration best practice, not software versions.

**Why do routers skip the Layer 2 checks?**
A router config has no `switchport` commands, so those checks do not apply and
are removed from the score.

**Can I add my own checks?**
Yes. Add a function and a `Check(...)` entry in the `CHECKS` list in
`auditor.py`. Scoring and the report update automatically.

**Can I share the report?**
Yes, but it contains the full analyzed config. Treat it as sensitive and remove
passwords or hashes before publishing it.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python: command not found` | Install Python from <https://www.python.org/downloads/> and tick **Add python.exe to PATH**. On Linux use `python3`. |
| PowerShell blocks `Activate.ps1` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, or use `.\.venv\Scripts\python.exe` directly. |
| `No config files found` | Pass a `.cfg` file, or a folder containing `.cfg`/`.conf`/`.txt` files. |
| Report looks empty | Open `report.html` in a browser, not a text editor. |
| A switch is scored like a router | The tool treats a config as a switch only when it contains `switchport` commands. Use a full `show running-config` capture. |

---

## Safety notes

- The tool never connects to a device and never changes anything.
- The sample configs are fake. `192.0.2.0/24`, `198.51.100.0/24` and
  `203.0.113.0/24` are reserved documentation ranges.
- Passwords and hashes in the samples are placeholders. Do not reuse them.
- The HTML report embeds the analyzed config, including any secrets it contains.
  Store and share it carefully.

---

 ## License
 
 MIT © 2026

---

**👨‍💻 Author**
---
**Pranjal Panta**
