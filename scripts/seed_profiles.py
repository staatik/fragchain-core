"""Seed the seven built-in logsource profiles (M13).

Run inside the API container with the DB up:

    python -m scripts.seed_profiles

Idempotent — re-runs leave existing rows alone unless body fields have
genuinely changed. The script NEVER flips the ``enabled`` flag on a
re-run: operator preference (enable / disable) wins. On a brand-new
deployment, ``linux-auditd`` and ``windows-security`` start enabled and
the other five start disabled.

Each profile carries:

* Sigma ``product`` / ``service`` — what the rule generator writes into
  the rule's logsource block.
* Field conventions — the field names common to that pipeline.
* Example rules — two or three short Sigma documents used as few-shot
  prompt context. These are hand-curated; M15's prompt template
  references them by index.

The seed data is intentionally embedded in this file (no separate JSON
file) so version control + diff review covers the canonical content.
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any

import structlog

from fragchain.db.session import dispose_engine, get_sessionmaker
from fragchain.profiles import ProfileStore

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Built-in profile data
# ---------------------------------------------------------------------------


BUILTIN_PROFILES: list[dict[str, Any]] = [
    {
        "name": "linux-auditd",
        "display_name": "Linux auditd",
        "platform": "linux",
        "description": (
            "Linux kernel audit subsystem. Default host-level audit "
            "trail on most enterprise distros."
        ),
        "sigma_product": "linux",
        "sigma_service": "auditd",
        "default_enabled": True,
        "field_conventions": {
            "type": "Audit record type (e.g. EXECVE, SYSCALL, PATH).",
            "exe": "Absolute path to the executing binary.",
            "comm": "Process command (typically argv[0] basename).",
            "a0": "First command-line argument.",
            "a1": "Second command-line argument.",
            "uid": "Real user ID of the actor.",
            "auid": (
                "Audit user ID — login user, unchanged by setuid; "
                "preferred over uid for attribution."
            ),
            "syscall": "Syscall name (e.g. execve, openat).",
            "key": (
                "Audit rule key set via auditctl -k, used to tag "
                "high-signal events."
            ),
        },
        "example_rules": [
            {
                "title": "Suspicious chmod 4755 (setuid bit) on a binary",
                "yaml": (
                    "title: Auditd Set-UID Bit Added\n"
                    "id: 00000000-0000-0000-0000-000000000001\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: linux\n"
                    "    service: auditd\n"
                    "detection:\n"
                    "    selection:\n"
                    "        type: SYSCALL\n"
                    "        syscall: chmod\n"
                    "        a1|startswith: '4'\n"
                    "    condition: selection\n"
                    "falsepositives:\n"
                    "    - Package installers\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Detects chmod calls where the new mode starts "
                    "with '4', which sets the setuid bit. Compare "
                    "the second argument to chmod (a1) using a "
                    "startswith match against the octal mode."
                ),
            },
            {
                "title": "Modification of /etc/passwd",
                "yaml": (
                    "title: Auditd /etc/passwd Modification\n"
                    "id: 00000000-0000-0000-0000-000000000002\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: linux\n"
                    "    service: auditd\n"
                    "detection:\n"
                    "    selection:\n"
                    "        type: PATH\n"
                    "        name: /etc/passwd\n"
                    "    write:\n"
                    "        syscall:\n"
                    "            - openat\n"
                    "            - open\n"
                    "    condition: selection and write\n"
                    "level: medium\n"
                ),
                "explanation": (
                    "Watches PATH records targeting /etc/passwd "
                    "joined with a write-mode syscall. Demonstrates "
                    "combining selections with AND."
                ),
            },
        ],
    },
    {
        "name": "linux-sysmon",
        "display_name": "Sysmon for Linux",
        "platform": "linux",
        "description": (
            "Microsoft Sysmon for Linux. Uses the same field schema as "
            "Windows Sysmon so cross-platform rules can share field names."
        ),
        "sigma_product": "linux",
        "sigma_service": "sysmon",
        "default_enabled": False,
        "field_conventions": {
            "EventID": (
                "Sysmon event ID — 1 ProcessCreation, 3 NetworkConnect, "
                "11 FileCreate, etc."
            ),
            "Image": "Absolute path to the executing binary.",
            "CommandLine": "Full command line.",
            "ParentImage": "Absolute path to the parent process binary.",
            "ParentCommandLine": "Parent process command line.",
            "User": "Effective user (uid:gid format on Linux).",
            "ProcessId": "PID of the new process.",
            "ProcessGuid": "Sysmon-assigned process correlation GUID.",
        },
        "example_rules": [
            {
                "title": "Reverse shell via bash -i",
                "yaml": (
                    "title: Reverse Shell via bash -i\n"
                    "id: 00000000-0000-0000-0000-000000000003\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: linux\n"
                    "    service: sysmon\n"
                    "detection:\n"
                    "    selection:\n"
                    "        EventID: 1\n"
                    "        Image|endswith: '/bash'\n"
                    "        CommandLine|contains|all:\n"
                    "            - '-i'\n"
                    "            - '/dev/tcp/'\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Process creation events (EventID 1) where bash "
                    "is launched interactively with a TCP socket "
                    "redirection — classic reverse shell pattern."
                ),
            },
            {
                "title": "curl piping a script to a shell",
                "yaml": (
                    "title: Curl Piped Into Shell\n"
                    "id: 00000000-0000-0000-0000-000000000004\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: linux\n"
                    "    service: sysmon\n"
                    "detection:\n"
                    "    selection:\n"
                    "        EventID: 1\n"
                    "        CommandLine|contains:\n"
                    "            - 'curl '\n"
                    "            - '| sh'\n"
                    "    condition: selection\n"
                    "level: medium\n"
                ),
                "explanation": (
                    "Watches for the canonical pipe-curl-to-shell "
                    "install pattern in a single CommandLine field."
                ),
            },
        ],
    },
    {
        "name": "linux-falco",
        "display_name": "Falco (container / k8s)",
        "platform": "linux",
        "description": (
            "Falco runtime security — eBPF / kmod, focused on "
            "container and Kubernetes workloads."
        ),
        "sigma_product": "linux",
        "sigma_service": "falco",
        "default_enabled": False,
        "field_conventions": {
            "rule": "Falco rule name that fired.",
            "priority": "Falco priority (Emergency..Debug).",
            "proc.name": "Process name (basename).",
            "proc.cmdline": "Full process command line.",
            "container.id": "Container ID (Docker / containerd short ID).",
            "container.image": "Container image name + tag.",
            "k8s.pod.name": "Pod name.",
            "k8s.ns.name": "Pod namespace.",
            "fd.name": "File descriptor target (file path or socket).",
        },
        "example_rules": [
            {
                "title": "Shell spawned inside a container",
                "yaml": (
                    "title: Falco Shell In Container\n"
                    "id: 00000000-0000-0000-0000-000000000005\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: linux\n"
                    "    service: falco\n"
                    "detection:\n"
                    "    selection:\n"
                    "        rule: 'Terminal shell in container'\n"
                    "    condition: selection\n"
                    "level: medium\n"
                ),
                "explanation": (
                    "Falco bundles a built-in rule for shells "
                    "spawned in containers — Sigma rules over Falco "
                    "logs typically pivot on the Falco rule name."
                ),
            },
            {
                "title": "Sensitive mount inside a container",
                "yaml": (
                    "title: Falco Sensitive Mount\n"
                    "id: 00000000-0000-0000-0000-000000000006\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: linux\n"
                    "    service: falco\n"
                    "detection:\n"
                    "    selection:\n"
                    "        rule: 'Launch Sensitive Mount Container'\n"
                    "        priority:\n"
                    "            - Warning\n"
                    "            - Error\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Pivots on Falco's bundled sensitive-mount rule "
                    "and narrows on priority."
                ),
            },
        ],
    },
    {
        "name": "windows-security",
        "display_name": "Windows Security Event Log",
        "platform": "windows",
        "description": (
            "Native Windows Security channel. Always available without "
            "a Sysmon install — preferred default for Windows EDR rules."
        ),
        "sigma_product": "windows",
        "sigma_service": "security",
        "default_enabled": True,
        "field_conventions": {
            "EventID": (
                "Security log event ID — 4624 logon, 4688 process "
                "creation, 4720 user created, etc."
            ),
            "TargetUserName": "Account name acted on.",
            "SubjectUserName": "Account name performing the action.",
            "LogonType": "Logon type (2 interactive, 3 network, 10 RDP, etc.).",
            "NewProcessName": "Full path to the new process (4688).",
            "ParentProcessName": "Full path to the parent process (4688).",
            "CommandLine": (
                "Command line — requires audit policy "
                "'Include command line in process creation events'."
            ),
            "IpAddress": "Source IP for remote logon events.",
        },
        "example_rules": [
            {
                "title": "Local user account created",
                "yaml": (
                    "title: New Local User Account\n"
                    "id: 00000000-0000-0000-0000-000000000007\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: windows\n"
                    "    service: security\n"
                    "detection:\n"
                    "    selection:\n"
                    "        EventID: 4720\n"
                    "    condition: selection\n"
                    "level: medium\n"
                ),
                "explanation": (
                    "4720 fires on local-user creation. Single-field "
                    "selection — the simplest Sigma shape."
                ),
            },
            {
                "title": "Logon with explicit credentials from suspicious host",
                "yaml": (
                    "title: 4624 Logon From RFC1918 With Explicit Creds\n"
                    "id: 00000000-0000-0000-0000-000000000008\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: windows\n"
                    "    service: security\n"
                    "detection:\n"
                    "    selection:\n"
                    "        EventID: 4624\n"
                    "        LogonType: 9\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "LogonType 9 = NewCredentials, used by "
                    "runas /netonly. Suspicious outside of admin "
                    "tooling."
                ),
            },
        ],
    },
    {
        "name": "windows-sysmon",
        "display_name": "Windows Sysmon",
        "platform": "windows",
        "description": (
            "Sysinternals Sysmon. Optional but extremely common on "
            "Windows endpoints; provides finer process / network detail "
            "than the Security log alone."
        ),
        "sigma_product": "windows",
        "sigma_service": "sysmon",
        "default_enabled": False,
        "field_conventions": {
            "EventID": (
                "Sysmon event ID — 1 ProcessCreation, 3 NetworkConnect, "
                "7 ImageLoad, 11 FileCreate, 22 DNSQuery, etc."
            ),
            "Image": "Absolute path to the executing binary.",
            "OriginalFileName": "PE OriginalFilename (resists renaming).",
            "CommandLine": "Full command line.",
            "ParentImage": "Absolute path to the parent process binary.",
            "ParentCommandLine": "Parent process command line.",
            "Hashes": "Pipe-delimited hashes (MD5, SHA1, SHA256, IMPHASH).",
            "User": "Effective user (DOMAIN\\\\user).",
            "TargetFilename": "File path being created/modified (EventID 11).",
            "QueryName": "DNS query (EventID 22).",
        },
        "example_rules": [
            {
                "title": "PowerShell encoded command",
                "yaml": (
                    "title: PowerShell Encoded Command\n"
                    "id: 00000000-0000-0000-0000-000000000009\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: windows\n"
                    "    service: sysmon\n"
                    "detection:\n"
                    "    selection:\n"
                    "        EventID: 1\n"
                    "        OriginalFileName: PowerShell.EXE\n"
                    "        CommandLine|contains:\n"
                    "            - ' -enc '\n"
                    "            - ' -EncodedCommand'\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Detects powershell.exe launched with an "
                    "encoded command. Use OriginalFileName to "
                    "resist file rename evasion."
                ),
            },
            {
                "title": "rundll32 spawning network connection",
                "yaml": (
                    "title: rundll32 Network Connection\n"
                    "id: 00000000-0000-0000-0000-00000000000a\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: windows\n"
                    "    service: sysmon\n"
                    "detection:\n"
                    "    selection:\n"
                    "        EventID: 3\n"
                    "        Image|endswith: '\\\\rundll32.exe'\n"
                    "        DestinationPort:\n"
                    "            - 80\n"
                    "            - 443\n"
                    "            - 8080\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "rundll32 making outbound HTTP/S is suspicious — "
                    "commonly used by malware loaders."
                ),
            },
        ],
    },
    {
        "name": "network-zeek",
        "display_name": "Zeek network logs",
        "platform": "network",
        "description": (
            "Zeek (formerly Bro) protocol-aware network logs. Rules "
            "typically pivot on conn.log, http.log, dns.log."
        ),
        "sigma_product": "zeek",
        "sigma_service": "conn",
        "default_enabled": False,
        "field_conventions": {
            "id.orig_h": "Source IP.",
            "id.orig_p": "Source port.",
            "id.resp_h": "Destination IP.",
            "id.resp_p": "Destination port.",
            "proto": "L4 protocol (tcp / udp / icmp).",
            "service": "Application protocol inferred by Zeek.",
            "host": "HTTP Host header (http.log).",
            "uri": "HTTP request URI (http.log).",
            "query": "DNS query name (dns.log).",
        },
        "example_rules": [
            {
                "title": "Outbound connection to known C2 port",
                "yaml": (
                    "title: Zeek Outbound Cobalt Strike Default Port\n"
                    "id: 00000000-0000-0000-0000-00000000000b\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: zeek\n"
                    "    service: conn\n"
                    "detection:\n"
                    "    selection:\n"
                    "        id.resp_p: 50050\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Cobalt Strike's default Team Server port is "
                    "50050. Connections out to it are high-signal."
                ),
            },
            {
                "title": "DNS query to known DGA-style domain length",
                "yaml": (
                    "title: Zeek Unusually Long DNS Query\n"
                    "id: 00000000-0000-0000-0000-00000000000c\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: zeek\n"
                    "    service: dns\n"
                    "detection:\n"
                    "    selection:\n"
                    "        query|re: '^[a-z0-9]{40,}\\\\..+'\n"
                    "    condition: selection\n"
                    "level: medium\n"
                ),
                "explanation": (
                    "Very long, single-label DNS queries are a "
                    "common DGA / exfiltration shape."
                ),
            },
        ],
    },
    {
        "name": "network-suricata",
        "display_name": "Suricata IDS alerts",
        "platform": "network",
        "description": (
            "Suricata EVE JSON alerts. Sigma rules over Suricata "
            "typically pivot on alert.signature / alert.category."
        ),
        "sigma_product": "suricata",
        "sigma_service": "alert",
        "default_enabled": False,
        "field_conventions": {
            "event_type": "EVE event type (alert, dns, http, flow, etc.).",
            "alert.signature": "Signature description string.",
            "alert.signature_id": "SID — numeric signature ID.",
            "alert.category": "Signature category (e.g. 'Trojan Activity').",
            "alert.severity": "Severity (1 high .. 4 low).",
            "src_ip": "Source IP.",
            "dest_ip": "Destination IP.",
            "dest_port": "Destination port.",
            "proto": "L4 protocol.",
        },
        "example_rules": [
            {
                "title": "Suricata alert classified as Trojan Activity",
                "yaml": (
                    "title: Suricata Trojan Category Alert\n"
                    "id: 00000000-0000-0000-0000-00000000000d\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: suricata\n"
                    "    service: alert\n"
                    "detection:\n"
                    "    selection:\n"
                    "        event_type: alert\n"
                    "        alert.category: 'A Network Trojan was Detected'\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Pivots on Suricata's 'A Network Trojan was "
                    "Detected' category. Generic but high-signal "
                    "baseline."
                ),
            },
            {
                "title": "Suricata high-severity alert",
                "yaml": (
                    "title: Suricata Severity 1 Alert\n"
                    "id: 00000000-0000-0000-0000-00000000000e\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    product: suricata\n"
                    "    service: alert\n"
                    "detection:\n"
                    "    selection:\n"
                    "        event_type: alert\n"
                    "        alert.severity: 1\n"
                    "    condition: selection\n"
                    "level: high\n"
                ),
                "explanation": (
                    "Severity 1 is Suricata's top class. Useful as "
                    "a catch-all when more specific signatures aren't "
                    "available."
                ),
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def _seed_one(spec: dict[str, Any]) -> tuple[str, str]:
    """Seed (or refresh) one built-in profile.

    Each profile is committed in its own session so a transient failure
    on profile N doesn't roll back the rows already written for 1..N-1.
    """
    sm = get_sessionmaker()
    async with sm() as session:
        store = ProfileStore(session)
        state, view = await store.upsert_builtin(
            name=spec["name"],
            display_name=spec["display_name"],
            platform=spec["platform"],
            description=spec.get("description"),
            sigma_product=spec.get("sigma_product"),
            sigma_service=spec.get("sigma_service"),
            field_conventions=spec["field_conventions"],
            example_rules=spec["example_rules"],
            default_enabled=bool(spec.get("default_enabled", False)),
        )
        await session.commit()
        return state, str(view.id)


async def _run() -> None:
    for spec in BUILTIN_PROFILES:
        state, profile_id = await _seed_one(spec)
        logger.info(
            "seed.profile",
            name=spec["name"],
            state=state,
            profile_id=profile_id,
        )
        print(f"{state.upper():>10}  {spec['name']:<20}  id={profile_id}")


async def _run_and_dispose() -> None:
    try:
        await _run()
    finally:
        await dispose_engine()


def main() -> None:
    asyncio.run(_run_and_dispose())


if __name__ == "__main__":
    main()
    sys.exit(0)
