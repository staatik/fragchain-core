"""Starter mapping data for the assessment chain-synthesis bridge.

Resolves spec §11 open question on the curated mapping tables by shipping
~10 common vuln classes mapped to ATT&CK TTPs in their typical exploitation
order, plus a per-TTP observable-category relevance table.

Operators extend these tables via the API or SQL; this file is the cold-start
seed only. Sourced from MITRE ATT&CK descriptions and CTID's published
common-mappings work; entries are kept narrow on purpose — better to omit a
weak mapping than push a synthesis run toward a wrong TTP.
"""
from __future__ import annotations

from typing import Literal, TypedDict


ObservableCategoryLiteral = Literal[
    "process", "command_line", "file", "network",
    "registry", "parent_child", "api_call",
]


class VulnClassRow(TypedDict):
    vuln_class: str
    technique_id: str
    tactic_id: str
    tactic: str
    technique_name: str
    seq_order: int
    base_confidence: float
    notes: str


class CategoryRelevanceRow(TypedDict):
    technique_id: str
    category: ObservableCategoryLiteral
    weight: float


VULN_CLASS_SEED: list[VulnClassRow] = [
    # Deserialization RCE
    {"vuln_class": "deserialization rce", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.80,
     "notes": "Initial code execution via crafted serialized payload."},
    {"vuln_class": "deserialization rce", "technique_id": "T1059",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "Command and Scripting Interpreter",
     "seq_order": 2, "base_confidence": 0.70,
     "notes": "Post-deserialization shell or script execution."},
    # SSRF
    {"vuln_class": "ssrf", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70,
     "notes": "SSRF as the public-facing entry point."},
    {"vuln_class": "ssrf", "technique_id": "T1090",
     "tactic_id": "TA0011", "tactic": "Command and Control",
     "technique_name": "Proxy", "seq_order": 2, "base_confidence": 0.60,
     "notes": "Server acts as a proxy to reach internal or cloud-metadata targets."},
    # Path traversal
    {"vuln_class": "path traversal", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70, "notes": ""},
    {"vuln_class": "path traversal", "technique_id": "T1083",
     "tactic_id": "TA0007", "tactic": "Discovery",
     "technique_name": "File and Directory Discovery",
     "seq_order": 2, "base_confidence": 0.60, "notes": ""},
    {"vuln_class": "path traversal", "technique_id": "T1005",
     "tactic_id": "TA0009", "tactic": "Collection",
     "technique_name": "Data from Local System",
     "seq_order": 3, "base_confidence": 0.55, "notes": ""},
    # Auth bypass
    {"vuln_class": "auth bypass", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70, "notes": ""},
    {"vuln_class": "auth bypass", "technique_id": "T1078",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Valid Accounts",
     "seq_order": 2, "base_confidence": 0.55,
     "notes": "Bypass results in effective valid-account access."},
    # SQL injection
    {"vuln_class": "sql injection", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.75, "notes": ""},
    {"vuln_class": "sql injection", "technique_id": "T1213",
     "tactic_id": "TA0009", "tactic": "Collection",
     "technique_name": "Data from Information Repositories",
     "seq_order": 2, "base_confidence": 0.60, "notes": ""},
    # XSS
    {"vuln_class": "xss", "technique_id": "T1189",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Drive-by Compromise",
     "seq_order": 1, "base_confidence": 0.65, "notes": ""},
    {"vuln_class": "xss", "technique_id": "T1059.007",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "JavaScript", "seq_order": 2,
     "base_confidence": 0.65, "notes": ""},
    # Command injection
    {"vuln_class": "command injection", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.80, "notes": ""},
    {"vuln_class": "command injection", "technique_id": "T1059",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "Command and Scripting Interpreter",
     "seq_order": 2, "base_confidence": 0.80, "notes": ""},
    # Memory corruption
    {"vuln_class": "memory corruption", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.70, "notes": ""},
    {"vuln_class": "memory corruption", "technique_id": "T1203",
     "tactic_id": "TA0002", "tactic": "Execution",
     "technique_name": "Exploitation for Client Execution",
     "seq_order": 2, "base_confidence": 0.65, "notes": ""},
    # Information disclosure
    {"vuln_class": "information disclosure", "technique_id": "T1190",
     "tactic_id": "TA0001", "tactic": "Initial Access",
     "technique_name": "Exploit Public-Facing Application",
     "seq_order": 1, "base_confidence": 0.60, "notes": ""},
    {"vuln_class": "information disclosure", "technique_id": "T1213",
     "tactic_id": "TA0009", "tactic": "Collection",
     "technique_name": "Data from Information Repositories",
     "seq_order": 2, "base_confidence": 0.55, "notes": ""},
    # DoS
    {"vuln_class": "denial of service", "technique_id": "T1499",
     "tactic_id": "TA0040", "tactic": "Impact",
     "technique_name": "Endpoint Denial of Service",
     "seq_order": 1, "base_confidence": 0.65, "notes": ""},
    {"vuln_class": "denial of service", "technique_id": "T1498",
     "tactic_id": "TA0040", "tactic": "Impact",
     "technique_name": "Network Denial of Service",
     "seq_order": 2, "base_confidence": 0.50, "notes": ""},
]


CATEGORY_RELEVANCE_SEED: list[CategoryRelevanceRow] = [
    # T1190 — Exploit Public-Facing Application
    {"technique_id": "T1190", "category": "network", "weight": 1.00},
    {"technique_id": "T1190", "category": "command_line", "weight": 0.70},
    # T1059 — Command and Scripting Interpreter
    {"technique_id": "T1059", "category": "process", "weight": 1.00},
    {"technique_id": "T1059", "category": "command_line", "weight": 1.00},
    {"technique_id": "T1059", "category": "parent_child", "weight": 0.90},
    # T1059.007 — JavaScript
    {"technique_id": "T1059.007", "category": "process", "weight": 0.80},
    {"technique_id": "T1059.007", "category": "command_line", "weight": 0.70},
    # T1090 — Proxy
    {"technique_id": "T1090", "category": "network", "weight": 1.00},
    # T1083 — File and Directory Discovery
    {"technique_id": "T1083", "category": "file", "weight": 1.00},
    {"technique_id": "T1083", "category": "api_call", "weight": 0.60},
    # T1005 — Data from Local System
    {"technique_id": "T1005", "category": "file", "weight": 1.00},
    # T1078 — Valid Accounts
    {"technique_id": "T1078", "category": "api_call", "weight": 0.80},
    {"technique_id": "T1078", "category": "network", "weight": 0.60},
    # T1213 — Data from Information Repositories
    {"technique_id": "T1213", "category": "api_call", "weight": 0.90},
    {"technique_id": "T1213", "category": "network", "weight": 0.60},
    # T1189 — Drive-by Compromise
    {"technique_id": "T1189", "category": "network", "weight": 0.90},
    {"technique_id": "T1189", "category": "process", "weight": 0.60},
    # T1203 — Exploitation for Client Execution
    {"technique_id": "T1203", "category": "process", "weight": 1.00},
    {"technique_id": "T1203", "category": "parent_child", "weight": 0.70},
    # T1499 — Endpoint Denial of Service
    {"technique_id": "T1499", "category": "network", "weight": 1.00},
    # T1498 — Network Denial of Service
    {"technique_id": "T1498", "category": "network", "weight": 1.00},
]
