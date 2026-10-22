"""Detection rules as code.

Each rule takes a DataFrame of connections and returns a True/False Series
saying which rows the rule flags. The ATT&CK technique IDs are our best
mapping; verify each one at https://attack.mitre.org.
"""
from dataclasses import dataclass
from typing import Callable

import pandas as pd


@dataclass
class Rule:
    name: str
    family: str          # which attack family this rule targets
    technique: str       # MITRE ATT&CK technique
    description: str
    check: Callable[[pd.DataFrame], pd.Series]


def syn_flood(df):
    # SYN packets that never get an answer, at a high error rate.
    return (df["flag"] == "S0") & (df["serror_rate"] >= 0.8)


def icmp_flood(df):
    # Unusually large ICMP payloads.
    return (df["protocol_type"] == "icmp") & (df["src_bytes"] >= 500)


def port_scan(df):
    # Rejected or reset connections that hop across many different services.
    failed = df["flag"].isin(["REJ", "RSTR", "RSTO", "S0"])
    return failed & (df["diff_srv_rate"] >= 0.5)


def brute_force(df):
    # Failed logins on the connection.
    return df["num_failed_logins"] >= 1


def privilege_escalation(df):
    # A root shell obtained, or a su attempt.
    return (df["root_shell"] == 1) | (df["su_attempted"] >= 1)


RULES = [
    Rule("syn_flood", "dos", "T1498.001 Direct Network Flood",
         "Unanswered SYNs with a high error rate", syn_flood),
    Rule("icmp_flood", "dos", "T1498 Network Denial of Service",
         "Large ICMP payloads", icmp_flood),
    Rule("port_scan", "probe", "T1046 Network Service Discovery",
         "Failed connections spread across many services", port_scan),
    Rule("brute_force", "r2l", "T1110 Brute Force",
         "Failed login attempts", brute_force),
    Rule("privilege_escalation", "u2r", "T1068 Exploitation for Privilege Escalation",
         "Root shell or su attempt", privilege_escalation),
]