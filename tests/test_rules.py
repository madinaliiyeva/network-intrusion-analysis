import pandas as pd

from rules import (brute_force, icmp_flood, port_scan, privilege_escalation,
                   syn_flood)

DEFAULTS = {
    "flag": "SF", "serror_rate": 0.0, "protocol_type": "tcp", "src_bytes": 100,
    "diff_srv_rate": 0.0, "num_failed_logins": 0, "root_shell": 0,
    "su_attempted": 0,
}


def make_df(*overrides):
    """Build a DataFrame where each row is DEFAULTS plus the given changes."""
    return pd.DataFrame([{**DEFAULTS, **change} for change in overrides])


def test_syn_flood_flags_unanswered_syns():
    df = make_df({"flag": "S0", "serror_rate": 1.0})
    assert syn_flood(df).tolist() == [True]


def test_syn_flood_ignores_normal_connection():
    df = make_df({})
    assert syn_flood(df).tolist() == [False]


def test_syn_flood_needs_high_error_rate():
    df = make_df({"flag": "S0", "serror_rate": 0.2})
    assert syn_flood(df).tolist() == [False]


def test_icmp_flood_flags_large_icmp():
    df = make_df({"protocol_type": "icmp", "src_bytes": 1032})
    assert icmp_flood(df).tolist() == [True]


def test_icmp_flood_ignores_small_icmp_and_large_tcp():
    df = make_df({"protocol_type": "icmp", "src_bytes": 18},
                 {"protocol_type": "tcp", "src_bytes": 1032})
    assert icmp_flood(df).tolist() == [False, False]


def test_port_scan_flags_rejected_connections_across_services():
    df = make_df({"flag": "REJ", "diff_srv_rate": 0.9})
    assert port_scan(df).tolist() == [True]


def test_port_scan_ignores_successful_connections():
    df = make_df({"flag": "SF", "diff_srv_rate": 0.9})
    assert port_scan(df).tolist() == [False]


def test_brute_force_flags_failed_logins():
    df = make_df({"num_failed_logins": 3}, {"num_failed_logins": 0})
    assert brute_force(df).tolist() == [True, False]


def test_privilege_escalation_flags_root_shell_or_su():
    df = make_df({"root_shell": 1}, {"su_attempted": 1}, {})
    assert privilege_escalation(df).tolist() == [True, True, False]