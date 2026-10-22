"""Load the NSL-KDD training data into a SQLite database."""
import sqlite3
from pathlib import Path

import pandas as pd

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

# Every attack label belongs to one of four families.
ATTACK_CATEGORY = {"normal": "normal"}
for name in ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
             "udpstorm", "processtable", "worm", "mailbomb"]:
    ATTACK_CATEGORY[name] = "dos"
for name in ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"]:
    ATTACK_CATEGORY[name] = "probe"
for name in ["guess_passwd", "ftp_write", "imap", "phf", "multihop",
             "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
             "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"]:
    ATTACK_CATEGORY[name] = "r2l"
for name in ["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
             "xterm", "ps"]:
    ATTACK_CATEGORY[name] = "u2r"


def load(csv_path, db_path):
    df = pd.read_csv(csv_path, header=None, names=COLUMNS)
    df["category"] = df["label"].map(ATTACK_CATEGORY)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    unmapped = df[df["category"].isna()]["label"].unique()
    if len(unmapped) > 0:
        print("Warning: labels with no category:", list(unmapped))
    conn = sqlite3.connect(db_path)
    df.to_sql("connections", conn, if_exists="replace", index=False)
    conn.close()
    return len(df)


if __name__ == "__main__":
    csv_path = Path("data/KDDTrain+.txt")
    db_path = Path("data/nsl_kdd.db")
    rows = load(csv_path, db_path)
    print(f"Loaded {rows} rows into {db_path}")