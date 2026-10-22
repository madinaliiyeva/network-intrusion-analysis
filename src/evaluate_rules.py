"""Score each detection rule against the labeled data."""
import sqlite3

import pandas as pd

from rules import RULES

DB_PATH = "data/nsl_kdd.db"


def score(fired, actual):
    tp = int((fired & actual).sum())
    fp = int((fired & ~actual).sum())
    fn = int((~fired & actual).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return tp, fp, fn, precision, recall


if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM connections", conn)
    conn.close()

    rows = []
    any_fired = pd.Series(False, index=df.index)
    for rule in RULES:
        fired = rule.check(df)
        any_fired = any_fired | fired
        actual = df["category"] == rule.family
        tp, fp, fn, precision, recall = score(fired, actual)
        rows.append({
            "rule": rule.name,
            "technique": rule.technique.split(" ")[0],
            "target": rule.family,
            "fired": int(fired.sum()),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
        })
    print(pd.DataFrame(rows).to_string(index=False))

    tp, fp, fn, precision, recall = score(any_fired, df["is_attack"] == 1)
    print(f"\nAll rules combined vs. any attack: "
          f"precision={precision:.3f} recall={recall:.3f}")