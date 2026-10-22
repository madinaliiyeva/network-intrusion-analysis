"""Run every SQL file in queries/ against the database and print the results."""
import sqlite3
from pathlib import Path

import pandas as pd

DB_PATH = Path("data/nsl_kdd.db")
QUERY_DIR = Path("queries")


def run_query(conn, sql_path):
    sql = sql_path.read_text()
    return pd.read_sql(sql, conn)


if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    for sql_path in sorted(QUERY_DIR.glob("*.sql")):
        print(f"\n=== {sql_path.stem} ===")
        print(run_query(conn, sql_path).to_string(index=False))
    conn.close()