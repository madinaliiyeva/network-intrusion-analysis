import sqlite3

import pandas as pd

from load_data import ATTACK_CATEGORY, COLUMNS, load


def make_row(label):
    # 4 leading fields, 37 numeric fields, then label and difficulty.
    return [0, "tcp", "http", "SF"] + [0] * 37 + [label, 20]


def test_column_count_matches_dataset_format():
    assert len(COLUMNS) == 43


def test_attack_labels_map_to_expected_families():
    assert ATTACK_CATEGORY["normal"] == "normal"
    assert ATTACK_CATEGORY["neptune"] == "dos"
    assert ATTACK_CATEGORY["nmap"] == "probe"
    assert ATTACK_CATEGORY["guess_passwd"] == "r2l"
    assert ATTACK_CATEGORY["rootkit"] == "u2r"


def test_load_creates_table_with_category_and_attack_flag(tmp_path):
    csv_path = tmp_path / "sample.txt"
    rows = [make_row("normal"), make_row("neptune")]
    pd.DataFrame(rows).to_csv(csv_path, header=False, index=False)
    db_path = tmp_path / "sample.db"

    assert load(csv_path, db_path) == 2

    conn = sqlite3.connect(db_path)
    result = conn.execute(
        "SELECT label, category, is_attack FROM connections ORDER BY label"
    ).fetchall()
    conn.close()
    assert result == [("neptune", "dos", 1), ("normal", "normal", 0)]