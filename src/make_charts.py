"""Create charts from the database and the rule evaluations."""
import sqlite3
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from ml_baseline import read
from evaluate_rules import score
from rules import RULES

DB_PATH = "data/nsl_kdd.db"
CHART_DIR = Path("charts")


def chart_attack_rate_by_protocol(conn):
    df = pd.read_sql(Path("queries/attack_rate_by_protocol.sql").read_text(), conn)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(df["protocol_type"], df["attack_pct"], color="#4c72b0")
    ax.set_ylabel("Share of connections that are attacks (%)")
    ax.set_title("Attack rate by protocol (NSL-KDD training data)")
    for i, value in enumerate(df["attack_pct"]):
        ax.text(i, value + 1, f"{value}%", ha="center")
    fig.tight_layout()
    fig.savefig(CHART_DIR / "attack_rate_by_protocol.png", dpi=150)
    plt.close(fig)


def chart_category_counts(conn):
    df = pd.read_sql(
        "SELECT category, COUNT(*) AS total FROM connections "
        "GROUP BY category ORDER BY total DESC", conn)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(df["category"], df["total"], color="#55a868")
    ax.set_yscale("log")
    ax.set_ylabel("Connections (log scale)")
    ax.set_title("Connections by category")
    fig.tight_layout()
    fig.savefig(CHART_DIR / "category_counts.png", dpi=150)
    plt.close(fig)


def chart_rule_recall_train_vs_test():
    train = read("data/KDDTrain+.txt")
    test = read("data/KDDTest+.txt")
    names, train_recall, test_recall = [], [], []
    for rule in RULES:
        names.append(rule.name)
        for data, store in ((train, train_recall), (test, test_recall)):
            fired = rule.check(data)
            actual = data["category"] == rule.family
            store.append(score(fired, actual)[4])
    x = range(len(names))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - 0.2 for i in x], train_recall, width=0.4, label="Training data")
    ax.bar([i + 0.2 for i in x], test_recall, width=0.4, label="Test data")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_ylabel("Recall")
    ax.set_ylim(0, 1)
    ax.set_title("Detection rule recall: training vs. test data")
    ax.legend()
    fig.tight_layout()
    fig.savefig(CHART_DIR / "rule_recall_train_vs_test.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    CHART_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    chart_attack_rate_by_protocol(conn)
    chart_category_counts(conn)
    conn.close()
    chart_rule_recall_train_vs_test()
    print("Charts saved in charts/")