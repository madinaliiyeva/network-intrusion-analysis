"""Train a machine learning model on KDDTrain+ and compare it with the rules.

The model is trained on the training file and scored on KDDTest+, a separate
file that contains attack variants the model never saw.
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

from evaluate_rules import score
from load_data import ATTACK_CATEGORY, COLUMNS
from rules import RULES

TRAIN_PATH = "data/KDDTrain+.txt"
TEST_PATH = "data/KDDTest+.txt"
CATEGORICAL = ["protocol_type", "service", "flag"]


def read(path):
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df["category"] = df["label"].map(ATTACK_CATEGORY)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


def features(df, columns=None):
    x = pd.get_dummies(df.drop(columns=["label", "difficulty", "category", "is_attack"]),
                       columns=CATEGORICAL)
    if columns is not None:
        x = x.reindex(columns=columns, fill_value=0)
    return x


if __name__ == "__main__":
    train = read(TRAIN_PATH)
    test = read(TEST_PATH)

    x_train = features(train)
    x_test = features(test, columns=x_train.columns)

    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(x_train, train["category"])
    predicted = model.predict(x_test)

    print("=== Random forest, scored on KDDTest+ ===")
    print(classification_report(test["category"], predicted, zero_division=0))

    print("=== Hand-written rules, scored on KDDTest+ ===")
    rows = []
    for rule in RULES:
        fired = rule.check(test)
        actual = test["category"] == rule.family
        _, _, _, precision, recall = score(fired, actual)
        rows.append({"rule": rule.name, "precision": round(precision, 3),
                     "recall": round(recall, 3)})
    print(pd.DataFrame(rows).to_string(index=False))

    print("\n=== Top 10 features the model relied on ===")
    importance = pd.Series(model.feature_importances_, index=x_train.columns)
    print(importance.sort_values(ascending=False).head(10).round(3).to_string())