# Network Intrusion Analyzer

SQL analysis and detection rules over the NSL-KDD benchmark dataset
(about 126,000 labeled network connections).

## Setup

    pip install -r requirements.txt
    mkdir -p data
    curl -L -o "data/KDDTrain+.txt" "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    python3 src/load_data.py
    python3 src/run_queries.py
    python3 src/evaluate_rules.py

## Note on the dataset

NSL-KDD is a benchmark dataset derived from 1999-era research traffic. It is
useful for comparing detection approaches but does not reflect modern traffic.

(Findings and more phases coming soon.)
