# phishML

Phishing detection pipeline for raw `.eml` emails. CLI-first: parse -> feature extraction -> dataset -> baseline model -> scoring.

## Quickstart

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .

# Parse a single email
python -m phishml.cli parse --input .\data\sample.eml --output .\out.json

# Build dataset from folders (expects data/raw/phish and data/raw/ham)
python -m phishml.cli build-dataset --input-dir .\data\raw --output .\data\features.csv

# Build dataset from CSV text sources
python -m phishml.cli build-dataset-text --input-dir .\data\csv --output .\data\features_text.csv

# Merge multiple datasets
python -m phishml.cli merge-datasets --inputs .\data\features_text.csv .\data\features_eml.csv --output .\data\features_all.csv

# Train baseline model
python -m phishml.cli train --dataset .\data\features.csv --model-out .\models\baseline.pkl

# Score a single email
python -m phishml.cli score --model .\models\baseline.pkl --input .\data\sample.eml
```

## Dataset layout

```
 data/
   raw/
     phish/   # phishing .eml
     ham/     # benign .eml
```

## Notes
- Input is raw RFC 5322 `.eml`.
- No PII restrictions assumed, but the pipeline can be adapted to hash/strip fields.
- URL parsing avoids network calls; TLD detection is heuristic.
