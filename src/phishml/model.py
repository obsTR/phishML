from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import extract_features
from .parser import parse_eml, parsed_to_dict


NUMERIC_FEATURES = [
    "subject_length",
    "body_length",
    "num_exclamations",
    "num_caps_words",
    "has_urgency_terms",
    "has_credential_terms",
    "num_urls",
    "num_unique_domains",
    "num_ip_urls",
    "num_shorteners",
    "avg_url_length",
    "has_at_symbol_url",
    "num_suspicious_tlds",
    "received_count",
    "from_replyto_mismatch",
    "return_path_mismatch",
    "num_html_links",
    "link_text_mismatch_count",
    "num_forms",
    "has_hidden_text",
    "num_attachments",
    "has_executable_attachment",
    "max_attachment_size",
]


def _build_pipeline() -> Pipeline:
    text_features = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.9)
    preprocessor = ColumnTransformer(
        transformers=[
            ("text", text_features, "text"),
            ("num", StandardScaler(), NUMERIC_FEATURES),
        ],
        remainder="drop",
    )

    clf = LogisticRegression(max_iter=1000, class_weight="balanced", solver="liblinear")
    return Pipeline(steps=[("prep", preprocessor), ("clf", clf)])


def train_baseline(dataset_path: str, model_out: str) -> None:
    df = pd.read_csv(dataset_path)

    if "label" not in df.columns:
        raise ValueError("Dataset must include a 'label' column")

    df = df.dropna(subset=["label"])
    X = df
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = _build_pipeline()
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, preds, digits=4))
    print("ROC AUC:", roc_auc_score(y_test, probs))

    Path(model_out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_out)
    print(f"Saved model to {model_out}")


def score_email(model_path: str, eml_path: str) -> dict:
    model = joblib.load(model_path)

    parsed = parse_eml(eml_path)
    data = parsed_to_dict(parsed)
    features = extract_features(data)

    row = {
        **features,
        "text": (data.get("subject", "") + "\n" + data.get("body_text", "")).strip(),
    }

    df = pd.DataFrame([row])
    proba = float(model.predict_proba(df)[0, 1])
    score = int(round(proba * 100))

    return {
        "score": score,
        "probability": proba,
    }
