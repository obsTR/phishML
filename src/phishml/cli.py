from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

import pandas as pd

from .features import extract_features
from .model import NUMERIC_FEATURES, train_baseline, score_email
from .parser import parse_eml, parsed_to_dict


def cmd_parse(args: argparse.Namespace) -> int:
    parsed = parse_eml(args.input)
    data = parsed_to_dict(parsed)
    if args.output:
        Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        print(json.dumps(data, indent=2))
    return 0


def _iter_eml_files(input_dir: Path):
    for path in input_dir.rglob("*.eml"):
        yield path


def cmd_build_dataset(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir)
    rows = []

    for path in _iter_eml_files(input_dir):
        label = None
        parent = path.parent.name.lower()
        if parent in {"phish", "phishing", "malicious"}:
            label = 1
        elif parent in {"ham", "benign", "legit"}:
            label = 0

        parsed = parse_eml(path)
        data = parsed_to_dict(parsed)
        features = extract_features(data)
        row = {
            **features,
            "text": (data.get("subject", "") + "\n" + data.get("body_text", "")).strip(),
            "label": label,
            "path": str(path),
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    print(f"Wrote {len(df)} rows to {output}")
    return 0


def _normalize_label(value):
    if value is None:
        return None
    if isinstance(value, (int, float)) and value in (0, 1):
        return int(value)

    text = str(value).strip().lower()
    if text in {"1", "phish", "phishing", "spam", "malicious", "fraud"}:
        return 1
    if text in {"0", "ham", "benign", "legit", "safe"}:
        return 0
    return None


def _build_text_row(subject: str, body: str, label, source: str) -> dict:
    parsed = {
        "subject": subject or "",
        "body_text": body or "",
        "body_html": "",
        "urls": [],
        "headers": {"return_path": "", "received": []},
        "attachments": [],
        "from_email": "",
        "reply_to_email": "",
    }
    features = extract_features(parsed)
    return {
        **features,
        "text": (parsed["subject"] + "\n" + parsed["body_text"]).strip(),
        "label": label,
        "path": source,
    }


def cmd_build_dataset_text(args: argparse.Namespace) -> int:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    input_paths = []
    if args.input_csv:
        input_paths.append(Path(args.input_csv))
    if args.input_dir:
        input_paths.extend(sorted(Path(args.input_dir).rglob("*.csv")))

    if not input_paths:
        raise ValueError("Provide --input-csv or --input-dir")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    out_fields = [*NUMERIC_FEATURES, "text", "label", "path"]
    written = 0

    with output.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=out_fields)
        writer.writeheader()

        for path in input_paths:
            with path.open("r", newline="", encoding="utf-8", errors="replace") as f_in:
                reader = csv.DictReader(f_in)
                if reader.fieldnames is None:
                    continue

                fieldnames = {name.lower(): name for name in reader.fieldnames}
                subject_col = fieldnames.get("subject")
                body_col = fieldnames.get("body")
                text_col = fieldnames.get("email text") or fieldnames.get("email_text") or fieldnames.get("text")
                label_col = fieldnames.get("label")

                for idx, row in enumerate(reader, start=1):
                    if label_col is None:
                        continue
                    label = _normalize_label(row.get(label_col))
                    if label is None:
                        continue

                    if text_col:
                        subject = ""
                        body = row.get(text_col, "")
                    else:
                        subject = row.get(subject_col, "") if subject_col else ""
                        body = row.get(body_col, "") if body_col else ""

                    source = f"{path}:{idx}"
                    out_row = _build_text_row(subject, body, label, source)
                    writer.writerow(out_row)
                    written += 1

    print(f"Wrote {written} rows to {output}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    train_baseline(args.dataset, args.model_out)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    result = score_email(args.model, args.input)
    print(json.dumps(result, indent=2))
    return 0


def cmd_merge_datasets(args: argparse.Namespace) -> int:
    input_paths = [Path(p) for p in args.inputs]
    frames = []
    for path in input_paths:
        frames.append(pd.read_csv(path))

    df = pd.concat(frames, ignore_index=True)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    print(f"Wrote {len(df)} rows to {output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishml")
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse", help="Parse a raw .eml to JSON")
    p_parse.add_argument("--input", required=True)
    p_parse.add_argument("--output")
    p_parse.set_defaults(func=cmd_parse)

    p_build = sub.add_parser("build-dataset", help="Build features.csv from a folder of .eml files")
    p_build.add_argument("--input-dir", required=True)
    p_build.add_argument("--output", required=True)
    p_build.set_defaults(func=cmd_build_dataset)

    p_build_text = sub.add_parser("build-dataset-text", help="Build features.csv from CSV text datasets")
    p_build_text.add_argument("--input-csv")
    p_build_text.add_argument("--input-dir")
    p_build_text.add_argument("--output", required=True)
    p_build_text.set_defaults(func=cmd_build_dataset_text)

    p_merge = sub.add_parser("merge-datasets", help="Merge multiple feature CSVs")
    p_merge.add_argument("--inputs", nargs="+", required=True)
    p_merge.add_argument("--output", required=True)
    p_merge.set_defaults(func=cmd_merge_datasets)

    p_train = sub.add_parser("train", help="Train a baseline model")
    p_train.add_argument("--dataset", required=True)
    p_train.add_argument("--model-out", required=True)
    p_train.set_defaults(func=cmd_train)

    p_score = sub.add_parser("score", help="Score a single .eml using a trained model")
    p_score.add_argument("--model", required=True)
    p_score.add_argument("--input", required=True)
    p_score.set_defaults(func=cmd_score)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
