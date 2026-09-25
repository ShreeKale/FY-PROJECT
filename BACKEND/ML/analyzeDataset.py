from pathlib import Path
import json
import ast
import re

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATASET_ROOT = (
    BASE_DIR
    / "dataset"
    / "windows_apt_2025"
)

DATASET_DIR = (
    DATASET_ROOT
    / "Windows-APT 2025 A Dataset for APT-Inspired Attack"
)

COMBINED_FILE = DATASET_DIR / "combined.csv"

MAPPING_FILE = next(
    DATASET_ROOT.rglob("log_to_scenario_mapping.csv")
)

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

MODEL_FILE = MODEL_DIR / "windows_apt_scenario_model.joblib"
META_FILE = MODEL_DIR / "windows_apt_scenario_metadata.json"


# ============================================================
# SETTINGS
# ============================================================

# Only use mappings whose attribution is relatively strong.
VALID_ATTRIBUTION = {
    "NARROWED",
    "UNIQUE-MATCH",
}

# Minimum samples required for a class to participate in the
# first supervised model.
MIN_CLASS_SAMPLES = 20

RANDOM_STATE = 42


# ============================================================
# HELPERS
# ============================================================

def clean_text(value):
    """Convert any dataset value into searchable text."""
    if pd.isna(value):
        return ""

    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)

    return str(value)


def parse_list_text(value):
    """
    Convert fields such as:
        ["T1078"]
        ["T1087", "T1059.003"]
    into a simple string.
    """
    if pd.isna(value):
        return ""

    text = str(value).strip()

    try:
        parsed = ast.literal_eval(text)

        if isinstance(parsed, list):
            return " ".join(str(x) for x in parsed)

    except Exception:
        pass

    return text


def build_event_text(row):
    """
    Build a compact textual representation of the important
    Windows/Wazuh fields.

    TF-IDF will learn useful patterns from these values.
    """

    fields = [
        "_source.rule.description",
        "_source.rule.groups",
        "_source.rule.mitre.technique",
        "_source.rule.mitre.id",
        "_source.rule.mitre.tactic",
        "_source.data.win.system.eventID",
        "_source.data.win.system.message",
        "_source.data.win.eventdata.commandLine",
        "_source.data.win.eventdata.parentImage",
        "_source.data.win.eventdata.newProcessName",
        "_source.data.win.eventdata.image",
        "_source.data.win.eventdata.targetFilename",
        "_source.data.win.eventdata.destinationIp",
        "_source.data.win.eventdata.destinationPort",
        "_source.data.win.eventdata.sourceIp",
        "_source.data.win.eventdata.sourcePort",
        "_source.data.win.eventdata.protocol",
        "_source.data.win.eventdata.targetUserName",
        "_source.data.win.eventdata.logonType",
        "_source.data.win.eventdata.authenticationPackageName",
        "_source.data.operation_type",
        "_source.data.type",
        "_source.syscheck.path",
        "_source.syscheck.event",
        "_source.full_log",
    ]

    parts = []

    for field in fields:
        if field in row.index:
            value = clean_text(row[field])

            if value:
                parts.append(f"{field}={value}")

    return " ".join(parts)


# ============================================================
# LOAD MAPPING
# ============================================================

print("=" * 70)
print("Windows-APT ML Training")
print("=" * 70)

print("\nLoading scenario mapping:")
print(MAPPING_FILE)

mapping = pd.read_csv(
    MAPPING_FILE,
    low_memory=False,
)

print(f"Mapping rows: {len(mapping):,}")


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading combined.csv:")
print(COMBINED_FILE)

combined = pd.read_csv(
    COMBINED_FILE,
    low_memory=False,
)

print(f"Dataset rows: {len(combined):,}")
print(f"Dataset columns: {len(combined.columns):,}")


# ============================================================
# VERIFY ROW ALIGNMENT
# ============================================================

if len(combined) != len(mapping):
    raise RuntimeError(
        "combined.csv and log_to_scenario_mapping.csv "
        "have different row counts."
    )

expected_indexes = np.arange(len(mapping))

if not np.array_equal(
    mapping["Row_Index"].to_numpy(),
    expected_indexes,
):
    raise RuntimeError(
        "Mapping Row_Index does not match combined.csv row order."
    )

print("\nRow alignment verified.")


# ============================================================
# JOIN MAPPING INFORMATION
# ============================================================

combined["_scenario_id"] = mapping["Scenario_ID"].values
combined["_scenario_name"] = mapping["Scenario_Name"].values
combined["_attribution_strength"] = (
    mapping["Attribution_Strength"].values
)
combined["_derived_label"] = mapping["Derived_Label"].values
combined["_mapping_evidence"] = mapping["Mapping_Evidence"].values
combined["_scenario_posterior"] = mapping["Scenario_Posterior"].values


# ============================================================
# SELECT STRONG MAPPINGS
# ============================================================

training = combined[
    combined["_attribution_strength"].isin(VALID_ATTRIBUTION)
].copy()

print("\nStrongly attributed rows:")
print(f"{len(training):,}")


# ============================================================
# REMOVE VERY SMALL CLASSES
# ============================================================

class_counts = training["_scenario_id"].value_counts()

valid_classes = class_counts[
    class_counts >= MIN_CLASS_SAMPLES
].index

training = training[
    training["_scenario_id"].isin(valid_classes)
].copy()

print("\nClasses used for training:")
print(
    training["_scenario_id"]
    .value_counts()
    .sort_index()
    .to_string()
)


# ============================================================
# BUILD TEXT FEATURES
# ============================================================

print("\nExtracting Windows event features...")

training["_event_text"] = training.apply(
    build_event_text,
    axis=1,
)

training = training[
    training["_event_text"].str.len() > 0
].copy()

print(
    f"Rows with usable event information: "
    f"{len(training):,}"
)


# ============================================================
# LABELS
# ============================================================

X = training["_event_text"]
y = training["_scenario_id"]


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y,
)

print("\nTrain rows:", len(X_train))
print("Test rows :", len(X_test))


# ============================================================
# MACHINE LEARNING PIPELINE
# ============================================================

model = Pipeline(
    steps=[
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                min_df=2,
                max_features=100000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
        ),
    ]
)


# ============================================================
# TRAIN
# ============================================================

print("\nTraining model...")

model.fit(
    X_train,
    y_train,
)

print("Training complete.")


# ============================================================
# EVALUATION
# ============================================================

print("\n" + "=" * 70)
print("MODEL EVALUATION")
print("=" * 70)

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions,
)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification report:")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0,
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

labels = sorted(y.unique())

cm = confusion_matrix(
    y_test,
    predictions,
    labels=labels,
)

cm_df = pd.DataFrame(
    cm,
    index=labels,
    columns=labels,
)

print("\nConfusion matrix:")
print(cm_df.to_string())


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    model,
    MODEL_FILE,
)

print("\nModel saved:")
print(MODEL_FILE)


# ============================================================
# SAVE METADATA
# ============================================================

metadata = {
    "model_type": "TF-IDF + LogisticRegression",
    "dataset": str(COMBINED_FILE),
    "mapping": str(MAPPING_FILE),
    "training_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "total_rows_used": int(len(training)),
    "accuracy": float(accuracy),
    "random_state": RANDOM_STATE,
    "minimum_class_samples": MIN_CLASS_SAMPLES,
    "valid_attribution": sorted(VALID_ATTRIBUTION),
    "classes": labels,
    "class_counts": {
        str(k): int(v)
        for k, v in y.value_counts().items()
    },
}

with open(
    META_FILE,
    "w",
    encoding="utf-8",
) as f:
    json.dump(
        metadata,
        f,
        indent=4,
    )

print("Metadata saved:")
print(META_FILE)

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)