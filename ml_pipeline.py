"""
ml_pipeline.py - NIDS Machine Learning Pipeline (XGBoost Edition)
==================================================================
Upgraded pipeline utilizing Extreme Gradient Boosting for maximum 
classification accuracy on the NSL-KDD dataset.
"""

import io
import os
import re
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib

# ──────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────
ARFF_PATH     = os.path.join("data", "KDDTest+.arff") 
MODEL_PATH    = "nids_model.joblib"
ENCODERS_PATH = "feature_encoders.joblib"
RANDOM_STATE  = 42

CATEGORICAL_COLS = [
    "protocol_type", "service", "flag", "land", 
    "logged_in", "is_host_login", "is_guest_login",
]

TARGET_COL = "class"

# ──────────────────────────────────────────────────────────────
# STEP 1 — LOAD ARFF FILE (Unchanged - Good Logic)
# ──────────────────────────────────────────────────────────────
def load_arff(path: str = ARFF_PATH) -> pd.DataFrame:
    print(f"[ml_pipeline] Loading ARFF file: {path}")
    col_names, data_lines = [], []
    in_data_section = False

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("%"): continue
            if stripped.lower() == "@data":
                in_data_section = True
                continue
            if not in_data_section:
                m = re.match(r"@attribute\s+'?([^'\s]+)'?\s+", stripped, re.IGNORECASE)
                if m: col_names.append(m.group(1))
            else:
                if stripped: data_lines.append(stripped)

    csv_content = "\n".join(data_lines)
    df = pd.read_csv(io.StringIO(csv_content), header=None, names=col_names, skipinitialspace=True)

    str_cols = df.select_dtypes(include=["object"]).columns
    for col in str_cols:
        df[col] = df[col].str.strip()
    return df

# ──────────────────────────────────────────────────────────────
# STEP 2 — PREPROCESS (Unchanged)
# ──────────────────────────────────────────────────────────────
def preprocess(df: pd.DataFrame, encoders: dict = None, fit: bool = True):
    if encoders is None: encoders = {}
    df = df.copy()

    if TARGET_COL in df.columns:
        y = (df[TARGET_COL].str.strip().str.lower() != "normal").astype(int).values
        df.drop(columns=[TARGET_COL], inplace=True)
    else:
        y = None 

    for col in CATEGORICAL_COLS:
        if col not in df.columns: continue
        le = encoders.get(col, LabelEncoder())
        if fit:
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le 
        else:
            known = set(le.classes_)
            df[col] = df[col].astype(str).apply(lambda v: v if v in known else le.classes_[0])
            df[col] = le.transform(df[col])

    X = df.values.astype(float)
    return X, y, encoders

# ──────────────────────────────────────────────────────────────
# STEP 3 — TRAIN & EVALUATE (XGBoost Upgrade)
# ──────────────────────────────────────────────────────────────
def train_model():
    print("[ml_pipeline] ═══ Starting NSL-KDD XGBoost Pipeline ════")
    df = load_arff(ARFF_PATH)
    
    X, y, encoders = preprocess(df, fit=True)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    # Calculate class imbalance for XGBoost scale_pos_weight
    neg_class = np.sum(y_train == 0)
    pos_class = np.sum(y_train == 1)
    ratio = float(neg_class) / float(pos_class)

    # The Heavy Artillery: XGBoost
    clf = XGBClassifier(
        n_estimators=300,          # Number of boosting rounds
        max_depth=7,               # Deeper trees for complex feature interactions
        learning_rate=0.05,        # Slower learning rate prevents overfitting
        scale_pos_weight=ratio,    # Forces model to care about rare anomalies
        subsample=0.8,             # Uses 80% of data per tree (prevents overfitting)
        colsample_bytree=0.8,      # Uses 80% of features per tree
        random_state=RANDOM_STATE,
        n_jobs=-1,                 # Use all CPU cores
        eval_metric='logloss'
    )
    
    print("[ml_pipeline] Training Extreme Gradient Boosting model...")
    clf.fit(X_train, y_train)
    print("[ml_pipeline] Model trained!")

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[ml_pipeline] Test Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Anomaly"]))

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    print(f"[ml_pipeline] Model saved to {MODEL_PATH}")

    return clf, encoders

# ──────────────────────────────────────────────────────────────
# STEP 4 — LOAD FOR INFERENCE
# ──────────────────────────────────────────────────────────────
def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at '{MODEL_PATH}'.")
    clf = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
    return clf, encoders

if __name__ == "__main__":
    train_model()