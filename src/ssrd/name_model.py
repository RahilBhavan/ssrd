"""Character n-gram name classifier for the CT filter (SPEC R2).

Positives: CBR-listed registrable labels. Negatives: the unfiltered CT background sample.
Training needs the optional `train` dependency group (scikit-learn); inference is pure Python
(mmh3-hashed n-grams + logistic weights) so the ingest container stays small.
"""

from __future__ import annotations

import json
import math
import random
from functools import cache
from pathlib import Path

import mmh3

from . import config, names

BUCKETS = 1 << 20
NGRAMS = (2, 3, 4, 5)


def label_of(domain: str) -> str:
    reg = names.registrable(domain) or domain
    return names.to_unicode(reg.rsplit(".", 1)[0] if "." in reg else reg)


def features(label: str) -> dict[int, float]:
    s = f"^{label}$"
    out: dict[int, float] = {}
    for n in NGRAMS:
        for i in range(len(s) - n + 1):
            h = mmh3.hash(s[i : i + n], 7) % BUCKETS
            out[h] = out.get(h, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in out.values())) or 1.0
    return {k: v / norm for k, v in out.items()}


def model_path() -> Path:
    return Path(config.load()["paths"]["data_dir"]) / "models" / "name_model.json"


@cache
def _load() -> dict | None:
    p = model_path()
    if not p.exists():
        return None
    m = json.loads(p.read_text())
    m["w"] = {int(k): v for k, v in m["w"].items()}
    return m


def score(domain: str) -> float | None:
    m = _load()
    if m is None:
        return None
    z = m["b"] + sum(m["w"].get(k, 0.0) * v for k, v in features(label_of(domain)).items())
    return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))


def _matrix(labels: list[str]):
    from scipy.sparse import csr_matrix

    rows, cols, vals = [], [], []
    for i, lab in enumerate(labels):
        for k, v in features(lab).items():
            rows.append(i)
            cols.append(k)
            vals.append(v)
    return csr_matrix((vals, (rows, cols)), shape=(len(labels), BUCKETS))


def train(conn, split_date: str = "2026-07-01", C: float = 4.0) -> dict:
    """Temporal split: train on CBR names listed before split_date, test on names listed after."""
    from sklearn.linear_model import LogisticRegression

    cbr = conn.execute("SELECT domain, MIN(listed_at) FROM seeds WHERE source='cbr' GROUP BY domain").fetchall()
    pos_train = sorted({label_of(d) for d, t in cbr if t and t < split_date})
    pos_test = sorted({label_of(d) for d, t in cbr if t and t >= split_date} - set(pos_train))
    neg = sorted(
        {label_of(r[0]) for r in conn.execute("SELECT domain FROM ct_sample")} - set(pos_train) - set(pos_test)
    )
    rnd = random.Random(42)
    rnd.shuffle(neg)
    cut = int(len(neg) * 0.8)
    neg_train, neg_test = neg[:cut], neg[cut:]
    X = _matrix(pos_train + neg_train)
    y = [1] * len(pos_train) + [0] * len(neg_train)
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=2000, solver="liblinear")
    clf.fit(X, y)
    coef = clf.coef_.ravel()
    nz = coef.nonzero()[0]
    model = {
        "b": float(clf.intercept_[0]),
        "w": {int(i): round(float(coef[i]), 5) for i in nz},
        "trained": {"pos": len(pos_train), "neg": len(neg_train), "split_date": split_date, "C": C},
    }
    p = model_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(model))
    _load.cache_clear()
    return evaluate(pos_test, neg_test) | {"trained": model["trained"]}


def evaluate(pos_test: list[str], neg_test: list[str]) -> dict:
    """Recall on future CBR names vs pass rate on background names, for the model, the keyword
    filter, and their union, at several thresholds."""
    kw = lambda lab: bool(names.keyword_matches(f"{lab}.com"))  # noqa: E731
    sp = [score(f"{lab}.com") for lab in pos_test]
    sn = [score(f"{lab}.com") for lab in neg_test]
    kp = [kw(lab) for lab in pos_test]
    kn = [kw(lab) for lab in neg_test]
    rows = [
        {"threshold": "keyword-only", "recall": round(sum(kp) / len(kp), 3), "pass_rate": round(sum(kn) / len(kn), 4)}
    ]
    for t in (0.5, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99):
        rows.append(
            {
                "threshold": t,
                "model_recall": round(sum(s >= t for s in sp) / len(sp), 3),
                "model_pass_rate": round(sum(s >= t for s in sn) / len(sn), 4),
                "union_recall": round(sum((s >= t) or k for s, k in zip(sp, kp, strict=True)) / len(sp), 3),
                "union_pass_rate": round(sum((s >= t) or k for s, k in zip(sn, kn, strict=True)) / len(sn), 4),
            }
        )
    return {"n_pos_test": len(pos_test), "n_neg_test": len(neg_test), "table": rows}
