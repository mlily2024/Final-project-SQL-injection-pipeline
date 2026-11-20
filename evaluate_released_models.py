"""Reproduce the clean-test results of the merged paper from the released trained models.

Loads main_models_seed{42,1,7,13,123}.pkl (GitHub Release assets), checks their SHA-256 against
results/merged/model_checksums.sha256, embeds the 9,276 test queries with DistilBERT and BERT, and
reports accuracy, precision, recall, F1, FPR and FP / FN per model and seed, the McNemar exact tests
for seed 42, and the difference from the published values in results/merged/phase3b_extended.json.
No training is performed. Model definitions are taken from merged_phase3b_extended.py.

Usage: python evaluate_released_models.py <directory with the model files>
"""
import hashlib
import json
import os
import pickle
import sys

from scipy.stats import binomtest

HERE = os.path.dirname(os.path.abspath(__file__))
P3B = os.path.join(HERE, "merged_phase3b_extended.py")
MODEL_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "release_assets")
os.environ.setdefault("PLAN", "cpu")

src = open(P3B, encoding="utf-8").read()
cut = lambda a, b: src[src.index(a):src.index(b)]
parts = [src[:src.index("# ================================================================= transforms")],
         cut("# ================================================================= encoders",
             "# =========================================================== features (cached)"),
         cut("# ================================================================= models", "MAIN = {"),
         cut("# ================================================================ metrics", "R = {")]
S = {"__file__": P3B, "__name__": "phase3b_definitions"}
exec(compile("\n".join(parts), P3B, "exec"), S)
log, met, MODELS_ORDER, NAMES = S["log"], S["met"], S["MODELS_ORDER"], S["NAMES"]
te_q, y_te = S["te_q"], S["y_te"]

expected = {}
sums = os.path.join(HERE, "results", "merged", "model_checksums.sha256")
if os.path.exists(sums):
    for line in open(sums, encoding="utf-8"):
        h, name = line.split()
        expected[name.lstrip("*")] = h

fams = {}
for s in [42, 1, 7, 13, 123]:
    name = f"main_models_seed{s}.pkl"
    path = os.path.join(MODEL_DIR, name)
    if not os.path.exists(path):
        continue
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if name in expected and digest != expected[name]:
        raise SystemExit(f"{name}: checksum mismatch")
    with open(path, "rb") as f:
        fams[s] = pickle.load(f)
if not fams:
    raise SystemExit(f"no main_models_seed*.pkl found in {MODEL_DIR}")
log(f"loaded seeds {sorted(fams)} from {MODEL_DIR}; embedding {len(te_q)} test queries")

D_te = S["distil_cls"](te_q)
B_te, G_te = S["bert_cls_graphs"](te_q, y_te)
P = {s: S["proba"](fam, D_te, B_te, G_te) for s, fam in fams.items()}

pub_path = os.path.join(HERE, "results", "merged", "phase3b_extended.json")
pub = json.load(open(pub_path, encoding="utf-8")) if os.path.exists(pub_path) else None
pub_seeds = pub["seeds"] if pub else []
print("\n| Seed | Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | FP / FN | Published accuracy (%) |")
print("|---|---|---|---|---|---|---|---|---|")
for s in sorted(P):
    for m in MODELS_ORDER:
        r = met(y_te, P[s][m])
        ref = (f"{pub['A'][m][pub_seeds.index(s)]['accuracy']:.2f}"
               if pub and s in pub_seeds and len(y_te) == 9276 else "-")
        print(f"| {s} | {NAMES[m]} | {r['accuracy']:.2f} | {r['precision']:.2f} | {r['recall']:.2f} | "
              f"{r['f1']:.2f} | {r['fpr']:.3f} | {r['fp']} / {r['fn']} | {ref} |")
if 42 in P:
    print("\nMcNemar exact tests, seed 42 (b: only the first correct; c: only the second correct)")
    for i, a in enumerate(MODELS_ORDER):
        for b_ in MODELS_ORDER[i + 1:]:
            ca = (P[42][a] > 0.5).astype(int) == y_te
            cb = (P[42][b_] > 0.5).astype(int) == y_te
            b, c = int((ca & ~cb).sum()), int((~ca & cb).sum())
            p = binomtest(b, b + c, 0.5).pvalue if b + c else 1.0
            print(f"  {NAMES[a]} vs {NAMES[b_]}: b = {b}, c = {c}, p = {p:.3g}")
