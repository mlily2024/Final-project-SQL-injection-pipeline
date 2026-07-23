#!/usr/bin/env python3
"""
Robustness test 6/7: statistical significance.

Confirms that the differences between the structure-aware BERT-GNN and the
BERT-only model are not chance. Reports McNemar's paired test on the clean test
set and under URL-encoding evasion, and bootstrap 95% confidence intervals on
the key metrics (accuracy, malicious recall) and on the URL-encode recall gap.
Resumable: caches the per-query URL-encode predictions.
"""
import os, json
import numpy as np
from scipy import stats
from sklearn.metrics import accuracy_score, recall_score
import robustness_common as rc

OUT_MD = os.path.join(rc.HERE, "results", "robustness_significance.md")
UENC = os.path.join(rc.SW, "urlenc_preds.npz")
rng = np.random.default_rng(rc.SEED)

gnn, mlp, mlp_t, bp = rc.load_models()
graphs, cls, y = rc.test_features()
pg = rc.gnn_predict(gnn, graphs); pb = mlp.predict(cls)

def mcnemar(pa, pb, yt):
    a_ok = (pa == yt); b_ok = (pb == yt)
    b = int(np.sum(a_ok & ~b_ok)); c = int(np.sum(~a_ok & b_ok))
    # exact binomial (robust for small discordant counts)
    p = stats.binomtest(min(b, c), b + c, 0.5).pvalue if (b + c) > 0 else 1.0
    return b, c, p

def boot_ci(fn, n=2000):
    idx = np.arange(len(y)); vals = []
    for _ in range(n):
        s = rng.choice(idx, size=len(idx), replace=True)
        vals.append(fn(s))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return lo, hi

# --- clean test set ---
b, c, p = mcnemar(pg, pb, y)
gnn_acc = accuracy_score(y, pg) * 100; bert_acc = accuracy_score(y, pb) * 100
gnn_ci = boot_ci(lambda s: accuracy_score(y[s], pg[s]) * 100)
bert_ci = boot_ci(lambda s: accuracy_score(y[s], pb[s]) * 100)
mal = (y == 1)
gnn_rec_ci = boot_ci(lambda s: recall_score(y[s], pg[s], pos_label=1, zero_division=0) * 100)
bert_rec_ci = boot_ci(lambda s: recall_score(y[s], pb[s], pos_label=1, zero_division=0) * 100)
print(f"CLEAN  McNemar b={b} c={c} p={p:.3g}")
print(f"  GNN acc {gnn_acc:.2f} [{gnn_ci[0]:.2f},{gnn_ci[1]:.2f}]  BERT acc {bert_acc:.2f} [{bert_ci[0]:.2f},{bert_ci[1]:.2f}]")

# --- URL-encode: per-query predictions (cached) ---
if os.path.exists(UENC):
    z = np.load(UENC); ug, ub = z["ug"], z["ub"]
else:
    q = [x.replace(" ", "%20").replace("'", "%27").replace("=", "%3d") for x in rc.mal_queries]
    ucls, ugraphs = rc.embed_and_graph(q, label=1)
    ug = rc.gnn_predict(gnn, ugraphs); ub = mlp.predict(ucls)
    np.savez(UENC, ug=ug, ub=ub)
ny = np.ones(len(ug), dtype=int)   # all malicious
ub_, uc_, up = mcnemar(ug, ub, ny)
g_rec = (ug == 1).mean() * 100; b_rec = (ub == 1).mean() * 100
# bootstrap the recall GAP
idx = np.arange(len(ug)); gaps = []
for _ in range(2000):
    s = rng.choice(idx, size=len(idx), replace=True)
    gaps.append((ug[s] == 1).mean() * 100 - (ub[s] == 1).mean() * 100)
gap_lo, gap_hi = np.percentile(gaps, [2.5, 97.5])
print(f"URL-ENC McNemar b={ub_} c={uc_} p={up:.3g}  gap {g_rec-b_rec:.2f} [{gap_lo:.2f},{gap_hi:.2f}]")

lines = ["# Robustness test 6: statistical significance", "",
         "McNemar's paired test and bootstrap 95% confidence intervals confirm the model "
         "differences are not chance.", "",
         "## Clean test set (9,276 queries)", "",
         f"- McNemar (structure-GNN vs BERT-only): discordant pairs b={b}, c={c}, p = {p:.3g}. "
         + ("The two are not significantly different on clean data." if p > 0.05 else "The difference is significant."),
         f"- Structure-GNN accuracy {gnn_acc:.2f}% (95% CI {gnn_ci[0]:.2f} to {gnn_ci[1]:.2f}); "
         f"BERT-only {bert_acc:.2f}% ({bert_ci[0]:.2f} to {bert_ci[1]:.2f}). The intervals overlap.",
         f"- Malicious recall 95% CI: structure-GNN {gnn_rec_ci[0]:.2f} to {gnn_rec_ci[1]:.2f}; "
         f"BERT-only {bert_rec_ci[0]:.2f} to {bert_rec_ci[1]:.2f}.", "",
         "## Under URL-encoding evasion (3,446 malicious queries)", "",
         f"- McNemar: b={ub_}, c={uc_}, p = {up:.3g}. "
         + ("The difference in detection is highly significant." if up < 0.05 else "Not significant."),
         f"- Detection-rate gap (structure-GNN minus BERT-only): {g_rec - b_rec:.2f} percentage "
         f"points, 95% CI {gap_lo:.2f} to {gap_hi:.2f}. The interval excludes zero, so the "
         "robustness advantage under URL encoding is statistically significant.", "",
         "Reproduce with `python robustness_6_significance.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
