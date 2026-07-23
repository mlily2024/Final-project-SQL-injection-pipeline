#!/usr/bin/env python3
"""
Robustness test 7/7: calibration under attack.

A detector that is confidently wrong under evasion is operationally dangerous.
We report the expected calibration error (ECE) of both models on the clean test
set and on URL-encoded malicious queries. Lower ECE means the model's confidence
better reflects its accuracy. Resumable: caches the URL-encode probabilities.
"""
import os
import numpy as np
import robustness_common as rc

OUT_MD = os.path.join(rc.HERE, "results", "robustness_calibration.md")
UPROB = os.path.join(rc.SW, "urlenc_probs.npz")

def ece(prob_pos, y_true, n_bins=15):
    conf = np.maximum(prob_pos, 1 - prob_pos)           # confidence in the predicted class
    pred = (prob_pos >= 0.5).astype(int)
    correct = (pred == y_true).astype(float)
    bins = np.linspace(0, 1, n_bins + 1); e = 0.0
    for i in range(n_bins):
        m = (conf > bins[i]) & (conf <= bins[i + 1])
        if m.sum() > 0:
            e += (m.mean()) * abs(correct[m].mean() - conf[m].mean())
    return e

gnn, mlp, mlp_t, bp = rc.load_models()
graphs, cls, y = rc.test_features()

# clean
_, gp_prob = rc.gnn_predict(gnn, graphs, want_prob=True)
bp_prob = mlp.predict_proba(cls)[:, 1]
ece_g_clean = ece(gp_prob, y); ece_b_clean = ece(bp_prob, y)
print(f"CLEAN  ECE  structure-GNN {ece_g_clean:.4f}  BERT-only {ece_b_clean:.4f}")

# URL-encode malicious (probs cached)
if os.path.exists(UPROB):
    z = np.load(UPROB); ug_p, ub_p = z["ug_p"], z["ub_p"]
else:
    q = [x.replace(" ", "%20").replace("'", "%27").replace("=", "%3d") for x in rc.mal_queries]
    ucls, ugraphs = rc.embed_and_graph(q, label=1)
    _, ug_p = rc.gnn_predict(gnn, ugraphs, want_prob=True)
    ub_p = mlp.predict_proba(ucls)[:, 1]
    np.savez(UPROB, ug_p=ug_p, ub_p=ub_p)
ny = np.ones(len(ug_p), dtype=int)
ece_g_u = ece(ug_p, ny); ece_b_u = ece(ub_p, ny)
# mean confidence on the MISSED malicious (predicted benign) = "confidently wrong" signal
gm = ug_p < 0.5; bm = ub_p < 0.5
gnn_wrong_conf = float((1 - ug_p[gm]).mean()) if gm.sum() else 0.0
bert_wrong_conf = float((1 - ub_p[bm]).mean()) if bm.sum() else 0.0
print(f"URL-ENC ECE  structure-GNN {ece_g_u:.4f}  BERT-only {ece_b_u:.4f}")
print(f"  mean confidence on MISSED attacks: GNN {gnn_wrong_conf:.3f} ({int(gm.sum())})  BERT {bert_wrong_conf:.3f} ({int(bm.sum())})")

lines = ["# Robustness test 7: calibration under attack", "",
         "Expected calibration error (ECE, 15 bins): the gap between a model's confidence and its "
         "accuracy. Lower is better; a high ECE under attack means the model is confidently wrong.", "",
         "| Setting | Structure-GNN ECE | BERT-only ECE |", "|---|---|---|",
         f"| Clean test set | {ece_g_clean:.4f} | {ece_b_clean:.4f} |",
         f"| URL-encoded malicious | {ece_g_u:.4f} | {ece_b_u:.4f} |", "",
         f"Under URL encoding the BERT-only model not only misses more attacks ({int(bm.sum())} vs "
         f"{int(gm.sum())}) but does so with high confidence (mean confidence {bert_wrong_conf:.2f} "
         f"on the queries it misclassifies, against {gnn_wrong_conf:.2f} for the structure-GNN). A "
         "detector that is confidently wrong under evasion is the more dangerous failure mode.", "",
         "Reproduce with `python robustness_7_calibration.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
