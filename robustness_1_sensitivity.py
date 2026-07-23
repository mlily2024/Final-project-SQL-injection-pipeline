#!/usr/bin/env python3
"""
Robustness test 1/7: sensitivity analysis.

Extends the dissertation's single-point sensitivity analysis (randomly removing
~10% of graph nodes) to a sweep, and adds a feature-space Gaussian-noise sweep so
the structure-aware BERT-GNN and the BERT-only model can be compared on the same
footing. Sensitivity is the fraction of test predictions that flip relative to the
clean prediction; a smaller flip rate (and smaller accuracy drop) means a more
robust model.
"""
import os, copy
import numpy as np
import torch
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score
import robustness_common as rc
from torch_geometric.data import Data

OUT_MD = os.path.join(rc.HERE, "results", "robustness_sensitivity.md")
FIG = os.path.join(rc.HERE, "results", "robustness_sensitivity.png")
rng = np.random.default_rng(rc.SEED)

gnn, mlp, mlp_t, bp = rc.load_models()
graphs, cls, y = rc.test_features()
base_gnn = rc.gnn_predict(gnn, graphs)          # clean structure-GNN predictions
base_bert = mlp.predict(cls)                     # clean BERT-only predictions

def drop_nodes(g, frac):
    n = g.x.shape[0]
    if n <= 1: return g
    k = max(1, int(round(n * (1 - frac))))       # nodes to KEEP
    keep = np.sort(rng.choice(n, size=k, replace=False))
    remap = {int(o): i for i, o in enumerate(keep)}
    x = g.x[torch.tensor(keep)]
    ei = g.edge_index.numpy()
    cols = [c for c in range(ei.shape[1]) if ei[0, c] in remap and ei[1, c] in remap]
    if cols:
        ne = np.array([[remap[ei[0, c]] for c in cols], [remap[ei[1, c]] for c in cols]])
        eit = torch.tensor(ne, dtype=torch.long)
    else:
        eit = torch.empty((2, 0), dtype=torch.long)
    return Data(x=x, edge_index=eit, y=g.y)

FRACS = [0.0, 0.05, 0.10, 0.20, 0.30]
SIGMAS = [0.0, 0.25, 0.5, 1.0, 2.0]
res = {"node_removal": {}, "feature_noise_gnn": {}, "feature_noise_bert": {}}

# --- (A) GNN node-removal sweep (extends the dissertation's analysis) ---
for f in FRACS:
    if f == 0.0:
        p = base_gnn
    else:
        pert = [drop_nodes(g, f) for g in graphs]
        p = rc.gnn_predict(gnn, pert)
    flip = float((p != base_gnn).mean()); acc = accuracy_score(y, p) * 100
    res["node_removal"][f] = {"flip_rate": round(flip, 4), "accuracy": round(acc, 2)}
    print(f"  node-removal {int(f*100):2d}%  flip={flip*100:5.2f}%  acc={acc:.2f}")

# --- (B) feature-noise sweep, both models (fair comparison) ---
xg = [g.x for g in graphs]
for s in SIGMAS:
    if s == 0.0:
        pg, pb = base_gnn, base_bert
    else:
        ng = [Data(x=g.x + s * torch.randn_like(g.x), edge_index=g.edge_index, y=g.y) for g in graphs]
        pg = rc.gnn_predict(gnn, ng)
        pb = mlp.predict(cls + s * rng.standard_normal(cls.shape).astype(np.float32))
    fg = float((pg != base_gnn).mean()); fb = float((pb != base_bert).mean())
    res["feature_noise_gnn"][s] = {"flip_rate": round(fg, 4), "accuracy": round(accuracy_score(y, pg)*100, 2)}
    res["feature_noise_bert"][s] = {"flip_rate": round(fb, 4), "accuracy": round(accuracy_score(y, pb)*100, 2)}
    print(f"  feat-noise sigma={s:.2f}  GNN flip={fg*100:5.2f}%  BERT flip={fb*100:5.2f}%")

# --- figure ---
fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
ax[0].plot([f*100 for f in FRACS], [res["node_removal"][f]["accuracy"] for f in FRACS], "o-", color="#2e7d32")
ax[0].set_xlabel("Nodes removed (%)"); ax[0].set_ylabel("Accuracy (%)")
ax[0].set_title("Structure-GNN sensitivity to node removal"); ax[0].grid(alpha=0.3)
ax[1].plot(SIGMAS, [res["feature_noise_gnn"][s]["accuracy"] for s in SIGMAS], "o-", color="#2e7d32", label="Structure-GNN")
ax[1].plot(SIGMAS, [res["feature_noise_bert"][s]["accuracy"] for s in SIGMAS], "s-", color="#c0504d", label="BERT-only")
ax[1].set_xlabel("Gaussian feature-noise sigma"); ax[1].set_ylabel("Accuracy (%)")
ax[1].set_title("Sensitivity to feature noise"); ax[1].legend(); ax[1].grid(alpha=0.3)
fig.tight_layout(); fig.savefig(FIG, dpi=200, bbox_inches="tight"); plt.close()

lines = ["# Robustness test 1: sensitivity analysis", "",
         "Prediction stability under (A) random removal of graph nodes (extending the "
         "dissertation's single 10% analysis to a sweep) and (B) Gaussian noise added to the "
         "input features of both models. Flip rate is the fraction of the 9,276 test "
         "predictions that change from the clean prediction; lower is more robust.", "",
         "## (A) Structure-GNN, node removal", "",
         "| Nodes removed | Flip rate (%) | Accuracy (%) |", "|---|---|---|"]
for f in FRACS: lines.append(f"| {int(f*100)} | {res['node_removal'][f]['flip_rate']*100:.2f} | {res['node_removal'][f]['accuracy']:.2f} |")
lines += ["", "## (B) Feature-noise, both models", "",
          "| Noise sigma | Structure-GNN flip (%) | BERT-only flip (%) |", "|---|---|---|"]
for s in SIGMAS: lines.append(f"| {s} | {res['feature_noise_gnn'][s]['flip_rate']*100:.2f} | {res['feature_noise_bert'][s]['flip_rate']*100:.2f} |")
lines += ["", "![Sensitivity curves](robustness_sensitivity.png)", "",
          "Reproduce with `python robustness_1_sensitivity.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
