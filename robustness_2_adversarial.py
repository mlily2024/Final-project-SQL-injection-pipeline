#!/usr/bin/env python3
"""
Robustness test 2/7: adversarial robustness (FGSM and PGD).

Gradient-based attacks in the feature space, consistent with the FGSM evaluation
in the sibling DistilBERT paper. For the structure-aware BERT-GNN the attack
perturbs the node features; for the BERT-only model it perturbs the [CLS]
embedding. We report robust accuracy on the full test set at increasing
perturbation budgets (FGSM), and a stronger iterative attack (PGD). A higher
robust accuracy means the model is harder to fool.
"""
import os
import numpy as np
import torch
import torch.nn.functional as F
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score
import robustness_common as rc
from torch_geometric.loader import DataLoader as GL

OUT_MD = os.path.join(rc.HERE, "results", "robustness_adversarial.md")
FIG = os.path.join(rc.HERE, "results", "robustness_adversarial.png")

gnn, mlp, mlp_t, bp = rc.load_models()
graphs, cls, y = rc.test_features()
yt = torch.tensor(y)

def gnn_attack(graphs, eps, steps=1, alpha=None):
    """FGSM (steps=1) or PGD (steps>1) on node features; returns predictions."""
    alpha = alpha or eps
    ld = GL(graphs, batch_size=128); preds = []
    for d in ld:
        x0 = d.x.detach(); x = x0.clone()
        for _ in range(steps):
            x.requires_grad_(True)
            out = gnn(x, d.edge_index, d.batch)
            loss = F.cross_entropy(out, d.y)
            g, = torch.autograd.grad(loss, x)
            x = x.detach() + alpha * g.sign()
            x = torch.max(torch.min(x, x0 + eps), x0 - eps)      # project to L-inf ball
        with torch.no_grad():
            preds.append(gnn(x, d.edge_index, d.batch).argmax(1))
    return torch.cat(preds).numpy()

def mlp_attack(cls, y, eps, steps=1, alpha=None):
    alpha = alpha or eps
    x0 = torch.tensor(cls); x = x0.clone(); yf = torch.tensor(y, dtype=torch.float)
    for _ in range(steps):
        x.requires_grad_(True)
        logit = mlp_t(x)
        loss = F.binary_cross_entropy_with_logits(logit, yf)
        g, = torch.autograd.grad(loss, x)
        x = x.detach() + alpha * g.sign()
        x = torch.max(torch.min(x, x0 + eps), x0 - eps)
    with torch.no_grad():
        return (mlp_t(x) > 0).long().numpy()

EPS = [0.0, 0.01, 0.05, 0.1, 0.2]
res = {"fgsm_gnn": {}, "fgsm_bert": {}}
for e in EPS:
    if e == 0.0:
        pg = rc.gnn_predict(gnn, graphs); pb = mlp.predict(cls)
    else:
        pg = gnn_attack(graphs, e); pb = mlp_attack(cls, y, e)
    ag = accuracy_score(y, pg) * 100; ab = accuracy_score(y, pb) * 100
    res["fgsm_gnn"][e] = round(ag, 2); res["fgsm_bert"][e] = round(ab, 2)
    print(f"  FGSM eps={e:.2f}  structure-GNN robust-acc={ag:5.2f}%  BERT-only={ab:5.2f}%")

# PGD (stronger) at eps=0.1
pgd_g = accuracy_score(y, gnn_attack(graphs, 0.1, steps=10, alpha=0.02)) * 100
pgd_b = accuracy_score(y, mlp_attack(cls, y, 0.1, steps=10, alpha=0.02)) * 100
res["pgd_eps0.1"] = {"structure_gnn": round(pgd_g, 2), "bert_only": round(pgd_b, 2)}
print(f"  PGD  eps=0.10 (10 steps)  structure-GNN={pgd_g:.2f}%  BERT-only={pgd_b:.2f}%")

fig, ax = plt.subplots(figsize=(6.5, 4.2))
ax.plot(EPS, [res["fgsm_gnn"][e] for e in EPS], "o-", color="#2e7d32", label="Structure-GNN (FGSM)")
ax.plot(EPS, [res["fgsm_bert"][e] for e in EPS], "s-", color="#c0504d", label="BERT-only (FGSM)")
ax.set_xlabel("Perturbation budget (epsilon)"); ax.set_ylabel("Robust accuracy (%)")
ax.set_title("Adversarial robustness (FGSM, feature space)"); ax.legend(); ax.grid(alpha=0.3)
fig.tight_layout(); fig.savefig(FIG, dpi=200, bbox_inches="tight"); plt.close()

lines = ["# Robustness test 2: adversarial robustness (FGSM / PGD)", "",
         "Gradient attacks in the feature space (node features for the structure-GNN, [CLS] for "
         "BERT-only), consistent with the sibling DistilBERT paper's FGSM evaluation. Robust "
         "accuracy is accuracy on the adversarially perturbed 9,276-query test set; higher is "
         "more robust.", "",
         "| FGSM epsilon | Structure-GNN robust acc (%) | BERT-only robust acc (%) |", "|---|---|---|"]
for e in EPS: lines.append(f"| {e} | {res['fgsm_gnn'][e]:.2f} | {res['fgsm_bert'][e]:.2f} |")
lines += ["", f"PGD (epsilon 0.1, 10 steps): structure-GNN {pgd_g:.2f}%, BERT-only {pgd_b:.2f}%.", "",
          "**Interpretation (reported honestly).** Under weak perturbation the structure-GNN is "
          "marginally more robust, but under strong white-box attacks (epsilon >= 0.1 and PGD) it "
          "is more vulnerable than BERT-only. This is the opposite of the random-noise (test 1) "
          "and realistic-evasion (URL-encoding) results, and the reason is instructive: the graph "
          "exposes a far larger perturbable surface (every node feature) to a gradient attacker "
          "than a single [CLS] vector, so a white-box adversary has more degrees of freedom. The "
          "structure-GNN's robustness advantage is therefore to random corruption and realistic "
          "obfuscation, not to worst-case gradient attacks; neither model is adversarially robust "
          "without dedicated adversarial training.", "",
          "![Adversarial robustness](robustness_adversarial.png)", "",
          "Reproduce with `python robustness_2_adversarial.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
