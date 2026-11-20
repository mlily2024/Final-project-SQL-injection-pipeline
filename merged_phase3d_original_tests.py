"""
Merged paper, phase 3d: the tests of the two arXiv papers that phases 2 to 3c did not repeat,
re-run on the shared 70/30 split with the phase 3b models.

Reuses the phase 3b setup and cached models: the part of merged_phase3b_extended.py before
section A is executed here (same approach as phase 3c).

Tests (paper of origin in brackets)
  A  all seven DistilBERT base classifiers with the notebook GridSearchCV grids (DistilBERT)
  B  TF-IDF baselines: as published (preprocessing, SMOTE, defaults) and a controlled version
     (no SMOTE, class weights, same grids as A) (DistilBERT)
  C  ensemble before Optuna (notebook default meta-learner), FGSM sweep per seed, and the
     meta-feature sensitivity analysis (DistilBERT)
  D  GNN node-removal sensitivity: mean change in P(malicious) on 99 attack graphs at 10%, and a
     flip-rate sweep on the full test set (BERT-GNN)
  E  edge ablation: GNN retrained with no edges and with random edges of the same count (BERT-GNN)
  F  white-box FGSM and PGD on the GNN node features and the BERT-only [CLS] input (BERT-GNN)
  G  feature noise with absolute sigma, as in the BERT-GNN paper, for all four models (BERT-GNN)
  H  BERT [CLS] + Logistic Regression head (BERT-GNN)
  I  calibration under URL-encoding evasion (repository robustness test 7)
  J  training and validation loss curves: GNN and meta-learner (both)
  K  GNN hyperparameter search with 40 Optuna trials, as in the BERT-GNN paper (BERT-GNN)

Environment: P3B_WORK (phase 3b cache root), WORK_DIR (phase 3d cache), SMOKE=1.
"""
import gc
import json
import os
import pickle
import re
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

HERE = os.path.dirname(os.path.abspath(__file__))
P3B = os.path.join(HERE, "merged_phase3b_extended.py")
OUT = os.path.join(HERE, "results", "merged")
SMOKE = os.environ.get("SMOKE") == "1"
WORK = os.environ.get("WORK_DIR", os.path.join(HERE, ".merged_work", "phase3d")) + ("_smoke" if SMOKE else "")
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

os.environ["PLAN"] = "cpu"
os.environ["WORK_DIR"] = os.environ.get("P3B_WORK", os.path.join(HERE, ".merged_work", "phase3b"))
os.environ.setdefault("SQLMAP_DIR", os.path.join(HERE, "..", "tools", "sqlmap"))
src = open(P3B, encoding="utf-8").read()
S = {"__file__": P3B, "__name__": "phase3b_setup"}
exec(compile(src[:src.index("# ===================================================================== A")], P3B, "exec"), S)
P3B_WORK = S["WORK"]
S["WORK"] = WORK
log, cached, met, ms, ece = S["log"], S["cached"], S["met"], S["ms"], S["ece"]
device = S["device"]
MODELS_ORDER, NAMES = S["MODELS_ORDER"], S["NAMES"]
train_df, test_df, tr_df, val_df = S["train_df"], S["test_df"], S["tr_df"], S["val_df"]
y_tr, y_te, te_q = S["y_tr"], S["y_te"], S["te_q"]
D_tr, D_te, B_tr, B_te = S["D_tr"], S["D_te"], S["B_tr"], S["B_te_cls"]
G_tr, G_val, G_te = S["G_tr"], S["G_val"], S["G_te"]
MAIN, P_TEST, GNN_P, ENS_P = S["MAIN"], S["P_TEST"], S["GNN_P"], S["ENS_P"]
GNNModel, MetaLearnerNN, GeoLoader = S["GNNModel"], S["MetaLearnerNN"], S["GeoLoader"]
SEEDS = S["SEEDS"]
SEEDS3 = [42] if SMOKE else [42, 1, 7]
N_JOBS = 2
gnn_cw = torch.tensor(np.bincount(tr_df["Label"].values, minlength=2).sum()
                      / (2 * np.bincount(tr_df["Label"].values, minlength=2)), dtype=torch.float, device=device)


def timed(fn):
    t = time.perf_counter()
    r = fn()
    return r, time.perf_counter() - t


def m_full(y, pred, prob=None):
    """Malicious-class metrics (as phase 3) plus weighted metrics (as the published tables)."""
    from sklearn.metrics import f1_score, precision_score, recall_score
    r = met(y, prob if prob is not None else pred.astype(float))
    lab = pred.astype(int)
    r.update({"w_precision": 100 * precision_score(y, lab, average="weighted", zero_division=0),
              "w_recall": 100 * recall_score(y, lab, average="weighted", zero_division=0),
              "w_f1": 100 * f1_score(y, lab, average="weighted", zero_division=0)})
    return r


R = {"seeds": SEEDS, "seeds3": SEEDS3}
L = ["# Phase 3d: tests of the arXiv papers repeated on the merged protocol", "",
     f"Same 70/30 split as phases 2 to 3c (test set {len(test_df)} queries, {int(y_te.sum())} malicious). "
     "Malicious-class precision, recall and F1 as in phase 3; weighted (both-class) values as in the published tables "
     "are given where the papers used them. Times are wall-clock on this machine (CPU).", ""]
METRIC_HDR = "| Model | Accuracy | Precision (mal.) | Recall (mal.) | F1 (mal.) | F1 (weighted) | FPR (%) | Train (s) | Test exec (s) |"


def metric_row(name, r, tt, te):
    return (f"| {name} | {r['accuracy']:.2f} | {r['precision']:.2f} | {r['recall']:.2f} | {r['f1']:.2f} | "
            f"{r['w_f1']:.2f} | {r['fpr']:.3f} | {tt:.1f} | {te:.4f} |")


# ===================================================================== A
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV
from sklearn.naive_bayes import GaussianNB, MultinomialNB
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
import xgboost as xgb

GRIDS = {"Random Forest": {"n_estimators": [50, 100, 200]}, "Decision Tree": {"max_depth": [None, 10, 20]},
         "Logistic Regression": {"C": [0.1, 1, 10]}, "SVM": {"C": [0.1, 1, 10], "kernel": ["linear", "rbf"]},
         "Gradient Boosting": {"n_estimators": [50, 100, 200]}, "XGBoost": {"n_estimators": [50, 100, 200]}}
if SMOKE:
    GRIDS = {k: {p: v[:1] for p, v in g.items()} for k, g in GRIDS.items()}
cw = np.bincount(y_tr).sum() / (2 * np.bincount(y_tr))


def distil_models():
    return {"Random Forest": RandomForestClassifier(class_weight="balanced", random_state=42, n_jobs=N_JOBS),
            "Decision Tree": DecisionTreeClassifier(random_state=42),
            "Naive Bayes": GaussianNB(),
            "Logistic Regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
            "SVM": SVC(probability=True, class_weight="balanced", random_state=42),
            "Gradient Boosting": GradientBoostingClassifier(random_state=42),
            "XGBoost": xgb.XGBClassifier(eval_metric="logloss", scale_pos_weight=cw[1], random_state=42, n_jobs=N_JOBS)}


def fit_eval(name, clf, Xtr, ytr, Xte, grid=None):
    def run():
        est = GridSearchCV(clf, grid, cv=5, scoring="accuracy", n_jobs=N_JOBS) if grid else clf
        _, tt = timed(lambda: est.fit(Xtr, ytr))
        pred, te = timed(lambda: est.predict(Xte))
        prob = est.predict_proba(Xte)[:, 1] if hasattr(est, "predict_proba") else None
        best = est.best_params_ if grid else None
        return {"pred": pred, "prob": prob, "train_s": tt, "exec_s": te, "best": best}
    tag = re.sub(r"[^a-z0-9]+", "_", name.lower())
    return cached(f"{tag}.pkl", run)


A = {}
for name, clf in distil_models().items():
    A[name] = fit_eval(f"distil {name}", clf, D_tr, y_tr, D_te, GRIDS.get(name))
    log(f"A: DistilBERT {name} done (best {A[name]['best']})")
R["A"] = {n: {**m_full(y_te, v["pred"]), "train_s": v["train_s"], "exec_s": v["exec_s"], "best": v["best"]}
          for n, v in A.items()}
L += ["## A. DistilBERT base classifiers (notebook grids, GridSearchCV 5-fold, accuracy)", "", METRIC_HDR,
      "|---|---|---|---|---|---|---|---|---|"]
for n, v in A.items():
    L.append(metric_row(f"DistilBERT-{n}", R["A"][n], v["train_s"], v["exec_s"]))
L += ["", "Best grid values: " + "; ".join(f"{n} {v['best']}" for n, v in A.items() if v["best"]) + ".", ""]

# ===================================================================== B
import nltk
from imblearn.over_sampling import SMOTE
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer

for pkg in ("stopwords", "wordnet", "omw-1.4"):
    nltk.download(pkg, quiet=True)
_lem = WordNetLemmatizer()
_stop = set(stopwords.words("english"))
SQL_KW = {"select", "from", "where", "insert", "update", "delete", "join", "on", "create", "table", "drop", "alter",
          "add", "and", "or", "not", "null", "like", "in", "between"}


def preprocess_text(text):
    """As the published TF-IDF baseline (BERT-GNN notebook, cell 45)."""
    text = re.sub(r"[^\w\s;\'\"=]", " ", text.lower())
    words = [w for w in text.split() if w not in _stop or w in SQL_KW]
    return " ".join(_lem.lemmatize(w) for w in words)


def tfidf_features():
    vec = TfidfVectorizer(max_features=5000)
    Xtr = vec.fit_transform([preprocess_text(q) for q in train_df["Query"]])
    Xte = vec.transform([preprocess_text(q) for q in te_q])
    return Xtr, Xte


Xtr_t, Xte_t = cached("tfidf.pkl", tfidf_features)
Xsm, ysm = cached("tfidf_smote.pkl", lambda: SMOTE(random_state=42).fit_resample(Xtr_t, y_tr))
published = {"Decision Tree": DecisionTreeClassifier(random_state=42),
             "Logistic Regression": LogisticRegression(max_iter=1000), "SVM": SVC(kernel="linear"),
             "Naive Bayes": MultinomialNB(), "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
             "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
             "XGBoost": xgb.XGBClassifier(eval_metric="logloss", random_state=42, n_jobs=N_JOBS)}
controlled = {k: v for k, v in distil_models().items() if k != "Naive Bayes"}
controlled["Naive Bayes"] = MultinomialNB()
B = {"published": {}, "controlled": {}}
for n, clf in published.items():
    B["published"][n] = fit_eval(f"tfidf pub {n}", clf, Xsm, ysm, Xte_t)
    log(f"B: TF-IDF published {n} done")
for n, clf in controlled.items():
    B["controlled"][n] = fit_eval(f"tfidf ctl {n}", clf, Xtr_t, y_tr, Xte_t, GRIDS.get(n))
    log(f"B: TF-IDF controlled {n} done (best {B['controlled'][n]['best']})")
R["B"] = {k: {n: {**m_full(y_te, v["pred"]), "train_s": v["train_s"], "exec_s": v["exec_s"], "best": v["best"]}
              for n, v in d.items()} for k, d in B.items()}
L += ["## B. TF-IDF baselines", "",
      "Published protocol: the notebook preprocessing (lower case, symbol filter keeping ; ' \" =, English stop words "
      "removed except SQL keywords, WordNet lemmatisation), TF-IDF (5,000 features), SMOTE, default classifiers. "
      "Controlled protocol: the same TF-IDF features, no SMOTE, class weights and the section A grids "
      "(Naive Bayes: multinomial, untuned).", ""]
for k, title in (("published", "As published"), ("controlled", "Controlled")):
    L += [f"### {title}", "", METRIC_HDR, "|---|---|---|---|---|---|---|---|---|"]
    for n, v in B[k].items():
        L.append(metric_row(f"TF-IDF {n}", R["B"][k][n], v["train_s"], v["exec_s"]))
    L.append("")
log("A and B done")


# ===================================================================== C
def svm_oof():
    from sklearn.model_selection import cross_val_predict
    return cross_val_predict(SVC(C=10, kernel="rbf", probability=True, class_weight="balanced", random_state=42),
                             D_tr, y_tr, cv=5, method="predict_proba", n_jobs=N_JOBS)


def xgb_oof():
    from sklearn.model_selection import cross_val_predict
    return cross_val_predict(xgb.XGBClassifier(n_estimators=100, eval_metric="logloss", scale_pos_weight=cw[1],
                                               random_state=42, n_jobs=N_JOBS), D_tr, y_tr, cv=5, method="predict_proba")


with open(os.path.join(P3B_WORK, "main_lr.pkl"), "rb") as f:
    lr_oof = pickle.load(f)[1]          # phase 3b Logistic Regression out-of-fold probabilities
M_tr = np.column_stack([lr_oof, cached("xgb_oof42.pkl", xgb_oof), cached("svm_oof42.pkl", svm_oof)]).astype(np.float32)


def meta_test_features(fam):
    return np.column_stack([fam["lr"].predict_proba(D_te), fam["xgb"].predict_proba(D_te),
                            fam["svm"].predict_proba(D_te)]).astype(np.float32)


def meta_from_state(state):
    m = MetaLearnerNN(6, ENS_P["hidden_dim"], ENS_P["dropout_rate"]).to(device)
    m.load_state_dict(state)
    return m.eval()


def train_meta_curve(M, y, hidden, drop, lr, epochs, eps, seed=42):
    """Meta-learner training with per-epoch train and validation loss (20% of the meta-features held out)."""
    from sklearn.model_selection import train_test_split
    torch.manual_seed(seed)
    i_tr, i_va = train_test_split(np.arange(len(y)), test_size=0.2, random_state=seed, stratify=y)
    m = MetaLearnerNN(M.shape[1], hidden, drop).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=lr)
    crit = nn.CrossEntropyLoss()
    X = torch.tensor(M[i_tr], device=device)
    Y = torch.tensor(y[i_tr], device=device)
    Xv = torch.tensor(M[i_va], device=device)
    Yv = torch.tensor(y[i_va], device=device)
    tl, vl = [], []
    for _ in range(epochs):
        m.train()
        opt.zero_grad()
        loss = crit(m(X), Y)
        loss.backward()
        opt.step()
        if eps:
            xa = X.clone().requires_grad_(True)
            m.zero_grad()
            crit(m(xa), Y).backward()
            xa = (xa + eps * xa.grad.sign()).detach()
            crit(m(xa), Y).backward()
            opt.step()
        m.eval()
        with torch.no_grad():
            tl.append(float(crit(m(X), Y)))
            vl.append(float(crit(m(Xv), Yv)))
    return tl, vl


def fgsm_acc(m, X, y, eps):
    Xt = torch.tensor(X, device=device, requires_grad=True)
    Yt = torch.tensor(y, device=device)
    loss = nn.CrossEntropyLoss()(m(Xt), Yt)
    loss.backward()
    with torch.no_grad():
        return 100 * (m(Xt + eps * Xt.grad.sign()).argmax(1) == Yt).float().mean().item()


def sensitivity(m, X):
    """As the DistilBERT notebook: zero one meta-feature at a time; share of predictions that change."""
    with torch.no_grad():
        Xt = torch.tensor(X, device=device)
        base = m(Xt).argmax(1)
        out = []
        for j in range(X.shape[1]):
            Xp = Xt.clone()
            Xp[:, j] = 0
            out.append((m(Xp).argmax(1) != base).float().mean().item())
    return out


def pre_optuna():
    """Notebook default meta-learner (hidden 64, dropout 0.5, lr 0.001, 20 epochs, no FGSM step)."""
    torch.manual_seed(42)
    m = MetaLearnerNN(6, 64, 0.5).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=0.001)
    X = torch.tensor(M_tr, device=device)
    Y = torch.tensor(y_tr, device=device)
    for _ in range(20):
        m.train()
        opt.zero_grad()
        nn.CrossEntropyLoss()(m(X), Y).backward()
        opt.step()
    return {k: v.cpu() for k, v in m.state_dict().items()}


pre_state = cached("pre_optuna_meta.pkl", pre_optuna)
pre = MetaLearnerNN(6, 64, 0.5).to(device)
pre.load_state_dict(pre_state)
pre.eval()
EPS_LIST = [0.05, 0.10, 0.20]
R["C"] = {"fgsm": {}, "sensitivity": {}}
Xte42 = meta_test_features(MAIN[42])
with torch.no_grad():
    pre_pred = pre(torch.tensor(Xte42, device=device)).argmax(1).cpu().numpy()
R["C"]["pre_optuna"] = m_full(y_te, pre_pred)
for s in SEEDS:
    m = meta_from_state(MAIN[s]["meta_state"])
    Xs = meta_test_features(MAIN[s])
    R["C"]["fgsm"][s] = {e: fgsm_acc(m, Xs, y_te, e) for e in EPS_LIST}
    R["C"]["sensitivity"][s] = sensitivity(m, Xs)
R["C"]["fgsm_pre_optuna"] = {e: fgsm_acc(pre, Xte42, y_te, e) for e in EPS_LIST}
R["C"]["sensitivity_pre_optuna"] = sensitivity(pre, Xte42)
L += ["## C. Stacked ensemble: before Optuna, FGSM, meta-feature sensitivity", "",
      f"Before Optuna (notebook defaults, seed 42 meta-features): accuracy {R['C']['pre_optuna']['accuracy']:.2f}%, "
      f"F1 (mal.) {R['C']['pre_optuna']['f1']:.2f}%; optimised ensemble (phase 3b, seeds {SEEDS}): "
      f"{ms([met(y_te, P_TEST[s]['ENS'])['accuracy'] for s in SEEDS])}%.", "",
      "FGSM on the six meta-features (accuracy %, untargeted, L-inf):", "",
      "| Model | " + " | ".join(f"eps {e}" for e in EPS_LIST) + " |", "|---|" + "---|" * len(EPS_LIST),
      "| Optimised ensemble (FGSM-trained) | " + " | ".join(
          ms([R["C"]["fgsm"][s][e] for s in SEEDS]) for e in EPS_LIST) + " |",
      "| Before Optuna (no FGSM training) | " + " | ".join(f"{R['C']['fgsm_pre_optuna'][e]:.2f}" for e in EPS_LIST) + " |",
      "", "Meta-feature sensitivity (share of test predictions that change when one feature is set to 0; "
      "features 0-1 LR, 2-3 XGBoost, 4-5 SVM):", "",
      "| Model | f0 | f1 | f2 | f3 | f4 | f5 | Mean |", "|---|---|---|---|---|---|---|---|",
      "| Optimised ensemble | " + " | ".join(ms([R["C"]["sensitivity"][s][j] for s in SEEDS], 4) for j in range(6))
      + f" | {ms([np.mean(R['C']['sensitivity'][s]) for s in SEEDS], 4)} |",
      "| Before Optuna | " + " | ".join(f"{x:.4f}" for x in R["C"]["sensitivity_pre_optuna"])
      + f" | {np.mean(R['C']['sensitivity_pre_optuna']):.4f} |", ""]
CURVE_META = cached("meta_curve.pkl", lambda: train_meta_curve(M_tr, y_tr, ENS_P["hidden_dim"], ENS_P["dropout_rate"],
                                                                 ENS_P["lr"], ENS_P["epochs"], ENS_P["epsilon"]))
log("C done")


# ===================================================================== D
def gnn_from(fam):
    g = GNNModel(GNN_P["hid"], GNN_P["drop"]).to(device)
    g.load_state_dict(fam["gnn_state"])
    return g.eval()


def gnn_prob(model, graphs, xform=None):
    model.eval()
    out = []
    with torch.no_grad():
        for d in GeoLoader(graphs, batch_size=256):
            d = d.to(device)
            x = d.x.float()
            if xform is not None:
                x = xform(x)
            out.append(F.softmax(model(x, d.edge_index, d.batch), 1)[:, 1].cpu())
    return torch.cat(out).numpy()


def drop_nodes(g, frac, rng):
    from torch_geometric.data import Data
    n = g.x.shape[0]
    if n <= 1:
        return g
    keep = np.sort(rng.choice(n, size=max(1, int(round(n * (1 - frac)))), replace=False))
    remap = -np.ones(n, int)
    remap[keep] = np.arange(len(keep))
    ei = g.edge_index.numpy()
    ok = (remap[ei[0]] >= 0) & (remap[ei[1]] >= 0)
    return Data(x=g.x[torch.tensor(keep)], edge_index=torch.tensor(remap[ei[:, ok]], dtype=torch.long), y=g.y)


FRACS = [0.05, 0.10, 0.20, 0.30]
mal_te = np.where(y_te == 1)[0]
att99 = np.sort(np.random.RandomState(0).choice(mal_te, min(99, len(mal_te)), replace=False))
R["D"] = {"mean_abs_change_10pct_99": [], "flip": {f: [] for f in FRACS}}
for s in SEEDS3:
    g = gnn_from(MAIN[s])
    base = P_TEST[s]["GNN"]
    rng = np.random.default_rng(s)
    p99 = gnn_prob(g, [drop_nodes(G_te[i], 0.10, rng) for i in att99])
    R["D"]["mean_abs_change_10pct_99"].append(float(np.abs(p99 - base[att99]).mean()))
    for f in FRACS:
        rng = np.random.default_rng(s)
        p = gnn_prob(g, [drop_nodes(x, f, rng) for x in G_te])
        R["D"]["flip"][f].append(100 * float(((p > 0.5) != (base > 0.5)).mean()))
L += ["## D. GNN node-removal sensitivity", "",
      f"Mean absolute change in P(malicious) when 10% of the nodes are removed at random, on 99 attack graphs (sample "
      f"seed 0): {ms(R['D']['mean_abs_change_10pct_99'], 4)} (seeds {SEEDS3}). Published value 0.0037.", "",
      "| Nodes removed | " + " | ".join(f"{int(f * 100)}%" for f in FRACS) + " |", "|---|" + "---|" * len(FRACS),
      "| Test predictions that flip (%) | " + " | ".join(ms(R["D"]["flip"][f]) for f in FRACS) + " |", ""]
log("D done")


# ===================================================================== E
def edge_variant(graphs, cond, seed):
    from torch_geometric.data import Data
    rng = np.random.RandomState(seed)
    out = []
    for g in graphs:
        n, m = g.x.shape[0], g.edge_index.shape[1]
        if cond == "none" or n < 2 or m == 0:
            ei = torch.empty((2, 0), dtype=torch.long)
        else:
            src_, dst = rng.randint(0, n, m), rng.randint(0, n, m)
            keep = src_ != dst
            ei = torch.tensor(np.stack([src_[keep], dst[keep]]), dtype=torch.long)
        out.append(Data(x=g.x, edge_index=ei, y=g.y))
    return out


R["E"] = {}
for cond in ("none", "random"):
    R["E"][cond] = []
    for s in SEEDS3:
        def run(cond=cond, s=s):
            m, ep = S["gnn_train"](s, edge_variant(G_tr, cond, s), edge_variant(G_val, cond, s), gnn_cw,
                                   3 if SMOKE else 50, 5)
            return gnn_prob(m, edge_variant(G_te, cond, s))
        p = cached(f"edge_{cond}_seed{s}.pkl", run)
        R["E"][cond].append(met(y_te, p))
        log(f"E: edges {cond} seed {s} done")
R["E"]["original"] = [met(y_te, P_TEST[s]["GNN"]) for s in SEEDS3]
L += ["## E. Edge ablation (GNN retrained, phase 3b hyperparameters)", "",
      "| Edges | Accuracy (%) | F1 (mal., %) | FPR (%) |", "|---|---|---|---|"]
for cond in ("original", "none", "random"):
    L.append(f"| {cond} | {ms([x['accuracy'] for x in R['E'][cond]])} | {ms([x['f1'] for x in R['E'][cond]])} | "
             f"{ms([x['fpr'] for x in R['E'][cond]])} |")
L.append("")


# ===================================================================== F, G
def mlp_torch(mlp):
    W0, W1 = [torch.tensor(w, dtype=torch.float32) for w in mlp.coefs_]
    b0, b1 = [torch.tensor(b, dtype=torch.float32) for b in mlp.intercepts_]
    return lambda x: (torch.relu(x @ W0 + b0) @ W1 + b1).squeeze(-1)


def gnn_attack(model, graphs, eps, steps=1, alpha=None):
    """FGSM (steps=1) or PGD on node features with a margin loss; returns predicted labels."""
    alpha = alpha or eps
    preds = []
    for d in GeoLoader(graphs, batch_size=128):
        d = d.to(device)
        x0 = d.x.float().detach()
        x = x0.clone()
        for _ in range(steps):
            x.requires_grad_(True)
            out = model(x, d.edge_index, d.batch)
            margin = ((2 * d.y - 1).float() * (out[:, 1] - out[:, 0])).sum()
            g, = torch.autograd.grad(margin, x)
            x = torch.max(torch.min(x.detach() - alpha * g.sign(), x0 + eps), x0 - eps)
        with torch.no_grad():
            preds.append(model(x, d.edge_index, d.batch).argmax(1).cpu())
    return torch.cat(preds).numpy()


def mlp_attack(f, X, y, eps, steps=1, alpha=None):
    """FGSM (steps=1) or PGD on the [CLS] input with a margin loss; returns predicted labels."""
    alpha = alpha or eps
    x0 = torch.tensor(X)
    x = x0.clone()
    sign = torch.tensor(2 * y - 1, dtype=torch.float)
    for _ in range(steps):
        x.requires_grad_(True)
        g, = torch.autograd.grad((sign * f(x)).sum(), x)
        x = torch.max(torch.min(x.detach() - alpha * g.sign(), x0 + eps), x0 - eps)
    with torch.no_grad():
        return (f(x) > 0).long().numpy()


ADV_EPS = [0.01, 0.05, 0.1, 0.2]
R["F"] = {"GNN": {e: [] for e in ADV_EPS}, "BERT": {e: [] for e in ADV_EPS}, "pgd_GNN": [], "pgd_BERT": []}
SIG_ABS = [0.25, 0.5, 1.0, 2.0]
R["G"] = {m: {sg: [] for sg in SIG_ABS} for m in MODELS_ORDER}
for s in SEEDS3:
    g = gnn_from(MAIN[s])
    f = mlp_torch(MAIN[s]["mlp"])
    for e in ADV_EPS:
        R["F"]["GNN"][e].append(100 * float((gnn_attack(g, G_te, e) == y_te).mean()))
        R["F"]["BERT"][e].append(100 * float((mlp_attack(f, B_te, y_te, e) == y_te).mean()))
    R["F"]["pgd_GNN"].append(100 * float((gnn_attack(g, G_te, 0.1, 10, 0.02) == y_te).mean()))
    R["F"]["pgd_BERT"].append(100 * float((mlp_attack(f, B_te, y_te, 0.1, 10, 0.02) == y_te).mean()))
    fam = MAIN[s]
    meta = meta_from_state(fam["meta_state"])
    base = P_TEST[s]
    for sg in SIG_ABS:
        rng = np.random.default_rng(0)
        Dn = D_te + rng.standard_normal(D_te.shape).astype(np.float32) * sg
        Bn = B_te + rng.standard_normal(B_te.shape).astype(np.float32) * sg
        gen = torch.Generator(device=device).manual_seed(0)
        pg = gnn_prob(g, G_te, xform=lambda x, sg=sg: x + sg * torch.randn(x.shape, device=device, generator=gen))
        p_svm = fam["svm"].predict_proba(Dn)
        Mx = np.column_stack([fam["lr"].predict_proba(Dn), fam["xgb"].predict_proba(Dn), p_svm]).astype(np.float32)
        with torch.no_grad():
            p_ens = F.softmax(meta(torch.tensor(Mx, device=device)), 1)[:, 1].cpu().numpy()
        new = {"ENS": p_ens, "SVM": p_svm[:, 1], "GNN": pg, "BERT": fam["mlp"].predict_proba(Bn)[:, 1]}
        for m in MODELS_ORDER:
            R["G"][m][sg].append(100 * float(((new[m] > 0.5) != (base[m] > 0.5)).mean()))
    log(f"F and G seed {s} done")
feat_sd = {"DistilBERT [CLS]": float(D_tr.std(0).mean()), "BERT [CLS]": float(B_tr.std(0).mean()),
           "GNN node features": float(torch.cat([x.x.float() for x in G_tr[:3000]]).std(0).mean())}
R["G"]["mean_feature_std"] = feat_sd
L += ["## F. White-box gradient attacks on the input features (accuracy %, untargeted, L-inf)", "",
      "Margin loss (score of the true class minus the other class), so that confidently classified queries still "
      "receive a gradient. With a cross-entropy loss the BERT-only model gave exactly zero gradient on about a third "
      "of the test queries (saturated scores), which made it look robust (gradient masking).", "",
      "| Model | " + " | ".join(f"FGSM eps {e}" for e in ADV_EPS) + " | PGD eps 0.1 (10 steps) |",
      "|---|" + "---|" * (len(ADV_EPS) + 1)]
for m, key in (("GNN", "pgd_GNN"), ("BERT", "pgd_BERT")):
    L.append(f"| {NAMES[m]} | " + " | ".join(ms(R["F"][m][e]) for e in ADV_EPS) + f" | {ms(R['F'][key])} |")
L += ["", "## G. Feature noise with absolute sigma (as the BERT-GNN paper): % of test predictions that change", "",
      "Gaussian noise of fixed standard deviation added to each model's own input features (DistilBERT [CLS] for the "
      "ensemble and SVM, BERT token features for the GNN, BERT [CLS] for BERT-only). Mean per-dimension standard "
      "deviation of each input: " + ", ".join(f"{k} {v:.3f}" for k, v in feat_sd.items())
      + ". Phase 3 section E scaled sigma by each feature's own standard deviation instead.", "",
      "| Model | " + " | ".join(f"sigma {sg}" for sg in SIG_ABS) + " |", "|---|" + "---|" * len(SIG_ABS)]
for m in MODELS_ORDER:
    L.append(f"| {NAMES[m]} | " + " | ".join(ms(R["G"][m][sg]) for sg in SIG_ABS) + " |")
L.append("")
log("E, F and G done")

# ===================================================================== H
lr_cls, tt = timed(lambda: LogisticRegression(max_iter=1000).fit(B_tr, y_tr))
p, te_ = timed(lambda: lr_cls.predict_proba(B_te)[:, 1])
R["H"] = {"bert_lr": m_full(y_te, (p > 0.5).astype(int), p), "train_s": tt, "exec_s": te_,
          "bert_mlp": [met(y_te, P_TEST[s]["BERT"]) for s in SEEDS], "gnn": [met(y_te, P_TEST[s]["GNN"]) for s in SEEDS]}
L += ["## H. BERT-only heads", "", "| Model | Accuracy (%) | Precision (mal.) | Recall (mal.) | F1 (mal.) |",
      "|---|---|---|---|---|",
      f"| BERT [CLS] + Logistic Regression | {R['H']['bert_lr']['accuracy']:.2f} | {R['H']['bert_lr']['precision']:.2f} | "
      f"{R['H']['bert_lr']['recall']:.2f} | {R['H']['bert_lr']['f1']:.2f} |"]
for key, name in (("bert_mlp", "BERT [CLS] + MLP"), ("gnn", "Structure-aware BERT-GNN")):
    L.append(f"| {name} | " + " | ".join(ms([x[k] for x in R["H"][key]]) for k in ("accuracy", "precision", "recall", "f1")) + " |")
L.append("")

# ===================================================================== I
with open(os.path.join(P3B_WORK, "tf_url_encode.pkl"), "rb") as f:
    url_p = pickle.load(f)
_r = np.random.RandomState(0)
n_bc = S["BC_PER_CLASS"]
mal_idx, ben_idx = S["mal_idx"], S["ben_idx"]
BC_IDX = np.sort(np.concatenate([_r.choice(mal_idx, min(n_bc, len(mal_idx)), replace=False),
                                 _r.choice(ben_idx, min(n_bc, len(ben_idx)), replace=False)]))
y_bc = y_te[BC_IDX]
R["I"] = {m: {"clean": [ece(y_te, P_TEST[s][m]) for s in SEEDS],
              "url_encode": [ece(y_bc, url_p[s][m]) for s in SEEDS]} for m in MODELS_ORDER}
L += ["## I. Calibration under URL-encoding evasion (expected calibration error, 15 bins; lower is better)", "",
      "| Model | Clean test set | URL-encoded (phase 3b sample, both classes) |", "|---|---|---|"]
for m in MODELS_ORDER:
    L.append(f"| {NAMES[m]} | {ms(R['I'][m]['clean'], 4)} | {ms(R['I'][m]['url_encode'], 4)} |")
L.append("")
log("H and I done")


# ===================================================================== J
def gnn_curve():
    torch.manual_seed(42)
    np.random.seed(42)
    m = GNNModel(GNN_P["hid"], GNN_P["drop"]).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=GNN_P["lr"])
    tl = GeoLoader(G_tr, batch_size=GNN_P["bs"], shuffle=True, generator=torch.Generator().manual_seed(42))
    vl = GeoLoader(G_val, batch_size=256)
    tr_l, va_l, best, bad = [], [], 1e9, 0
    for _ in range(3 if SMOKE else 50):
        tr_l.append(S["gnn_run"](m, tl, gnn_cw, opt)[0])
        v = S["gnn_run"](m, vl, gnn_cw)[0]
        va_l.append(v)
        if v < best - 1e-4:
            best, bad = v, 0
        else:
            bad += 1
        if bad >= 5:
            break
    return tr_l, va_l


CURVE_GNN = cached("gnn_curve.pkl", gnn_curve)
R["J"] = {"gnn": {"train": CURVE_GNN[0], "val": CURVE_GNN[1]}, "meta": {"train": CURVE_META[0], "val": CURVE_META[1]}}
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    for a, (k, t) in zip(ax, (("gnn", "Structure-aware BERT-GNN (seed 42)"),
                              ("meta", "Stacked-ensemble meta-learner (seed 42)"))):
        a.plot(range(1, len(R["J"][k]["train"]) + 1), R["J"][k]["train"], label="Training loss")
        a.plot(range(1, len(R["J"][k]["val"]) + 1), R["J"][k]["val"], label="Validation loss")
        a.set(xlabel="Epoch", ylabel="Cross-entropy loss", title=t)
        a.grid(alpha=0.3)
        a.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "phase3d_loss_curves.png"), dpi=200)
except Exception as e:
    log(f"figure skipped: {e!r}")
L += ["## J. Loss curves", "", f"GNN: {len(CURVE_GNN[0])} epochs to early stopping (patience 5); final training loss "
      f"{CURVE_GNN[0][-1]:.4f}, best validation loss {min(CURVE_GNN[1]):.4f}. Meta-learner: {len(CURVE_META[0])} epochs "
      f"on 80% of the out-of-fold meta-features, validation on 20%; final training loss {CURVE_META[0][-1]:.4f}, "
      f"validation {CURVE_META[1][-1]:.4f}. Figure: `phase3d_loss_curves.png`.", ""]
log("J done")


# ===================================================================== K
def gnn_search40():
    import optuna
    from sklearn.metrics import f1_score
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    storage = f"sqlite:///{os.path.join(WORK, 'optuna40.db')}".replace("\\", "/")
    st = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=42),
                             study_name="gnn40", storage=storage, load_if_exists=True)
    y_val = val_df["Label"].values

    def obj(t):
        p = dict(hid=t.suggest_int("hid", 32, 256), drop=t.suggest_float("drop", 0.1, 0.5),
                 lr=t.suggest_float("lr", 1e-5, 1e-2, log=True), bs=t.suggest_int("bs", 32, 128))
        saved = dict(S["GNN_P"])
        S["GNN_P"].update(p)
        try:
            m, _ = S["gnn_train"](42, G_tr, G_val, gnn_cw, 2 if SMOKE else 12, 3)
            f1 = f1_score(y_val, S["gnn_run"](m, GeoLoader(G_val, batch_size=256), gnn_cw)[1], average="weighted")
        finally:
            S["GNN_P"].clear()
            S["GNN_P"].update(saved)
        log(f"  K: trial {t.number}: validation weighted F1 {f1:.4f} {p}")
        return f1
    n_done = len([t for t in st.trials if t.state.name == "COMPLETE"])
    st.optimize(obj, n_trials=max(0, (2 if SMOKE else 40) - n_done))
    return st.best_params, st.best_value


best40, val40 = gnn_search40()


def train_best40():
    saved = dict(S["GNN_P"])
    S["GNN_P"].update(best40)
    try:
        res = []
        for s in SEEDS3:
            m, _ = S["gnn_train"](s, G_tr, G_val, gnn_cw, 3 if SMOKE else 50, 5)
            res.append(gnn_prob(m, G_te))
        return res
    finally:
        S["GNN_P"].clear()
        S["GNN_P"].update(saved)


P40 = cached("gnn_best40_preds.pkl", train_best40)
R["K"] = {"best40": best40, "val_f1_40": val40, "best8": dict(GNN_P),
          "test40": [met(y_te, p) for p in P40], "test8": [met(y_te, P_TEST[s]["GNN"]) for s in SEEDS3]}
L += ["## K. GNN hyperparameters: 40 Optuna trials (as published) against the 8 used in phases 3 to 3c", "",
      f"40-trial best (validation weighted F1 {val40:.4f}): {best40}. 8-trial: {dict(GNN_P)}.", "",
      "| Search | Accuracy (%) | F1 (mal., %) | FPR (%) |", "|---|---|---|---|"]
for k, name in (("test8", "8 trials (phases 3 to 3c)"), ("test40", "40 trials")):
    L.append(f"| {name} | {ms([x['accuracy'] for x in R['K'][k]])} | {ms([x['f1'] for x in R['K'][k]])} | "
             f"{ms([x['fpr'] for x in R['K'][k]])} |")
log("K done")

L += ["", "## Notes", "",
      "- Section A trains every classifier with its notebook grid on this machine; training and execution times are "
      "therefore CPU times and are not comparable with the published Colab times.",
      "- The TF-IDF features are fitted on the 70/30 training split only.",
      "- Section C uses the seed 42 out-of-fold meta-features for the pre-Optuna model and the loss curve.",
      f"- Seeds: {SEEDS} where phase 3b models are only evaluated; {SEEDS3} where models are retrained or attacked.", "",
      "Reproduce: `python merged_phase3d_original_tests.py` (after phase 3b; P3B_WORK, WORK_DIR)."]
open(os.path.join(OUT, "phase3d_original_tests.md"), "w", encoding="utf-8").write("\n".join(L))
json.dump(R, open(os.path.join(OUT, "phase3d_original_tests.json"), "w"), indent=1,
          default=lambda o: o.tolist() if isinstance(o, np.ndarray) else float(o) if isinstance(o, np.floating)
          else int(o) if isinstance(o, np.integer) else str(o))
gc.collect()
log("done: results/merged/phase3d_original_tests.md")
