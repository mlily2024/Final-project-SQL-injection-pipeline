"""
Merged paper, phase 2: DistilBERT-Stacked Ensemble re-run on the BERT-GNN split.

Same pipeline as DistilBERT_Stacked_Ensemble_pipeline.ipynb, with ONE change:
the outer split is 70/30 (test_size=0.30, random_state=42), identical to
corrected_bertgnn_retrain.py / bert_only_ablation.py, so both pipelines are
scored on the same 9,276 test queries.

Kept from the notebook:
  * preprocessing: Query lower-cased and stripped; LabelEncoder
  * DistilBERT (distilbert-base-uncased) [CLS] embeddings, max_length=128
  * balanced class weights
  * base models LR / SVM / XGBoost, GridSearchCV (5-fold, accuracy), same grids
  * meta-features: out-of-fold cross_val_predict(predict_proba, cv=5) on train
  * meta-learner MLP + FGSM adversarial training, Optuna 100 trials,
    objective = mean adversarial accuracy over 5-fold CV on TRAIN meta-features

Changes (recorded in the output):
  * seeds fixed (torch, numpy, Optuna sampler) for reproducibility
  * the final meta-learner is trained on train meta-features only; the test
    set is used once, for the final evaluation (the notebook also logged a
    test loss curve during training, which did not affect the model)
  * Random Forest, Decision Tree, Naive Bayes and Gradient Boosting are not
    re-run: they are not part of the ensemble

Outputs: results/merged/phase2_distilbert_7030.md and .json, plus test-set
predictions (.merged_work/phase2_test_predictions.csv) for later phases.
Embeddings are cached in .merged_work/ so the run can be resumed.
"""
import json
import os
import time

import numpy as np
import optuna
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import xgboost as xgb
from scipy.stats import binomtest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             matthews_corrcoef, precision_score, recall_score)
from sklearn.model_selection import (GridSearchCV, KFold, cross_val_predict,
                                     train_test_split)
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC
from sklearn.utils.class_weight import compute_class_weight
from transformers import DistilBertModel, DistilBertTokenizer

SEED = 42
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "SQL_Injection_Dataset.csv")
WORK = os.path.join(HERE, ".merged_work")
OUT = os.path.join(HERE, "results", "merged")
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

np.random.seed(SEED)
torch.manual_seed(SEED)
torch.set_num_threads(6)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ---------------------------------------------------------------- data
df = pd.read_csv(DATA)
df["Query"] = df["Query"].astype(str).apply(lambda x: x.lower().strip())
df["Label"] = LabelEncoder().fit_transform(df["Label"])
train_df, test_df = train_test_split(df, test_size=0.30, random_state=SEED)
y_tr = train_df["Label"].values
y_te = test_df["Label"].values
log(f"train {len(train_df)}, test {len(test_df)} "
    f"(benign {int((y_te == 0).sum())}, malicious {int((y_te == 1).sum())})")
assert len(test_df) == 9276, "test set must match the BERT-GNN test set"

class_weights = compute_class_weight("balanced", classes=np.unique(y_tr), y=y_tr)

# ---------------------------------------------------------- embeddings
emb_tr_p = os.path.join(WORK, "distil_train_cls.npy")
emb_te_p = os.path.join(WORK, "distil_test_cls.npy")
emb_time_p = os.path.join(WORK, "distil_embedding_time.json")
if os.path.exists(emb_tr_p) and os.path.exists(emb_te_p):
    X_tr, X_te = np.load(emb_tr_p), np.load(emb_te_p)
    emb_info = json.load(open(emb_time_p))
    log("embeddings loaded from cache")
else:
    tok = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
    bert = DistilBertModel.from_pretrained("distilbert-base-uncased").to(device).eval()

    BS, CHUNK = 32, 1024     # small batches; each 1,024-query chunk saved to disk

    def embed(queries, tag):
        """Resumable: a crash (e.g. low memory) loses at most one chunk."""
        parts, t_total = [], 0.0
        for start in range(0, len(queries), CHUNK):
            p = os.path.join(WORK, f"{tag}_chunk_{start:06d}.npy")
            if os.path.exists(p):
                parts.append(np.load(p))
                continue
            t0 = time.perf_counter()
            out = []
            for i in range(start, min(start + CHUNK, len(queries)), BS):
                enc = tok(queries[i:i + BS], max_length=128, padding=True,
                          truncation=True, return_tensors="pt").to(device)
                with torch.inference_mode():
                    out.append(bert(**enc).last_hidden_state[:, 0, :].cpu().numpy())
                del enc
            t_total += time.perf_counter() - t0
            arr = np.vstack(out).astype(np.float32)
            np.save(p, arr)
            parts.append(arr)
            log(f"  {tag}: {start + len(arr)}/{len(queries)}")
        return np.vstack(parts), t_total

    log("embedding train set")
    X_tr, _ = embed(train_df["Query"].tolist(), "train")
    log("embedding test set (timed)")
    X_te, t_emb = embed(test_df["Query"].tolist(), "test")
    emb_info = {"test_embedding_seconds": t_emb,
                "ms_per_query": 1000 * t_emb / len(test_df),
                "batch_size": BS, "device": str(device),
                "note": "time summed over chunks embedded in this run"}
    del bert, tok
    import glob
    for f in glob.glob(os.path.join(WORK, "*_chunk_*.npy")):
        os.remove(f)
    np.save(emb_tr_p, X_tr)
    np.save(emb_te_p, X_te)
    json.dump(emb_info, open(emb_time_p, "w"), indent=2)
log(f"embeddings {X_tr.shape} / {X_te.shape}; "
    f"{emb_info['ms_per_query']:.2f} ms per test query ({emb_info['device']})")

# ---------------------------------------------------------- base models
base = {
    "Logistic Regression": (LogisticRegression(max_iter=1000, class_weight="balanced"),
                            {"C": [0.1, 1, 10]}),
    "SVM": (SVC(probability=True, class_weight="balanced", random_state=SEED),
            {"C": [0.1, 1, 10], "kernel": ["linear", "rbf"]}),
    "XGBoost": (xgb.XGBClassifier(eval_metric="logloss", scale_pos_weight=class_weights[1],
                                  random_state=SEED, n_jobs=4),
                {"n_estimators": [50, 100, 200]}),
}


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {
        "accuracy": 100 * accuracy_score(y, p),
        "weighted_f1": 100 * f1_score(y, p, average="weighted"),
        "mal_precision": 100 * precision_score(y, p),
        "mal_recall": 100 * recall_score(y, p),
        "mal_f1": 100 * f1_score(y, p),
        "fpr": 100 * fp / (fp + tn),
        "mcc": matthews_corrcoef(y, p),
        "fp": int(fp), "fn": int(fn),
    }


results, fitted, preds = {}, {}, {}
for name, (clf, grid) in base.items():
    log(f"GridSearchCV {name}")
    t0 = time.perf_counter()
    gs = GridSearchCV(clf, grid, cv=5, scoring="accuracy", n_jobs=3).fit(X_tr, y_tr)
    t_train = time.perf_counter() - t0
    best = gs.best_estimator_
    t0 = time.perf_counter()
    p = best.predict(X_te)
    t_exec = time.perf_counter() - t0
    fitted[name], preds[name] = best, p
    results[name] = {**metrics(y_te, p), "best_params": gs.best_params_,
                     "train_s": t_train, "test_exec_s": t_exec}
    log(f"  {name}: acc {results[name]['accuracy']:.2f}%  {gs.best_params_}  "
        f"train {t_train:.0f}s exec {t_exec:.4f}s")

# ------------------------------------------------------- meta-features
names = ["Logistic Regression", "XGBoost", "SVM"]   # notebook order
log("out-of-fold meta-features (cross_val_predict, cv=5)")
M_tr = np.column_stack([cross_val_predict(fitted[n], X_tr, y_tr, cv=5,
                                          method="predict_proba", n_jobs=3)
                        for n in names]).astype(np.float32)
M_te = np.column_stack([fitted[n].predict_proba(X_te) for n in names]).astype(np.float32)


class MetaLearnerNN(nn.Module):
    def __init__(self, input_dim, hidden_dim, dropout_rate):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout_rate)
        self.fc2 = nn.Linear(hidden_dim, 2)

    def forward(self, x):
        return self.fc2(self.dropout(torch.relu(self.fc1(x))))


def fgsm(x, eps, grad):
    return x + eps * grad.sign()


def adv_train(model, X, y, eps, epochs, lr):
    """Notebook procedure: per epoch, one clean step and one FGSM step."""
    opt = optim.Adam(model.parameters(), lr=lr)
    crit = nn.CrossEntropyLoss()
    for _ in range(epochs):
        model.train()
        opt.zero_grad()
        crit(model(X), y).backward()
        opt.step()
        xa = X.clone().detach().requires_grad_(True)
        model.zero_grad()
        crit(model(xa), y).backward()
        xa = fgsm(xa, eps, xa.grad.data).detach()
        crit(model(xa), y).backward()
        opt.step()
    return model


def evaluate(model, X, y, eps):
    model.eval()
    Xt = torch.tensor(X, dtype=torch.float32, device=device)
    yt = torch.tensor(y, dtype=torch.long, device=device)
    t0 = time.perf_counter()
    with torch.no_grad():
        out = model(Xt)
    t_exec = time.perf_counter() - t0
    p = out.argmax(1)
    xa = Xt.clone().detach().requires_grad_(True)
    model.zero_grad()
    nn.CrossEntropyLoss()(model(xa), yt).backward()
    xa = fgsm(xa, eps, xa.grad.data)
    with torch.no_grad():
        pa = model(xa).argmax(1)
    return (p == yt).float().mean().item(), (pa == yt).float().mean().item(), \
        p.cpu().numpy(), torch.softmax(out, 1)[:, 1].cpu().numpy(), t_exec


def objective(trial):
    hd = trial.suggest_int("hidden_dim", 32, 256)
    dr = trial.suggest_float("dropout_rate", 0.1, 0.6)
    lr = trial.suggest_float("lr", 1e-5, 1e-2, log=True)
    ep = trial.suggest_int("epochs", 10, 100)
    eps = trial.suggest_float("epsilon", 0.1, 0.5)
    adv = []
    for tri, vai in KFold(5, shuffle=True, random_state=SEED).split(M_tr):
        torch.manual_seed(SEED)
        m = MetaLearnerNN(M_tr.shape[1], hd, dr).to(device)
        m = adv_train(m, torch.tensor(M_tr[tri], device=device),
                      torch.tensor(y_tr[tri], dtype=torch.long, device=device), eps, ep, lr)
        adv.append(evaluate(m, M_tr[vai], y_tr[vai], eps)[1])
    return float(np.mean(adv))


log("Optuna: 100 trials on train meta-features only")
optuna.logging.set_verbosity(optuna.logging.WARNING)
study = optuna.create_study(direction="maximize",
                            sampler=optuna.samplers.TPESampler(seed=SEED))
study.optimize(objective, n_trials=100)
bp = study.best_params
log(f"best params {bp} (CV adversarial acc {study.best_value:.4f})")

torch.manual_seed(SEED)
meta = MetaLearnerNN(M_tr.shape[1], bp["hidden_dim"], bp["dropout_rate"]).to(device)
t0 = time.perf_counter()
meta = adv_train(meta, torch.tensor(M_tr, device=device),
                 torch.tensor(y_tr, dtype=torch.long, device=device),
                 bp["epsilon"], bp["epochs"], bp["lr"])
t_meta_train = time.perf_counter() - t0
acc, adv_acc, p_ens, prob_ens, t_meta_exec = evaluate(meta, M_te, y_te, bp["epsilon"])
torch.save(meta.state_dict(), os.path.join(WORK, "phase2_meta_learner.pth"))

# base-model stage for the ensemble at inference = 3 predict_proba calls
t0 = time.perf_counter()
_ = [fitted[n].predict_proba(X_te) for n in names]
t_base_proba = time.perf_counter() - t0

results["DistilBERT-Stacked Ensemble"] = {
    **metrics(y_te, p_ens), "fgsm_adv_accuracy": 100 * adv_acc,
    "best_params": bp, "train_s": t_meta_train,
    "test_exec_s": t_meta_exec, "test_exec_incl_base_models_s": t_meta_exec + t_base_proba,
}
log(f"ensemble: acc {100 * acc:.2f}%  FGSM {100 * adv_acc:.2f}%")

# McNemar exact test: SVM vs ensemble (same test predictions)
b = int(((preds["SVM"] == y_te) & (p_ens != y_te)).sum())
c = int(((preds["SVM"] != y_te) & (p_ens == y_te)).sum())
mcn_p = binomtest(b, b + c, 0.5).pvalue if b + c else 1.0

pd.DataFrame({"index": test_df.index, "label": y_te, "ensemble_pred": p_ens,
              "ensemble_prob_mal": prob_ens,
              **{f"{n}_pred": preds[n] for n in names}}) \
    .to_csv(os.path.join(WORK, "phase2_test_predictions.csv"), index=False)

summary = {"split": "70/30, random_state=42", "n_train": len(train_df), "n_test": len(test_df),
           "embedding": emb_info, "models": results,
           "mcnemar_svm_vs_ensemble": {"svm_right_ens_wrong": b, "ens_right_svm_wrong": c,
                                       "exact_p": mcn_p}}
json.dump(summary, open(os.path.join(OUT, "phase2_distilbert_7030.json"), "w"),
          indent=2, default=float)

rows = ["| Model | Accuracy | Mal. precision | Mal. recall | Mal. F1 | FPR (%) | MCC | FP/FN | Train (s) | Test exec (s) |",
        "|---|---|---|---|---|---|---|---|---|---|"]
for n, r in results.items():
    rows.append(f"| {n} | {r['accuracy']:.2f} | {r['mal_precision']:.2f} | {r['mal_recall']:.2f} | "
                f"{r['mal_f1']:.2f} | {r['fpr']:.3f} | {r['mcc']:.4f} | {r['fp']}/{r['fn']} | "
                f"{r['train_s']:.1f} | {r['test_exec_s']:.4f} |")
e = results["DistilBERT-Stacked Ensemble"]
md = f"""# Phase 2: DistilBERT-Stacked Ensemble on the 70/30 split

Same split as the BERT-GNN scripts (`test_size=0.30, random_state=42`): {len(train_df)} training and {len(test_df)} test queries ({int((y_te == 0).sum())} benign, {int((y_te == 1).sum())} malicious). Device: {emb_info['device']}.

{chr(10).join(rows)}

- Ensemble under single-step FGSM on the meta-features (epsilon {bp['epsilon']:.3f}): **{e['fgsm_adv_accuracy']:.2f}%**.
- Ensemble test-set time: meta-learner {e['test_exec_s']:.4f} s; with the three base-model probability calls {e['test_exec_incl_base_models_s']:.4f} s.
- Shared DistilBERT embedding: {emb_info['ms_per_query']:.2f} ms per query (batch 64), common to every model above.
- McNemar exact test, SVM against ensemble: {b} queries only SVM got right, {c} only the ensemble got right, p = {mcn_p:.3g}.
- Meta-learner (Optuna, 100 trials, 5-fold CV on training meta-features): {json.dumps({k: round(v, 4) if isinstance(v, float) else v for k, v in bp.items()})}.
- Base-model grids as in the notebook; best: """ + "; ".join(f"{n} {results[n]['best_params']}" for n in names) + """.

Earlier result (80/20 split, notebook): ensemble 99.81%, SVM 99.82%, LR 99.76%, XGBoost 99.74%, FGSM 99.77%.
Reproduce: `python merged_phase2_distilbert_7030.py`.
"""
open(os.path.join(OUT, "phase2_distilbert_7030.md"), "w", encoding="utf-8").write(md)
log("done: results/merged/phase2_distilbert_7030.md")
