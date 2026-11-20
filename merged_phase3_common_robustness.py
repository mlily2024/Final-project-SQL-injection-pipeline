"""
Merged paper, phase 3: one common robustness protocol for every model.

Models (all trained on the same 70/30 split, test set = 9,276 queries):
  ENS   DistilBERT-Stacked Ensemble (LR + XGBoost + SVM -> FGSM-trained meta-learner)
  SVM   DistilBERT-SVM (strongest single DistilBERT model)
  GNN   structure-aware BERT-GNN (sqlparse tokens, sequential + parenthesis +
        clause-scope edges; held-out validation protocol)
  BERT  BERT-only ([CLS] -> MLP, 159 hidden units), the no-graph baseline

Tests
  A  clean test set: full metrics, pairwise McNemar exact tests (seed 42)
  B  query-level evasion: recall on the 3,446 malicious test queries after
     each WAF-bypass transform (re-embedded through each model's own encoder)
  C  adaptive best-of-N evasion: a query is evaded if ANY transform evades
  D  cross-dataset: trained on Kaggle only, tested on HTTPParams (30,156) and on
     the curated out-of-distribution set (35 attacks, 34 benign)
  E  input-noise stability: Gaussian noise on each model's input features,
     scaled to the per-dimension std of its own training features; flip rate
  F  five seeds (42, 1, 7, 13, 123) for everything above: mean and std

Fixed hyperparameters (no re-tuning per seed):
  ENS/SVM from phase 2 (LR C=1; SVM C=10 rbf; XGBoost 100 trees; meta-learner
  hidden 195, dropout 0.4828, lr 0.006257, 92 epochs, FGSM eps 0.1004).
  GNN: Optuna, 8 trials on the validation set, seed 42 (as structure_graph_gnn.py),
  then fixed for all seeds. BERT-only MLP: as bert_only_ablation.py.

Resumable: every artefact is cached in WORK (environment variable WORK_DIR,
default .merged_work/phase3). Re-running continues from the last finished step.
"""
import json
import os
import pickle
import re
import time
import zlib

import numpy as np
import pandas as pd
import sqlparse
import torch
import torch.nn as nn
import torch.nn.functional as F
import xgboost as xgb
from scipy.stats import binomtest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             matthews_corrcoef, precision_score, recall_score)
from sklearn.model_selection import cross_val_predict, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.utils.class_weight import compute_class_weight
from sqlparse.tokens import Newline, Whitespace
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader as GeoLoader
from torch_geometric.nn import GCNConv, global_mean_pool

os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get("WORK_DIR", os.path.join(HERE, ".merged_work", "phase3"))
OUT = os.path.join(HERE, "results", "merged")
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)
SMOKE = os.environ.get("SMOKE") == "1"   # tiny end-to-end check, separate WORK dir
SEEDS = [42, 1] if SMOKE else [42, 1, 7, 13, 123]
if SMOKE:
    WORK = WORK + "_smoke"
    os.makedirs(WORK, exist_ok=True)
MAX_LEN = 128
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
SIGMAS = [0.1, 0.25, 0.5]
KEYWORDS = {"select", "from", "where", "union", "and", "or", "insert", "update",
            "delete", "join", "on", "group", "order", "having", "limit", "values", "set"}
ENS_P = dict(hidden_dim=195, dropout_rate=0.48280235776814573, lr=0.006257488041237617,
             epochs=92, epsilon=0.1004122390391398)


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def W(name):
    return os.path.join(WORK, name)


def cached(name, fn):
    """Load W(name) if present, else compute with fn(), save, return."""
    p = W(name)
    if os.path.exists(p):
        with open(p, "rb") as f:
            return pickle.load(f)
    v = fn()
    with open(p + ".tmp", "wb") as f:
        pickle.dump(v, f, protocol=4)
    os.replace(p + ".tmp", p)
    return v


# ======================================================================= data
df = pd.read_csv(os.path.join(HERE, "SQL_Injection_Dataset.csv"))
df["Query"] = df["Query"].astype(str).apply(lambda x: x.lower().strip())
train_df, test_df = train_test_split(df, test_size=0.30, random_state=42)
tr_df, val_df = train_test_split(train_df, test_size=0.15, random_state=42,
                                 stratify=train_df["Label"])
if SMOKE:
    train_df = train_df.sample(800, random_state=0)
    test_df = test_df.sample(300, random_state=0)
    tr_df, val_df = train_test_split(train_df, test_size=0.15, random_state=42,
                                     stratify=train_df["Label"])
y_tr, y_te = train_df["Label"].values, test_df["Label"].values
assert SMOKE or len(test_df) == 9276
mal_q = test_df.loc[test_df["Label"] == 1, "Query"].tolist()
hp = pd.read_csv(os.path.join(HERE, "httpparams_sqli.csv"))
hp["Query"] = hp["Query"].astype(str).apply(lambda x: x.lower().strip())
if SMOKE:
    hp = hp.sample(300, random_state=0)
log(f"train {len(train_df)} (GNN: tr {len(tr_df)} val {len(val_df)}), test {len(test_df)}, "
    f"malicious test {len(mal_q)}, HTTPParams {len(hp)}; device {device}")

# curated out-of-distribution set: identical to robustness_5_crossdataset.py
OOD_MAL = [
    "' or 1=1--", "' or '1'='1", "admin'--", "' or 1=1#", "') or ('1'='1",
    "' union select null,username,password from users--",
    "1 union all select 1,2,3,4,5,6,7,8,9,10--",
    "' union select @@version--", "-1' union select database(),user()--",
    "1' and 1=convert(int,(select @@version))--",
    "' and extractvalue(1,concat(0x7e,version()))--",
    "' and updatexml(1,concat(0x7e,(select version())),1)--",
    "1' waitfor delay '0:0:5'--", "' or sleep(5)#", "1 and (select sleep(5))",
    "'; drop table users;--", "1'; exec xp_cmdshell('whoami')--",
    "1); drop table logs;--", "' or username like '%admin%'--",
    "1 procedure analyse(extractvalue(1,concat(0x3a,version())),1)",
    "' union select 1,2,load_file('/etc/passwd')--",
    "' or 1=1 limit 1 offset 0--", "1' group by columnnames having 1=1--",
    "' unioN sELeCt 1,2,3--", "1/**/union/**/select/**/1,2,3--",
    "%27%20or%201%3d1--", "' or 0x50=0x50--", "1' or 'a'='a",
    "'||(select user())||'", "'+(select top 1 name from sysobjects)+'",
    "1' and substring(@@version,1,1)='5'--", "' or exists(select * from users)--",
    "'; begin declare @x int; end--", "1 or 1=1", "' having 1=1--",
]
OOD_BEN = [
    "select * from products where id = 42", "SELECT name, price FROM catalogue WHERE category = 'books'",
    "update users set last_login = now() where user_id = 7",
    "insert into orders (customer, total) values ('alice', 29.99)",
    "delete from cart where session = 'abc123'", "select count(*) from visits where day = '2024-05-01'",
    "john.doe@example.com", "my order number is 12345", "search: blue running shoes size 10",
    "the quick brown fox jumps over the lazy dog", "please reset my password", "2024-05-14T10:30:00",
    "SELECT first_name, last_name FROM employees ORDER BY hire_date DESC",
    "select p.name, c.title from products p join categories c on p.cat_id = c.id",
    "update inventory set qty = qty - 1 where sku = 'ABC-123'", "hello world", "invoice #INV-2024-0042",
    "contact us at support@shop.example.com", "London, United Kingdom", "temperature is 21 degrees",
    "select * from bookings where checkin between '2024-06-01' and '2024-06-07'",
    "add 3 items to the basket", "the meeting is at 3pm on tuesday",
    "insert into feedback (rating, comment) values (5, 'great service')",
    "user profile updated successfully", "select avg(price) from listings where region = 'north'",
    "my name is o'brien", "select id, email from subscribers where active = true",
    "product code: XZ-9981", "order confirmed, thank you for shopping",
    "grant select on reports to analyst_role", "show me my recent transactions",
    "select title from articles where published = 1 and author = 'smith'", "café latte and a croissant",
]
ood_q = [q.lower().strip() for q in OOD_MAL + OOD_BEN]
ood_y = np.array([1] * len(OOD_MAL) + [0] * len(OOD_BEN))

# ================================================================= transforms
# Union of the transforms in query_level_evasion.py, robustness_3 and robustness_4.
KW = ["select", "from", "where", "union", "and", "or", "insert", "update", "delete", "join"]


def url_encode(q): return q.replace(" ", "%20").replace("'", "%27").replace("=", "%3d").replace('"', "%22")
def double_url(q): return q.replace("%", "%25").replace(" ", "%2520").replace("'", "%2527")
def inline_comment(q): return q.replace(" ", "/**/")


def keyword_split(q):
    for k in KW:
        q = q.replace(k, k[:2] + "/**/" + k[2:])
    return q


def mysql_comment(q):
    for k in KW:
        q = q.replace(k, f"/*!50000{k}*/")
    return q


def case_random(q):
    # zlib.crc32 replaces Python hash() (randomised per process) -> reproducible
    rng = np.random.RandomState(zlib.crc32(q.encode("utf-8")) % (2 ** 31))
    return "".join(c.upper() if (c.isalpha() and rng.rand() < 0.5) else c.lower() for c in q)


def tab_whitespace(q): return re.sub(r" +", "\t", q)


def mixed_whitespace(q):
    subs = ["\t", "\n", "\x0b", "\x0c", "/**/"]
    out, i = [], 0
    for c in q:
        if c == " ":
            out.append(subs[i % len(subs)])
            i += 1
        else:
            out.append(c)
    return "".join(out)


def url_case(q): return case_random(url_encode(q))


TRANSFORMS = {"url_encode": url_encode, "double_url_encode": double_url,
              "inline_comment": inline_comment, "keyword_split": keyword_split,
              "mysql_versioned_comment": mysql_comment, "case_random": case_random,
              "tab_whitespace": tab_whitespace, "mixed_whitespace": mixed_whitespace,
              "url_encode+case_random": url_case}
# Note: the models lower-case at training; evaluation queries are NOT re-lower-cased
# after a transform (an attacker controls the raw string); both tokenisers are
# uncased, so case_random tests the tokeniser normalisation path.

# ================================================================= encoders
_enc = {}


def distil():
    if "d" not in _enc:
        from transformers import DistilBertModel, DistilBertTokenizerFast
        _enc["d"] = (DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased"),
                     DistilBertModel.from_pretrained("distilbert-base-uncased").to(device).eval())
    return _enc["d"]


def bert():
    if "b" not in _enc:
        from transformers import BertModel, BertTokenizerFast
        _enc["b"] = (BertTokenizerFast.from_pretrained("bert-base-uncased"),
                     BertModel.from_pretrained("bert-base-uncased").to(device).eval())
    return _enc["b"]


def distil_cls(queries, bs=128):
    tok, m = distil()
    order = np.argsort([len(q) for q in queries], kind="stable")
    out = np.zeros((len(queries), 768), np.float32)
    with torch.inference_mode():
        for k in range(0, len(order), bs):
            idx = order[k:k + bs]
            enc = tok([queries[i] for i in idx], max_length=MAX_LEN, padding=True,
                      truncation=True, return_tensors="pt").to(device)
            out[idx] = m(**enc).last_hidden_state[:, 0, :].float().cpu().numpy()
    return out


def sql_tokens(query):
    """As structure_graph_gnn.py: [(text, start, end)] for significant sqlparse tokens."""
    toks, pos = [], 0
    try:
        flat = list(sqlparse.parse(query)[0].flatten()) if query.strip() else []
    except Exception:
        flat = []
    for t in flat:
        val = t.value
        if t.ttype in (Whitespace, Newline) or val.strip() == "":
            pos += len(val)
            continue
        toks.append((val, pos, pos + len(val)))
        pos += len(val)
    return toks


def structure_edges(tokens):
    """As structure_graph_gnn.py: sequential + parenthesis-match + clause-scope, undirected."""
    edges, stack, last_kw = set(), [], None
    for i in range(len(tokens) - 1):
        edges.add((i, i + 1))
    for i, (val, a, b) in enumerate(tokens):
        v = val.lower()
        if val == "(":
            stack.append(i)
        elif val == ")" and stack:
            edges.add((stack.pop(), i))
        if v in KEYWORDS:
            last_kw = i
        elif last_kw is not None:
            edges.add((last_kw, i))
    return [(a, b) for a, b in edges] + [(b, a) for a, b in edges]


def bert_cls_graphs(queries, labels=None, bs=64):
    """One BERT pass -> ([CLS] matrix, structure graphs), aligned to input order.
    Node features = BERT sub-word embeddings mean-pooled over each sqlparse token's
    character span (offset mapping), as structure_graph_gnn.py; stored float16.
    A query with no sqlparse token gets a single [CLS] node (robustness_common.py)."""
    tok, m = bert()
    order = np.argsort([len(q) for q in queries], kind="stable")
    cls = np.zeros((len(queries), 768), np.float32)
    graphs = [None] * len(queries)
    with torch.inference_mode():
        for k in range(0, len(order), bs):
            idx = order[k:k + bs]
            enc = tok([queries[i] for i in idx], truncation=True, max_length=MAX_LEN, padding=True,
                      return_offsets_mapping=True, return_tensors="pt")
            hs = m(input_ids=enc["input_ids"].to(device),
                   attention_mask=enc["attention_mask"].to(device)).last_hidden_state.float().cpu().numpy()
            offs = enc["offset_mapping"].numpy()
            for bi, qi in enumerate(idx):
                cls[qi] = hs[bi][0]
                y = torch.tensor([int(labels[qi]) if labels is not None else 0])
                toks = sql_tokens(queries[qi])
                if not toks:
                    graphs[qi] = Data(x=torch.tensor(hs[bi][:1]).half(),
                                      edge_index=torch.empty((2, 0), dtype=torch.long), y=y)
                    continue
                so = offs[bi]
                valid = ~((so[:, 0] == 0) & (so[:, 1] == 0))
                feats = []
                for (val, a, b) in toks:
                    msk = valid & (so[:, 0] < b) & (so[:, 1] > a)
                    feats.append(hs[bi][msk].mean(axis=0) if msk.any() else hs[bi][0])
                e = structure_edges(toks)
                graphs[qi] = Data(x=torch.tensor(np.stack(feats)).half(),
                                  edge_index=(torch.tensor(e, dtype=torch.long).t().contiguous()
                                              if e else torch.empty((2, 0), dtype=torch.long)), y=y)
    return cls, graphs


# =========================================================== features (cached)
t0 = time.time()
D_tr = cached("distil_train.pkl", lambda: distil_cls(train_df["Query"].tolist()))
D_te = cached("distil_test.pkl", lambda: distil_cls(test_df["Query"].tolist()))
log(f"DistilBERT train/test features ready ({time.time() - t0:.0f}s)")


def bert_set(tag, frame):
    return cached(f"bert_{tag}.pkl",
                  lambda: bert_cls_graphs(frame["Query"].tolist(), frame["Label"].values))


B_trn_cls, G_tr = bert_set("tr", tr_df)
B_val_cls, G_val = bert_set("val", val_df)
B_te_cls, G_te = bert_set("test", test_df)
# BERT-only MLP is trained on the full training portion (tr + val), as bert_only_ablation.py
tr_pos = {ix: i for i, ix in enumerate(tr_df.index)}
val_pos = {ix: i for i, ix in enumerate(val_df.index)}
B_tr = np.stack([B_trn_cls[tr_pos[ix]] if ix in tr_pos else B_val_cls[val_pos[ix]]
                 for ix in train_df.index])
log(f"BERT features and structure graphs ready ({time.time() - t0:.0f}s)")

# ================================================================= models
class GNNModel(nn.Module):
    def __init__(self, hid, drop):
        super().__init__()
        self.c1 = GCNConv(768, hid)
        self.c2 = GCNConv(hid, hid)
        self.f1 = nn.Linear(hid, hid)
        self.f2 = nn.Linear(hid, 2)
        self.dp = nn.Dropout(drop)

    def forward(self, x, ei, b):
        x = F.relu(self.c1(x, ei))
        x = F.relu(self.c2(x, ei))
        x = global_mean_pool(x, b)
        return self.f2(self.dp(F.relu(self.f1(x))))


gnn_cw = torch.tensor(compute_class_weight("balanced", classes=np.array([0, 1]),
                                           y=tr_df["Label"].values), dtype=torch.float, device=device)


def gnn_run(model, loader, opt=None, noise=None):
    """One pass. noise: per-dim std vector (torch) * sigma added to node features."""
    crit = nn.CrossEntropyLoss(weight=gnn_cw)
    train = opt is not None
    model.train() if train else model.eval()
    tot, P, PR = 0.0, [], []
    gen = torch.Generator(device=device).manual_seed(0) if noise is not None else None
    with (torch.enable_grad() if train else torch.no_grad()):
        for d in loader:
            d = d.to(device)
            x = d.x.float()
            if noise is not None:
                x = x + noise * torch.randn(x.shape, device=device, generator=gen)
            if train:
                opt.zero_grad()
            out = model(x, d.edge_index, d.batch)
            loss = crit(out, d.y)
            if train:
                loss.backward()
                opt.step()
            tot += loss.item()
            P.append(out.argmax(1).detach().cpu())
            PR.append(F.softmax(out, 1)[:, 1].detach().cpu())
    return tot / max(len(loader), 1), torch.cat(P).numpy(), torch.cat(PR).numpy()


def gnn_train(p, seed, max_ep, pat):
    torch.manual_seed(seed)
    np.random.seed(seed)
    m = GNNModel(p["hid"], p["drop"]).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=p["lr"])
    g = torch.Generator().manual_seed(seed)
    tl = GeoLoader(G_tr, batch_size=p["bs"], shuffle=True, generator=g)
    vl = GeoLoader(G_val, batch_size=256)
    best, state, bad = 1e9, None, 0
    for ep in range(max_ep):
        gnn_run(m, tl, opt)
        vloss = gnn_run(m, vl)[0]
        if vloss < best - 1e-4:
            best, state, bad = vloss, {k: v.detach().cpu().clone() for k, v in m.state_dict().items()}, 0
        else:
            bad += 1
        if bad >= pat:
            break
    m.load_state_dict(state)
    return m, ep + 1


def gnn_search():
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    y_val = val_df["Label"].values

    def obj(t):
        p = dict(hid=t.suggest_int("hid", 32, 256), drop=t.suggest_float("drop", 0.1, 0.5),
                 lr=t.suggest_float("lr", 1e-5, 1e-2, log=True), bs=t.suggest_int("bs", 32, 128))
        m, _ = gnn_train(p, 42, 12, 3)
        f1 = f1_score(y_val, gnn_run(m, GeoLoader(G_val, batch_size=256))[1], average="weighted")
        log(f"  GNN trial {t.number}: val weighted F1 {f1:.4f} {p}")
        return f1
    st = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=42))
    st.optimize(obj, n_trials=2 if SMOKE else 8)
    return st.best_params


gnn_p = cached("gnn_best_params.pkl", gnn_search)
log(f"GNN hyperparameters {gnn_p}")


class MetaLearnerNN(nn.Module):
    def __init__(self, input_dim, hidden_dim, dropout_rate):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout_rate)
        self.fc2 = nn.Linear(hidden_dim, 2)

    def forward(self, x):
        return self.fc2(self.dropout(torch.relu(self.fc1(x))))


def meta_train(M, y, seed):
    """Phase 2 procedure: per epoch one clean step and one FGSM step (full batch)."""
    torch.manual_seed(seed)
    m = MetaLearnerNN(M.shape[1], ENS_P["hidden_dim"], ENS_P["dropout_rate"]).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=ENS_P["lr"])
    crit = nn.CrossEntropyLoss()
    X = torch.tensor(M, dtype=torch.float32, device=device)
    Y = torch.tensor(y, dtype=torch.long, device=device)
    for _ in range(ENS_P["epochs"]):
        m.train()
        opt.zero_grad()
        crit(m(X), Y).backward()
        opt.step()
        xa = X.clone().detach().requires_grad_(True)
        m.zero_grad()
        crit(m(xa), Y).backward()
        xa = (xa + ENS_P["epsilon"] * xa.grad.data.sign()).detach()
        crit(m(xa), Y).backward()
        opt.step()
    return m.eval()


LR_MODEL = cached("lr.pkl", lambda: LogisticRegression(max_iter=1000, class_weight="balanced",
                                                       C=1).fit(D_tr, y_tr))
LR_OOF = cached("lr_oof.pkl", lambda: cross_val_predict(
    LogisticRegression(max_iter=1000, class_weight="balanced", C=1), D_tr, y_tr, cv=5,
    method="predict_proba", n_jobs=-1))
cw = compute_class_weight("balanced", classes=np.unique(y_tr), y=y_tr)


def train_seed(seed):
    log(f"seed {seed}: SVM (+5-fold out-of-fold)")
    svm = SVC(C=10, kernel="rbf", probability=True, class_weight="balanced",
              random_state=seed).fit(D_tr, y_tr)
    svm_oof = cross_val_predict(SVC(C=10, kernel="rbf", probability=True, class_weight="balanced",
                                    random_state=seed), D_tr, y_tr, cv=5,
                                method="predict_proba", n_jobs=-1)
    log(f"seed {seed}: XGBoost")
    mk = lambda: xgb.XGBClassifier(n_estimators=100, eval_metric="logloss",
                                   scale_pos_weight=cw[1], random_state=seed, n_jobs=-1)
    xg = mk().fit(D_tr, y_tr)
    xg_oof = cross_val_predict(mk(), D_tr, y_tr, cv=5, method="predict_proba")
    M = np.column_stack([LR_OOF, xg_oof, svm_oof]).astype(np.float32)   # notebook order LR, XGB, SVM
    meta = meta_train(M, y_tr, seed)
    log(f"seed {seed}: BERT-GNN")
    gnn, n_ep = gnn_train(gnn_p, seed, 3 if SMOKE else 50, 5)
    log(f"seed {seed}: BERT-only MLP")
    mlp = MLPClassifier(hidden_layer_sizes=(159,), max_iter=300, random_state=seed).fit(B_tr, y_tr)
    return {"svm": svm, "xgb": xg, "meta_state": {k: v.cpu() for k, v in meta.state_dict().items()},
            "gnn_state": {k: v.cpu() for k, v in gnn.state_dict().items()}, "gnn_epochs": n_ep,
            "mlp": mlp}


MODELS = {s: cached(f"models_seed{s}.pkl", lambda s=s: train_seed(s)) for s in SEEDS}
log("all seeds trained")


def build(seed):
    mo = MODELS[seed]
    meta = MetaLearnerNN(6, ENS_P["hidden_dim"], ENS_P["dropout_rate"]).to(device)
    meta.load_state_dict(mo["meta_state"])
    gnn = GNNModel(gnn_p["hid"], gnn_p["drop"]).to(device)
    gnn.load_state_dict(mo["gnn_state"])
    return mo, meta.eval(), gnn.eval()


def predict_all(seed, D, Bc, G, d_noise=None, b_noise=None, g_noise=None):
    """Predictions of the four models. *_noise: absolute per-dimension std vectors."""
    mo, meta, gnn = build(seed)
    rng = np.random.default_rng(0)
    Dx = D + rng.standard_normal(D.shape).astype(np.float32) * d_noise if d_noise is not None else D
    Bx = Bc + rng.standard_normal(Bc.shape).astype(np.float32) * b_noise if b_noise is not None else Bc
    p_svm = mo["svm"].predict_proba(Dx)
    M = np.column_stack([LR_MODEL.predict_proba(Dx), mo["xgb"].predict_proba(Dx), p_svm]).astype(np.float32)
    with torch.no_grad():
        p_ens = meta(torch.tensor(M, device=device)).argmax(1).cpu().numpy()
    gn = torch.tensor(g_noise, device=device) if g_noise is not None else None
    p_gnn = gnn_run(gnn, GeoLoader(G, batch_size=256), noise=gn)[1]
    return {"ENS": p_ens, "SVM": p_svm.argmax(1), "GNN": p_gnn, "BERT": mo["mlp"].predict(Bx)}


# ========================================================== evaluation sets
def eval_set(tag, queries, labels):
    """Features for both encoders, then predictions for all seeds (cached)."""
    def make():
        D = distil_cls(queries)
        Bc, G = bert_cls_graphs(queries, labels)
        return {s: predict_all(s, D, Bc, G) for s in SEEDS}
    return cached(f"preds_{tag}.pkl", make)


PRED = {"test": {s: predict_all(s, D_te, B_te_cls, G_te) for s in SEEDS}}
log("clean test predictions done")
for name, fn in TRANSFORMS.items():
    PRED[name] = eval_set(f"tf_{name}", [fn(q) for q in mal_q], np.ones(len(mal_q), int))
    log(f"transform {name} done")
PRED["httpparams"] = eval_set("httpparams", hp["Query"].tolist(), hp["Label"].values)
log("HTTPParams done")
PRED["ood"] = eval_set("ood", ood_q, ood_y)


def noise_preds():
    d_sd = D_tr.std(0)
    b_sd = B_tr.std(0)
    g_x = torch.cat([g.x.float() for g in G_tr[:5000]])
    g_sd = g_x.std(0).numpy()
    out = {}
    for s in SEEDS:
        for sg in SIGMAS:
            out[(s, sg)] = predict_all(s, D_te, B_te_cls, G_te, d_noise=sg * d_sd,
                                       b_noise=sg * b_sd, g_noise=sg * g_sd)
    return out


NOISE = cached("preds_noise.pkl", noise_preds)
log("noise test done")

# ================================================================ reporting
MODELS_ORDER = ["ENS", "SVM", "GNN", "BERT"]
NAMES = {"ENS": "DistilBERT-Stacked Ensemble", "SVM": "DistilBERT-SVM",
         "GNN": "Structure-aware BERT-GNN", "BERT": "BERT-only (MLP)"}


def met(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"accuracy": 100 * accuracy_score(y, p), "mal_precision": 100 * precision_score(y, p, zero_division=0),
            "mal_recall": 100 * recall_score(y, p), "mal_f1": 100 * f1_score(y, p),
            "fpr": 100 * fp / max(fp + tn, 1), "mcc": matthews_corrcoef(y, p), "fp": int(fp), "fn": int(fn)}


def ms(vals, nd=2):
    v = np.array(vals, float)
    return f"{v.mean():.{nd}f} ± {v.std(ddof=1):.{nd}f}"


R = {"seeds": SEEDS, "gnn_params": gnn_p, "ensemble_params": ENS_P}
L = ["# Phase 3: common robustness protocol", "",
     f"Same 70/30 split for every model (test set {len(test_df)} queries: {int((y_te == 0).sum())} benign, "
     f"{int((y_te == 1).sum())} malicious). Five seeds {SEEDS}; values are mean ± standard deviation over "
     "seeds unless marked seed 42. Hyperparameters fixed across seeds (phase 2 for the DistilBERT models; "
     f"GNN {gnn_p}).", ""]

# A
L += ["## A. Clean test set", "",
      "| Model | Accuracy (%) | Mal. precision | Mal. recall | Mal. F1 | FPR (%) | MCC | FP / FN (seed 42) |",
      "|---|---|---|---|---|---|---|---|"]
R["A"] = {}
for m in MODELS_ORDER:
    per = [met(y_te, PRED["test"][s][m]) for s in SEEDS]
    R["A"][m] = per
    s42 = per[0]
    L.append(f"| {NAMES[m]} | {ms([x['accuracy'] for x in per])} | {ms([x['mal_precision'] for x in per])} | "
             f"{ms([x['mal_recall'] for x in per])} | {ms([x['mal_f1'] for x in per])} | "
             f"{ms([x['fpr'] for x in per], 3)} | {ms([x['mcc'] for x in per], 4)} | {s42['fp']} / {s42['fn']} |")
L += ["", "McNemar exact test (seed 42), pairs of models: b = only the first correct, c = only the second correct.", "",
      "| Pair | b | c | p |", "|---|---|---|---|"]
R["A_mcnemar"] = {}
for i, a in enumerate(MODELS_ORDER):
    for b_ in MODELS_ORDER[i + 1:]:
        ca, cb = PRED["test"][42][a] == y_te, PRED["test"][42][b_] == y_te
        b, c = int((ca & ~cb).sum()), int((~ca & cb).sum())
        p = binomtest(b, b + c, 0.5).pvalue if b + c else 1.0
        R["A_mcnemar"][f"{a}-{b_}"] = {"b": b, "c": c, "p": p}
        L.append(f"| {NAMES[a]} vs {NAMES[b_]} | {b} | {c} | {p:.3g} |")

# B and C
L += ["", "## B. Query-level evasion: detection rate (%) of the "
      f"{len(mal_q)} malicious test queries after each transform", "",
      "| Transform | " + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |",
      "|---|" + "---|" * len(MODELS_ORDER)]
R["B"] = {}
clean_rec = {m: [100 * PRED["test"][s][m][y_te == 1].mean() for s in SEEDS] for m in MODELS_ORDER}
L.append("| (clean) | " + " | ".join(ms(clean_rec[m]) for m in MODELS_ORDER) + " |")
for name in TRANSFORMS:
    R["B"][name] = {m: [100 * PRED[name][s][m].mean() for s in SEEDS] for m in MODELS_ORDER}
    L.append(f"| {name} | " + " | ".join(ms(R["B"][name][m]) for m in MODELS_ORDER) + " |")
L += ["", f"## C. Adaptive best-of-{len(TRANSFORMS)} evasion rate (%): an attack counts as evaded if ANY "
      "transform makes the model call it benign (lower is better)", "",
      "| Model | Evasion rate (%) |", "|---|---|"]
R["C"] = {}
for m in MODELS_ORDER:
    ev = [100 * np.max(np.stack([PRED[n][s][m] == 0 for n in TRANSFORMS]), axis=0).mean() for s in SEEDS]
    R["C"][m] = ev
    L.append(f"| {NAMES[m]} | {ms(ev)} |")

# D
yh = hp["Label"].values
L += ["", f"## D. Cross-dataset: trained on Kaggle only, tested on HTTPParams ({len(hp)} queries, "
      f"{int(yh.sum())} SQLi) and the curated OOD set ({len(OOD_MAL)} attacks, {len(OOD_BEN)} benign)", "",
      "| Model | HTTPParams accuracy | HTTPParams detection | HTTPParams FPR (%) | HTTPParams MCC | "
      "OOD detection | OOD FPR (%) |", "|---|---|---|---|---|---|---|"]
R["D"] = {}
for m in MODELS_ORDER:
    h = [met(yh, PRED["httpparams"][s][m]) for s in SEEDS]
    o = [met(ood_y, PRED["ood"][s][m]) for s in SEEDS]
    R["D"][m] = {"httpparams": h, "ood": o}
    L.append(f"| {NAMES[m]} | {ms([x['accuracy'] for x in h])} | {ms([x['mal_recall'] for x in h])} | "
             f"{ms([x['fpr'] for x in h])} | {ms([x['mcc'] for x in h], 3)} | "
             f"{ms([x['mal_recall'] for x in o], 1)} | {ms([x['fpr'] for x in o], 1)} |")

# E
L += ["", "## E. Input-noise stability: % of test predictions that change when Gaussian noise "
      "(sigma × per-dimension training std of each model's own input features) is added (lower is better)", "",
      "| Model | " + " | ".join(f"sigma {sg}" for sg in SIGMAS) + " |", "|---|" + "---|" * len(SIGMAS)]
R["E"] = {}
for m in MODELS_ORDER:
    R["E"][m] = {sg: [100 * (NOISE[(s, sg)][m] != PRED["test"][s][m]).mean() for s in SEEDS] for sg in SIGMAS}
    L.append(f"| {NAMES[m]} | " + " | ".join(ms(R["E"][m][sg]) for sg in SIGMAS) + " |")

L += ["", "## Notes", "",
      "- Seed variation: SVM (Platt scaling), XGBoost, meta-learner, GNN initialisation and batch order, MLP. "
      "Logistic Regression is deterministic and shared across seeds.",
      "- The GNN graphs give a query with no sqlparse token a single [CLS] node (as robustness_common.py).",
      "- Transformed queries are not re-lower-cased; both tokenisers are uncased.",
      "- case_random uses a CRC32 seed per query (the earlier scripts used Python hash(), which varies per run).",
      "- The DistilBERT-SVM is also a base model of the ensemble, so their errors are correlated.",
      f"- GNN epochs to early stop per seed: {[MODELS[s]['gnn_epochs'] for s in SEEDS]}.",
      "", "Reproduce: `python merged_phase3_common_robustness.py` (set WORK_DIR for resumable caches)."]
open(os.path.join(OUT, "phase3_common_robustness.md"), "w", encoding="utf-8").write("\n".join(L))
json.dump(R, open(os.path.join(OUT, "phase3_common_robustness.json"), "w"), indent=1, default=float)
np.savez_compressed(os.path.join(OUT, "phase3_seed42_test_predictions.npz"),
                    y=y_te, **{m: PRED["test"][42][m] for m in MODELS_ORDER})
log("done: results/merged/phase3_common_robustness.md")
