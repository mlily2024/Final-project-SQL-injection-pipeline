"""
Merged paper, phase 3b: extended evaluation and timing for the four models of phase 3.

Models (same 70/30 split, same fixed hyperparameters as phase 3):
  ENS   DistilBERT-Stacked Ensemble (LR + XGBoost + SVM -> FGSM-trained meta-learner)
  SVM   DistilBERT-SVM
  GNN   structure-aware BERT-GNN (phase 3 Optuna result, fixed)
  BERT  BERT-only ([CLS] -> MLP, 159 hidden units)

Tests
  A  clean test set: accuracy, precision, recall, F1, FPR, MCC, ROC-AUC, PR-AUC,
     detection at fixed false-alarm rates, calibration (Brier score, ECE)
  B  disguises applied to BOTH classes (phase 3 transforms, new transforms, stacked
     transforms, sqlmap tamper scripts): recall, FPR, precision, F1 per transform
  C  adaptive best-of-N over all disguises (attacks evaded, harmless queries flagged)
  D  score-guided mutation attack (WAF-A-MoLE style, semantics-preserving operators)
  E  recall by attack type (rule-based categories)
  F  error analysis: missed attacks and false alarms (seed 42)
  G  reverse cross-dataset: trained on HTTPParams, tested on the full Kaggle dataset
  H  test set without exact and template duplicates of training queries
  I  learning curve: 10%, 25%, 50% of the training data
  J  query length bins and the 128-token truncation test
  K  timing: per-stage latency (batch 1) and throughput (batched), GPU and CPU

Seeds: [42, 1, 7, 13, 123] for A, B, C, E, H, J; [42, 1, 7] for D, G, I (compute).
Resumable: artefacts are cached in WORK (environment variable WORK_DIR).
sqlmap tampers are read from SQLMAP_DIR (a sqlmap checkout); skipped if absent.
"""
import importlib
import json
import os
import pickle
import platform
import random
import re
import sys
import time
import zlib

import numpy as np
import pandas as pd
import sqlparse
import torch
import torch.nn as nn
import torch.nn.functional as F
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, matthews_corrcoef,
                             precision_score, recall_score, roc_auc_score, roc_curve,
                             precision_recall_curve)
from sklearn.model_selection import cross_val_predict, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.utils.class_weight import compute_class_weight
from sqlparse.tokens import Newline, Whitespace
from torch_geometric.data import Batch, Data
from torch_geometric.loader import DataLoader as GeoLoader
from torch_geometric.nn import GCNConv, global_mean_pool

os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get("WORK_DIR", os.path.join(HERE, ".merged_work", "phase3b"))
OUT = os.path.join(HERE, "results", "merged")
SMOKE = os.environ.get("SMOKE") == "1"
CPU_PLAN = os.environ.get("PLAN", "full") == "cpu"   # reduced workload for a CPU-only machine
if SMOKE:
    WORK = WORK + "_smoke"
elif CPU_PLAN:
    WORK = WORK + "_cpu"
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)
SEEDS = [42] if SMOKE else [42, 1, 7, 13, 123]
HEAVY_SEEDS = [42] if SMOKE else [42, 1, 7]
MAX_LEN = 128
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
KEYWORDS = {"select", "from", "where", "union", "and", "or", "insert", "update",
            "delete", "join", "on", "group", "order", "having", "limit", "values", "set"}
ENS_P = dict(hidden_dim=195, dropout_rate=0.48280235776814573, lr=0.006257488041237617,
             epochs=92, epsilon=0.1004122390391398)
GNN_P = {"hid": 100, "drop": 0.3099025726528951, "lr": 0.00019762189340280086, "bs": 60}  # phase 3 search
MODELS_ORDER = ["ENS", "SVM", "GNN", "BERT"]
NAMES = {"ENS": "DistilBERT-Stacked Ensemble", "SVM": "DistilBERT-SVM",
         "GNN": "Structure-aware BERT-GNN", "BERT": "BERT-only (MLP)"}
FPR_POINTS = [0.001, 0.005, 0.01]
N_MUT, MUT_ROUNDS, MUT_K = (8, 2, 4) if SMOKE else (100, 20, 8) if CPU_PLAN else (200, 30, 8)
N_JOBS = 2 if CPU_PLAN else -1   # parallel cross-validation folds (each fold holds its own SVM in memory)
MUT_SEEDS = [42] if (SMOKE or CPU_PLAN) else None   # None: HEAVY_SEEDS
BC_PER_CLASS = (20 if SMOKE else 1000) if CPU_PLAN else None   # disguise tests on a stratified test subset
LC_FRACS = [0.5] if SMOKE else [0.1, 0.25, 0.5]


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
te_q = test_df["Query"].tolist()
mal_idx = np.where(y_te == 1)[0]
ben_idx = np.where(y_te == 0)[0]
hp = pd.read_csv(os.path.join(HERE, "httpparams_sqli.csv"))
hp["Query"] = hp["Query"].astype(str).apply(lambda x: x.lower().strip())
if SMOKE:
    hp = hp.groupby("Label").sample(n=300, random_state=0)
log(f"train {len(train_df)}, test {len(test_df)} ({len(mal_idx)} malicious), "
    f"HTTPParams {len(hp)}; device {device}")

# ================================================================= transforms
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


# string literal: no spaces inside, delimited by an operator, bracket, comma or space
# (an attack's first quote usually closes the application's own string)
QUOTED = re.compile(r"(?:(?<=[\s=(,<>])|^)'([^'\s\\]{1,40})'(?=[\s),;=<>/#-]|$)")
KW_RE = re.compile(r"\b(" + "|".join(KW) + r")\b")


def hex_strings(q): return QUOTED.sub(lambda m: "0x" + m.group(1).encode("utf-8").hex(), q)


def char_strings(q):
    return QUOTED.sub(lambda m: "char(" + ",".join(str(ord(c)) for c in m.group(1)) + ")", q)


def string_concat(q):
    def split(m):
        s = m.group(1)
        if len(s) < 2:
            return m.group(0)
        h = len(s) // 2
        return f"concat('{s[:h]}','{s[h:]}')"
    return QUOTED.sub(split, q)


def equivalent_logic(q):
    q = re.sub(r"\b(\d+)\s*=\s*\1\b", lambda m: f"{int(m.group(1)) + 1}>{m.group(1)}", q)
    return re.sub(r"'(\w*)'\s*=\s*'\1'", r"'\1' like '\1'", q)


def operator_symbols(q): return re.sub(r"\band\b", "&&", re.sub(r"\bor\b", "||", q))


SYNONYMS = [(r"\bsubstring\s*\(", "mid("), (r"\bsubstr\s*\(", "mid("), (r"\bascii\s*\(", "ord("),
            (r"\bifnull\s*\(", "coalesce("), (r"@@version", "version()"),
            (r"\buser\s*\(\s*\)", "current_user()"), (r"\bdatabase\s*\(\s*\)", "schema()")]


def function_synonyms(q):
    for a, b in SYNONYMS:
        q = re.sub(a, b, q)
    return q


FULLWIDTH = {c: chr(ord(c) - 0x61 + 0xFF41) for c in "abcdefghijklmnopqrstuvwxyz"}


def fullwidth_keywords(q): return KW_RE.sub(lambda m: "".join(FULLWIDTH[c] for c in m.group(1)), q)
def iis_unicode(q): return q.replace("'", "%u0027").replace(" ", "%u0020")
def nested_keywords(q): return KW_RE.sub(lambda m: m.group(1)[:2] + m.group(1) + m.group(1)[2:], q)


def bracket_conditions(q):
    operand = r"(?:'[^'\s]*'|[\w.@]+)"
    return re.sub(rf"\b(or|and)\s+({operand}\s*(?:=|<|>|like)\s*{operand})(?![\w.]*\s*\()(?!')", r"\1 (\2)", q)


P3_TRANSFORMS = {"url_encode": url_encode, "double_url_encode": double_url,
                 "inline_comment": inline_comment, "keyword_split": keyword_split,
                 "mysql_versioned_comment": mysql_comment, "case_random": case_random,
                 "tab_whitespace": tab_whitespace, "mixed_whitespace": mixed_whitespace,
                 "url_encode+case_random": url_case}
NEW_TRANSFORMS = {"hex_strings": hex_strings, "char_strings": char_strings,
                  "string_concat": string_concat, "equivalent_logic": equivalent_logic,
                  "operator_symbols": operator_symbols, "function_synonyms": function_synonyms,
                  "fullwidth_keywords": fullwidth_keywords, "iis_unicode": iis_unicode,
                  "nested_keywords": nested_keywords, "bracket_conditions": bracket_conditions}
STACKED = {
    "hex+inline_comment+url": lambda q: url_encode(inline_comment(hex_strings(q))),
    "logic+versioned+case": lambda q: case_random(mysql_comment(equivalent_logic(q))),
    "synonyms+symbols+hex+comment": lambda q: inline_comment(hex_strings(operator_symbols(function_synonyms(q)))),
    "fullwidth+inline_comment": lambda q: inline_comment(fullwidth_keywords(q)),
    "concat+double_url": lambda q: double_url(string_concat(q)),
}

TAMPER_SAMPLE = "1 and 1=1 union select 1,'abc',user()-- -"


def time_limited(fn, seconds):
    """Run fn(); raise TimeoutError after `seconds` (SIGALRM, Linux only; elsewhere no limit)."""
    import signal
    if not hasattr(signal, "setitimer"):
        return fn()

    def stop(signum, frame):
        raise TimeoutError(f"over {seconds}s")
    prev = signal.signal(signal.SIGALRM, stop)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


VET_CODE = r"""
import importlib, sys, time
sys.path.insert(0, sys.argv[1])
D = sys.argv[1]
exec(sys.argv[3])
fn = importlib.import_module("tamper." + sys.argv[2]).tamper
probe = ["' or 1=1--", "1 union select null,username,password from users--",
         "select name from products where id = 42", "1' and sleep(5)#"] * 25
t = time.perf_counter()
out = [fn(q) for q in probe]
assert all(isinstance(o, str) for o in out), "non-string output"
assert time.perf_counter() - t < 2.0, "too slow on the probe queries"
"""


SQLMAP_CTX = r"""
import os
from lib.core.data import kb
kb.keywords = set(l.strip().upper() for l in open(os.path.join(D, "data", "txt", "keywords.txt"), encoding="utf-8")
                  if l.strip() and not l.startswith("#"))
kb.aliasName = "sqlmapalias"
"""


def load_tampers():
    """sqlmap tamper functions from SQLMAP_DIR; each is first vetted in a separate process
    with a time limit, so a script that hangs or needs a sqlmap run context is skipped."""
    import subprocess
    d = os.environ.get("SQLMAP_DIR", "")
    if not d or not os.path.isdir(os.path.join(d, "tamper")):
        if os.environ.get("ALLOW_NO_SQLMAP") == "1":
            return {}, {"(all)": "SQLMAP_DIR not set"}, None
        raise SystemExit("SQLMAP_DIR must point to a sqlmap 1.9.9 checkout (git clone --branch 1.9.9 "
                         "https://github.com/sqlmapproject/sqlmap); without it the 68 tamper-script "
                         "disguises are skipped. Set ALLOW_NO_SQLMAP=1 to run without them.")
    try:
        VERSION = re.search(r'VERSION = "([^"]+)"',
                            open(os.path.join(d, "lib", "core", "settings.py"), encoding="utf-8").read()).group(1)
    except Exception as e:
        VERSION = f"unknown ({e!r})"
    funcs, skipped, ok = {}, {}, []
    for f in sorted(os.listdir(os.path.join(d, "tamper"))):
        if not f.endswith(".py") or f.startswith("__"):
            continue
        name = f[:-3]
        try:
            r = subprocess.run([sys.executable, "-c", VET_CODE, d, name, SQLMAP_CTX], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                ok.append(name)
            else:
                skipped[name] = (r.stderr.strip().splitlines() or ["failed"])[-1][:120]
        except subprocess.TimeoutExpired:
            skipped[name] = "timed out (30 s)"
    sys.path.insert(0, d)
    exec(SQLMAP_CTX, {"D": d})
    for name in ok:
        try:
            funcs[name] = importlib.import_module("tamper." + name).tamper
        except Exception as e:
            skipped[name] = repr(e)[:120]
    return funcs, skipped, VERSION


def tamper_wrap(fn):
    def t(q):
        random.seed(zlib.crc32(q.encode("utf-8")))
        try:
            r = time_limited(lambda: fn(q), 2)
            return r if isinstance(r, str) else q
        except Exception:
            return q
    return t


TAMPERS, TAMPER_SKIPPED, SQLMAP_VERSION = load_tampers()
ALL_TRANSFORMS = {**P3_TRANSFORMS, **NEW_TRANSFORMS, **STACKED,
                  **{f"sqlmap:{k}": tamper_wrap(v) for k, v in TAMPERS.items()}}
GROUP = {**{k: "phase 3" for k in P3_TRANSFORMS}, **{k: "new" for k in NEW_TRANSFORMS},
         **{k: "stacked" for k in STACKED}, **{f"sqlmap:{k}": "sqlmap" for k in TAMPERS}}
log(f"transforms: {len(P3_TRANSFORMS)} phase 3, {len(NEW_TRANSFORMS)} new, {len(STACKED)} stacked, "
    f"{len(TAMPERS)} sqlmap (version {SQLMAP_VERSION}, {len(TAMPER_SKIPPED)} not loadable)")

# ================================================================= encoders
_enc = {}


def encoder(kind, dev=None):
    dev = dev or device
    key = (kind, str(dev))
    if key not in _enc:
        if kind == "d":
            from transformers import DistilBertModel, DistilBertTokenizerFast
            _enc[key] = (DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased"),
                         DistilBertModel.from_pretrained("distilbert-base-uncased").to(dev).eval())
        else:
            from transformers import BertModel, BertTokenizerFast
            _enc[key] = (BertTokenizerFast.from_pretrained("bert-base-uncased"),
                         BertModel.from_pretrained("bert-base-uncased").to(dev).eval())
    return _enc[key]


def distil_cls(queries, bs=128):
    tok, m = encoder("d")
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
    """[(text, start, end)] for significant sqlparse tokens."""
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
    """Sequential + parenthesis-match + clause-scope edges, undirected."""
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


def graph_from_hidden(query, h, so, label=0):
    """Structure graph: node = sqlparse token, feature = mean of its BERT sub-word states."""
    y = torch.tensor([int(label)])
    toks = sql_tokens(query)
    if not toks:
        return Data(x=torch.tensor(h[:1]).half(), edge_index=torch.empty((2, 0), dtype=torch.long), y=y)
    valid = ~((so[:, 0] == 0) & (so[:, 1] == 0))
    feats = []
    for (val, a, b) in toks:
        msk = valid & (so[:, 0] < b) & (so[:, 1] > a)
        feats.append(h[msk].mean(axis=0) if msk.any() else h[0])
    e = structure_edges(toks)
    return Data(x=torch.tensor(np.stack(feats)).half(),
                edge_index=(torch.tensor(e, dtype=torch.long).t().contiguous()
                            if e else torch.empty((2, 0), dtype=torch.long)), y=y)


def bert_cls_graphs(queries, labels=None, bs=64):
    """One BERT pass -> ([CLS] matrix, structure graphs), aligned to input order."""
    tok, m = encoder("b")
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
                graphs[qi] = graph_from_hidden(queries[qi], hs[bi], offs[bi],
                                               labels[qi] if labels is not None else 0)
    return cls, graphs


# =========================================================== features (cached)
t0 = time.time()
D_tr = cached("distil_train.pkl", lambda: distil_cls(train_df["Query"].tolist()))
D_te = cached("distil_test.pkl", lambda: distil_cls(te_q))


def bert_set(tag, frame):
    return cached(f"bert_{tag}.pkl", lambda: bert_cls_graphs(frame["Query"].tolist(), frame["Label"].values))


B_trn_cls, G_tr = bert_set("tr", tr_df)
B_val_cls, G_val = bert_set("val", val_df)
B_te_cls, G_te = bert_set("test", test_df)
tr_pos = {ix: i for i, ix in enumerate(tr_df.index)}
val_pos = {ix: i for i, ix in enumerate(val_df.index)}
B_tr = np.stack([B_trn_cls[tr_pos[ix]] if ix in tr_pos else B_val_cls[val_pos[ix]] for ix in train_df.index])
G_train_order = [G_tr[tr_pos[ix]] if ix in tr_pos else G_val[val_pos[ix]] for ix in train_df.index]
log(f"features ready ({time.time() - t0:.0f}s)")


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


class MetaLearnerNN(nn.Module):
    def __init__(self, input_dim, hidden_dim, dropout_rate):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout_rate)
        self.fc2 = nn.Linear(hidden_dim, 2)

    def forward(self, x):
        return self.fc2(self.dropout(torch.relu(self.fc1(x))))


def gnn_run(model, loader, cw, opt=None):
    """One pass: (mean loss, predicted labels, P(malicious))."""
    crit = nn.CrossEntropyLoss(weight=cw)
    train = opt is not None
    model.train() if train else model.eval()
    tot, P, PR = 0.0, [], []
    with (torch.enable_grad() if train else torch.no_grad()):
        for d in loader:
            d = d.to(device)
            if train:
                opt.zero_grad()
            out = model(d.x.float(), d.edge_index, d.batch)
            loss = crit(out, d.y)
            if train:
                loss.backward()
                opt.step()
            tot += loss.item()
            P.append(out.argmax(1).detach().cpu())
            PR.append(F.softmax(out, 1)[:, 1].detach().cpu())
    if not P:
        return 0.0, np.zeros(0, int), np.zeros(0, np.float32)
    return tot / max(len(loader), 1), torch.cat(P).numpy(), torch.cat(PR).numpy()


def gnn_train(seed, Gtr, Gval, cw, max_ep, pat):
    torch.manual_seed(seed)
    np.random.seed(seed)
    m = GNNModel(GNN_P["hid"], GNN_P["drop"]).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=GNN_P["lr"])
    g = torch.Generator().manual_seed(seed)
    tl = GeoLoader(Gtr, batch_size=GNN_P["bs"], shuffle=True, generator=g)
    vl = GeoLoader(Gval, batch_size=256)
    best, state, bad = 1e9, None, 0
    for ep in range(max_ep):
        gnn_run(m, tl, cw, opt)
        vloss = gnn_run(m, vl, cw)[0]
        if vloss < best - 1e-4:
            best, state, bad = vloss, {k: v.detach().cpu().clone() for k, v in m.state_dict().items()}, 0
        else:
            bad += 1
        if bad >= pat:
            break
    m.load_state_dict(state)
    return m, ep + 1


def meta_train(M, y, seed):
    """Per epoch one clean step and one FGSM step (full batch), as phase 2."""
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


def lr_parts(tag, D, y):
    """Logistic Regression (deterministic): full fit and 5-fold out-of-fold probabilities."""
    return cached(f"{tag}_lr.pkl", lambda: (
        LogisticRegression(max_iter=1000, class_weight="balanced", C=1).fit(D, y),
        cross_val_predict(LogisticRegression(max_iter=1000, class_weight="balanced", C=1), D, y,
                          cv=5, method="predict_proba", n_jobs=N_JOBS)))


def train_family(tag, seed, D, y, Bc, Gtr, Gval, y_gnn):
    """The four models on one training set (phase 3 procedure)."""
    lr, lr_oof = lr_parts(tag, D, y)
    log(f"{tag} seed {seed}: SVM (+5-fold out-of-fold)")
    svm = SVC(C=10, kernel="rbf", probability=True, class_weight="balanced", random_state=seed).fit(D, y)
    svm_oof = cross_val_predict(SVC(C=10, kernel="rbf", probability=True, class_weight="balanced",
                                    random_state=seed), D, y, cv=5, method="predict_proba", n_jobs=N_JOBS)
    log(f"{tag} seed {seed}: XGBoost")
    cw = compute_class_weight("balanced", classes=np.unique(y), y=y)
    mk = lambda: xgb.XGBClassifier(n_estimators=100, eval_metric="logloss", scale_pos_weight=cw[1],
                                   random_state=seed, n_jobs=-1)
    xg = mk().fit(D, y)
    xg_oof = cross_val_predict(mk(), D, y, cv=5, method="predict_proba")
    M = np.column_stack([lr_oof, xg_oof, svm_oof]).astype(np.float32)
    meta = meta_train(M, y, seed)
    log(f"{tag} seed {seed}: BERT-GNN")
    gcw = torch.tensor(compute_class_weight("balanced", classes=np.array([0, 1]), y=y_gnn),
                       dtype=torch.float, device=device)
    gnn, n_ep = gnn_train(seed, Gtr, Gval, gcw, 3 if SMOKE else 50, 5)
    log(f"{tag} seed {seed}: BERT-only MLP")
    mlp = MLPClassifier(hidden_layer_sizes=(159,), max_iter=300, random_state=seed).fit(Bc, y)
    return {"lr": lr, "svm": svm, "xgb": xg, "meta_state": {k: v.cpu() for k, v in meta.state_dict().items()},
            "gnn_state": {k: v.cpu() for k, v in gnn.state_dict().items()}, "gnn_epochs": n_ep,
            "gnn_cw": gcw.cpu(), "mlp": mlp}


def build(fam, dev=None):
    dev = dev or device
    meta = MetaLearnerNN(6, ENS_P["hidden_dim"], ENS_P["dropout_rate"]).to(dev)
    meta.load_state_dict(fam["meta_state"])
    gnn = GNNModel(GNN_P["hid"], GNN_P["drop"]).to(dev)
    gnn.load_state_dict(fam["gnn_state"])
    return meta.eval(), gnn.eval()


def proba(fam, D=None, Bc=None, G=None, only=None):
    """P(malicious) per model; only = subset of model keys."""
    want = only or MODELS_ORDER
    meta, gnn = build(fam)
    out = {}
    if D is not None and ("ENS" in want or "SVM" in want):
        if len(D) == 0:
            out.update({k: np.zeros(0, np.float32) for k in ("ENS", "SVM") if k in want})
        else:
            p_svm = fam["svm"].predict_proba(D)
            if "SVM" in want:
                out["SVM"] = p_svm[:, 1]
            if "ENS" in want:
                M = np.column_stack([fam["lr"].predict_proba(D), fam["xgb"].predict_proba(D), p_svm]).astype(np.float32)
                with torch.no_grad():
                    out["ENS"] = F.softmax(meta(torch.tensor(M, device=device)), 1)[:, 1].cpu().numpy()
    if G is not None and "GNN" in want:
        out["GNN"] = gnn_run(gnn, GeoLoader(G, batch_size=256), fam["gnn_cw"].to(device))[2]
    if Bc is not None and "BERT" in want:
        out["BERT"] = fam["mlp"].predict_proba(Bc)[:, 1] if len(Bc) else np.zeros(0, np.float32)
    return out


def proba_queries(fams, queries, labels=None, only=None):
    """Embed once, then P(malicious) for every family in fams {seed: family}."""
    want = only or MODELS_ORDER
    D = distil_cls(queries) if ("ENS" in want or "SVM" in want) else None
    Bc, G = bert_cls_graphs(queries, labels) if ("GNN" in want or "BERT" in want) else (None, None)
    return {s: proba(f, D, Bc, G, want) for s, f in fams.items()}


MAIN = {s: cached(f"main_models_seed{s}.pkl",
                  lambda s=s: train_family("main", s, D_tr, y_tr, B_tr, G_tr, G_val, tr_df["Label"].values))
        for s in SEEDS}
log("main models trained")
P_TEST = cached("p_test.pkl", lambda: {s: proba(MAIN[s], D_te, B_te_cls, G_te) for s in SEEDS})
log("clean test probabilities done")


# ================================================================ metrics
def met(y, p):
    lab = (p > 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, lab, labels=[0, 1]).ravel()
    return {"accuracy": 100 * accuracy_score(y, lab),
            "precision": 100 * precision_score(y, lab, zero_division=0),
            "recall": 100 * recall_score(y, lab, zero_division=0),
            "f1": 100 * f1_score(y, lab, zero_division=0),
            "fpr": 100 * fp / max(fp + tn, 1),
            "mcc": matthews_corrcoef(y, lab) if len(np.unique(y)) > 1 else float("nan"),
            "fp": int(fp), "fn": int(fn)}


def ece(y, p, bins=15):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    return sum(abs(y[idx == b].mean() - p[idx == b].mean()) * (idx == b).sum()
               for b in range(bins) if (idx == b).any()) / len(y)


def tpr_at(y, p, f):
    fpr, tpr, _ = roc_curve(y, p)
    return 100 * tpr[fpr <= f].max()


def ms(vals, nd=2):
    v = np.array(vals, float)
    if len(v) < 2:
        return f"{v.mean():.{nd}f}"
    return f"{v.mean():.{nd}f} ± {v.std(ddof=1):.{nd}f}"


def fmt(x, nd):
    return "-" if x is None else f"{x:.{nd}f}"


def md_q(q, n=150):
    q = q if len(q) <= n else q[:n] + "..."
    return q.replace("|", "\\|").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")


R = {"plan": "cpu" if CPU_PLAN else "full", "seeds": SEEDS, "heavy_seeds": HEAVY_SEEDS, "gnn_params": GNN_P, "ensemble_params": ENS_P}
L = ["# Phase 3b: extended evaluation and timing", "",
     f"Same 70/30 split and models as phase 3 (test set {len(test_df)} queries: {len(ben_idx)} benign, "
     f"{len(mal_idx)} malicious). Seeds {SEEDS} (mean ± std) unless stated; D, G and I use {HEAVY_SEEDS}. "
     "A query is called malicious when P(malicious) > 0.5." + (" Reduced CPU plan: disguise tests on a "
     "stratified 1,000 + 1,000 test sample, mutation attack 100 queries x 160 tries, seed 42." if CPU_PLAN else ""), ""]

# ===================================================================== A
A = {}
for m in MODELS_ORDER:
    rows = []
    for s in SEEDS:
        p = P_TEST[s][m]
        r = met(y_te, p)
        r.update({"roc_auc": roc_auc_score(y_te, p), "pr_auc": average_precision_score(y_te, p),
                  "brier": brier_score_loss(y_te, p), "ece": ece(y_te, p)})
        r.update({f"tpr_at_{f}": tpr_at(y_te, p, f) for f in FPR_POINTS})
        rows.append(r)
    A[m] = rows
R["A"] = A
L += ["## A. Clean test set", "",
      "| Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | MCC | FP / FN (seed 42) |",
      "|---|---|---|---|---|---|---|---|"]
for m in MODELS_ORDER:
    a = A[m]
    L.append(f"| {NAMES[m]} | {ms([x['accuracy'] for x in a])} | {ms([x['precision'] for x in a])} | "
             f"{ms([x['recall'] for x in a])} | {ms([x['f1'] for x in a])} | {ms([x['fpr'] for x in a], 3)} | "
             f"{ms([x['mcc'] for x in a], 4)} | {a[0]['fp']} / {a[0]['fn']} |")
L += ["", "Threshold-free metrics, detection at fixed false-alarm rates, and calibration (lower Brier and ECE "
      "are better).", "",
      "| Model | ROC-AUC | PR-AUC | Detection at 0.1% FPR | at 0.5% FPR | at 1% FPR | Brier | ECE |",
      "|---|---|---|---|---|---|---|---|"]
for m in MODELS_ORDER:
    a = A[m]
    L.append(f"| {NAMES[m]} | {ms([x['roc_auc'] for x in a], 5)} | {ms([x['pr_auc'] for x in a], 5)} | "
             + " | ".join(ms([x[f'tpr_at_{f}'] for x in a]) for f in FPR_POINTS)
             + f" | {ms([x['brier'] for x in a], 5)} | {ms([x['ece'] for x in a], 5)} |")

curves = {}
for m in MODELS_ORDER:
    p = P_TEST[42][m]
    fpr, tpr, _ = roc_curve(y_te, p)
    pr, rc, _ = precision_recall_curve(y_te, p)
    curves.update({f"{m}_fpr": fpr, f"{m}_tpr": tpr, f"{m}_precision": pr, f"{m}_recall": rc, f"{m}_p": p})
np.savez_compressed(os.path.join(OUT, "phase3b_seed42_curves.npz"), y=y_te, **curves)
log("A done")

# ===================================================================== B, C
if BC_PER_CLASS:
    _r = np.random.RandomState(0)
    BC_IDX = np.sort(np.concatenate([_r.choice(mal_idx, min(BC_PER_CLASS, len(mal_idx)), replace=False),
                                     _r.choice(ben_idx, min(BC_PER_CLASS, len(ben_idx)), replace=False)]))
else:
    BC_IDX = np.arange(len(te_q))
bc_q = [te_q[i] for i in BC_IDX]
y_bc = y_te[BC_IDX]
bc_mal = np.where(y_bc == 1)[0]
bc_ben = np.where(y_bc == 0)[0]
TF_P = {}
TF_CHANGED = {}
for name, fn in ALL_TRANSFORMS.items():
    tq = [fn(q) for q in bc_q]
    changed = np.array([a != b for a, b in zip(tq, bc_q)])
    TF_CHANGED[name] = changed

    def make(tq=tq, changed=changed):
        ci = np.where(changed)[0]
        sub = proba_queries(MAIN, [tq[i] for i in ci], y_bc[ci]) if len(ci) else None
        out = {}
        for s in SEEDS:
            out[s] = {}
            for m in MODELS_ORDER:
                p = P_TEST[s][m][BC_IDX].copy()
                if sub is not None:
                    p[ci] = sub[s][m]
                out[s][m] = p
        return out
    TF_P[name] = cached(f"tf_{re.sub(r'[^A-Za-z0-9_+.-]', '_', name)}.pkl", make)
    log(f"transform {name}: {100 * changed[bc_mal].mean():.1f}% of attacks and "
        f"{100 * changed[bc_ben].mean():.1f}% of benign queries changed")

B = {}
for name in ALL_TRANSFORMS:
    B[name] = {"group": GROUP[name],
               "changed_mal": 100 * TF_CHANGED[name][bc_mal].mean(),
               "changed_ben": 100 * TF_CHANGED[name][bc_ben].mean(),
               "models": {m: [met(y_bc, TF_P[name][s][m]) for s in SEEDS] for m in MODELS_ORDER}}
R["B"] = B
R["sqlmap"] = {"version": SQLMAP_VERSION, "loaded": sorted(TAMPERS), "skipped": TAMPER_SKIPPED}

L += ["", "## B. Disguises applied to both classes", "",
      f"Each disguise is applied to {len(bc_q)} test queries ({len(bc_mal)} attacks, {len(bc_ben)} benign; "
      f"{'stratified sample, seed 0' if BC_PER_CLASS else 'the full test set'}); a query the disguise does not alter keeps its "
      f"clean prediction. Groups: phase 3 ({len(P3_TRANSFORMS)}), new ({len(NEW_TRANSFORMS)}), stacked "
      f"({len(STACKED)}), sqlmap tamper scripts ({len(TAMPERS)}; sqlmap {SQLMAP_VERSION}).", ""]
for metric, title, nd in [("recall", "Detection rate (recall, %) of the malicious queries", 2),
                          ("fpr", "False-alarm rate (FPR, %) on the benign queries", 2),
                          ("precision", "Precision (%)", 2), ("f1", "F1 (%)", 2)]:
    L += [f"### {title}", "", "| Disguise | Group | Changed: attacks / benign (%) | "
          + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |", "|---|---|---|" + "---|" * len(MODELS_ORDER)]
    L.append("| (clean) | | | " + " | ".join(ms([met(y_bc, P_TEST[s][m][BC_IDX])[metric] for s in SEEDS], nd)
                                         for m in MODELS_ORDER) + " |")
    for name, b in B.items():
        L.append(f"| {name} | {b['group']} | {b['changed_mal']:.1f} / {b['changed_ben']:.1f} | "
                 + " | ".join(ms([x[metric] for x in b['models'][m]], nd) for m in MODELS_ORDER) + " |")
    L.append("")
if TAMPER_SKIPPED:
    L += ["sqlmap tamper scripts not loadable (they need a sqlmap run context): "
          + ", ".join(sorted(TAMPER_SKIPPED)) + ".", ""]

C = {}
groups = {"phase 3": [k for k in ALL_TRANSFORMS if GROUP[k] == "phase 3"],
          "new + stacked": [k for k in ALL_TRANSFORMS if GROUP[k] in ("new", "stacked")],
          "sqlmap": [k for k in ALL_TRANSFORMS if GROUP[k] == "sqlmap"],
          "all": list(ALL_TRANSFORMS)}
for gname, names in groups.items():
    if not names:
        continue
    C[gname] = {}
    for m in MODELS_ORDER:
        ev, fa = [], []
        for s in SEEDS:
            stack = np.stack([TF_P[n][s][m] for n in names])
            ev.append(100 * (stack[:, bc_mal] <= 0.5).any(0).mean())
            fa.append(100 * (stack[:, bc_ben] > 0.5).any(0).mean())
        C[gname][m] = {"evasion": ev, "false_alarm_any": fa}
R["C"] = C
L += ["## C. Adaptive best-of-N", "",
      "Evasion: % of attacks that at least one disguise in the group turns into a 'benign' prediction. "
      "False alarm (any): % of benign queries that at least one disguise turns into a 'malicious' prediction. "
      "Lower is better for both.", "",
      "| Group (N disguises) | " + " | ".join(f"{NAMES[m]}: evasion / false alarm" for m in MODELS_ORDER) + " |",
      "|---|" + "---|" * len(MODELS_ORDER)]
for gname, cm in C.items():
    L.append(f"| {gname} ({len(groups[gname])}) | " + " | ".join(
        f"{ms(cm[m]['evasion'])} / {ms(cm[m]['false_alarm_any'])}" for m in MODELS_ORDER) + " |")
log("B and C done")


# ===================================================================== D
def m_case(q, rng):
    ms_ = [m for m in re.finditer(r"[a-z]+", q) if m.group(0) in KEYWORDS]
    if not ms_:
        return q
    m = ms_[rng.randint(len(ms_))]
    w = "".join(c.upper() if rng.rand() < 0.5 else c for c in m.group(0))
    return q[:m.start()] + w + q[m.end():]


def m_space(q, rng):
    pos = [i for i, c in enumerate(q) if c == " "]
    if not pos:
        return q
    i = pos[rng.randint(len(pos))]
    return q[:i] + ["\t", "\n", "\r", "\x0b", "\x0c", "/**/", "/*x*/"][rng.randint(7)] + q[i + 1:]


def m_comment(q, rng):
    word = "".join(chr(97 + rng.randint(26)) for _ in range(rng.randint(1, 6)))
    if re.search(r"/\*(?!!).*?\*/", q):   # plain comment only; a /*! versioned comment is code
        return re.sub(r"/\*(?!!).*?\*/", f"/*{word}*/", q, count=1)
    m = re.search(r"(--|#)", q)
    if m:
        return q + word
    pos = [i for i, c in enumerate(q) if c == " "]
    if not pos:
        return q
    i = pos[rng.randint(len(pos))]
    return q[:i] + f"/*{word}*/" + q[i + 1:]


def m_int(q, rng):
    ms_ = list(re.finditer(r"(?<![\w.'])(\d+)(?![\w.'])", q))
    if not ms_:
        return q
    m = ms_[rng.randint(len(ms_))]
    n = int(m.group(1))
    return q[:m.start()] + (hex(n) if rng.rand() < 0.5 else f"({n})") + q[m.end():]


def m_operator(q, rng):
    opts = [(r"\bor\b", "||"), (r"\band\b", "&&"), (r"(?<![<>!])=(?!=)", " like "), (r"<>", "!=")]
    opts = [o for o in opts if re.search(o[0], q)]
    if not opts:
        return q
    a, b = opts[rng.randint(len(opts))]
    ms_ = list(re.finditer(a, q))
    m = ms_[rng.randint(len(ms_))]
    return q[:m.start()] + b + q[m.end():]


def m_invariant(q, rng):
    clause = [" and 1=1", " and 'a'='a'", " and 2>1", " or 0=1", " and true"][rng.randint(5)]
    m = re.search(r"(--|#)", q)
    i = m.start() if m else len(q)
    # without a comment the application closes the payload; an odd quote count means the payload
    # ends inside a string literal, so a clause appended there would become string data
    if not m and (q.count("'") % 2 or q.count('"') % 2):
        return q
    return q[:i] + clause + q[i:]


def m_hex(q, rng):
    ms_ = list(QUOTED.finditer(q))
    if not ms_:
        return q
    m = ms_[rng.randint(len(ms_))]
    return q[:m.start()] + "0x" + m.group(1).encode("utf-8").hex() + q[m.end():]


def m_versioned(q, rng):
    ms_ = [m for m in re.finditer(r"[a-z]+", q) if m.group(0) in KEYWORDS]
    if not ms_:
        return q
    m = ms_[rng.randint(len(ms_))]
    return q[:m.start()] + f"/*!{m.group(0)}*/" + q[m.end():]


MUT_OPS = [m_case, m_space, m_comment, m_int, m_operator, m_invariant, m_hex, m_versioned]


def mutate(q, rng):
    for k in rng.permutation(len(MUT_OPS)):
        r = MUT_OPS[k](q, rng)
        if r != q:
            return r
    return q


def mutation_attack(fam, model, queries, seed):
    """Score-guided search: each round K mutants of the current best, keep the lowest P(malicious)."""
    score = lambda qs: proba_queries({0: fam}, qs, only=[model])[0][model]
    master = np.random.RandomState(seed)
    rngs = [np.random.RandomState(master.randint(2 ** 31)) for _ in queries]
    best_q, best_p = list(queries), score(list(queries))
    rounds = np.full(len(queries), -1)
    rounds[best_p <= 0.5] = 0
    for r in range(MUT_ROUNDS):
        active = [i for i in range(len(queries)) if rounds[i] < 0]
        if not active:
            break
        cands, owner = [], []
        for i in active:
            for _ in range(MUT_K):
                cands.append(mutate(best_q[i], rngs[i]))
                owner.append(i)
        p = score(cands)
        for j, i in enumerate(owner):
            if p[j] < best_p[i]:
                best_p[i], best_q[i] = p[j], cands[j]
        for i in active:
            if best_p[i] <= 0.5:
                rounds[i] = r + 1
    return {"rounds": rounds, "final_p": best_p, "final_q": best_q}


D_SEEDS = MUT_SEEDS or HEAVY_SEEDS
detected_all = np.all(np.stack([P_TEST[42][m][mal_idx] > 0.5 for m in MODELS_ORDER]), 0)
mut_pool = mal_idx[detected_all]
mut_sel = np.sort(np.random.RandomState(0).choice(mut_pool, min(N_MUT, len(mut_pool)), replace=False))
mut_q = [te_q[i] for i in mut_sel]
D_RES = {}
for s in D_SEEDS:
    for m in MODELS_ORDER:
        D_RES[(s, m)] = cached(f"mutation_{m}_seed{s}.pkl", lambda s=s, m=m: mutation_attack(MAIN[s], m, mut_q, s))
        log(f"mutation attack {m} seed {s}: {100 * (D_RES[(s, m)]['rounds'] >= 0).mean():.1f}% evaded")
R["D"] = {m: {"evasion": [100 * (D_RES[(s, m)]["rounds"] >= 0).mean() for s in D_SEEDS],
              "median_queries": [float(np.median(D_RES[(s, m)]["rounds"][D_RES[(s, m)]["rounds"] >= 0]) * MUT_K)
                                 if (D_RES[(s, m)]["rounds"] >= 0).any() else None for s in D_SEEDS],
              "mean_final_p": [float(D_RES[(s, m)]["final_p"].mean()) for s in D_SEEDS]}
          for m in MODELS_ORDER}
L += ["", "## D. Score-guided mutation attack (WAF-A-MoLE style)", "",
      f"{len(mut_q)} attacks detected by all four models (seed 42), sampled with seed 0. Each round creates "
      f"{MUT_K} mutants of the current best candidate with one semantics-preserving operator (keyword case, "
      "whitespace substitution, comment rewriting, integer encoding, operator swap, logical invariant, string "
      f"to hex, versioned comment) and keeps the one with the lowest P(malicious). Budget {MUT_ROUNDS} rounds "
      f"({MUT_ROUNDS * MUT_K} model queries per attack). Seeds {D_SEEDS}.", "",
      "| Model | Evaded within budget (%) | Median model queries to evade | Mean final P(malicious) |",
      "|---|---|---|---|"]
for m in MODELS_ORDER:
    d = R["D"][m]
    mq = [x for x in d["median_queries"] if x is not None]
    L.append(f"| {NAMES[m]} | {ms(d['evasion'])} | {ms(mq, 0) if mq else 'none evaded'} | "
             f"{ms(d['mean_final_p'], 3)} |")
L += ["", "Examples (seed 42, up to three per model): original -> evasive variant.", ""]
for m in MODELS_ORDER:
    res = D_RES[(D_SEEDS[0], m)]
    ex = [i for i in range(len(mut_q)) if res["rounds"][i] > 0][:3]
    for i in ex:
        L.append(f"- {NAMES[m]}: `{md_q(mut_q[i], 100)}` -> `{md_q(res['final_q'][i], 140)}`")
log("D done")

# ===================================================================== E
CAT_RULES = [("time-based", r"sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep"),
             ("error-based", r"extractvalue|updatexml|convert\s*\(|exp\s*\(\s*~|floor\s*\(\s*rand|"
                             r"geometrycollection|multipoint|polygon\s*\(|xmltype|ctxsys|utl_inaddr"),
             ("union-based", r"\bunion\b.*\bselect\b"),
             ("stacked", r";\s*(drop|insert|update|delete|exec|execute|declare|create|alter|shutdown|truncate)\b"),
             ("boolean / tautology", r"\b(or|and)\b\s*[(\s]*['\"\w@]+\s*(=|<|>|like|between|is|in)|"
                                     r"\b(or|and)\b\s+\d+\b|'\s*(or|and)\s*'|\|\||&&")]


def category(q):
    for name, rx in CAT_RULES:
        if re.search(rx, q):
            return name
    return "other"


cats = np.array([category(te_q[i]) for i in mal_idx])
E = {}
L += ["", "## E. Detection rate (%) by attack type", "",
      "Rule-based categories, first match in the order shown.", "",
      "| Attack type | Queries | " + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |",
      "|---|---|" + "---|" * len(MODELS_ORDER)]
for cname in [c for c, _ in CAT_RULES] + ["other"]:
    sel = mal_idx[cats == cname]
    if not len(sel):
        continue
    E[cname] = {"n": int(len(sel)), **{m: [100 * (P_TEST[s][m][sel] > 0.5).mean() for s in SEEDS]
                                       for m in MODELS_ORDER}}
    L.append(f"| {cname} | {len(sel)} | " + " | ".join(ms(E[cname][m]) for m in MODELS_ORDER) + " |")
R["E"] = E

# ===================================================================== F
wrong = {m: (P_TEST[42][m] > 0.5).astype(int) != y_te for m in MODELS_ORDER}
any_wrong = np.where(np.any(np.stack(list(wrong.values())), 0))[0]
always_wrong = {m: int(np.all(np.stack([(P_TEST[s][m] > 0.5).astype(int) != y_te for s in SEEDS]), 0).sum())
                for m in MODELS_ORDER}
err = pd.DataFrame({"label": y_te[any_wrong], "query": [te_q[i] for i in any_wrong],
                    "category": [category(te_q[i]) if y_te[i] == 1 else "" for i in any_wrong],
                    **{m: wrong[m][any_wrong].astype(int) for m in MODELS_ORDER},
                    **{f"p_{m}": P_TEST[42][m][any_wrong] for m in MODELS_ORDER}})
err["n_models_wrong"] = err[MODELS_ORDER].sum(1)
err = err.sort_values(["n_models_wrong", "label"], ascending=[False, True])
err.to_csv(os.path.join(OUT, "phase3b_seed42_errors.csv"), index=False)
R["F"] = {"n_any": int(len(err)), "all_four": int((err["n_models_wrong"] == 4).sum()),
          "only_this_model": {m: int(((err[m] == 1) & (err["n_models_wrong"] == 1)).sum()) for m in MODELS_ORDER},
          "wrong_in_every_seed": always_wrong}
L += ["", "## F. Error analysis (seed 42)", "",
      f"{len(err)} test queries are misclassified by at least one model; {R['F']['all_four']} by all four. "
      "Wrong only for this model: " + ", ".join(f"{NAMES[m]} {R['F']['only_this_model'][m]}" for m in MODELS_ORDER)
      + ". Wrong in every seed: " + ", ".join(f"{NAMES[m]} {always_wrong[m]}" for m in MODELS_ORDER)
      + ". Full list: `phase3b_seed42_errors.csv`. Labels are as in the dataset; check by hand before quoting.", "",
      "| True label | Query | ENS | SVM | GNN | BERT |", "|---|---|---|---|---|---|"]
for _, r in err.head(40).iterrows():
    L.append(f"| {'attack' if r['label'] == 1 else 'benign'} | `{md_q(r['query'])}` | "
             + " | ".join("x" if r[m] else "" for m in MODELS_ORDER) + " |")
log("E and F done")

# ===================================================================== G
hp_q, hp_y = hp["Query"].tolist(), hp["Label"].values
hp_D = cached("hp_distil.pkl", lambda: distil_cls(hp_q))
hp_B, hp_G = cached("hp_bert.pkl", lambda: bert_cls_graphs(hp_q, hp_y))
hp_tr, hp_val = train_test_split(np.arange(len(hp_q)), test_size=0.15, random_state=42, stratify=hp_y)
kag_q = train_df["Query"].tolist() + te_q
kag_y = np.concatenate([y_tr, y_te])
kag_D = np.vstack([D_tr, D_te])
kag_B = np.vstack([B_tr, B_te_cls])
kag_G = G_train_order + list(G_te)


def norm_exact(q): return re.sub(r"\s+", " ", q.strip())


hp_set = {norm_exact(q) for q in hp_q}
overlap = np.array([norm_exact(q) in hp_set for q in kag_q])
G_RES = {}
for s in HEAVY_SEEDS:
    G_RES[s] = cached(f"reverse_p_seed{s}.pkl", lambda s=s: proba(
        train_family("httpparams", s, hp_D, hp_y, hp_B, [hp_G[i] for i in hp_tr], [hp_G[i] for i in hp_val],
                     hp_y[hp_tr]), kag_D, kag_B, kag_G))
    log(f"reverse cross-dataset seed {s} done")
R["G"] = {"kaggle_queries": len(kag_q), "overlap_with_httpparams": int(overlap.sum()),
          "full": {m: [met(kag_y, G_RES[s][m]) for s in HEAVY_SEEDS] for m in MODELS_ORDER},
          "no_overlap": {m: [met(kag_y[~overlap], G_RES[s][m][~overlap]) for s in HEAVY_SEEDS] for m in MODELS_ORDER}}
L += ["", "## G. Reverse cross-dataset: trained on HTTPParams, tested on the full Kaggle dataset", "",
      f"Training: all {len(hp_q)} HTTPParams queries ({int(hp_y.sum())} SQLi; GNN early stopping on a stratified "
      f"15% of them). Test: {len(kag_q)} Kaggle queries ({int(kag_y.sum())} SQLi), of which {int(overlap.sum())} "
      f"also appear in HTTPParams after whitespace normalisation. Seeds {HEAVY_SEEDS}.", "",
      "| Model | Test set | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | MCC |",
      "|---|---|---|---|---|---|---|---|"]
for m in MODELS_ORDER:
    for key, label in [("full", "all"), ("no_overlap", "without overlap")]:
        g = R["G"][key][m]
        L.append(f"| {NAMES[m]} | {label} | {ms([x['accuracy'] for x in g])} | {ms([x['precision'] for x in g])} | "
                 f"{ms([x['recall'] for x in g])} | {ms([x['f1'] for x in g])} | {ms([x['fpr'] for x in g])} | "
                 f"{ms([x['mcc'] for x in g], 4)} |")
log("G done")


# ===================================================================== H
def norm_template(q):
    q = norm_exact(q)
    q = re.sub(r"'[^']*'", "'s'", q)
    q = re.sub(r'"[^"]*"', '"s"', q)
    return re.sub(r"\d+", "0", q)


tr_exact = {norm_exact(q) for q in train_df["Query"]}
tr_tmpl = {norm_template(q) for q in train_df["Query"]}
keep_exact = np.array([norm_exact(q) not in tr_exact for q in te_q])
keep_tmpl = np.array([norm_template(q) not in tr_tmpl for q in te_q])
R["H"] = {}
L += ["", "## H. Test set without duplicates of training queries", "",
      "Exact: same query after whitespace normalisation. Template: also with every quoted string and number "
      "replaced by a placeholder.", "",
      "| Test set | Queries (attacks) | " + " | ".join(f"{NAMES[m]} F1 / FPR" for m in MODELS_ORDER) + " |",
      "|---|---|" + "---|" * len(MODELS_ORDER)]
for key, label, keep in [("full", "full", np.ones(len(te_q), bool)), ("no_exact", "without exact duplicates", keep_exact),
                         ("no_template", "without template duplicates", keep_tmpl)]:
    R["H"][key] = {"n": int(keep.sum()), "n_mal": int(y_te[keep].sum()),
                   **{m: [met(y_te[keep], P_TEST[s][m][keep]) for s in SEEDS] for m in MODELS_ORDER}}
    L.append(f"| {label} | {int(keep.sum())} ({int(y_te[keep].sum())}) | " + " | ".join(
        f"{ms([x['f1'] for x in R['H'][key][m]])} / {ms([x['fpr'] for x in R['H'][key][m]])}" for m in MODELS_ORDER) + " |")
log("H done")

# ===================================================================== I
tr_lab = tr_df["Label"]
I_RES = {}
for frac in LC_FRACS:
    for s in HEAVY_SEEDS:
        def run(frac=frac, s=s):
            tr_sub = tr_df.groupby("Label").sample(frac=frac, random_state=s)
            val_sub = val_df.groupby("Label").sample(frac=frac, random_state=s)
            keep = set(tr_sub.index) | set(val_sub.index)
            mask = np.array([ix in keep for ix in train_df.index])
            fam = train_family(f"lc{frac}_s{s}", s, D_tr[mask], y_tr[mask], B_tr[mask],
                               [G_tr[tr_pos[ix]] for ix in tr_sub.index], [G_val[val_pos[ix]] for ix in val_sub.index],
                               tr_sub["Label"].values)
            return {"n_train": int(mask.sum()), "p": proba(fam, D_te, B_te_cls, G_te)}
        I_RES[(frac, s)] = cached(f"lc_{frac}_seed{s}.pkl", run)
        log(f"learning curve {frac} seed {s} done")
R["I"] = {}
L += ["", "## I. Learning curve: F1 (%) on the full test set by training-set size", "",
      f"Stratified samples of the training set (seeds {HEAVY_SEEDS}); 100% = main models (all seeds).", "",
      "| Training share | Training queries | " + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |",
      "|---|---|" + "---|" * len(MODELS_ORDER)]
for frac in LC_FRACS:
    R["I"][frac] = {"n_train": I_RES[(frac, HEAVY_SEEDS[0])]["n_train"],
                    **{m: [met(y_te, I_RES[(frac, s)]["p"][m]) for s in HEAVY_SEEDS] for m in MODELS_ORDER}}
    L.append(f"| {int(frac * 100)}% | {R['I'][frac]['n_train']} | "
             + " | ".join(ms([x["f1"] for x in R["I"][frac][m]]) for m in MODELS_ORDER) + " |")
L.append(f"| 100% | {len(train_df)} | " + " | ".join(ms([x["f1"] for x in A[m]]) for m in MODELS_ORDER) + " |")
log("I done")

# ===================================================================== J
btok = encoder("b")[0]
tok_len = np.array([len(x) for x in btok(te_q, truncation=False, add_special_tokens=True)["input_ids"]])
BINS = [(1, 16), (17, 32), (33, 64), (65, 128), (129, 10 ** 6)]
R["J"] = {"bins": {}}
L += ["", "## J. Query length", "", "Length in BERT sub-word tokens (both encoders share the uncased vocabulary); "
      f"inputs are cut at {MAX_LEN} tokens.", "",
      "| Tokens | Queries (attacks) | " + " | ".join(f"{NAMES[m]} recall / FPR" for m in MODELS_ORDER) + " |",
      "|---|---|" + "---|" * len(MODELS_ORDER)]
for lo, hi in BINS:
    sel = (tok_len >= lo) & (tok_len <= hi)
    if not sel.any():
        continue
    key = f"{lo}-{hi}" if hi < 10 ** 6 else f">{lo - 1}"
    R["J"]["bins"][key] = {"n": int(sel.sum()), "n_mal": int(y_te[sel].sum()),
                           **{m: [met(y_te[sel], P_TEST[s][m][sel]) for s in SEEDS] for m in MODELS_ORDER}}
    cell = lambda m: (f"{ms([x['recall'] for x in R['J']['bins'][key][m]]) if y_te[sel].sum() else '-'} / "
                      f"{ms([x['fpr'] for x in R['J']['bins'][key][m]]) if (y_te[sel] == 0).sum() else '-'}")
    L.append(f"| {key} | {int(sel.sum())} ({int(y_te[sel].sum())}) | " + " | ".join(cell(m) for m in MODELS_ORDER) + " |")

ben_train = train_df.loc[train_df["Label"] == 0, "Query"].tolist()
order = np.random.RandomState(0).permutation(len(ben_train))
filler, n_tok = "", 0
for i in order:
    filler = (filler + " " + ben_train[i]).strip()
    n_tok = len(btok(filler, truncation=False)["input_ids"])
    if n_tok >= 140:
        break
rs = np.random.RandomState(1)
t_mal = rs.choice(mal_idx, min(1000, len(mal_idx)), replace=False)
t_ben = rs.choice(ben_idx, min(1000, len(ben_idx)), replace=False)
t_idx = np.concatenate([t_mal, t_ben])
t_y = y_te[t_idx]
J_T = {}
for pos in ("before", "after"):
    qs = [(filler + " " + te_q[i]) if pos == "before" else (te_q[i] + " " + filler) for i in t_idx]
    J_T[pos] = cached(f"trunc_{pos}.pkl", lambda qs=qs: proba_queries(MAIN, qs, t_y))
R["J"]["truncation"] = {"filler_tokens": int(n_tok),
                        **{pos: {m: [met(t_y, J_T[pos][s][m]) for s in SEEDS] for m in MODELS_ORDER}
                           for pos in J_T}}
L += ["", f"Truncation test: {len(t_mal)} attacks and {len(t_ben)} benign test queries with {n_tok} tokens of benign "
      "training text placed before the query (the query starts after the cut) or after it (benign padding: the "
      "query is still read in full, followed by benign text).", "",
      "| Filler | " + " | ".join(f"{NAMES[m]} recall / FPR" for m in MODELS_ORDER) + " |",
      "|---|" + "---|" * len(MODELS_ORDER)]
L.append("| none | " + " | ".join(f"{ms([100 * (P_TEST[s][m][t_mal] > 0.5).mean() for s in SEEDS])} / "
                                   f"{ms([100 * (P_TEST[s][m][t_ben] > 0.5).mean() for s in SEEDS])}"
                                   for m in MODELS_ORDER) + " |")
for pos in ("after", "before"):
    L.append(f"| {pos} the query | " + " | ".join(
        f"{ms([x['recall'] for x in R['J']['truncation'][pos][m]])} / {ms([x['fpr'] for x in R['J']['truncation'][pos][m]])}"
        for m in MODELS_ORDER) + " |")
log("J done")


# ===================================================================== K
def sync(dev):
    if dev.type == "cuda":
        torch.cuda.synchronize()


def pipeline(m, fam, qs, dev, meta, gnn):
    """Full prediction for a batch of raw queries; returns {stage: seconds}."""
    T = {}
    t = time.perf_counter()
    if m in ("ENS", "SVM"):
        tok, enc = encoder("d", dev)
        x = tok(qs, max_length=MAX_LEN, padding=True, truncation=True, return_tensors="pt").to(dev)
        with torch.inference_mode():
            D = enc(**x).last_hidden_state[:, 0, :].float().cpu().numpy()
        sync(dev)
        T["encode"] = time.perf_counter() - t
        t = time.perf_counter()
        p_svm = fam["svm"].predict_proba(D)
        if m == "ENS":
            M = np.column_stack([fam["lr"].predict_proba(D), fam["xgb"].predict_proba(D), p_svm]).astype(np.float32)
            with torch.no_grad():
                meta(torch.tensor(M, device=dev)).argmax(1).cpu()
            sync(dev)
        T["classify"] = time.perf_counter() - t
        return T
    tok, enc = encoder("b", dev)
    x = tok(qs, max_length=MAX_LEN, padding=True, truncation=True, return_offsets_mapping=(m == "GNN"),
            return_tensors="pt")
    offs = x.pop("offset_mapping", None)
    with torch.inference_mode():
        hs = enc(input_ids=x["input_ids"].to(dev), attention_mask=x["attention_mask"].to(dev)).last_hidden_state
        hs = hs.float().cpu().numpy()
    sync(dev)
    T["encode"] = time.perf_counter() - t
    t = time.perf_counter()
    if m == "BERT":
        fam["mlp"].predict_proba(hs[:, 0, :])
        T["classify"] = time.perf_counter() - t
        return T
    graphs = [graph_from_hidden(q, hs[i], offs[i].numpy()) for i, q in enumerate(qs)]
    T["graph"] = time.perf_counter() - t
    t = time.perf_counter()
    b = Batch.from_data_list(graphs).to(dev)
    with torch.no_grad():
        gnn(b.x.float(), b.edge_index, b.batch).argmax(1).cpu()
    sync(dev)
    T["classify"] = time.perf_counter() - t
    return T


def hardware():
    cpu = platform.processor()
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except Exception:
        pass
    ram = None
    try:
        ram = round(int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemTotal"))) / 1e6, 1)
    except Exception:
        pass
    return {"gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None, "cpu": cpu,
            "cpu_count": os.cpu_count(), "torch_threads": torch.get_num_threads(), "ram_gb": ram,
            "python": platform.python_version(), "torch": torch.__version__}


def timing():
    fam = MAIN[42]
    rs = np.random.RandomState(0)
    configs = []
    if torch.cuda.is_available():
        configs += [("cuda", 1, 20 if SMOKE else 300), ("cuda", 256, len(te_q))]
    configs += [("cpu", 1, 10 if SMOKE else 100), ("cpu", 64, 64 if SMOKE else 1000)]
    res = {}
    for devname, bs, n in configs:
        dev = torch.device(devname)
        meta, gnn = build(fam, dev)
        qs = [te_q[i] for i in rs.choice(len(te_q), min(n, len(te_q)), replace=False)]
        for m in MODELS_ORDER:
            for _ in range(2):
                pipeline(m, fam, qs[:bs], dev, meta, gnn)
            stages = []
            for k in range(0, len(qs), bs):
                stages.append(pipeline(m, fam, qs[k:k + bs], dev, meta, gnn))
            keys = list(stages[0])
            if bs == 1:
                tot = np.array([sum(t.values()) for t in stages]) * 1000
                res[(devname, bs, m)] = {"n": len(qs), "median_ms": float(np.median(tot)),
                                         "p95_ms": float(np.percentile(tot, 95)),
                                         **{f"{k}_median_ms": float(np.median([t[k] for t in stages]) * 1000) for k in keys}}
            else:
                total = sum(sum(t.values()) for t in stages)
                res[(devname, bs, m)] = {"n": len(qs), "ms_per_query": 1000 * total / len(qs),
                                         "queries_per_s": len(qs) / total,
                                         **{f"{k}_ms_per_query": 1000 * sum(t[k] for t in stages) / len(qs) for k in keys}}
            log(f"timing {devname} batch {bs} {m} done")
    return res


TIM = cached("timing.pkl", timing)
HW = hardware()
R["K"] = {"hardware": HW, "results": {f"{d}|{b}|{m}": v for (d, b, m), v in TIM.items()}}
L += ["", "## K. Timing (seed 42 models, full pipeline from raw query to label)", "",
      f"Platform: GPU {HW['gpu']}; CPU {HW['cpu']} ({HW['cpu_count']} logical cores, {HW['torch_threads']} torch "
      f"threads); RAM {HW['ram_gb']} GB; Python {HW['python']}; torch {HW['torch']}. Scikit-learn and XGBoost "
      "models always run on the CPU. Two warm-up passes before each measurement.", "",
      "Batch size 1 (per-query latency, ms):", "",
      "| Device | Model | Queries | Median | 95th percentile | Encoder | Graph build | Classifier |",
      "|---|---|---|---|---|---|---|---|"]
for (d, b, m), v in TIM.items():
    if b == 1:
        L.append(f"| {d} | {NAMES[m]} | {v['n']} | {v['median_ms']:.2f} | {v['p95_ms']:.2f} | "
                 f"{v['encode_median_ms']:.2f} | {fmt(v.get('graph_median_ms'), 2)} | {v['classify_median_ms']:.2f} |")
L += ["", "Batched (throughput):", "",
      "| Device | Batch | Model | Queries | ms per query | Queries per second | Encoder ms/q | Graph ms/q | Classifier ms/q |",
      "|---|---|---|---|---|---|---|---|---|"]
for (d, b, m), v in TIM.items():
    if b > 1:
        L.append(f"| {d} | {b} | {NAMES[m]} | {v['n']} | {v['ms_per_query']:.3f} | {v['queries_per_s']:.0f} | "
                 f"{v['encode_ms_per_query']:.3f} | {fmt(v.get('graph_ms_per_query'), 3)} | "
                 f"{v['classify_ms_per_query']:.3f} |")
log("K done")

# ================================================================ figures
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 3, figsize=(15, 4.5))
    for m in MODELS_ORDER:
        ax[0].plot(np.maximum(curves[f"{m}_fpr"], 1e-5), curves[f"{m}_tpr"], label=NAMES[m])
        ax[1].plot(curves[f"{m}_recall"], curves[f"{m}_precision"], label=NAMES[m])
        p = curves[f"{m}_p"]
        edges = np.linspace(0, 1, 11)
        idx = np.clip(np.digitize(p, edges[1:-1]), 0, 9)
        xs = [p[idx == b].mean() for b in range(10) if (idx == b).any()]
        ys = [y_te[idx == b].mean() for b in range(10) if (idx == b).any()]
        ax[2].plot(xs, ys, marker="o", label=NAMES[m])
    ax[0].set(xscale="log", xlabel="False-alarm rate (log scale)", ylabel="Detection rate", title="ROC (seed 42)")
    ax[1].set(xlabel="Recall", ylabel="Precision", title="Precision-recall (seed 42)", ylim=(0.9, 1.001))
    ax[2].plot([0, 1], [0, 1], "k--", lw=0.8)
    ax[2].set(xlabel="Mean predicted P(malicious)", ylabel="Observed share malicious", title="Reliability (seed 42)")
    for a in ax:
        a.legend(fontsize=8)
        a.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "phase3b_roc_pr_reliability.png"), dpi=200)
    fig, ax = plt.subplots(figsize=(6, 4.5))
    xs = [R["I"][f]["n_train"] for f in LC_FRACS] + [len(train_df)]
    for m in MODELS_ORDER:
        ys = [np.mean([x["f1"] for x in R["I"][f][m]]) for f in LC_FRACS] + [np.mean([x["f1"] for x in A[m]])]
        ax.plot(xs, ys, marker="o", label=NAMES[m])
    ax.set(xscale="log", xlabel="Training queries (log scale)", ylabel="F1 on the test set (%)", title="Learning curve")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "phase3b_learning_curve.png"), dpi=200)
except Exception as e:
    log(f"figures skipped: {e!r}")

L += ["", "## Notes", "",
      "- Models, split and hyperparameters as phase 3; GNN hyperparameters are the phase 3 Optuna result, not re-searched.",
      "- Transformed queries are not re-lower-cased; both tokenisers are uncased.",
      "- sqlmap tamper scripts run as plain string functions on the test queries (no target system); "
      "random choices inside them are seeded per query.",
      "- A disguise that leaves a query unchanged keeps the clean prediction for that query.",
      f"- GNN epochs to early stop per seed (main models): {[MAIN[s]['gnn_epochs'] for s in SEEDS]}.",
      "", "Reproduce: `python merged_phase3b_extended.py` (WORK_DIR for caches, SQLMAP_DIR for the tamper scripts)."]
open(os.path.join(OUT, "phase3b_extended.md"), "w", encoding="utf-8").write("\n".join(L))
json.dump(R, open(os.path.join(OUT, "phase3b_extended.json"), "w"), indent=1,
          default=lambda o: o.tolist() if isinstance(o, np.ndarray) else float(o) if isinstance(o, np.floating)
          else int(o) if isinstance(o, np.integer) else str(o))
np.savez_compressed(os.path.join(OUT, "phase3b_seed42_test_predictions.npz"), y=y_te,
                    **{m: (P_TEST[42][m] > 0.5).astype(int) for m in MODELS_ORDER})
log("done: results/merged/phase3b_extended.md")
