#!/usr/bin/env python3
"""
Shared harness for the robustness test suite.

Loads the trained structure-aware BERT-GNN and the BERT-only classifier (the
sklearn MLP, plus a weight-identical torch copy so it can be attacked by
gradient methods), and the aligned test features (structure graphs, [CLS]
embeddings and labels in test-row order). Also exposes BERT + the SQL-structure
graph builder so new / perturbed queries can be re-embedded.

Everything is derived deterministically from SQL_Injection_Dataset.csv and the
cached artefacts in .structure_work/ (gitignored); test [CLS] is extracted once
and cached locally.
"""
import os, json, pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import sqlparse
from sqlparse.tokens import Whitespace, Newline
from sklearn.model_selection import train_test_split
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "SQL_Injection_Dataset.csv")
SW = os.path.join(HERE, ".structure_work")
MODEL_NAME = "bert-base-uncased"; MAX_LEN = 128; SEED = 42
KEYWORDS = {"select","from","where","union","and","or","insert","update","delete",
            "join","on","group","order","having","limit","values","set"}
device = "cpu"; torch.set_num_threads(os.cpu_count() or 4)

# ---------- splits ----------
_df = pd.read_csv(DATA); _df["Query"] = _df["Query"].astype(str).apply(lambda x: x.lower().strip())
train_df, test_df = train_test_split(_df, test_size=0.30, random_state=SEED)
y_test = test_df["Label"].to_numpy()
mal_idx = np.where(y_test == 1)[0]
mal_queries = test_df["Query"].to_numpy()[mal_idx].tolist()

# ---------- SQL structure graph ----------
def sql_tokens(q):
    toks, pos = [], 0
    flat = list(sqlparse.parse(q)[0].flatten()) if q.strip() else []
    for t in flat:
        if t.ttype in (Whitespace, Newline) or t.value.strip() == "": pos += len(t.value); continue
        toks.append((t.value, pos, pos + len(t.value))); pos += len(t.value)
    return toks

def structure_edges(tokens):
    n = len(tokens); edges = set(); stack = []; last_kw = None
    for i in range(n - 1): edges.add((i, i + 1))
    for i, (val, a, b) in enumerate(tokens):
        v = val.lower()
        if val == "(": stack.append(i)
        elif val == ")" and stack: edges.add((stack.pop(), i))
        if v in KEYWORDS: last_kw = i
        elif last_kw is not None: edges.add((last_kw, i))
    e = [(a, b) for a, b in edges] + [(b, a) for a, b in edges]
    return e

# ---------- BERT ----------
_tok = _bert = None
def bert():
    global _tok, _bert
    if _bert is None:
        from transformers import BertTokenizerFast, BertModel
        _tok = BertTokenizerFast.from_pretrained(MODEL_NAME)
        _bert = BertModel.from_pretrained(MODEL_NAME).eval()
    return _tok, _bert

def embed_and_graph(queries, label=1):
    """One BERT pass -> ([CLS] matrix, list of structure-graphs) for queries."""
    tok, model = bert()
    order = np.argsort([len(q) for q in queries], kind="stable")
    cls = np.zeros((len(queries), 768), dtype=np.float32); graphs = [None] * len(queries)
    B = 32
    with torch.no_grad():
        for k in range(0, len(order), B):
            idx = order[k:k+B]; batch = [queries[i] for i in idx]
            enc = tok(batch, truncation=True, max_length=MAX_LEN, padding=True,
                      return_offsets_mapping=True, return_tensors="pt")
            hs = model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]).last_hidden_state.numpy()
            offs = enc["offset_mapping"].numpy()
            for bi, qi in enumerate(idx):
                cls[qi] = hs[bi][0]
                toks = sql_tokens(queries[qi])
                if not toks:
                    graphs[qi] = Data(x=torch.tensor(hs[bi][:1]), edge_index=torch.empty((2,0),dtype=torch.long),
                                      y=torch.tensor([label])); continue
                feats = []; so = offs[bi]
                for (val, a, bch) in toks:
                    m = [j for j in range(len(so)) if not (so[j][0]==0 and so[j][1]==0) and so[j][0] < bch and so[j][1] > a]
                    feats.append(hs[bi][m].mean(axis=0) if m else hs[bi][0])
                e = structure_edges(toks)
                graphs[qi] = Data(x=torch.tensor(np.stack(feats), dtype=torch.float),
                                  edge_index=(torch.tensor(e,dtype=torch.long).t().contiguous() if e else torch.empty((2,0),dtype=torch.long)),
                                  y=torch.tensor([label]))
    return cls, graphs

# ---------- models ----------
class GNNModel(nn.Module):
    def __init__(self, hid, drop):
        super().__init__(); self.c1=GCNConv(768,hid); self.c2=GCNConv(hid,hid)
        self.f1=nn.Linear(hid,hid); self.f2=nn.Linear(hid,2); self.dp=nn.Dropout(drop)
    def forward(self, x, ei, b):
        x=F.relu(self.c1(x,ei)); x=F.relu(self.c2(x,ei)); x=global_mean_pool(x,b)
        return self.f2(self.dp(F.relu(self.f1(x))))

class TorchMLP(nn.Module):
    """Weight-identical torch copy of the sklearn MLPClassifier (159 hidden, ReLU,
    single logistic output for binary) so it can be attacked by gradient methods.
    forward() returns the logit; P(malicious) = sigmoid(logit); predict = logit>0."""
    def __init__(self, sk):
        super().__init__()
        h = sk.hidden_layer_sizes[0]
        self.l1 = nn.Linear(768, h); self.l2 = nn.Linear(h, 1)
        with torch.no_grad():
            self.l1.weight.copy_(torch.tensor(sk.coefs_[0].T)); self.l1.bias.copy_(torch.tensor(sk.intercepts_[0]))
            self.l2.weight.copy_(torch.tensor(sk.coefs_[1].T)); self.l2.bias.copy_(torch.tensor(sk.intercepts_[1]))
    def forward(self, x): return self.l2(F.relu(self.l1(x))).squeeze(-1)   # logit
    def prob(self, x): return torch.sigmoid(self.forward(x))
    def predict(self, x): return (self.forward(x) > 0).long()

def load_models():
    bp = json.load(open(os.path.join(SW, "best.json")))
    gnn = GNNModel(bp["hid"], bp["drop"]); gnn.load_state_dict(torch.load(os.path.join(SW, "gnn_model.pt"))); gnn.eval()
    mlp = pickle.load(open(os.path.join(SW, "mlp_model.pkl"), "rb"))
    mlp_t = TorchMLP(mlp).eval()
    return gnn, mlp, mlp_t, bp

# ---------- aligned test features (test-row order) ----------
def _load_chunks(tag, n):
    C = 3000; nc = (n + C - 1) // C; gl = []
    for c in range(nc):
        with open(os.path.join(SW, f"sg_{tag}_{c:03d}.pkl"), "rb") as f: gl += pickle.load(f)
    return gl

def test_features():
    """Returns (test_graphs_rowB, test_cls_rowB, y_test) all in test-row order."""
    sorted_g = _load_chunks("test", len(test_df))
    order = np.argsort([len(q) for q in test_df["Query"].tolist()], kind="stable")
    graphs = [None] * len(test_df)
    for i, gi in enumerate(order): graphs[gi] = sorted_g[i]
    cache = os.path.join(SW, "test_cls_rowB.npy")
    if os.path.exists(cache):
        cls = np.load(cache)
    else:
        cls, _ = embed_and_graph(test_df["Query"].tolist(), label=0)  # label unused here
        np.save(cache, cls)
    return graphs, cls, y_test

def gnn_predict(gnn, graphs, want_prob=False):
    from torch_geometric.loader import DataLoader as GL
    ld = GL([g for g in graphs], batch_size=128); pr, pb = [], []
    with torch.no_grad():
        for d in ld:
            out = gnn(d.x, d.edge_index, d.batch); pr.append(out.argmax(1)); pb.append(F.softmax(out,1)[:,1])
    p = torch.cat(pr).numpy()
    return (p, torch.cat(pb).numpy()) if want_prob else p
