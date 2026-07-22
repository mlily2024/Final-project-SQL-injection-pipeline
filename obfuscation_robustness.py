#!/usr/bin/env python3
"""
Obfuscation / evasion robustness: structure-aware BERT-GNN vs BERT-only.

Clean accuracy on this dataset is saturated (see bert_only_ablation.py and
structure_graph_gnn.py), so it cannot show whether modelling SQL structure
helps. The place structure should matter is EVASION: an attacker obscures the
surface form of a malicious query (inline comments, case mixing, encoding,
whitespace tricks) to slip past a detector. A sentence embedding keys on surface
patterns and should degrade; a graph over SQL structure should hold up better.

This script takes the malicious test queries (label = 1, the pristine test set),
applies real WAF-bypass transforms that preserve malicious intent, and measures
the DETECTION RATE (recall) of each model on the obfuscated queries. The model
whose recall drops least is the more robust to evasion.

Both models are trained exactly as in the honest held-out protocol:
  * structure-GNN: retrained from the cached structure-graphs + best params;
  * BERT-only: MLP on the cached [CLS] embeddings.
Resumable: caches per-obfuscation results to disk.
"""
import os, time, json, pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import sqlparse
from sqlparse.tokens import Whitespace, Newline
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.neural_network import MLPClassifier
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader as GeoLoader

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "SQL_Injection_Dataset.csv")
SW = os.path.join(HERE, ".structure_work")
OUT_MD = os.path.join(HERE, "results", "obfuscation_robustness.md")
RES_JSON = os.path.join(SW, "obf_results.json")
MODEL_NAME = "bert-base-uncased"; MAX_LEN = 128; SEED = 42
KEYWORDS = {"select","from","where","union","and","or","insert","update","delete",
            "join","on","group","order","having","limit","values","set"}
device = "cpu"; torch.set_num_threads(os.cpu_count() or 4)
def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

# ---------- data ----------
df = pd.read_csv(DATA); df["Query"] = df["Query"].astype(str).apply(lambda x: x.lower().strip())
train_df, test_df = train_test_split(df, test_size=0.30, random_state=SEED)
tr_df, val_df = train_test_split(train_df, test_size=0.15, random_state=SEED, stratify=train_df["Label"])
mal = test_df[test_df["Label"] == 1]["Query"].tolist()      # malicious test queries
log(f"malicious test queries: {len(mal)}")

# ---------- obfuscation transforms (preserve malicious intent) ----------
def inline_comments(q): return q.replace(" ", "/**/")
def case_mix(q): return "".join(c.upper() if (i % 2 == 0 and c.isalpha()) else c for i, c in enumerate(q))
def ws_newline(q): return q.replace(" ", "\t")
def url_encode(q): return q.replace(" ", "%20").replace("'", "%27").replace("=", "%3d")
def combined(q): return case_mix(inline_comments(q))
OBF = {"clean": lambda q: q, "inline_comments(/**/)": inline_comments,
       "case_mix": case_mix, "tab_whitespace": ws_newline,
       "url_encode": url_encode, "combined(case+/**/)": combined}

# ---------- BERT (per-token + [CLS]) ----------
from transformers import BertTokenizerFast, BertModel
tok = BertTokenizerFast.from_pretrained(MODEL_NAME); bert = BertModel.from_pretrained(MODEL_NAME).eval()

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

def embed_and_graph(queries):
    """One BERT pass -> ([CLS] matrix, list of structure-graphs) for the queries."""
    order = np.argsort([len(q) for q in queries], kind="stable")
    cls = np.zeros((len(queries), 768), dtype=np.float32); graphs = [None] * len(queries)
    B = 32
    with torch.no_grad():
        for k in range(0, len(order), B):
            idx = order[k:k + B]; batch = [queries[i] for i in idx]
            enc = tok(batch, truncation=True, max_length=MAX_LEN, padding=True,
                      return_offsets_mapping=True, return_tensors="pt")
            hs = bert(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]).last_hidden_state.numpy()
            offs = enc["offset_mapping"].numpy()
            for bi, qi in enumerate(idx):
                cls[qi] = hs[bi][0]
                toks = sql_tokens(queries[qi])
                if not toks:
                    graphs[qi] = Data(x=torch.tensor(hs[bi][:1]), edge_index=torch.empty((2,0),dtype=torch.long),
                                      y=torch.tensor([1])); continue
                feats = []; so = offs[bi]
                for (val, a, bch) in toks:
                    m = [j for j in range(len(so)) if not (so[j][0]==0 and so[j][1]==0) and so[j][0] < bch and so[j][1] > a]
                    feats.append(hs[bi][m].mean(axis=0) if m else hs[bi][0])
                e = structure_edges(toks)
                graphs[qi] = Data(x=torch.tensor(np.stack(feats), dtype=torch.float),
                                  edge_index=(torch.tensor(e,dtype=torch.long).t().contiguous() if e else torch.empty((2,0),dtype=torch.long)),
                                  y=torch.tensor([1]))
    return cls, graphs

# ---------- models ----------
class GNNModel(nn.Module):
    def __init__(self, hid, drop):
        super().__init__(); self.c1=GCNConv(768,hid); self.c2=GCNConv(hid,hid)
        self.f1=nn.Linear(hid,hid); self.f2=nn.Linear(hid,2); self.dp=nn.Dropout(drop)
    def forward(self,x,ei,b):
        x=F.relu(self.c1(x,ei)); x=F.relu(self.c2(x,ei)); x=global_mean_pool(x,b)
        return self.f2(self.dp(F.relu(self.f1(x))))

def load_g(tag, frame):
    C=3000; n=(len(frame)+C-1)//C; gl=[]
    for c in range(n):
        with open(os.path.join(SW,f"sg_{tag}_{c:03d}.pkl"),"rb") as f: gl+=pickle.load(f)
    return gl

bp = json.load(open(os.path.join(SW,"best.json")))
GNN_PT = os.path.join(SW, "gnn_model.pt"); MLP_PKL = os.path.join(SW, "mlp_model.pkl")
gnn = GNNModel(bp["hid"], bp["drop"])
if os.path.exists(GNN_PT):
    gnn.load_state_dict(torch.load(GNN_PT)); gnn.eval(); log("loaded cached structure-GNN")
else:
    log("retraining structure-GNN from cached graphs")
    tg, vg = load_g("train", tr_df), load_g("val", val_df)
    cw = compute_class_weight("balanced", classes=np.array([0,1]), y=np.array([int(g.y.item()) for g in tg]))
    crit = nn.CrossEntropyLoss(weight=torch.tensor(cw, dtype=torch.float))
    torch.manual_seed(SEED); opt = torch.optim.Adam(gnn.parameters(), lr=bp["lr"])
    tl = GeoLoader(tg, batch_size=bp["bs"], shuffle=True); vl = GeoLoader(vg, batch_size=bp["bs"])
    best, state, bad = 1e9, None, 0
    for ep in range(50):
        gnn.train()
        for d in tl:
            opt.zero_grad(); loss = crit(gnn(d.x, d.edge_index, d.batch), d.y); loss.backward(); opt.step()
        gnn.eval(); vlo = 0.0
        with torch.no_grad():
            for d in vl: vlo += crit(gnn(d.x, d.edge_index, d.batch), d.y).item()
        vlo /= len(vl)
        if vlo < best - 1e-4: best, state, bad = vlo, {k: v.clone() for k, v in gnn.state_dict().items()}, 0
        else: bad += 1
        if bad >= 5: break
    gnn.load_state_dict(state); gnn.eval(); torch.save(state, GNN_PT)
    log(f"structure-GNN ready + cached (val_loss={best:.4f})")

def cls_only(queries):
    """BERT [CLS] embedding per query (one pass, length-bucketed for speed)."""
    order = np.argsort([len(q) for q in queries], kind="stable")
    out = np.zeros((len(queries), 768), dtype=np.float32); B = 32
    with torch.no_grad():
        for k in range(0, len(order), B):
            idx = order[k:k + B]
            enc = tok([queries[i] for i in idx], truncation=True, max_length=MAX_LEN,
                      padding=True, return_tensors="pt")
            hs = bert(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]).last_hidden_state
            out[idx] = hs[:, 0, :].numpy()
    return out

if os.path.exists(MLP_PKL):
    mlp = pickle.load(open(MLP_PKL, "rb")); log("loaded cached BERT-only MLP")
else:
    log("extracting train [CLS] + fitting BERT-only MLP")
    TR_CLS = os.path.join(SW, "train_cls.npy")
    Xtr = np.load(TR_CLS) if os.path.exists(TR_CLS) else cls_only(train_df["Query"].tolist())
    if not os.path.exists(TR_CLS): np.save(TR_CLS, Xtr)
    mlp = MLPClassifier(hidden_layer_sizes=(159,), max_iter=300, random_state=SEED).fit(
        Xtr, train_df["Label"].to_numpy())
    pickle.dump(mlp, open(MLP_PKL, "wb")); log("BERT-only MLP ready + cached")

def gnn_recall(graphs):
    ld = GeoLoader(graphs, batch_size=64); pred = []
    with torch.no_grad():
        for d in ld: pred.append(gnn(d.x, d.edge_index, d.batch).argmax(1))
    pred = torch.cat(pred).numpy()
    return float((pred == 1).mean())

# ---------- run each obfuscation ----------
results = json.load(open(RES_JSON)) if os.path.exists(RES_JSON) else {}
for name, fn in OBF.items():
    if name in results: continue
    q = [fn(x) for x in mal]
    cls, graphs = embed_and_graph(q)
    r_gnn = gnn_recall(graphs)
    r_bert = float((mlp.predict(cls) == 1).mean())
    results[name] = {"structure_gnn_recall": round(r_gnn, 4), "bert_only_recall": round(r_bert, 4)}
    json.dump(results, open(RES_JSON, "w"), indent=2)
    log(f"{name:22s} structure-GNN recall={r_gnn*100:5.2f}%  BERT-only recall={r_bert*100:5.2f}%")

# ---------- report ----------
base_g = results["clean"]["structure_gnn_recall"]; base_b = results["clean"]["bert_only_recall"]
lines = ["# Evasion-robustness: structure-aware BERT-GNN vs BERT-only", "",
         f"Detection rate (recall) on {len(mal)} malicious test queries under WAF-bypass "
         "obfuscations that preserve malicious intent. Higher is better; the smaller the drop "
         "from the clean rate, the more robust the model to evasion.", "",
         "| Obfuscation | Structure-GNN recall (%) | BERT-only recall (%) | GNN more robust |",
         "|---|---|---|---|"]
for name in OBF:
    g = results[name]["structure_gnn_recall"] * 100; b = results[name]["bert_only_recall"] * 100
    lines.append(f"| {name} | {g:.2f} | {b:.2f} | {'yes' if g > b else ('tie' if abs(g-b)<0.01 else 'no')} |")
lines += ["", f"Clean baseline: structure-GNN {base_g*100:.2f}%, BERT-only {base_b*100:.2f}%.",
          "Reproduce with `python obfuscation_robustness.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines)); log(f"DONE -> {OUT_MD}")
