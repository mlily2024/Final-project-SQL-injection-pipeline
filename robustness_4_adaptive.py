#!/usr/bin/env python3
"""
Robustness test 4/7: adaptive (best-of-N) evasion attack.

A non-adaptive obfuscation applies one fixed transform. An adaptive attacker
tries several and keeps whichever evades the detector. For a sample of malicious
test queries we apply a library of WAF-bypass transforms and mark a query as
evaded if ANY transform makes the model predict benign. The evasion rate under
this best-of-N attack is a stronger robustness measure than any single transform;
a lower evasion rate means the model is harder to evade. Resumable: caches the
per-transform predictions.
"""
import os, json
import numpy as np
import robustness_common as rc

OUT_MD = os.path.join(rc.HERE, "results", "robustness_adaptive.md")
CACHE = os.path.join(rc.SW, "adaptive_preds.json")
rng = np.random.default_rng(rc.SEED)
KW = ["select","from","where","union","and","or","insert","update","delete","join"]

def url_encode(q): return q.replace(" ", "%20").replace("'", "%27").replace("=", "%3d")
def inline(q): return q.replace(" ", "/**/")
def case_mix(q): return "".join(c.upper() if (i % 2 == 0 and c.isalpha()) else c for i, c in enumerate(q))
def kw_split(q):
    for k in KW: q = q.replace(k, k[:2] + "/**/" + k[2:])
    return q
def mysql(q):
    for k in KW: q = q.replace(k, f"/*!50000{k}*/")
    return q
def double_url(q): return q.replace("%", "%25").replace(" ", "%2520").replace("'", "%2527")
def combined(q): return case_mix(inline(q))
LIB = {"url_encode": url_encode, "inline": inline, "case_mix": case_mix,
       "kw_split": kw_split, "mysql": mysql, "double_url": double_url, "combined": combined}

# sample of malicious test queries
SAMPLE = 400
sidx = rng.choice(len(rc.mal_queries), size=min(SAMPLE, len(rc.mal_queries)), replace=False)
sample = [rc.mal_queries[i] for i in sidx]

gnn, mlp, mlp_t, bp = rc.load_models()
cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
for name, fn in LIB.items():
    if name in cache: continue
    q = [fn(x) for x in sample]
    cls, graphs = rc.embed_and_graph(q, label=1)
    gp = rc.gnn_predict(gnn, graphs); pb = mlp.predict(cls)
    cache[name] = {"gnn_evade": [int(p == 0) for p in gp], "bert_evade": [int(p == 0) for p in pb]}
    json.dump(cache, open(CACHE, "w"))
    print(f"  {name:12s} single-transform evasion: GNN {np.mean(cache[name]['gnn_evade'])*100:5.2f}%  BERT {np.mean(cache[name]['bert_evade'])*100:5.2f}%")

# best-of-N: a query is evaded if ANY transform evades
G = np.array([cache[n]["gnn_evade"] for n in LIB])   # (n_transforms, n_sample)
B = np.array([cache[n]["bert_evade"] for n in LIB])
gnn_evasion = float(G.max(axis=0).mean()) * 100      # evaded by at least one transform
bert_evasion = float(B.max(axis=0).mean()) * 100
print(f"\nADAPTIVE best-of-{len(LIB)} evasion rate: structure-GNN {gnn_evasion:.2f}%  BERT-only {bert_evasion:.2f}%")

lines = ["# Robustness test 4: adaptive (best-of-N) evasion attack", "",
         f"For a sample of {len(sample)} malicious test queries, an adaptive attacker tries a "
         f"library of {len(LIB)} WAF-bypass transforms and keeps whichever evades the detector. "
         "A query counts as evaded if any transform makes the model predict benign. The best-of-N "
         "evasion rate is a stronger robustness measure than any single transform; lower is more "
         "robust.", "",
         "| Transform | Structure-GNN evasion (%) | BERT-only evasion (%) |", "|---|---|---|"]
for n in LIB:
    lines.append(f"| {n} | {np.mean(cache[n]['gnn_evade'])*100:.2f} | {np.mean(cache[n]['bert_evade'])*100:.2f} |")
lines += ["", f"**Adaptive best-of-{len(LIB)} evasion rate: structure-GNN {gnn_evasion:.2f}%, "
          f"BERT-only {bert_evasion:.2f}%.** The structure-aware model is evaded "
          + ("less" if gnn_evasion < bert_evasion else "more") + " often by an adaptive attacker.",
          "", "Reproduce with `python robustness_4_adaptive.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
