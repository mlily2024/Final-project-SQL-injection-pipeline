#!/usr/bin/env python3
"""
Robustness test 3/7: extended obfuscation battery.

Broadens obfuscation_robustness.py with additional WAF-bypass mutation operators
and reports the detection rate (recall) of each model on the malicious test
queries under each. Resumable: caches per-operator results.
"""
import os, json
import numpy as np
import robustness_common as rc

OUT_MD = os.path.join(rc.HERE, "results", "robustness_obfuscation_extended.md")
RES = os.path.join(rc.SW, "obf_extended.json")
KW = ["select","from","where","union","and","or","insert","update","delete","join"]

def double_url(q): return q.replace("%", "%25").replace(" ", "%2520").replace("'", "%2527")
def keyword_split(q):
    for k in KW: q = q.replace(k, k[:2] + "/**/" + k[2:])   # se/**/lect etc
    return q
def mysql_comment(q):
    for k in KW: q = q.replace(k, f"/*!50000{k}*/")
    return q
def mixed_ws(q):
    subs = ["\t", "\n", "\x0b", "\x0c", "/**/"]; out = []; i = 0
    for c in q:
        out.append(subs[i % len(subs)] if c == " " else c); i += 1 if c == " " else 0
    return "".join(out)
def comment_flood(q): return q.replace(" ", "/**/ --x\n").replace(" ", " ")

OBF = {"double_url_encode": double_url, "keyword_split(/**/)": keyword_split,
       "mysql_versioned_comment": mysql_comment, "mixed_whitespace": mixed_ws}

gnn, mlp, mlp_t, bp = rc.load_models()
results = json.load(open(RES)) if os.path.exists(RES) else {}
for name, fn in OBF.items():
    if name in results: continue
    q = [fn(x) for x in rc.mal_queries]
    cls, graphs = rc.embed_and_graph(q, label=1)
    rg = float((rc.gnn_predict(gnn, graphs) == 1).mean())
    rb = float((mlp.predict(cls) == 1).mean())
    results[name] = {"structure_gnn_recall": round(rg, 4), "bert_only_recall": round(rb, 4)}
    json.dump(results, open(RES, "w"), indent=2)
    print(f"  {name:26s} structure-GNN {rg*100:5.2f}%  BERT-only {rb*100:5.2f}%")

lines = ["# Robustness test 3: extended obfuscation battery", "",
         f"Detection rate (recall) on {len(rc.mal_queries)} malicious test queries under further "
         "WAF-bypass operators, extending the five in `obfuscation_robustness.md`. Higher is more "
         "robust to evasion.", "",
         "| Obfuscation operator | Structure-GNN recall (%) | BERT-only recall (%) | GNN more robust |",
         "|---|---|---|---|"]
for name in OBF:
    g = results[name]["structure_gnn_recall"]*100; b = results[name]["bert_only_recall"]*100
    lines.append(f"| {name} | {g:.2f} | {b:.2f} | {'yes' if g>b+0.05 else ('tie' if abs(g-b)<=0.05 else 'no')} |")
lines += ["", "Together with URL-encoding (test in `obfuscation_robustness.md`), this profiles the "
          "models across the common evasion families. Reproduce with "
          "`python robustness_3_obfuscation_extended.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
