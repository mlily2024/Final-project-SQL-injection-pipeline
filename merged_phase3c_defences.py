"""
Merged paper, phase 3c: defences and novel-attack tests for the four models of phase 3b.

Reuses the phase 3b setup (data split, disguises, encoders, model code) and its cached models
and predictions: the part of merged_phase3b_extended.py before section A is executed here, so
both phases share one definition of every model and transform.

Pipelines
  raw            phase 3b models on the query as received
  raw+canon      phase 3b models on the canonicalised query (decoding at test time only)
  canon          models retrained on canonicalised training queries, canonicalised input
  +window        long inputs read in overlapping 126-token windows; malicious if any window is

Tests
  A  clean test set under each pipeline
  B  the 92 phase 3b disguises (same 1,000 + 1,000 test sample): detection and false alarms
  C  best-of-N per disguise group
  D  padding attacks (plain text before/after, inside a line comment, inside a block comment)
  E  short and long queries by token length
  F  novel attacks: leave-one-attack-type-out training, and the curated phase 3 OOD set

Environment: P3B_WORK (phase 3b cache root, default .merged_work/phase3b), WORK_DIR (phase 3c
cache), SQLMAP_DIR (default ../tools/sqlmap), SMOKE=1 (uses the phase 3b smoke caches).
"""
import ast
import gc
import html
import json
import os
import pickle
import re
import unicodedata
import urllib.parse

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
P3B = os.path.join(HERE, "merged_phase3b_extended.py")
OUT = os.path.join(HERE, "results", "merged")
SMOKE = os.environ.get("SMOKE") == "1"
WORK = os.environ.get("WORK_DIR", os.path.join(HERE, ".merged_work", "phase3c")) + ("_smoke" if SMOKE else "")
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

# ------------------------------------------------------------ phase 3b setup
os.environ["PLAN"] = "cpu"
os.environ["WORK_DIR"] = os.environ.get("P3B_WORK", os.path.join(HERE, ".merged_work", "phase3b"))
os.environ.setdefault("SQLMAP_DIR", os.path.join(HERE, "..", "tools", "sqlmap"))
src = open(P3B, encoding="utf-8").read()
S = {"__file__": P3B, "__name__": "phase3b_setup"}
exec(compile(src[:src.index("# ===================================================================== A")], P3B, "exec"), S)
exec(compile(src[src.index("CAT_RULES = ["):src.index("cats = np.array")], P3B, "exec"), S)
P3B_WORK = S["WORK"]
S["WORK"] = WORK                       # every new cache entry goes to the phase 3c directory
log, cached, met, ms = S["log"], S["cached"], S["met"], S["ms"]
MODELS_ORDER, NAMES = S["MODELS_ORDER"], S["NAMES"]
te_q, y_te, mal_idx, ben_idx = S["te_q"], S["y_te"], S["mal_idx"], S["ben_idx"]
train_df, tr_df, val_df, y_tr = S["train_df"], S["tr_df"], S["val_df"], S["y_tr"]
MAIN, P_TEST = S["MAIN"], S["P_TEST"]
category, CAT_NAMES = S["category"], [c for c, _ in S["CAT_RULES"]] + ["other"]
SEEDS = [42] if SMOKE else [42, 1, 7]
WINDOWS = [(126, 64), (32, 16)]        # (content tokens, step): full encoder width, and a short scale
WIN = WINDOWS[0][0]                    # inputs longer than this are windowed
PAD_N = 20 if SMOKE else 500           # attacks and benign queries per padding test


def load_p3b(name):
    with open(os.path.join(P3B_WORK, name), "rb") as f:
        return pickle.load(f)


# ========================================================== canonicalisation
OVERLONG = re.compile(r"%(c[01])%([89ab][0-9a-f])", re.I)


def canon(q):
    """Decode and normalise a query before classification, as a WAF does.
    URL (%XX, %uXXXX, overlong 2-byte UTF-8), HTML entities and \\u / \\x escapes are decoded
    repeatedly; Unicode NFKC folds full-width letters; NUL bytes are removed; a MySQL versioned
    comment keeps its content; other block comments become a space; a line comment keeps its
    marker but loses its text; whitespace is collapsed; the result is lower-cased.
    Not decoded: base64, and '+' as a space (ambiguous outside form encoding)."""
    s = q
    for _ in range(4):
        prev = s
        s = OVERLONG.sub(lambda m: chr(((int(m.group(1), 16) & 0x1F) << 6) | (int(m.group(2), 16) & 0x3F)), s)
        s = re.sub(r"%u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), s, flags=re.I)
        s = urllib.parse.unquote(s, errors="replace")
        s = html.unescape(s)
        s = re.sub(r"\\u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), s, flags=re.I)
        s = re.sub(r"\\x([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), s, flags=re.I)
        if s == prev:
            break
    s = unicodedata.normalize("NFKC", s).replace("\x00", "")
    s = re.sub(r"/\*!\d*(.*?)\*/", r" \1 ", s, flags=re.S)
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"(--|#)[^\n]*", r" \1", s)
    return re.sub(r"\s+", " ", s).strip().lower()


# ======================================================= features and models
FAMS = {f"raw{s}": MAIN[s] for s in SEEDS}


def train_canon():
    """Models of the phase 3b procedure, trained on canonicalised training queries."""
    tr_c = [canon(q) for q in tr_df["Query"]]
    val_c = [canon(q) for q in val_df["Query"]]
    Dc = S["cached"]("c_distil_train.pkl", lambda: S["distil_cls"]([canon(q) for q in train_df["Query"]]))
    Bt, Gt = S["cached"]("c_bert_tr.pkl", lambda: S["bert_cls_graphs"](tr_c, tr_df["Label"].values))
    Bv, Gv = S["cached"]("c_bert_val.pkl", lambda: S["bert_cls_graphs"](val_c, val_df["Label"].values))
    tp = {ix: i for i, ix in enumerate(tr_df.index)}
    vp = {ix: i for i, ix in enumerate(val_df.index)}
    Bc = np.stack([Bt[tp[ix]] if ix in tp else Bv[vp[ix]] for ix in train_df.index])
    log("canonical training features ready")
    out = {s: S["cached"](f"canon_models_seed{s}.pkl", lambda s=s: S["train_family"](
        "canon", s, Dc, y_tr, Bc, Gt, Gv, tr_df["Label"].values)) for s in SEEDS}
    return out


# =========================================== F (first: needs the raw graphs)
def loto():
    """Leave one attack type out of training (seed 42, raw pipeline); test on that type."""
    tr_cat = np.array([category(q) if l == 1 else "" for q, l in zip(train_df["Query"], y_tr)])
    te_cat = np.array([category(te_q[i]) if y_te[i] == 1 else "" for i in range(len(te_q))])
    tr_lab = dict(zip(train_df.index, tr_cat))
    res = {}
    for c in CAT_NAMES:
        n_test = int((te_cat == c).sum())
        if n_test < (5 if SMOKE else 20):
            continue

        def run(c=c):
            keep = tr_cat != c
            tr_keep = [ix for ix in tr_df.index if tr_lab[ix] != c]
            val_keep = [ix for ix in val_df.index if tr_lab[ix] != c]
            fam = S["train_family"](f"loto_{re.sub(r'[^a-z]+', '_', c)}", 42, S["D_tr"][keep], y_tr[keep],
                                    S["B_tr"][keep], [S["G_tr"][S["tr_pos"][ix]] for ix in tr_keep],
                                    [S["G_val"][S["val_pos"][ix]] for ix in val_keep], tr_df.loc[tr_keep, "Label"].values)
            return {"removed": int((~keep).sum()), "p": S["proba"](fam, S["D_te"], S["B_te_cls"], S["G_te"])}
        r = cached(f"loto_{re.sub(r'[^a-z]+', '_', c)}.pkl", run)
        sel = te_cat == c
        res[c] = {"train_removed": r["removed"], "test_attacks": n_test,
                  **{m: {"recall_held_out": 100 * (r["p"][m][sel] > 0.5).mean(),
                         "recall_main": 100 * (P_TEST[42][m][sel] > 0.5).mean(),
                         "fpr": 100 * (r["p"][m][y_te == 0] > 0.5).mean()} for m in MODELS_ORDER}}
        log(f"leave-one-type-out {c} done")
    return res


LOTO = loto()
for k in ("G_tr", "G_val", "G_te"):
    S[k] = None
gc.collect()
CANON = train_canon()
FAMS.update({f"canon{s}": CANON[s] for s in SEEDS})
FK = [(f, m) for f in FAMS for m in MODELS_ORDER]
log("canonical models trained")

# ================================================ memoised string prediction
MEMO_PATH = os.path.join(WORK, "memo.pkl")
MEMO = pickle.load(open(MEMO_PATH, "rb")) if os.path.exists(MEMO_PATH) else {}


def predict(queries, chunk=2000):
    """P(malicious) of every family and model for each string; each distinct string is embedded once."""
    pending = [q for q in dict.fromkeys(queries) if q not in MEMO]
    for k in range(0, len(pending), chunk):
        part = pending[k:k + chunk]
        res = S["proba_queries"](FAMS, part)
        for i, q in enumerate(part):
            MEMO[q] = np.array([res[f][m][i] for f, m in FK], np.float32)
        with open(MEMO_PATH + ".tmp", "wb") as f:
            pickle.dump(MEMO, f, protocol=4)
        os.replace(MEMO_PATH + ".tmp", MEMO_PATH)
    arr = np.stack([MEMO[q] for q in queries]) if queries else np.zeros((0, len(FK)), np.float32)
    return {(f, m): arr[:, j] for j, (f, m) in enumerate(FK)}


_btok = S["encoder"]("b")[0]


def windows(q):
    enc = _btok(q, add_special_tokens=False, truncation=False, return_offsets_mapping=True)
    offs = enc["offset_mapping"]
    n = len(offs)
    if n <= WIN:
        return [q]
    out = []
    for size, step in WINDOWS:
        for start in range(0, n, step):
            end = min(start + size, n)
            out.append(q[offs[start][0]:offs[end - 1][1]])
            if end == n:
                break
    return out


def predict_windowed(queries):
    """Malicious if any window is: max P(malicious) over the windows of each query."""
    wins = [windows(q) for q in queries]
    flat = [w for ws in wins for w in ws]
    p = predict(flat)
    owner = np.repeat(np.arange(len(queries)), [len(ws) for ws in wins])
    out = {}
    for k, v in p.items():
        r = np.full(len(queries), -1.0, np.float32)
        np.maximum.at(r, owner, v)
        out[k] = r
    return out


def pipelines(queries, raw_p=None, with_windows=False):
    """{pipeline: {seed: {model: P}}}; raw_p = phase 3b raw predictions {seed: {model: P}} if known."""
    cq = [canon(q) for q in queries]
    pc = predict(cq)
    out = {"raw+canon": {s: {m: pc[(f"raw{s}", m)] for m in MODELS_ORDER} for s in SEEDS},
           "canon": {s: {m: pc[(f"canon{s}", m)] for m in MODELS_ORDER} for s in SEEDS}}
    if raw_p is None:
        pr = predict(queries)
        raw_p = {s: {m: pr[(f"raw{s}", m)] for m in MODELS_ORDER} for s in SEEDS}
    out["raw"] = raw_p
    if with_windows:
        pw = predict_windowed(queries)
        pcw = predict_windowed(cq)
        out["raw+window"] = {s: {m: pw[(f"raw{s}", m)] for m in MODELS_ORDER} for s in SEEDS}
        out["canon+window"] = {s: {m: pcw[(f"canon{s}", m)] for m in MODELS_ORDER} for s in SEEDS}
    return out


PIPE_NAMES = {"raw": "raw", "raw+canon": "decode at test time only", "canon": "decode + retrained",
              "raw+window": "raw + windows", "canon+window": "decode + retrained + windows"}


def cell(y, P, m, key):
    return ms([met(y, P[s][m])[key] for s in SEEDS])


R = {"seeds": SEEDS, "windows": WINDOWS}
L = ["# Phase 3c: defences, obfuscation, query length and novel attacks", "",
     f"Models and disguises as phase 3b. Seeds {SEEDS} (mean ± std). Pipelines: " + "; ".join(
         f"**{v}** ({k})" for k, v in PIPE_NAMES.items()) + ". Decoding: URL (%XX, %uXXXX, overlong UTF-8), HTML "
     "entities, \\u and \\x escapes (repeated), Unicode NFKC, NUL removal, versioned comments unwrapped, block comments "
     "removed, line-comment text removed (marker kept), whitespace collapsed, lower case. Not decoded: base64, '+'. "
     "Windows (inputs over 126 tokens only): " + ", ".join(f"{a} tokens step {b}" for a, b in WINDOWS)
     + "; a query is malicious if any window is.", ""]

# ===================================================================== A
PT = pipelines(te_q, raw_p={s: P_TEST[s] for s in SEEDS})
log("A: clean test set done")
R["A"] = {k: {m: [met(y_te, v[s][m]) for s in SEEDS] for m in MODELS_ORDER} for k, v in PT.items()}
L += ["## A. Clean test set", "", "| Pipeline | Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) |",
      "|---|---|---|---|---|---|---|"]
for k in ("raw", "raw+canon", "canon"):
    for m in MODELS_ORDER:
        L.append(f"| {PIPE_NAMES[k]} | {NAMES[m]} | " + " | ".join(
            cell(y_te, PT[k], m, x) for x in ("accuracy", "precision", "recall", "f1", "fpr")) + " |")

# ===================================================================== B, C
_r = np.random.RandomState(0)
n_bc = S["BC_PER_CLASS"]
BC_IDX = np.sort(np.concatenate([_r.choice(mal_idx, min(n_bc, len(mal_idx)), replace=False),
                                 _r.choice(ben_idx, min(n_bc, len(ben_idx)), replace=False)]))
bc_q, y_bc = [te_q[i] for i in BC_IDX], y_te[BC_IDX]
bc_mal, bc_ben = np.where(y_bc == 1)[0], np.where(y_bc == 0)[0]
TP = {}
for name, fn in S["ALL_TRANSFORMS"].items():
    raw = load_p3b(f"tf_{re.sub(r'[^A-Za-z0-9_+.-]', '_', name)}.pkl")
    TP[name] = pipelines([fn(q) for q in bc_q], raw_p={s: raw[s] for s in SEEDS})
    log(f"disguise {name} done ({len(MEMO)} distinct strings embedded so far)")
GROUP = S["GROUP"]
R["B"] = {n: {"group": GROUP[n], **{k: {m: [met(y_bc, v[s][m]) for s in SEEDS] for m in MODELS_ORDER}
                                    for k, v in TP[n].items()}} for n in TP}
L += ["", "## B. Disguises (phase 3b sample: "
      f"{len(bc_mal)} attacks, {len(bc_ben)} benign)", "",
      "Each cell: raw pipeline → decode + retrained.", ""]
for key, title in (("recall", "Detection rate (recall, %)"), ("fpr", "False-alarm rate (FPR, %)")):
    L += [f"### {title}", "", "| Disguise | Group | " + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |",
          "|---|---|" + "---|" * len(MODELS_ORDER)]
    for n in TP:
        L.append(f"| {n} | {GROUP[n]} | " + " | ".join(
            f"{np.mean([x[key] for x in R['B'][n]['raw'][m]]):.1f} → {np.mean([x[key] for x in R['B'][n]['canon'][m]]):.1f}"
            for m in MODELS_ORDER) + " |")
    L.append("")

groups = {"phase 3": [n for n in TP if GROUP[n] == "phase 3"],
          "new + stacked": [n for n in TP if GROUP[n] in ("new", "stacked")],
          "sqlmap": [n for n in TP if GROUP[n] == "sqlmap"], "all": list(TP)}
R["C"] = {}
L += ["## C. Best-of-N: evasion (% of attacks) / false alarm (% of benign) by any disguise in the group", "",
      "| Group | Pipeline | " + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |", "|---|---|" + "---|" * len(MODELS_ORDER)]
for g, names in groups.items():
    if not names:
        continue
    R["C"][g] = {}
    for k in ("raw", "raw+canon", "canon"):
        R["C"][g][k] = {}
        cells = []
        for m in MODELS_ORDER:
            ev, fa = [], []
            for s in SEEDS:
                st = np.stack([TP[n][k][s][m] for n in names])
                ev.append(100 * (st[:, bc_mal] <= 0.5).any(0).mean())
                fa.append(100 * (st[:, bc_ben] > 0.5).any(0).mean())
            R["C"][g][k][m] = {"evasion": ev, "false_alarm": fa}
            cells.append(f"{ms(ev)} / {ms(fa)}")
        L.append(f"| {g} ({len(names)}) | {PIPE_NAMES[k]} | " + " | ".join(cells) + " |")
log("B and C done")

# ===================================================================== D
ben_train = train_df.loc[train_df["Label"] == 0, "Query"].tolist()
order = np.random.RandomState(0).permutation(len(ben_train))
filler, n_tok = "", 0
for i in order:
    filler = (filler + " " + ben_train[i]).strip()
    n_tok = len(_btok(filler, truncation=False)["input_ids"])
    if n_tok >= 140:
        break
rs = np.random.RandomState(1)
t_mal = rs.choice(mal_idx, min(1000, len(mal_idx)), replace=False)[:PAD_N]
t_ben = rs.choice(ben_idx, min(1000, len(ben_idx)), replace=False)[:PAD_N]
t_idx = np.concatenate([t_mal, t_ben])
t_y = y_te[t_idx]
PAD = {"plain text after": lambda q: q + " " + filler, "plain text before": lambda q: filler + " " + q,
       "line comment after": lambda q: q + " -- " + filler, "block comment before": lambda q: "/* " + filler + " */ " + q}
R["D"] = {"filler_tokens": int(n_tok)}
L += ["", "## D. Padding attacks", "",
      f"{len(t_mal)} attacks and {len(t_ben)} benign test queries (first {PAD_N} of each class of the phase 3b truncation "
      f"sample) with {n_tok} tokens of "
      "benign training text. Plain text before or after is the phase 3b test; the comment forms keep the SQL valid.", "",
      "| Padding | Pipeline | " + " | ".join(f"{NAMES[m]} recall / FPR" for m in MODELS_ORDER) + " |",
      "|---|---|" + "---|" * len(MODELS_ORDER)]
for pname, fn in PAD.items():
    P = pipelines([fn(te_q[i]) for i in t_idx], with_windows=True)
    R["D"][pname] = {k: {m: [met(t_y, v[s][m]) for s in SEEDS] for m in MODELS_ORDER} for k, v in P.items()}
    for k in ("raw", "raw+window", "canon", "canon+window"):
        L.append(f"| {pname} | {PIPE_NAMES[k]} | " + " | ".join(
            f"{ms([x['recall'] for x in R['D'][pname][k][m]])} / {ms([x['fpr'] for x in R['D'][pname][k][m]])}"
            for m in MODELS_ORDER) + " |")
    log(f"padding {pname} done")

# ===================================================================== E
tok_len = np.array([len(x) for x in _btok(te_q, truncation=False)["input_ids"]])
long_idx = np.where(tok_len > 128)[0]
PL = pipelines([te_q[i] for i in long_idx], raw_p={s: {m: P_TEST[s][m][long_idx] for m in MODELS_ORDER} for s in SEEDS},
               with_windows=True) if len(long_idx) else None
BINS = [(1, 8), (9, 16), (17, 32), (33, 64), (65, 128), (129, 10 ** 6)]
R["E"] = {}
L += ["", "## E. Short and long queries", "", "Length in BERT tokens of the raw query. Long queries (> 128 tokens) "
      "are also shown with windows.", "",
      "| Tokens | Queries (attacks) | Pipeline | " + " | ".join(f"{NAMES[m]} recall / FPR" for m in MODELS_ORDER) + " |",
      "|---|---|---|" + "---|" * len(MODELS_ORDER)]
for lo, hi in BINS:
    sel = np.where((tok_len >= lo) & (tok_len <= hi))[0]
    if not len(sel):
        continue
    key = f"{lo}-{hi}" if hi < 10 ** 6 else f">{lo - 1}"
    ys = y_te[sel]
    srcs = {k: {s: {m: PT[k][s][m][sel] for m in MODELS_ORDER} for s in SEEDS} for k in ("raw", "canon")}
    if hi >= 10 ** 6 and PL is not None:
        srcs.update({k: PL[k] for k in ("raw+window", "canon+window")})
    R["E"][key] = {"n": int(len(sel)), "n_mal": int(ys.sum()),
                   **{k: {m: [met(ys, v[s][m]) for s in SEEDS] for m in MODELS_ORDER} for k, v in srcs.items()}}
    for k in srcs:
        L.append(f"| {key} | {len(sel)} ({int(ys.sum())}) | {PIPE_NAMES[k]} | " + " | ".join(
            (f"{ms([x['recall'] for x in R['E'][key][k][m]]) if ys.sum() else '-'} / "
             f"{ms([x['fpr'] for x in R['E'][key][k][m]]) if (ys == 0).sum() else '-'}") for m in MODELS_ORDER) + " |")
log("E done")

# ===================================================================== F
R["F"] = {"leave_one_type_out": LOTO}
L += ["", "## F. Novel attacks", "", "### Leave one attack type out of training (seed 42, raw pipeline)", "",
      "Training attacks of the type are removed; the model is tested on the test attacks of that type it never saw. "
      "Cells: detection without the type in training (with it, main model) / FPR on all benign test queries.", "",
      "| Attack type | Training attacks removed | Test attacks | " + " | ".join(NAMES[m] for m in MODELS_ORDER) + " |",
      "|---|---|---|" + "---|" * len(MODELS_ORDER)]
for c, v in LOTO.items():
    L.append(f"| {c} | {v['train_removed']} | {v['test_attacks']} | " + " | ".join(
        f"{v[m]['recall_held_out']:.1f} ({v[m]['recall_main']:.1f}) / {v[m]['fpr']:.2f}" for m in MODELS_ORDER) + " |")

tree = ast.parse(open(os.path.join(HERE, "merged_phase3_common_robustness.py"), encoding="utf-8").read())
lists = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
         if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("OOD_MAL", "OOD_BEN")}
ood_q = [q.lower().strip() for q in lists["OOD_MAL"] + lists["OOD_BEN"]]
ood_y = np.array([1] * len(lists["OOD_MAL"]) + [0] * len(lists["OOD_BEN"]))
PO = pipelines(ood_q)
R["F"]["ood"] = {k: {m: [met(ood_y, v[s][m]) for s in SEEDS] for m in MODELS_ORDER} for k, v in PO.items()}
L += ["", f"### Curated out-of-distribution set (phase 3: {int(ood_y.sum())} attacks, {int((ood_y == 0).sum())} benign)", "",
      "| Pipeline | " + " | ".join(f"{NAMES[m]} recall / FPR" for m in MODELS_ORDER) + " |", "|---|" + "---|" * len(MODELS_ORDER)]
for k in ("raw", "raw+canon", "canon"):
    L.append(f"| {PIPE_NAMES[k]} | " + " | ".join(
        f"{ms([x['recall'] for x in R['F']['ood'][k][m]], 1)} / {ms([x['fpr'] for x in R['F']['ood'][k][m]], 1)}"
        for m in MODELS_ORDER) + " |")
log("F done")

L += ["", "## Notes", "",
      "- Raw-pipeline disguise results are the phase 3b cached predictions for the same sample and seeds.",
      "- 'Decode at test time only' keeps the phase 3b models; 'decode + retrained' retrains the four models on "
      "canonicalised training queries with the phase 3b procedure.",
      "- Line-comment text is removed, so benign text after '#' (for example an invoice number) is also removed.",
      "- Leave-one-type-out uses the rule-based categories of phase 3b section E.",
      f"- Distinct strings embedded: {len(MEMO)}.", "",
      "Reproduce: `python merged_phase3c_defences.py` (after phase 3b; P3B_WORK, WORK_DIR, SQLMAP_DIR)."]
open(os.path.join(OUT, "phase3c_defences.md"), "w", encoding="utf-8").write("\n".join(L))
json.dump(R, open(os.path.join(OUT, "phase3c_defences.json"), "w"), indent=1,
          default=lambda o: o.tolist() if isinstance(o, np.ndarray) else float(o) if isinstance(o, np.floating)
          else int(o) if isinstance(o, np.integer) else str(o))
log("done: results/merged/phase3c_defences.md")
