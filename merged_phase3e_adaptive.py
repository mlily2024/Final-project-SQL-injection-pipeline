"""
Merged paper, phase 3e: adaptive attacker against the defences, more seeds, confidence intervals.

Reuses the phase 3b setup and models (the part of merged_phase3b_extended.py before section A,
plus its mutation operators) and the phase 3c decoder and retrained models.

Tests
  A  score-guided mutation attack (phase 3b section D operators, budget and attack sample) on
     the raw models for seeds 42, 1, 7 (phase 3b ran seed 42 only)
  B  the same attack against the defended pipeline: decode first, models retrained on decoded
     queries, two-scale windows on long inputs; the attacker queries the whole pipeline
  C  95% Wilson confidence intervals for the small-sample results of phases 3b to 3e

Environment: P3B_WORK, P3C_WORK (phase 3b and 3c cache roots), WORK_DIR (phase 3e cache), SMOKE=1.
"""
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
P3C = os.path.join(HERE, "merged_phase3c_defences.py")
OUT = os.path.join(HERE, "results", "merged")
SMOKE = os.environ.get("SMOKE") == "1"
WORK = os.environ.get("WORK_DIR", os.path.join(HERE, ".merged_work", "phase3e")) + ("_smoke" if SMOKE else "")
P3C_WORK = os.environ.get("P3C_WORK", os.path.join(HERE, ".merged_work", "phase3c")) + ("_smoke" if SMOKE else "")
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

os.environ["PLAN"] = "cpu"
os.environ["WORK_DIR"] = os.environ.get("P3B_WORK", os.path.join(HERE, ".merged_work", "phase3b"))
os.environ.setdefault("SQLMAP_DIR", os.path.join(HERE, "..", "tools", "sqlmap"))
src = open(P3B, encoding="utf-8").read()
S = {"__file__": P3B, "__name__": "phase3b_setup"}
exec(compile(src[:src.index("# ===================================================================== A")], P3B, "exec"), S)
exec(compile(src[src.index("def m_case"):src.index("def mutation_attack")], P3B, "exec"), S)
P3B_WORK = S["WORK"]
S["WORK"] = WORK
src_c = open(P3C, encoding="utf-8").read()
C = {"re": re, "html": html, "unicodedata": unicodedata, "urllib": urllib}
exec(compile(src_c[src_c.index("OVERLONG = "):src_c.index("# ======================================================= features")], P3C, "exec"), C)
canon = C["canon"]

log, cached, ms = S["log"], S["cached"], S["ms"]
MODELS_ORDER, NAMES = S["MODELS_ORDER"], S["NAMES"]
te_q, mal_idx, P_TEST, MAIN = S["te_q"], S["mal_idx"], S["P_TEST"], S["MAIN"]
N_MUT, MUT_ROUNDS, MUT_K, mutate = S["N_MUT"], S["MUT_ROUNDS"], S["MUT_K"], S["mutate"]
SEEDS = [42] if SMOKE else [42, 1, 7]
WINDOWS = [(126, 64), (32, 16)]
_btok = S["encoder"]("b")[0]


def load(path):
    with open(path, "rb") as f:
        return pickle.load(f)


CANON = {s: load(os.path.join(P3C_WORK, f"canon_models_seed{s}.pkl")) for s in SEEDS}


def windows(q):
    offs = _btok(q, add_special_tokens=False, truncation=False, return_offsets_mapping=True)["offset_mapping"]
    n = len(offs)
    if n <= WINDOWS[0][0]:
        return [q]
    out = []
    for size, step in WINDOWS:
        for start in range(0, n, step):
            end = min(start + size, n)
            out.append(q[offs[start][0]:offs[end - 1][1]])
            if end == n:
                break
    return out


def raw_score(fam, model):
    return lambda qs: S["proba_queries"]({0: fam}, qs, only=[model])[0][model]


def defended_score(fam, model):
    """P(malicious) of the defended pipeline: decode, then the maximum over windows."""
    def f(qs):
        wins = [windows(canon(q)) for q in qs]
        flat = [w for ws in wins for w in ws]
        p = S["proba_queries"]({0: fam}, flat, only=[model])[0][model]
        out = np.full(len(qs), -1.0)
        np.maximum.at(out, np.repeat(np.arange(len(qs)), [len(w) for w in wins]), p)
        return out
    return f


def search(score, queries, seed):
    """Phase 3b section D search: each round K mutants of the current best; keep the lowest score."""
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
    return {"rounds": rounds, "final_p": np.asarray(best_p), "final_q": best_q}


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * (c - h), 100 * (c + h))


# ================================================================ A and B
detected_all = np.all(np.stack([P_TEST[42][m][mal_idx] > 0.5 for m in MODELS_ORDER]), 0)
mut_pool = mal_idx[detected_all]
mut_sel = np.sort(np.random.RandomState(0).choice(mut_pool, min(N_MUT, len(mut_pool)), replace=False))
mut_q = [te_q[i] for i in mut_sel]
# defended pipeline: start only from attacks it detects (evasion is measured from detection)
RES = {"raw": {}, "defended": {}}
for s in SEEDS:
    for m in MODELS_ORDER:
        p3b = os.path.join(P3B_WORK, f"mutation_{m}_seed{s}.pkl")
        RES["raw"][(s, m)] = load(p3b) if os.path.exists(p3b) else cached(
            f"raw_{m}_seed{s}.pkl", lambda s=s, m=m: search(raw_score(MAIN[s], m), mut_q, s))
        log(f"A: raw {m} seed {s}: {100 * (RES['raw'][(s, m)]['rounds'] > 0).mean():.1f}% evaded")
        RES["defended"][(s, m)] = cached(f"defended_{m}_seed{s}.pkl",
                                         lambda s=s, m=m: search(defended_score(CANON[s], m), mut_q, s))
        d = RES["defended"][(s, m)]
        log(f"B: defended {m} seed {s}: {100 * (d['rounds'] > 0).mean():.1f}% evaded, "
            f"{100 * (d['rounds'] == 0).mean():.1f}% not detected at the start")


def summary(r):
    rounds = r["rounds"]
    start_missed = int((rounds == 0).sum())
    evaded = int((rounds > 0).sum())
    n_start = len(rounds) - start_missed
    return {"start_missed": start_missed, "evaded": evaded, "n_start": n_start,
            "evasion": 100 * evaded / max(n_start, 1),
            "median_queries": float(np.median(rounds[rounds > 0]) * MUT_K) if evaded else None}


R = {"seeds": SEEDS, "n_attacks": len(mut_q), "budget": MUT_ROUNDS * MUT_K, "A": {}, "B": {}}
L = ["# Phase 3e: adaptive attacker against the defences; confidence intervals", "",
     f"{len(mut_q)} attacks (the phase 3b section D sample: detected by all four raw models, seed 42). Mutation "
     f"operators and budget as phase 3b ({MUT_ROUNDS} rounds x {MUT_K} mutants = {MUT_ROUNDS * MUT_K} pipeline "
     f"queries per attack). Seeds {SEEDS}. Evasion is counted among the attacks the pipeline detects before "
     "mutation; the defended pipeline (decode, retrained models, two-scale windows) is queried end to end, so "
     "the attacker adapts to it.", "",
     "| Model | Raw: evaded (%) | Raw: median queries | Defended: not detected before mutation | "
     "Defended: evaded (%) | Defended: median queries |", "|---|---|---|---|---|---|"]
for m in MODELS_ORDER:
    ra = [summary(RES["raw"][(s, m)]) for s in SEEDS]
    de = [summary(RES["defended"][(s, m)]) for s in SEEDS]
    R["A"][m], R["B"][m] = ra, de
    def mq(xs):
        v = [x["median_queries"] for x in xs if x["median_queries"] is not None]
        return ms(v, 0) if v else "-"
    L.append(f"| {NAMES[m]} | {ms([x['evasion'] for x in ra])} | {mq(ra)} | "
             f"{ms([x['start_missed'] for x in de], 1)} | {ms([x['evasion'] for x in de])} | {mq(de)} |")
L += ["", "Examples that evade the defended pipeline (seed 42): original -> variant.", ""]
for m in MODELS_ORDER:
    d = RES["defended"][(SEEDS[0], m)]
    for i in [i for i in range(len(mut_q)) if d["rounds"][i] > 0][:2]:
        L.append(f"- {NAMES[m]}: `{S['md_q'](mut_q[i], 100)}` -> `{S['md_q'](d['final_q'][i], 140)}`")
log("A and B done")

# ======================================================================= C
L += ["", "## Confidence intervals (95%, Wilson score; pooled over seeds where several)", "",
      "| Result | Model | Rate (%) | 95% interval (%) | n |", "|---|---|---|---|---|"]
R["C"] = []


def ci_row(label, m, k, n):
    lo, hi = wilson(k, n)
    R["C"].append({"result": label, "model": m, "rate": 100 * k / n, "lo": lo, "hi": hi, "n": n})
    L.append(f"| {label} | {NAMES[m]} | {100 * k / n:.1f} | {lo:.1f}–{hi:.1f} | {n} |")


for m in MODELS_ORDER:
    for key, label in (("A", "Mutation attack, raw"), ("B", "Mutation attack, defended")):
        xs = R[key][m]
        ci_row(label, m, sum(x["evaded"] for x in xs), sum(x["n_start"] for x in xs))
P3C_JSON = os.path.join(OUT, "phase3c_defences.json")
if os.path.exists(P3C_JSON) and not SMOKE:
    R3c = json.load(open(P3C_JSON, encoding="utf-8"))
    short = R3c["E"].get("1-8")
    if short:
        n = short["n_mal"]
        for m in MODELS_ORDER:
            for k_, label in (("raw", "Attacks of 1-8 tokens detected, raw"), ("canon", "Attacks of 1-8 tokens detected, decoded")):
                rec = np.mean([x["recall"] for x in short[k_][m]])
                ci_row(label, m, int(round(rec * n / 100)), n)
    for c, v in R3c["F"]["leave_one_type_out"].items():
        for m in MODELS_ORDER:
            ci_row(f"Unseen type '{c}' detected", m, int(round(v[m]["recall_held_out"] * v["test_attacks"] / 100)),
                   v["test_attacks"])
L += ["", "Rows for decoded detection and unseen types are computed from the phase 3c results (mean over seeds "
      "times n, rounded); mutation rows pool the seeds of this phase.", "",
      "Reproduce: `python merged_phase3e_adaptive.py` (after phases 3b and 3c)."]
open(os.path.join(OUT, "phase3e_adaptive.md"), "w", encoding="utf-8").write("\n".join(L))
json.dump(R, open(os.path.join(OUT, "phase3e_adaptive.json"), "w"), indent=1,
          default=lambda o: o.tolist() if isinstance(o, np.ndarray) else float(o) if isinstance(o, np.floating)
          else int(o) if isinstance(o, np.integer) else str(o))
log("done: results/merged/phase3e_adaptive.md")
