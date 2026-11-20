"""Regenerate every table of the merged paper from the result files in results/merged.

Usage: python paper_tables.py   (writes results/merged/paper_tables.md)
Each table caption names the result section it is computed from.
"""
import json
import os
import re

import numpy as np

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "merged")
OUT = os.path.join(R, "paper_tables.md")
J = lambda p: json.load(open(os.path.join(R, os.path.basename(p)), encoding="utf-8"))
b = J("phase3b_results_20261115/phase3b_extended.json")
c = J("phase3c_results_20261116/phase3c_defences.json")
d = J("phase3d_results_20261117/phase3d_original_tests.json")
e = J("phase3e_results_20261117/phase3e_adaptive.json")
p3 = J("phase3_results_20261113/results/merged/phase3_common_robustness.json")
M = ["ENS", "SVM", "GNN", "BERT"]
N = {"ENS": "DistilBERT-Stacked Ensemble", "SVM": "DistilBERT-SVM", "GNN": "Structure-aware BERT-GNN",
     "BERT": "BERT-only (MLP)"}


def ms(xs, nd=2):
    v = np.array(xs, float)
    if len(v) < 2 or round(float(v.std(ddof=1)), nd) == 0:
        return f"{v.mean():.{nd}f}"
    return f"{v.mean():.{nd}f} ± {v.std(ddof=1):.{nd}f}"


def mean(xs, k):
    return float(np.mean([x[k] for x in xs]))


L = []
w = L.append

w("""---
title: "SQL Injection Detection with Transformer Encoders for Web Application Firewalls: A Common Evaluation of Stacked-Ensemble and Graph Neural Network Pipelines, with Defences against Evasion"
subtitle: "SKELETON, 17 November 2026: headings, notes and pre-filled tables; text to be written by the authors"
---

**Authors:** Lilliane Linnet Musoke, Atta Badii, Ahmed Ashlam (order to confirm).

**How to use this skeleton.** Each section lists what to write (*Write:*) and the numbers to use. Every table is generated from the result files of phases 3 to 3e (no value typed by hand); the run is named under each table. Delete the notes as each section is written. Format: standard IEEE journal structure (Roman-numeral sections, Index Terms, numbered references), so the text can be placed into the IEEE Word or LaTeX template unchanged. Style: UK English, no em dashes, formal register, expansion then (ABBREVIATION) on first use, no latency claim without naming the platform.

# Abstract

*Write (one paragraph, about 200 to 250 words, no citations):* the problem; the gap (accuracy-only evaluation, no common protocol); what was done (four detectors under one common evaluation protocol); main results with numbers; the defences and their effect; the open-validation sentence.

Numbers to use: clean accuracy about 99.8% for all four models; disguised harmless queries raise false alarms up to about 60%; padding cuts detection to 0 to 10%; decoding first (with retraining) fixes 81 of 92 disguises with an F1 change of 0.03 points or less; two-scale windows and comment removal stop padding; the full defended pipeline cuts adaptive evasion from about 9% to 1 to 5%.

Closing sentence (required wording): "For open validation, the dataset, test sets and models are made available at https://github.com/mlily2024/Final-project-SQL-injection-pipeline."

**Index Terms:** SQL injection, web application firewall, transformer, DistilBERT, BERT, graph neural network, adversarial evasion, input canonicalisation.

# I. Introduction

*Write:*

- SQL Injection (SQLi) and why Web Application Firewalls (WAFs) need learned detectors (one paragraph, cite).
- The gap: reported accuracies near 99% are not comparable across studies (different splits, tests and hardware), and evasion is usually tested on attacks only.
- This paper combines and extends two earlier arXiv studies [cite 2608.28889, 2608.28882] under one common evaluation protocol (CEP).
- Contributions (numbered list, five to seven items): (1) common evaluation of four detectors; (2) evidence that attack-only evasion tests are misleading; (3) a large realistic attack suite (92 disguises including 68 sqlmap tamper scripts, adaptive mutation attacker, padding, short queries, unseen attack types, cross-dataset in both directions); (4) decode-first and two-scale window defences with measured effect, including against an adaptive attacker; (5) where graph structure helps and where it does not; (6) a reproducibility audit of the earlier claims; (7) measured deployment costs.
- Paper organisation (one sentence per section).

# II. Related Work

*Write (adapt the BERT-GNN review, add the rest):* A. rule-based WAFs and their evasion; B. classical machine learning and TF-IDF detectors; C. transformer encoders for SQLi; D. graph neural networks on code and queries; E. adversarial evasion of ML WAFs (WAF-A-MoLE, sqlmap tamper scripts); F. input normalisation in WAFs. End with the gap this paper fills.

# III. Dataset and Common Evaluation Protocol
""")

g = b["G"]
w(f"""*Write:* the dataset, the split, seeds, metrics and the platform. Define the CEP here.

TABLE I: Data and protocol (sources: phase 3, 3b G and H).

| Item | Value |
|---|---|
| Main dataset | Kaggle SQL injection dataset, {g['kaggle_queries']:,} queries |
| Split | 70/30, random state 42: 21,643 training, 9,276 test (5,830 benign, 3,446 malicious) |
| Graph model validation | 15% of training, stratified (18,396 / 3,247) |
| Seeds | 42, 1, 7, 13, 123 (three seeds where models are retrained or attacked) |
| Second dataset | HTTPParams, 30,156 queries (10,852 SQLi); {g['overlap_with_httpparams']:,} Kaggle queries also appear in it |
| Leakage check | Removing exact and template duplicates of training queries changes F1 by under 0.1 points |
| Metrics | Accuracy; malicious-class precision, recall, F1; false-positive rate (FPR); Matthews correlation coefficient (MCC); ROC-AUC; PR-AUC; detection at fixed FPR; Brier score; expected calibration error (ECE); McNemar exact test; Wilson 95% intervals |
| Platforms | Google Colab T4 GPU (phases 2 and 3); laptop CPU, Intel 12 logical cores (phases 3b to 3e) |

# IV. Pipeline A: DistilBERT-Stacked Ensemble

*Write (adapt from the DistilBERT paper):* encoder ([CLS], 768 dimensions, 128 tokens); seven base classifiers with grid search; top three (Logistic Regression, XGBoost, SVM) produce six out-of-fold probabilities; neural meta-learner (hidden 195, dropout 0.48, learning rate 0.0063, 92 epochs) tuned with Optuna (100 trials) and trained with FGSM (epsilon 0.10). Architecture figure (reuse, redraw to one style). Do not describe the ensemble as faster than the SVM.

# V. Pipeline B: Structure-Aware BERT-GNN

*Write (adapt from the BERT-GNN paper):* sqlparse tokens as nodes; node features = BERT sub-word states mean-pooled over each token; sequential, bracket and clause-scope edges (undirected); two GCN layers, mean pooling, two dense layers; class-weighted cross-entropy, early stopping (patience 5). Hyperparameters: Optuna, 8 trials (hidden 100, dropout 0.31, learning rate 1.98e-4, batch 60); 40 trials give the same accuracy (Section IX-G). Graph figure (reuse, redraw).

# VI. Baselines

*Write:* DistilBERT-SVM (strongest single model); BERT-only heads ([CLS] with MLP or Logistic Regression) to isolate the graph; TF-IDF baselines under the published protocol (SMOTE, defaults) and a controlled protocol (no SMOTE, class weights, same grids).

# VII. Evaluation Suite

*Write one short subsection per family, with the exact definitions:*

- A. Disguises on both classes: 9 earlier transforms, 10 new, 5 stacked, 68 sqlmap 1.9.9 tamper scripts (two skipped: one hangs, one needs a sqlmap session); applied to 1,000 attacks and 1,000 benign queries (stratified, seed 0).
- B. Best-of-N per group.
- C. Score-guided mutation attack (WAF-A-MoLE style): eight semantics-preserving operators, 20 rounds x 8 mutants, 100 attacks.
- D. Padding: benign text before or after; inside a line or block comment (valid SQL).
- E. Query length (1 to 8 up to over 128 tokens).
- F. Unseen attack types: train without one rule-based type, test on it.
- G. Cross-dataset in both directions; curated out-of-distribution set (35 attacks, 34 benign).
- H. Feature noise (scaled and absolute), white-box FGSM and PGD (margin loss), node removal, edge ablation, calibration.

# VIII. Defences

*Write:* A. decode-first canonicalisation (URL %XX, %uXXXX, overlong UTF-8, HTML entities, \\\\u and \\\\x escapes, Unicode NFKC, NUL removal, versioned comments unwrapped, other comments removed, line-comment text removed, whitespace collapsed, lower case; not decoded: base64, '+'); B. two-scale windows (126 tokens step 64, and 32 tokens step 16; malicious if any window is); C. models retrained on decoded training queries. State the limits honestly.

# IX. Results

## A. Clean test set
""")

w("TABLE II: Clean test set, mean ± standard deviation over five seeds (source: phase 3b A).\n")
w("| Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | MCC | FP / FN (seed 42) |")
w("|---|---|---|---|---|---|---|---|")
for m in M:
    a = b["A"][m]
    w(f"| {N[m]} | {ms([x['accuracy'] for x in a])} | {ms([x['precision'] for x in a])} | {ms([x['recall'] for x in a])} | "
      f"{ms([x['f1'] for x in a])} | {ms([x['fpr'] for x in a], 3)} | {ms([x['mcc'] for x in a], 4)} | {a[0]['fp']} / {a[0]['fn']} |")
w("")
w("TABLE III: Threshold-free metrics, detection at fixed false-alarm rates and calibration (source: phase 3b A).\n")
w("| Model | ROC-AUC | PR-AUC | Detection at 0.1% FPR | 0.5% FPR | 1% FPR | Brier | ECE |")
w("|---|---|---|---|---|---|---|---|")
for m in M:
    a = b["A"][m]
    w(f"| {N[m]} | {ms([x['roc_auc'] for x in a], 5)} | {ms([x['pr_auc'] for x in a], 5)} | {ms([x['tpr_at_0.001'] for x in a])} | "
      f"{ms([x['tpr_at_0.005'] for x in a])} | {ms([x['tpr_at_0.01'] for x in a])} | {ms([x['brier'] for x in a], 5)} | {ms([x['ece'] for x in a], 5)} |")
w("")
w("McNemar exact tests, seed 42 (source: phase 3 A): ")
w("; ".join(f"{N[k.split('-')[0]]} vs {N[k.split('-')[1]]}: b = {v['b']}, c = {v['c']}, p = {v['p']:.3g}" for k, v in p3["A_mcnemar"].items()) + " (b: only the first correct; c: only the second correct).")
w("\n*Write:* accuracy is saturated; the ensemble equals its SVM; the graph adds nothing on clean data; detection at 0.1% FPR separates the models more than accuracy does.\n")

w("## B. Baselines\n")
w("TABLE IV: Base classifiers on DistilBERT embeddings and TF-IDF baselines (source: phase 3d A and B; CPU times).\n")
w("| Features | Model | Accuracy (%) | F1 (mal., %) | FPR (%) | Train (s) | Test exec (s) |")
w("|---|---|---|---|---|---|---|")
for n, v in d["A"].items():
    w(f"| DistilBERT | {n} | {v['accuracy']:.2f} | {v['f1']:.2f} | {v['fpr']:.3f} | {v['train_s']:.1f} | {v['exec_s']:.4f} |")
for k, lab in (("published", "TF-IDF (as published)"), ("controlled", "TF-IDF (controlled)")):
    for n, v in d["B"][k].items():
        w(f"| {lab} | {n} | {v['accuracy']:.2f} | {v['f1']:.2f} | {v['fpr']:.3f} | {v['train_s']:.1f} | {v['exec_s']:.4f} |")
dc = d["C"]
w(f"\nEnsemble before Optuna: {dc['pre_optuna']['accuracy']:.2f}%. BERT [CLS] + Logistic Regression: {d['H']['bert_lr']['accuracy']:.2f}%.\n")

w("## C. Timing\n")
w("TABLE V: Time from raw query to label, seed 42 models (source: phase 3b K; laptop CPU, 12 logical cores).\n")
w("| Model | Median per query, batch 1 (ms) | 95th percentile (ms) | Encoder share of median (%) | Batch 64 (ms per query) |")
w("|---|---|---|---|---|")
K = b["K"]["results"]
for m in M:
    v1, v64 = K[f"cpu|1|{m}"], K[f"cpu|64|{m}"]
    w(f"| {N[m]} | {v1['median_ms']:.1f} | {v1['p95_ms']:.1f} | {100 * v1['encode_median_ms'] / v1['median_ms']:.0f} | {v64['ms_per_query']:.1f} |")
w("\nGPU reference (phase 2, Colab T4): DistilBERT embedding 3.22 ms per query (batch 64); ensemble test set 3.77 s including base models against 3.20 s for the SVM alone.\n")
w("*Write:* the encoder dominates; the ensemble is not faster than the SVM (correction of the earlier claim); always name the platform.\n")

w("## D. Obfuscation and the defences\n")
sel = ["url_encode", "double_url_encode", "inline_comment", "mysql_versioned_comment", "fullwidth_keywords",
       "nested_keywords", "sqlmap:charunicodeescape", "sqlmap:base64encode", "sqlmap:htmlencode",
       "sqlmap:space2comment", "sqlmap:space2hash", "sqlmap:randomcase"]
for key, title in (("recall", "Detection rate (%)"), ("fpr", "False-alarm rate on disguised benign queries (%)")):
    w(f"TABLE {'VI' if key == 'recall' else 'VII'}: {title}, raw → decode + retrained, mean over three seeds (source: phase 3c B; full 92-row table in the appendix).\n")
    w("| Disguise | " + " | ".join(N[m] for m in M) + " |")
    w("|---|" + "---|" * 4)
    for n in sel:
        r = c["B"][n]
        w(f"| {n} | " + " | ".join(f"{mean(r['raw'][m], key):.1f} → {mean(r['canon'][m], key):.1f}" for m in M) + " |")
    w("")
bad = lambda r: max(mean(r[m], "fpr") for m in M) > 5 or min(mean(r[m], "recall") for m in M) < 95
w(f"Disguises with detection under 95% or false alarms over 5% for any model: {sum(bad(v['raw']) for v in c['B'].values())} of {len(c['B'])} raw; "
  f"{sum(bad(v['canon']) for v in c['B'].values())} after decode + retrained.\n")
w("TABLE VIII: Clean test set with the defences (source: phase 3c A).\n")
w("| Pipeline | " + " | ".join(f"{N[m]} F1 / FPR" for m in M) + " |")
w("|---|" + "---|" * 4)
for k, lab in (("raw", "Raw"), ("raw+canon", "Decode at test time"), ("canon", "Decode + retrained")):
    w(f"| {lab} | " + " | ".join(f"{ms([x['f1'] for x in c['A'][k][m]])} / {ms([x['fpr'] for x in c['A'][k][m]])}" for m in M) + " |")
w("\n*Write:* attack-only tests overstate robustness; decoding removes most of the problem at almost no clean cost; what remains (base64, ASP percentage, comment-based space swaps) and why comment-laden benign input is suspicious in itself.\n")

w("## E. Padding and query length\n")
w("TABLE IX: Padding attacks, detection / false alarms (%) (source: phase 3c D; 500 attacks, 500 benign; 146 tokens of benign text).\n")
w("| Padding | Pipeline | " + " | ".join(N[m] for m in M) + " |")
w("|---|---|" + "---|" * 4)
for pn, v in c["D"].items():
    if pn == "filler_tokens":
        continue
    for k, lab in (("raw", "Raw"), ("raw+window", "Raw + windows"), ("canon", "Decode + retrained"), ("canon+window", "Decode + retrained + windows")):
        w(f"| {pn} | {lab} | " + " | ".join(f"{mean(v[k][m], 'recall'):.1f} / {mean(v[k][m], 'fpr'):.1f}" for m in M) + " |")
w("")
w("TABLE X: Detection by query length, raw pipeline (source: phase 3c E).\n")
w("| Tokens | Attacks | " + " | ".join(N[m] for m in M) + " |")
w("|---|---|" + "---|" * 4)
for k, v in c["E"].items():
    if v["n_mal"]:
        w(f"| {k} | {v['n_mal']} | " + " | ".join(f"{mean(v['raw'][m], 'recall'):.1f}" for m in M) + " |")
w("\n*Write:* padding is a cheap, valid evasion; windows and comment removal stop it; very short attacks are the remaining weak spot (66 attacks of 1 to 8 tokens; Wilson 95% intervals in phase 3e, for example the ensemble 86.4%, 76.1 to 92.7%).\n")

w("## F. Adaptive attacker and novel attacks\n")
w("TABLE XI: Score-guided mutation attack, 100 attacks, 160 queries each, three seeds (source: phase 3e).\n")
w("| Model | Evaded, raw (%) | 95% interval | Evaded, defended (%) | 95% interval |")
w("|---|---|---|---|---|")
ci = {(x["result"], x["model"]): x for x in e["C"]}
for m in M:
    r, dd = ci[("Mutation attack, raw", m)], ci[("Mutation attack, defended", m)]
    w(f"| {N[m]} | {r['rate']:.1f} | {r['lo']:.1f}–{r['hi']:.1f} | {dd['rate']:.1f} | {dd['lo']:.1f}–{dd['hi']:.1f} |")
w("")
w("TABLE XII: Unseen attack types: detection when the type is removed from training (with it), seed 42 (source: phase 3c F).\n")
w("| Attack type | Test attacks | " + " | ".join(N[m] for m in M) + " |")
w("|---|---|" + "---|" * 4)
for t, v in c["F"]["leave_one_type_out"].items():
    w(f"| {t} | {v['test_attacks']} | " + " | ".join(f"{v[m]['recall_held_out']:.1f} ({v[m]['recall_main']:.1f})" for m in M) + " |")
w("")
w("TABLE XIII: Cross-dataset in both directions (sources: phase 3 D; phase 3b G).\n")
w("| Direction | " + " | ".join(f"{N[m]} recall / FPR" for m in M) + " |")
w("|---|" + "---|" * 4)
w("| Kaggle → HTTPParams | " + " | ".join(f"{mean(p3['D'][m]['httpparams'], 'mal_recall'):.2f} / {mean(p3['D'][m]['httpparams'], 'fpr'):.2f}" for m in M) + " |")
w("| HTTPParams → Kaggle | " + " | ".join(f"{mean(g['full'][m], 'recall'):.2f} / {mean(g['full'][m], 'fpr'):.2f}" for m in M) + " |")
w("| HTTPParams → Kaggle, no overlap | " + " | ".join(f"{mean(g['no_overlap'][m], 'recall'):.2f} / {mean(g['no_overlap'][m], 'fpr'):.2f}" for m in M) + " |")
w("\n*Write:* the defences hold against an attacker who adapts to them; unseen types are mostly still detected (exception: GNN on union attacks); transfer works in one direction only.\n")

w("## G. What the graph contributes\n")
w("TABLE XIV: Graph-model analyses (sources: phase 3 E; 3d D, E, F, G, I, K).\n")
w("| Analysis | Structure-aware BERT-GNN | BERT-only (MLP) |")
w("|---|---|---|")
w(f"| Clean accuracy, edges original / none / random (%) | {ms([x['accuracy'] for x in d['E']['original']])} / {ms([x['accuracy'] for x in d['E']['none']])} / {ms([x['accuracy'] for x in d['E']['random']])} | - |")
w(f"| Node removal 10%: mean change in P(malicious), 99 attack graphs | {ms(d['D']['mean_abs_change_10pct_99'], 4)} | - |")
w(f"| Noise flips, sigma 0.5 absolute (%) | {ms(d['G']['GNN']['0.5'])} | {ms(d['G']['BERT']['0.5'])} |")
w(f"| Noise flips, sigma 0.5 x feature spread (%) | {ms(p3['E']['GNN']['0.5'])} | {ms(p3['E']['BERT']['0.5'])} |")
w(f"| White-box FGSM eps 0.05, accuracy (%) | {ms(d['F']['GNN']['0.05'])} | {ms(d['F']['BERT']['0.05'])} |")
w(f"| White-box PGD eps 0.1, accuracy (%) | {ms(d['F']['pgd_GNN'])} | {ms(d['F']['pgd_BERT'])} |")
w(f"| ECE under URL encoding | {ms(d['I']['GNN']['url_encode'], 4)} | {ms(d['I']['BERT']['url_encode'], 4)} |")
w(f"| sqlmap best-of-68 evasion, raw (%) | {ms(b['C']['sqlmap']['GNN']['evasion'])} | {ms(b['C']['sqlmap']['BERT']['evasion'])} |")
w(f"| Optuna 8 / 40 trials, accuracy (%) | {ms([x['accuracy'] for x in d['K']['test8']])} / {ms([x['accuracy'] for x in d['K']['test40']])} | - |")
w("\n*Write:* the edges are inert on clean data; the graph model is more robust to encodings and padding and stays calibrated; the noise advantage is mostly a scale effect; both models fall to white-box attacks (earlier BERT-only result was gradient masking).\n")

w("""# X. Discussion

*Write:* A. recommendations for a WAF (decode first, windows, DistilBERT-SVM for accuracy and speed, graph model where encoding robustness matters, threshold set by FPR); B. corrections to the earlier versions (ensemble not faster, not more robust; white-box result was gradient masking; noise advantage scale-dependent), stated once and neutrally; C. limitations (base64 and ASP percentage not decoded; comment-based false alarms; CPU timing; one main dataset; rule-based attack types; mutation operators not checked for SQL validity, so defended evasion is an upper bound).

# XI. Conclusion and Future Work

*Write:* three to five sentences of findings; future work from the limitations (SQL-validity filter for mutations, more datasets, GPU deployment timing, learned canonicalisation). End with the open-validation sentence.

# Acknowledgment

*Write if needed.*

# References

*Start list (IEEE numbered style; complete details when writing):* the two arXiv papers (2608.28889, 2608.28882); Devlin et al. (BERT); Sanh et al. (DistilBERT); Kipf and Welling (GCN); Goodfellow et al. (FGSM); Madry et al. (PGD); Demetrio et al. (WAF-A-MoLE); sqlmap project; Kaggle SQL injection dataset; HTTPParams dataset; Optuna; McNemar test; Wilson score interval; the related-work sources of both papers.

# Figures available

| Figure | File |
|---|---|
| ROC, precision-recall and reliability (seed 42) | phase3b_results_20261115/phase3b_roc_pr_reliability.png |
| Learning curve | phase3b_results_20261115/phase3b_learning_curve.png |
| Loss curves (GNN, meta-learner) | phase3d_results_20261117/phase3d_loss_curves.png |
| Architectures (Pipelines A and B) | redraw from the arXiv papers |

# Appendix

*Full 92-disguise tables (phase 3c B), the error list (phase 3b F) and per-seed values; or place in the repository and cite.*
""")
text = "\n".join(L) + "\n"
blocks = re.findall(r"^TABLE [IVX]+:.*?\n\n(?:\|.*\n)+|^McNemar exact tests.*\n.*\n", text, flags=re.M)
open(OUT, "w", encoding="utf-8").write("# Tables of the merged paper\n\n" + "\n".join(b.strip() + "\n" for b in blocks))
print("written", len(L), "lines")
