# Tables of the merged paper

TABLE I: Data and protocol (sources: phase 3, 3b G and H).

| Item | Value |
|---|---|
| Main dataset | Kaggle SQL injection dataset, 30,919 queries |
| Split | 70/30, random state 42: 21,643 training, 9,276 test (5,830 benign, 3,446 malicious) |
| Graph model validation | 15% of training, stratified (18,396 / 3,247) |
| Seeds | 42, 1, 7, 13, 123 (three seeds where models are retrained or attacked) |
| Second dataset | HTTPParams, 30,156 queries (10,852 SQLi); 7,595 Kaggle queries also appear in it |
| Leakage check | Removing exact and template duplicates of training queries changes F1 by under 0.1 points |
| Metrics | Accuracy; malicious-class precision, recall, F1; false-positive rate (FPR); Matthews correlation coefficient (MCC); ROC-AUC; PR-AUC; detection at fixed FPR; Brier score; expected calibration error (ECE); McNemar exact test; Wilson 95% intervals |
| Platforms | Google Colab T4 GPU (phases 2 and 3); laptop CPU, Intel 12 logical cores (phases 3b to 3e) |

TABLE II: Clean test set, mean ± standard deviation over five seeds (source: phase 3b A).

| Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | MCC | FP / FN (seed 42) |
|---|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 99.84 | 99.83 | 99.74 | 99.78 | 0.103 | 0.9965 | 6 / 9 |
| DistilBERT-SVM | 99.85 | 99.85 | 99.74 | 99.80 | 0.086 | 0.9968 | 5 / 9 |
| Structure-aware BERT-GNN | 99.64 ± 0.02 | 99.53 ± 0.16 | 99.51 ± 0.15 | 99.52 ± 0.03 | 0.278 ± 0.095 | 0.9924 ± 0.0005 | 16 / 17 |
| BERT-only (MLP) | 99.74 ± 0.04 | 99.78 ± 0.03 | 99.51 ± 0.12 | 99.65 ± 0.05 | 0.127 ± 0.020 | 0.9944 ± 0.0009 | 7 / 18 |

TABLE III: Threshold-free metrics, detection at fixed false-alarm rates and calibration (source: phase 3b A).

| Model | ROC-AUC | PR-AUC | Detection at 0.1% FPR | 0.5% FPR | 1% FPR | Brier | ECE |
|---|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 0.99985 | 0.99985 | 99.69 ± 0.01 | 99.88 | 99.94 | 0.00143 ± 0.00001 | 0.00094 ± 0.00006 |
| DistilBERT-SVM | 0.99989 | 0.99987 | 99.77 | 99.88 | 99.91 | 0.00135 | 0.00145 ± 0.00010 |
| Structure-aware BERT-GNN | 0.99990 ± 0.00002 | 0.99984 ± 0.00002 | 98.57 ± 0.19 | 99.70 ± 0.06 | 99.84 ± 0.06 | 0.00289 ± 0.00009 | 0.00235 ± 0.00015 |
| BERT-only (MLP) | 0.99994 ± 0.00002 | 0.99991 ± 0.00002 | 99.37 ± 0.12 | 99.83 ± 0.03 | 99.88 ± 0.02 | 0.00235 ± 0.00027 | 0.00238 ± 0.00028 |

McNemar exact tests, seed 42 (source: phase 3 A): 
DistilBERT-Stacked Ensemble vs DistilBERT-SVM: b = 1, c = 2, p = 1; DistilBERT-Stacked Ensemble vs Structure-aware BERT-GNN: b = 25, c = 3, p = 2.74e-05; DistilBERT-Stacked Ensemble vs BERT-only (MLP): b = 17, c = 3, p = 0.00258; DistilBERT-SVM vs Structure-aware BERT-GNN: b = 27, c = 4, p = 3.4e-05; DistilBERT-SVM vs BERT-only (MLP): b = 18, c = 3, p = 0.00149; Structure-aware BERT-GNN vs BERT-only (MLP): b = 12, c = 20, p = 0.215 (b: only the first correct; c: only the second correct).

TABLE IV: Base classifiers on DistilBERT embeddings and TF-IDF baselines (source: phase 3d A and B; CPU times).

| Features | Model | Accuracy (%) | F1 (mal., %) | FPR (%) | Train (s) | Test exec (s) |
|---|---|---|---|---|---|---|
| DistilBERT | Random Forest | 99.49 | 99.31 | 0.034 | 437.4 | 0.4569 |
| DistilBERT | Decision Tree | 98.11 | 97.44 | 0.995 | 252.5 | 0.1844 |
| DistilBERT | Naive Bayes | 90.46 | 87.43 | 8.868 | 0.2 | 0.0977 |
| DistilBERT | Logistic Regression | 99.78 | 99.71 | 0.223 | 12.2 | 0.0315 |
| DistilBERT | SVM | 99.84 | 99.78 | 0.086 | 938.0 | 1.5248 |
| DistilBERT | Gradient Boosting | 99.66 | 99.53 | 0.120 | 5452.4 | 0.2872 |
| DistilBERT | XGBoost | 99.72 | 99.62 | 0.120 | 122.3 | 0.0475 |
| TF-IDF (as published) | Decision Tree | 98.92 | 98.54 | 0.635 | 0.3 | 0.0079 |
| TF-IDF (as published) | Logistic Regression | 98.76 | 98.32 | 0.652 | 0.1 | 0.0008 |
| TF-IDF (as published) | SVM | 99.09 | 98.77 | 0.395 | 6.8 | 1.0171 |
| TF-IDF (as published) | Naive Bayes | 98.28 | 97.68 | 1.321 | 0.0 | 0.0009 |
| TF-IDF (as published) | Random Forest | 99.51 | 99.34 | 0.069 | 3.7 | 0.7732 |
| TF-IDF (as published) | Gradient Boosting | 98.11 | 97.41 | 0.429 | 4.4 | 0.0107 |
| TF-IDF (as published) | XGBoost | 99.42 | 99.21 | 0.120 | 1.4 | 0.0186 |
| TF-IDF (controlled) | Random Forest | 99.51 | 99.34 | 0.051 | 60.2 | 0.4928 |
| TF-IDF (controlled) | Decision Tree | 99.14 | 98.84 | 0.566 | 1.8 | 0.0066 |
| TF-IDF (controlled) | Logistic Regression | 99.08 | 98.76 | 0.446 | 0.5 | 0.0006 |
| TF-IDF (controlled) | SVM | 99.09 | 98.78 | 0.669 | 601.2 | 2.6286 |
| TF-IDF (controlled) | Gradient Boosting | 99.07 | 98.74 | 0.240 | 72.8 | 0.0219 |
| TF-IDF (controlled) | XGBoost | 99.41 | 99.20 | 0.120 | 14.4 | 0.0191 |
| TF-IDF (controlled) | Naive Bayes | 96.38 | 94.98 | 1.149 | 0.0 | 0.0012 |

TABLE V: Time from raw query to label, seed 42 models (source: phase 3b K; laptop CPU, 12 logical cores).

| Model | Median per query, batch 1 (ms) | 95th percentile (ms) | Encoder share of median (%) | Batch 64 (ms per query) |
|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 41.7 | 109.5 | 88 | 69.1 |
| DistilBERT-SVM | 33.8 | 92.2 | 97 | 51.0 |
| Structure-aware BERT-GNN | 74.7 | 208.7 | 91 | 136.3 |
| BERT-only (MLP) | 65.7 | 182.4 | 99 | 116.5 |

TABLE VI: Detection rate (%), raw → decode + retrained, mean over three seeds (source: phase 3c B; full 92-row table in the appendix).

| Disguise | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|
| url_encode | 99.2 → 99.7 | 99.3 → 99.6 | 95.3 → 99.5 | 85.0 → 99.3 |
| double_url_encode | 99.5 → 99.7 | 99.5 → 99.6 | 99.8 → 99.5 | 99.4 → 99.3 |
| inline_comment | 98.8 → 99.7 | 99.4 → 99.6 | 99.8 → 99.5 | 99.6 → 99.3 |
| mysql_versioned_comment | 99.7 → 99.7 | 99.7 → 99.6 | 99.7 → 99.5 | 99.6 → 99.3 |
| fullwidth_keywords | 99.3 → 99.7 | 99.3 → 99.6 | 99.4 → 99.5 | 99.2 → 99.3 |
| nested_keywords | 98.2 → 98.3 | 98.6 → 98.7 | 97.1 → 97.0 | 98.3 → 97.1 |
| sqlmap:charunicodeescape | 1.4 → 99.7 | 2.3 → 99.6 | 80.8 → 99.5 | 100.0 → 99.3 |
| sqlmap:base64encode | 68.1 → 79.5 | 68.3 → 73.7 | 66.3 → 63.6 | 72.5 → 66.6 |
| sqlmap:htmlencode | 99.8 → 99.7 | 99.8 → 99.6 | 99.8 → 99.5 | 23.8 → 99.3 |
| sqlmap:space2comment | 98.8 → 99.7 | 99.4 → 99.6 | 99.8 → 99.5 | 99.6 → 99.3 |
| sqlmap:space2hash | 99.5 → 99.8 | 99.5 → 99.8 | 99.5 → 99.7 | 69.1 → 99.4 |
| sqlmap:randomcase | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |

TABLE VII: False-alarm rate on disguised benign queries (%), raw → decode + retrained, mean over three seeds (source: phase 3c B; full 92-row table in the appendix).

| Disguise | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|
| url_encode | 18.3 → 0.0 | 29.2 → 0.0 | 1.9 → 0.3 | 35.1 → 0.0 |
| double_url_encode | 52.6 → 0.0 | 56.8 → 0.0 | 59.4 → 0.3 | 55.3 → 0.0 |
| inline_comment | 16.3 → 0.0 | 22.2 → 0.0 | 35.8 → 0.3 | 42.5 → 0.0 |
| mysql_versioned_comment | 47.1 → 0.7 | 50.9 → 0.6 | 38.9 → 0.8 | 52.0 → 0.6 |
| fullwidth_keywords | 4.7 → 0.0 | 6.5 → 0.0 | 14.6 → 0.3 | 22.7 → 0.0 |
| nested_keywords | 1.5 → 1.0 | 1.6 → 0.5 | 1.9 → 1.2 | 5.2 → 2.3 |
| sqlmap:charunicodeescape | 22.3 → 0.0 | 35.9 → 0.0 | 82.9 → 0.3 | 99.0 → 0.0 |
| sqlmap:base64encode | 66.1 → 68.0 | 66.3 → 67.0 | 27.3 → 22.6 | 46.0 → 46.4 |
| sqlmap:htmlencode | 40.8 → 0.0 | 40.0 → 0.0 | 58.8 → 0.3 | 2.0 → 0.0 |
| sqlmap:space2comment | 16.3 → 0.0 | 22.2 → 0.0 | 35.7 → 0.3 | 42.5 → 0.0 |
| sqlmap:space2hash | 59.1 → 28.6 | 60.4 → 34.4 | 50.7 → 19.7 | 50.1 → 19.0 |
| sqlmap:randomcase | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |

TABLE VIII: Clean test set with the defences (source: phase 3c A).

| Pipeline | DistilBERT-Stacked Ensemble F1 / FPR | DistilBERT-SVM F1 / FPR | Structure-aware BERT-GNN F1 / FPR | BERT-only (MLP) F1 / FPR |
|---|---|---|---|---|
| Raw | 99.78 / 0.10 | 99.80 / 0.09 | 99.53 ± 0.04 / 0.22 ± 0.05 | 99.66 ± 0.03 / 0.12 ± 0.02 |
| Decode at test time | 99.80 / 0.14 | 99.81 / 0.12 | 99.55 ± 0.04 / 0.26 ± 0.05 | 99.67 ± 0.04 / 0.14 ± 0.03 |
| Decode + retrained | 99.77 / 0.17 | 99.77 / 0.14 | 99.54 ± 0.06 / 0.25 ± 0.06 | 99.64 ± 0.07 / 0.16 ± 0.05 |

TABLE IX: Padding attacks, detection / false alarms (%) (source: phase 3c D; 500 attacks, 500 benign; 146 tokens of benign text).

| Padding | Pipeline | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| plain text after | Raw | 10.4 / 0.2 | 10.4 / 0.2 | 42.5 / 0.0 | 7.9 / 0.2 |
| plain text after | Raw + windows | 71.6 / 2.4 | 73.1 / 2.4 | 85.7 / 1.1 | 76.1 / 6.8 |
| plain text after | Decode + retrained | 59.4 / 0.2 | 59.4 / 0.2 | 61.1 / 0.0 | 57.4 / 0.2 |
| plain text after | Decode + retrained + windows | 86.9 / 2.4 | 87.1 / 2.4 | 86.9 / 1.1 | 88.7 / 11.7 |
| plain text before | Raw | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| plain text before | Raw + windows | 98.0 / 4.1 | 98.2 / 3.3 | 97.1 / 1.0 | 98.1 / 8.1 |
| plain text before | Decode + retrained | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| plain text before | Decode + retrained + windows | 97.6 / 3.4 | 97.6 / 2.7 | 97.0 / 1.0 | 97.1 / 5.5 |
| line comment after | Raw | 11.2 / 0.2 | 11.4 / 0.2 | 76.5 / 0.4 | 9.7 / 0.2 |
| line comment after | Raw + windows | 75.9 / 6.8 | 77.5 / 6.8 | 97.5 / 3.0 | 81.1 / 8.8 |
| line comment after | Decode + retrained | 99.8 / 14.3 | 99.8 / 16.2 | 99.8 / 4.1 | 99.7 / 17.5 |
| line comment after | Decode + retrained + windows | 99.8 / 14.3 | 99.8 / 16.2 | 99.8 / 4.3 | 99.7 / 17.5 |
| block comment before | Raw | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| block comment before | Raw + windows | 97.8 / 3.9 | 97.4 / 3.8 | 98.0 / 2.2 | 98.5 / 11.7 |
| block comment before | Decode + retrained | 99.4 / 0.2 | 99.4 / 0.2 | 98.8 / 0.3 | 99.3 / 0.3 |
| block comment before | Decode + retrained + windows | 99.4 / 0.2 | 99.4 / 0.2 | 98.8 / 0.5 | 99.3 / 0.3 |

TABLE X: Detection by query length, raw pipeline (source: phase 3c E).

| Tokens | Attacks | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| 1-8 | 66 | 86.4 | 86.4 | 79.3 | 78.3 |
| 9-16 | 522 | 100.0 | 100.0 | 99.3 | 99.7 |
| 17-32 | 1171 | 100.0 | 100.0 | 99.9 | 100.0 |
| 33-64 | 1009 | 100.0 | 100.0 | 99.9 | 100.0 |
| 65-128 | 586 | 100.0 | 100.0 | 100.0 | 100.0 |
| >128 | 92 | 100.0 | 100.0 | 100.0 | 100.0 |

TABLE XI: Score-guided mutation attack, 100 attacks, 160 queries each, three seeds (source: phase 3e).

| Model | Evaded, raw (%) | 95% interval | Evaded, defended (%) | 95% interval |
|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 9.7 | 6.8–13.5 | 1.0 | 0.3–2.9 |
| DistilBERT-SVM | 9.0 | 6.3–12.8 | 1.3 | 0.5–3.4 |
| Structure-aware BERT-GNN | 9.7 | 6.8–13.5 | 2.7 | 1.4–5.2 |
| BERT-only (MLP) | 8.7 | 6.0–12.4 | 4.7 | 2.8–7.7 |

TABLE XII: Unseen attack types: detection when the type is removed from training (with it), seed 42 (source: phase 3c F).

| Attack type | Test attacks | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| time-based | 524 | 97.9 (99.8) | 98.3 (100.0) | 96.9 (99.4) | 95.4 (99.4) |
| error-based | 350 | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) |
| union-based | 620 | 97.1 (100.0) | 97.7 (99.8) | 85.5 (99.8) | 96.6 (99.8) |
| boolean / tautology | 1321 | 100.0 (100.0) | 100.0 (100.0) | 99.4 (99.9) | 98.4 (100.0) |
| other | 628 | 94.4 (98.7) | 94.1 (98.7) | 93.0 (98.2) | 92.7 (97.8) |

TABLE XIII: Cross-dataset in both directions (sources: phase 3 D; phase 3b G).

| Direction | DistilBERT-Stacked Ensemble recall / FPR | DistilBERT-SVM recall / FPR | Structure-aware BERT-GNN recall / FPR | BERT-only (MLP) recall / FPR |
|---|---|---|---|---|
| Kaggle → HTTPParams | 99.97 / 0.15 | 99.97 / 0.12 | 99.97 / 0.27 | 99.98 / 0.42 |
| HTTPParams → Kaggle | 98.58 / 48.90 | 98.47 / 48.11 | 98.81 / 53.07 | 98.76 / 44.61 |
| HTTPParams → Kaggle, no overlap | 98.55 / 77.48 | 98.44 / 76.22 | 98.79 / 84.07 | 98.74 / 70.68 |

TABLE XIV: Graph-model analyses (sources: phase 3 E; 3d D, E, F, G, I, K).

| Analysis | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|
| Clean accuracy, edges original / none / random (%) | 99.65 ± 0.03 / 99.65 ± 0.04 / 99.60 ± 0.04 | - |
| Node removal 10%: mean change in P(malicious), 99 attack graphs | 0.0041 ± 0.0024 | - |
| Noise flips, sigma 0.5 absolute (%) | 0.73 ± 0.16 | 8.72 ± 0.71 |
| Noise flips, sigma 0.5 x feature spread (%) | 0.12 ± 0.01 | 0.30 ± 0.16 |
| White-box FGSM eps 0.05, accuracy (%) | 33.32 ± 2.89 | 10.79 ± 2.71 |
| White-box PGD eps 0.1, accuracy (%) | 0.73 ± 0.21 | 0.00 |
| ECE under URL encoding | 0.0288 ± 0.0093 | 0.1994 ± 0.0286 |
| sqlmap best-of-68 evasion, raw (%) | 51.00 ± 13.43 | 99.26 ± 1.22 |
| Optuna 8 / 40 trials, accuracy (%) | 99.65 ± 0.03 / 99.67 ± 0.06 | - |
