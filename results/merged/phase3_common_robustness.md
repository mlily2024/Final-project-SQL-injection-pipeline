# Phase 3: common robustness protocol

Same 70/30 split for every model (test set 9276 queries: 5830 benign, 3446 malicious). Five seeds [42, 1, 7, 13, 123]; values are mean ± standard deviation over seeds unless marked seed 42. Hyperparameters fixed across seeds (phase 2 for the DistilBERT models; GNN {'hid': 100, 'drop': 0.3099025726528951, 'lr': 0.00019762189340280086, 'bs': 60}).

## A. Clean test set

| Model | Accuracy (%) | Mal. precision | Mal. recall | Mal. F1 | FPR (%) | MCC | FP / FN (seed 42) |
|---|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 99.84 ± 0.00 | 99.82 ± 0.01 | 99.74 ± 0.01 | 99.78 ± 0.00 | 0.106 ± 0.008 | 0.9965 ± 0.0000 | 6 / 9 |
| DistilBERT-SVM | 99.85 ± 0.00 | 99.85 ± 0.00 | 99.74 ± 0.00 | 99.80 ± 0.00 | 0.086 ± 0.000 | 0.9968 ± 0.0000 | 5 / 9 |
| Structure-aware BERT-GNN | 99.63 ± 0.05 | 99.53 ± 0.10 | 99.48 ± 0.13 | 99.51 ± 0.06 | 0.278 ± 0.061 | 0.9922 ± 0.0010 | 20 / 17 |
| BERT-only (MLP) | 99.71 ± 0.03 | 99.68 ± 0.22 | 99.55 ± 0.19 | 99.61 ± 0.04 | 0.189 ± 0.129 | 0.9939 ± 0.0007 | 7 / 22 |

McNemar exact test (seed 42), pairs of models: b = only the first correct, c = only the second correct.

| Pair | b | c | p |
|---|---|---|---|
| DistilBERT-Stacked Ensemble vs DistilBERT-SVM | 1 | 2 | 1 |
| DistilBERT-Stacked Ensemble vs Structure-aware BERT-GNN | 25 | 3 | 2.74e-05 |
| DistilBERT-Stacked Ensemble vs BERT-only (MLP) | 17 | 3 | 0.00258 |
| DistilBERT-SVM vs Structure-aware BERT-GNN | 27 | 4 | 3.4e-05 |
| DistilBERT-SVM vs BERT-only (MLP) | 18 | 3 | 0.00149 |
| Structure-aware BERT-GNN vs BERT-only (MLP) | 12 | 20 | 0.215 |

## B. Query-level evasion: detection rate (%) of the 3446 malicious test queries after each transform

| Transform | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|
| (clean) | 99.74 ± 0.01 | 99.74 ± 0.00 | 99.48 ± 0.13 | 99.55 ± 0.19 |
| url_encode | 99.37 ± 0.06 | 99.59 ± 0.00 | 93.62 ± 1.63 | 88.93 ± 5.18 |
| double_url_encode | 99.59 ± 0.02 | 99.61 ± 0.03 | 99.72 ± 0.07 | 99.66 ± 0.21 |
| inline_comment | 98.91 ± 0.07 | 99.63 ± 0.01 | 99.70 ± 0.09 | 99.72 ± 0.15 |
| keyword_split | 99.69 ± 0.02 | 99.71 ± 0.00 | 99.43 ± 0.13 | 99.63 ± 0.16 |
| mysql_versioned_comment | 99.80 ± 0.01 | 99.80 ± 0.00 | 99.67 ± 0.09 | 99.73 ± 0.14 |
| case_random | 99.74 ± 0.01 | 99.74 ± 0.00 | 99.48 ± 0.13 | 99.55 ± 0.19 |
| tab_whitespace | 99.74 ± 0.01 | 99.74 ± 0.00 | 99.48 ± 0.13 | 99.55 ± 0.19 |
| mixed_whitespace | 99.76 ± 0.02 | 99.74 ± 0.00 | 99.48 ± 0.09 | 99.66 ± 0.18 |
| url_encode+case_random | 99.37 ± 0.06 | 99.59 ± 0.00 | 93.62 ± 1.63 | 88.93 ± 5.18 |

## C. Adaptive best-of-9 evasion rate (%): an attack counts as evaded if ANY transform makes the model call it benign (lower is better)

| Model | Evasion rate (%) |
|---|---|
| DistilBERT-Stacked Ensemble | 1.68 ± 0.12 |
| DistilBERT-SVM | 0.71 ± 0.04 |
| Structure-aware BERT-GNN | 6.70 ± 1.66 |
| BERT-only (MLP) | 11.30 ± 5.21 |

## D. Cross-dataset: trained on Kaggle only, tested on HTTPParams (30156 queries, 10852 SQLi) and the curated OOD set (35 attacks, 34 benign)

| Model | HTTPParams accuracy | HTTPParams detection | HTTPParams FPR (%) | HTTPParams MCC | OOD detection | OOD FPR (%) |
|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 99.90 ± 0.00 | 99.97 ± 0.00 | 0.15 ± 0.01 | 0.998 ± 0.000 | 100.0 ± 0.0 | 2.9 ± 0.0 |
| DistilBERT-SVM | 99.91 ± 0.00 | 99.97 ± 0.00 | 0.12 ± 0.00 | 0.998 ± 0.000 | 100.0 ± 0.0 | 3.5 ± 1.3 |
| Structure-aware BERT-GNN | 99.82 ± 0.05 | 99.97 ± 0.00 | 0.27 ± 0.08 | 0.996 ± 0.001 | 100.0 ± 0.0 | 8.8 ± 2.9 |
| BERT-only (MLP) | 99.73 ± 0.27 | 99.98 ± 0.01 | 0.42 ± 0.42 | 0.994 ± 0.006 | 100.0 ± 0.0 | 10.0 ± 7.9 |

## E. Input-noise stability: % of test predictions that change when Gaussian noise (sigma × per-dimension training std of each model's own input features) is added (lower is better)

| Model | sigma 0.1 | sigma 0.25 | sigma 0.5 |
|---|---|---|---|
| DistilBERT-Stacked Ensemble | 0.02 ± 0.01 | 0.05 ± 0.02 | 0.17 ± 0.01 |
| DistilBERT-SVM | 0.01 ± 0.00 | 0.03 ± 0.00 | 0.11 ± 0.00 |
| Structure-aware BERT-GNN | 0.02 ± 0.00 | 0.05 ± 0.02 | 0.12 ± 0.01 |
| BERT-only (MLP) | 0.05 ± 0.04 | 0.13 ± 0.09 | 0.30 ± 0.16 |

## Notes

- Seed variation: SVM (Platt scaling), XGBoost, meta-learner, GNN initialisation and batch order, MLP. Logistic Regression is deterministic and shared across seeds.
- The GNN graphs give a query with no sqlparse token a single [CLS] node (as robustness_common.py).
- Transformed queries are not re-lower-cased; both tokenisers are uncased.
- case_random uses a CRC32 seed per query (the earlier scripts used Python hash(), which varies per run).
- The DistilBERT-SVM is also a base model of the ensemble, so their errors are correlated.
- GNN epochs to early stop per seed: [9, 9, 9, 8, 14].

Reproduce: `python merged_phase3_common_robustness.py` (set WORK_DIR for resumable caches).