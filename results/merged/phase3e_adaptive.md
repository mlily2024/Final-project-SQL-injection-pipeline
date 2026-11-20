# Phase 3e: adaptive attacker against the defences; confidence intervals

100 attacks (the phase 3b section D sample: detected by all four raw models, seed 42). Mutation operators and budget as phase 3b (20 rounds x 8 mutants = 160 pipeline queries per attack). Seeds [42, 1, 7]. Evasion is counted among the attacks the pipeline detects before mutation; the defended pipeline (decode, retrained models, two-scale windows) is queried end to end, so the attacker adapts to it.

| Model | Raw: evaded (%) | Raw: median queries | Defended: not detected before mutation | Defended: evaded (%) | Defended: median queries |
|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 9.67 ± 0.58 | 69 ± 30 | 0.0 ± 0.0 | 1.00 ± 1.00 | 22 ± 20 |
| DistilBERT-SVM | 9.00 ± 0.00 | 85 ± 30 | 0.0 ± 0.0 | 1.33 ± 0.58 | 36 ± 28 |
| Structure-aware BERT-GNN | 9.67 ± 1.15 | 72 ± 37 | 0.0 ± 0.0 | 2.67 ± 0.58 | 31 ± 29 |
| BERT-only (MLP) | 8.67 ± 1.53 | 53 ± 12 | 0.0 ± 0.0 | 4.67 ± 3.79 | 24 ± 8 |

Examples that evade the defended pipeline (seed 42): original -> variant.

- DistilBERT-Stacked Ensemble: `union all select` -> `union all select and true`
- DistilBERT-Stacked Ensemble: `1 where 7055  =  7055` -> `1 /*!/*!where*/*/ 0x1b8f   like   7055`
- DistilBERT-SVM: `union all select` -> `union all select and true`
- DistilBERT-SVM: `1 where 7055  =  7055` -> `1 /*!/*!where*/*/ 0x1b8f   like   7055`
- Structure-aware BERT-GNN: `1'   )    )    as yqek where 1957  =  1957` -> `1'   )    )    as yqek where 0x7a5   like   1957`
- Structure-aware BERT-GNN: `union all select` -> `union all select and true`
- BERT-only (MLP): `1'   )    )    as yqek where 1957  =  1957` -> `1'   )    )    as yqek where (1957)   like   1957`
- BERT-only (MLP): `union all select` -> `union all select and true`

## Confidence intervals (95%, Wilson score; pooled over seeds where several)

| Result | Model | Rate (%) | 95% interval (%) | n |
|---|---|---|---|---|
| Mutation attack, raw | DistilBERT-Stacked Ensemble | 9.7 | 6.8–13.5 | 300 |
| Mutation attack, defended | DistilBERT-Stacked Ensemble | 1.0 | 0.3–2.9 | 300 |
| Mutation attack, raw | DistilBERT-SVM | 9.0 | 6.3–12.8 | 300 |
| Mutation attack, defended | DistilBERT-SVM | 1.3 | 0.5–3.4 | 300 |
| Mutation attack, raw | Structure-aware BERT-GNN | 9.7 | 6.8–13.5 | 300 |
| Mutation attack, defended | Structure-aware BERT-GNN | 2.7 | 1.4–5.2 | 300 |
| Mutation attack, raw | BERT-only (MLP) | 8.7 | 6.0–12.4 | 300 |
| Mutation attack, defended | BERT-only (MLP) | 4.7 | 2.8–7.7 | 300 |
| Attacks of 1-8 tokens detected, raw | DistilBERT-Stacked Ensemble | 86.4 | 76.1–92.7 | 66 |
| Attacks of 1-8 tokens detected, decoded | DistilBERT-Stacked Ensemble | 90.9 | 81.6–95.8 | 66 |
| Attacks of 1-8 tokens detected, raw | DistilBERT-SVM | 86.4 | 76.1–92.7 | 66 |
| Attacks of 1-8 tokens detected, decoded | DistilBERT-SVM | 87.9 | 77.9–93.7 | 66 |
| Attacks of 1-8 tokens detected, raw | Structure-aware BERT-GNN | 78.8 | 67.5–86.9 | 66 |
| Attacks of 1-8 tokens detected, decoded | Structure-aware BERT-GNN | 81.8 | 70.9–89.3 | 66 |
| Attacks of 1-8 tokens detected, raw | BERT-only (MLP) | 78.8 | 67.5–86.9 | 66 |
| Attacks of 1-8 tokens detected, decoded | BERT-only (MLP) | 81.8 | 70.9–89.3 | 66 |
| Unseen type 'time-based' detected | DistilBERT-Stacked Ensemble | 97.9 | 96.3–98.8 | 524 |
| Unseen type 'time-based' detected | DistilBERT-SVM | 98.3 | 96.8–99.1 | 524 |
| Unseen type 'time-based' detected | Structure-aware BERT-GNN | 96.9 | 95.1–98.1 | 524 |
| Unseen type 'time-based' detected | BERT-only (MLP) | 95.4 | 93.3–96.9 | 524 |
| Unseen type 'error-based' detected | DistilBERT-Stacked Ensemble | 100.0 | 98.9–100.0 | 350 |
| Unseen type 'error-based' detected | DistilBERT-SVM | 100.0 | 98.9–100.0 | 350 |
| Unseen type 'error-based' detected | Structure-aware BERT-GNN | 100.0 | 98.9–100.0 | 350 |
| Unseen type 'error-based' detected | BERT-only (MLP) | 100.0 | 98.9–100.0 | 350 |
| Unseen type 'union-based' detected | DistilBERT-Stacked Ensemble | 97.1 | 95.5–98.2 | 620 |
| Unseen type 'union-based' detected | DistilBERT-SVM | 97.7 | 96.2–98.7 | 620 |
| Unseen type 'union-based' detected | Structure-aware BERT-GNN | 85.5 | 82.5–88.0 | 620 |
| Unseen type 'union-based' detected | BERT-only (MLP) | 96.6 | 94.9–97.8 | 620 |
| Unseen type 'boolean / tautology' detected | DistilBERT-Stacked Ensemble | 100.0 | 99.7–100.0 | 1321 |
| Unseen type 'boolean / tautology' detected | DistilBERT-SVM | 100.0 | 99.7–100.0 | 1321 |
| Unseen type 'boolean / tautology' detected | Structure-aware BERT-GNN | 99.4 | 98.8–99.7 | 1321 |
| Unseen type 'boolean / tautology' detected | BERT-only (MLP) | 98.4 | 97.6–99.0 | 1321 |
| Unseen type 'other' detected | DistilBERT-Stacked Ensemble | 94.4 | 92.3–96.0 | 628 |
| Unseen type 'other' detected | DistilBERT-SVM | 94.1 | 92.0–95.7 | 628 |
| Unseen type 'other' detected | Structure-aware BERT-GNN | 93.0 | 90.7–94.7 | 628 |
| Unseen type 'other' detected | BERT-only (MLP) | 92.7 | 90.4–94.5 | 628 |

Rows for decoded detection and unseen types are computed from the phase 3c results (mean over seeds times n, rounded); mutation rows pool the seeds of this phase.

Reproduce: `python merged_phase3e_adaptive.py` (after phases 3b and 3c).