# Phase 2: DistilBERT-Stacked Ensemble on the 70/30 split

Same split as the BERT-GNN scripts (`test_size=0.30, random_state=42`): 21643 training and 9276 test queries (5830 benign, 3446 malicious). Device: cuda.

| Model | Accuracy | Mal. precision | Mal. recall | Mal. F1 | FPR (%) | MCC | FP/FN | Train (s) | Test exec (s) |
|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 99.77 | 99.65 | 99.74 | 99.70 | 0.206 | 0.9952 | 12/9 | 20.4 | 0.0241 |
| SVM | 99.84 | 99.85 | 99.71 | 99.78 | 0.086 | 0.9965 | 5/10 | 1836.8 | 3.1982 |
| XGBoost | 99.70 | 99.80 | 99.39 | 99.59 | 0.120 | 0.9935 | 7/21 | 245.5 | 0.0408 |
| DistilBERT-Stacked Ensemble | 99.84 | 99.83 | 99.74 | 99.78 | 0.103 | 0.9965 | 6/9 | 0.4 | 0.0003 |

- Ensemble under single-step FGSM on the meta-features (epsilon 0.100): **99.80%**.
- Ensemble test-set time: meta-learner 0.0003 s; with the three base-model probability calls 3.7663 s.
- Shared DistilBERT embedding: 3.22 ms per query (batch 64), common to every model above.
- McNemar exact test, SVM against ensemble: 2 queries only SVM got right, 2 only the ensemble got right, p = 1.
- Meta-learner (Optuna, 100 trials, 5-fold CV on training meta-features): {"hidden_dim": 195, "dropout_rate": 0.4828, "lr": 0.0063, "epochs": 92, "epsilon": 0.1004}.
- Base-model grids as in the notebook; best: Logistic Regression {'C': 1}; XGBoost {'n_estimators': 100}; SVM {'C': 10, 'kernel': 'rbf'}.

Earlier result (80/20 split, notebook): ensemble 99.81%, SVM 99.82%, LR 99.76%, XGBoost 99.74%, FGSM 99.77%.
Reproduce: `python merged_phase2_distilbert_7030.py`.
