# Phase 3d: tests of the arXiv papers repeated on the merged protocol

Same 70/30 split as phases 2 to 3c (test set 9276 queries, 3446 malicious). Malicious-class precision, recall and F1 as in phase 3; weighted (both-class) values as in the published tables are given where the papers used them. Times are wall-clock on this machine (CPU).

## A. DistilBERT base classifiers (notebook grids, GridSearchCV 5-fold, accuracy)

| Model | Accuracy | Precision (mal.) | Recall (mal.) | F1 (mal.) | F1 (weighted) | FPR (%) | Train (s) | Test exec (s) |
|---|---|---|---|---|---|---|---|---|
| DistilBERT-Random Forest | 99.49 | 99.94 | 98.69 | 99.31 | 99.49 | 0.034 | 437.4 | 0.4569 |
| DistilBERT-Decision Tree | 98.11 | 98.29 | 96.60 | 97.44 | 98.11 | 0.995 | 252.5 | 0.1844 |
| DistilBERT-Naive Bayes | 90.46 | 85.62 | 89.32 | 87.43 | 90.50 | 8.868 | 0.2 | 0.0977 |
| DistilBERT-Logistic Regression | 99.78 | 99.62 | 99.80 | 99.71 | 99.78 | 0.223 | 12.2 | 0.0315 |
| DistilBERT-SVM | 99.84 | 99.85 | 99.71 | 99.78 | 99.84 | 0.086 | 938.0 | 1.5248 |
| DistilBERT-Gradient Boosting | 99.66 | 99.80 | 99.27 | 99.53 | 99.65 | 0.120 | 5452.4 | 0.2872 |
| DistilBERT-XGBoost | 99.72 | 99.80 | 99.45 | 99.62 | 99.72 | 0.120 | 122.3 | 0.0475 |

Best grid values: Random Forest {'n_estimators': 200}; Decision Tree {'max_depth': 10}; Logistic Regression {'C': 10}; SVM {'C': 10, 'kernel': 'rbf'}; Gradient Boosting {'n_estimators': 200}; XGBoost {'n_estimators': 200}.

## B. TF-IDF baselines

Published protocol: the notebook preprocessing (lower case, symbol filter keeping ; ' " =, English stop words removed except SQL keywords, WordNet lemmatisation), TF-IDF (5,000 features), SMOTE, default classifiers. Controlled protocol: the same TF-IDF features, no SMOTE, class weights and the section A grids (Naive Bayes: multinomial, untuned).

### As published

| Model | Accuracy | Precision (mal.) | Recall (mal.) | F1 (mal.) | F1 (weighted) | FPR (%) | Train (s) | Test exec (s) |
|---|---|---|---|---|---|---|---|---|
| TF-IDF Decision Tree | 98.92 | 98.92 | 98.17 | 98.54 | 98.92 | 0.635 | 0.3 | 0.0079 |
| TF-IDF Logistic Regression | 98.76 | 98.88 | 97.77 | 98.32 | 98.76 | 0.652 | 0.1 | 0.0008 |
| TF-IDF SVM | 99.09 | 99.33 | 98.23 | 98.77 | 99.09 | 0.395 | 6.8 | 1.0171 |
| TF-IDF Naive Bayes | 98.28 | 97.76 | 97.59 | 97.68 | 98.27 | 1.321 | 0.0 | 0.0009 |
| TF-IDF Random Forest | 99.51 | 99.88 | 98.81 | 99.34 | 99.51 | 0.069 | 3.7 | 0.7732 |
| TF-IDF Gradient Boosting | 98.11 | 99.25 | 95.65 | 97.41 | 98.11 | 0.429 | 4.4 | 0.0107 |
| TF-IDF XGBoost | 99.42 | 99.79 | 98.64 | 99.21 | 99.42 | 0.120 | 1.4 | 0.0186 |

### Controlled

| Model | Accuracy | Precision (mal.) | Recall (mal.) | F1 (mal.) | F1 (weighted) | FPR (%) | Train (s) | Test exec (s) |
|---|---|---|---|---|---|---|---|---|
| TF-IDF Random Forest | 99.51 | 99.91 | 98.78 | 99.34 | 99.51 | 0.051 | 60.2 | 0.4928 |
| TF-IDF Decision Tree | 99.14 | 99.04 | 98.64 | 98.84 | 99.14 | 0.566 | 1.8 | 0.0066 |
| TF-IDF Logistic Regression | 99.08 | 99.24 | 98.29 | 98.76 | 99.08 | 0.446 | 0.5 | 0.0006 |
| TF-IDF SVM | 99.09 | 98.87 | 98.69 | 98.78 | 99.09 | 0.669 | 601.2 | 2.6286 |
| TF-IDF Gradient Boosting | 99.07 | 99.59 | 97.91 | 98.74 | 99.07 | 0.240 | 72.8 | 0.0219 |
| TF-IDF XGBoost | 99.41 | 99.79 | 98.61 | 99.20 | 99.41 | 0.120 | 14.4 | 0.0191 |
| TF-IDF Naive Bayes | 96.38 | 97.93 | 92.19 | 94.98 | 96.35 | 1.149 | 0.0 | 0.0012 |

## C. Stacked ensemble: before Optuna, FGSM, meta-feature sensitivity

Before Optuna (notebook defaults, seed 42 meta-features): accuracy 99.81%, F1 (mal.) 99.74%; optimised ensemble (phase 3b, seeds [42, 1, 7, 13, 123]): 99.84 ± 0.00%.

FGSM on the six meta-features (accuracy %, untargeted, L-inf):

| Model | eps 0.05 | eps 0.1 | eps 0.2 |
|---|---|---|---|
| Optimised ensemble (FGSM-trained) | 99.81 ± 0.01 | 99.79 ± 0.01 | 99.72 ± 0.01 |
| Before Optuna (no FGSM training) | 99.76 | 99.69 | 62.85 |

Meta-feature sensitivity (share of test predictions that change when one feature is set to 0; features 0-1 LR, 2-3 XGBoost, 4-5 SVM):

| Model | f0 | f1 | f2 | f3 | f4 | f5 | Mean |
|---|---|---|---|---|---|---|---|
| Optimised ensemble | 0.0005 ± 0.0001 | 0.0001 ± 0.0000 | 0.0005 ± 0.0001 | 0.0002 ± 0.0000 | 0.0011 ± 0.0002 | 0.0003 ± 0.0000 | 0.0005 ± 0.0000 |
| Before Optuna | 0.0002 | 0.0000 | 0.0003 | 0.0001 | 0.0004 | 0.3704 | 0.0619 |

## D. GNN node-removal sensitivity

Mean absolute change in P(malicious) when 10% of the nodes are removed at random, on 99 attack graphs (sample seed 0): 0.0041 ± 0.0024 (seeds [42, 1, 7]). Published value 0.0037.

| Nodes removed | 5% | 10% | 20% | 30% |
|---|---|---|---|---|
| Test predictions that flip (%) | 0.01 ± 0.02 | 0.05 ± 0.03 | 0.09 ± 0.07 | 0.14 ± 0.03 |

## E. Edge ablation (GNN retrained, phase 3b hyperparameters)

| Edges | Accuracy (%) | F1 (mal., %) | FPR (%) |
|---|---|---|---|
| original | 99.65 ± 0.03 | 99.53 ± 0.04 | 0.22 ± 0.05 |
| none | 99.65 ± 0.04 | 99.53 ± 0.06 | 0.29 ± 0.04 |
| random | 99.60 ± 0.04 | 99.47 ± 0.05 | 0.31 ± 0.05 |

## F. White-box gradient attacks on the input features (accuracy %, untargeted, L-inf)

Margin loss (score of the true class minus the other class), so that confidently classified queries still receive a gradient. With a cross-entropy loss the BERT-only model gave exactly zero gradient on about a third of the test queries (saturated scores), which made it look robust (gradient masking).

| Model | FGSM eps 0.01 | FGSM eps 0.05 | FGSM eps 0.1 | FGSM eps 0.2 | PGD eps 0.1 (10 steps) |
|---|---|---|---|---|---|
| Structure-aware BERT-GNN | 98.81 ± 0.09 | 33.32 ± 2.89 | 1.97 ± 0.30 | 0.00 ± 0.00 | 0.73 ± 0.21 |
| BERT-only (MLP) | 98.63 ± 0.24 | 10.79 ± 2.71 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

## G. Feature noise with absolute sigma (as the BERT-GNN paper): % of test predictions that change

Gaussian noise of fixed standard deviation added to each model's own input features (DistilBERT [CLS] for the ensemble and SVM, BERT token features for the GNN, BERT [CLS] for BERT-only). Mean per-dimension standard deviation of each input: DistilBERT [CLS] 0.140, BERT [CLS] 0.231, GNN node features 0.400. Phase 3 section E scaled sigma by each feature's own standard deviation instead.

| Model | sigma 0.25 | sigma 0.5 | sigma 1.0 | sigma 2.0 |
|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 2.99 ± 0.02 | 14.79 ± 0.26 | 30.37 ± 0.23 | 35.87 ± 0.10 |
| DistilBERT-SVM | 3.53 ± 0.06 | 28.37 ± 0.13 | 37.11 ± 0.00 | 37.11 ± 0.00 |
| Structure-aware BERT-GNN | 0.19 ± 0.05 | 0.73 ± 0.16 | 3.41 ± 0.32 | 13.46 ± 0.37 |
| BERT-only (MLP) | 1.67 ± 0.24 | 8.72 ± 0.71 | 23.03 ± 0.41 | 34.60 ± 0.34 |

## H. BERT-only heads

| Model | Accuracy (%) | Precision (mal.) | Recall (mal.) | F1 (mal.) |
|---|---|---|---|---|
| BERT [CLS] + Logistic Regression | 99.66 | 99.80 | 99.27 | 99.53 |
| BERT [CLS] + MLP | 99.74 ± 0.04 | 99.78 ± 0.03 | 99.51 ± 0.12 | 99.65 ± 0.05 |
| Structure-aware BERT-GNN | 99.64 ± 0.02 | 99.53 ± 0.16 | 99.51 ± 0.15 | 99.52 ± 0.03 |

## I. Calibration under URL-encoding evasion (expected calibration error, 15 bins; lower is better)

| Model | Clean test set | URL-encoded (phase 3b sample, both classes) |
|---|---|---|
| DistilBERT-Stacked Ensemble | 0.0009 ± 0.0001 | 0.0880 ± 0.0053 |
| DistilBERT-SVM | 0.0014 ± 0.0001 | 0.1408 ± 0.0015 |
| Structure-aware BERT-GNN | 0.0023 ± 0.0001 | 0.0288 ± 0.0093 |
| BERT-only (MLP) | 0.0024 ± 0.0003 | 0.1994 ± 0.0286 |

## J. Loss curves

GNN: 10 epochs to early stopping (patience 5); final training loss 0.0015, best validation loss 0.0086. Meta-learner: 92 epochs on 80% of the out-of-fold meta-features, validation on 20%; final training loss 0.0137, validation 0.0075. Figure: `phase3d_loss_curves.png`.

## K. GNN hyperparameters: 40 Optuna trials (as published) against the 8 used in phases 3 to 3c

40-trial best (validation weighted F1 0.9985): {'hid': 116, 'drop': 0.4802857225639665, 'lr': 0.001570297088405539, 'bs': 90}. 8-trial: {'hid': 100, 'drop': 0.3099025726528951, 'lr': 0.00019762189340280086, 'bs': 60}.

| Search | Accuracy (%) | F1 (mal., %) | FPR (%) |
|---|---|---|---|
| 8 trials (phases 3 to 3c) | 99.65 ± 0.03 | 99.53 ± 0.04 | 0.22 ± 0.05 |
| 40 trials | 99.67 ± 0.06 | 99.56 ± 0.08 | 0.19 ± 0.05 |

## Notes

- Section A trains every classifier with its notebook grid on this machine; training and execution times are therefore CPU times and are not comparable with the published Colab times.
- The TF-IDF features are fitted on the 70/30 training split only.
- Section C uses the seed 42 out-of-fold meta-features for the pre-Optuna model and the loss curve.
- Seeds: [42, 1, 7, 13, 123] where phase 3b models are only evaluated; [42, 1, 7] where models are retrained or attacked.

Reproduce: `python merged_phase3d_original_tests.py` (after phase 3b; P3B_WORK, WORK_DIR).