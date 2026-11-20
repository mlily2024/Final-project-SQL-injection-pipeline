# SQL Injection Detection — Hybrid ML Pipelines

**Source code for the MSc dissertation:** *Enhancing Web Application Firewall with Machine Learning for SQL Injection Detection*

| | |
|---|---|
| **Author** | Lilliane Linnet Musoke |
| **Institution** | University of Reading, Department of Computer Science |
| **Programme** | MSc Data Science and Advanced Computing |
| **Supervisor** | Professor Atta Badii |
| **Submitted** | 17 September 2024 |

---

## Merged paper (2026): common evaluation of both pipelines

*SQL Injection Detection with Transformer Encoders for Web Application Firewalls: A Common Evaluation of Stacked-Ensemble and Graph Neural Network Pipelines, with Defences against Evasion*, L. L. Musoke, A. Badii and A. Ashlam (under review). It combines and extends arXiv:2608.28889 (DistilBERT-Stacked Ensemble) and arXiv:2608.28882 (BERT-GNN). All files of this work start with `merged_` or sit in `results/merged/`.

### Main results

Test set of 9,276 queries (5,830 benign, 3,446 malicious), 70/30 split, five seeds (mean ± standard deviation where it is not zero). Full tables: `results/merged/paper_tables.md`.

| Model | Accuracy (%) | F1, malicious (%) | False-positive rate (%) |
|---|---|---|---|
| DistilBERT-Stacked Ensemble | 99.84 | 99.78 | 0.103 |
| DistilBERT-SVM | 99.85 | 99.80 | 0.086 |
| Structure-aware BERT-GNN | 99.64 ± 0.02 | 99.52 ± 0.03 | 0.278 ± 0.095 |
| BERT-only (MLP) | 99.74 ± 0.04 | 99.65 ± 0.05 | 0.127 ± 0.020 |

Beyond clean accuracy: obfuscation applied to harmless queries raises false alarms by up to about 60%; benign padding reduces detection to as low as 0 to 10%; decode-first canonicalisation with retraining resolves 81 of 92 obfuscations (68 of them sqlmap tamper scripts) at an F1 change of 0.03 points or less; and the defended pipeline reduces a score-guided adaptive attacker from 8.7 to 9.7% evasion to 1.0 to 4.7%.

### Files

| File | Purpose |
|---|---|
| `merged_phase2_distilbert_7030.py`, `merged_phase2_colab.ipynb` | DistilBERT-Stacked Ensemble on the 70/30 split (GPU) |
| `merged_phase3_common_robustness.py`, `merged_phase3_colab.ipynb` | Common protocol for the four models, five seeds (GPU) |
| `merged_phase3b_extended.py` | Extended evaluation: threshold-free metrics, 92 obfuscations on both classes, mutation attack, attack types, reverse cross-dataset, de-duplication, learning curve, length and padding, timing |
| `merged_phase3c_defences.py` | Decode-first and two-scale window defences; leave-one-attack-type-out |
| `merged_phase3d_original_tests.py` | Every test of the two arXiv papers repeated on the common protocol |
| `merged_phase3e_adaptive.py` | Adaptive attacker against the defended pipeline; Wilson intervals |
| `export_test_sets.py` | Writes the split and evaluation samples to `results/merged/test_sets/` |
| `evaluate_released_models.py` | Recomputes the clean results from the released trained models (no training) |
| `paper_tables.py` | Regenerates every table of the paper from `results/merged/` |
| `requirements-merged.txt` | Exact library versions of the CPU runs |

### Reproducing the merged results

Three levels, from quickest to complete.

1. **Check the numbers.** Every result is in `results/merged/` (`phase*.md` reports, `phase*.json` data). `python paper_tables.py` regenerates all tables of the paper into `results/merged/paper_tables.md`. The exact test split and evaluation samples are in `results/merged/test_sets/` (row numbers of `SQL_Injection_Dataset.csv`).

2. **Re-evaluate the trained models (about 30 to 60 minutes on a CPU, no training).** Download the model files from the GitHub Release of this paper, check them against `results/merged/model_checksums.sha256`, and run:

   ```bash
   pip install -r requirements-merged.txt
   python evaluate_released_models.py <folder with main_models_seed*.pkl>
   ```

   The files are Python pickles: load only files whose checksums match, with the library versions in `requirements-merged.txt`.

3. **Retrain everything.** The GPU phases run in Google Colab from `merged_phase2_colab.ipynb` and `merged_phase3_colab.ipynb`. The CPU phases need sqlmap 1.9.9 for the tamper scripts and run in this order, each reusing the caches of the previous one (`.merged_work/`, not tracked):

   ```bash
   git clone --branch 1.9.9 https://github.com/sqlmapproject/sqlmap ../sqlmap
   PLAN=cpu WORK_DIR=.merged_work/phase3b SQLMAP_DIR=../sqlmap python merged_phase3b_extended.py
   P3B_WORK=.merged_work/phase3b WORK_DIR=.merged_work/phase3c SQLMAP_DIR=../sqlmap python merged_phase3c_defences.py
   P3B_WORK=.merged_work/phase3b WORK_DIR=.merged_work/phase3d SQLMAP_DIR=../sqlmap python merged_phase3d_original_tests.py
   P3B_WORK=.merged_work/phase3b P3C_WORK=.merged_work/phase3c WORK_DIR=.merged_work/phase3e SQLMAP_DIR=../sqlmap python merged_phase3e_adaptive.py
   ```

   On the platform of the paper (Intel Core i5-1335U, 8 GB, no GPU) phase 3b takes about half a day and each later phase several hours. Every phase is resumable: run the same command again to continue after an interruption. `SMOKE=1` runs a small end-to-end check of any phase.

**Expected precision.** Retraining on other hardware or library versions changes results slightly: between the GPU and CPU runs of this work, the ensemble and SVM reached the same accuracy in every seed and the graph and BERT-only models differed by at most 0.10 accuracy points per seed (0.03 or less on the five-seed mean). Conclusions are unaffected at that scale.

### Data

`SQL_Injection_Dataset.csv` is the Kaggle *SQL Injection Dataset* by Sajid576 (https://www.kaggle.com/datasets/sajid576/sql-injection-dataset; licence stated as unknown on Kaggle). `httpparams_sqli.csv` is derived from *HttpParamsDataset* by Morzeux (https://github.com/Morzeux/HttpParamsDataset, MIT licence).

### Corrections to the earlier versions

Repeating every published test under the common protocol confirmed most results and corrected three claims: the ensemble is not faster than the SVM end to end (it contains the SVM); the ensemble is not more robust to query-level evasion than the SVM; and the BERT-only model is not more robust to white-box gradient attacks than the BERT-GNN (the earlier result came from saturated gradients). Details: `results/merged/phase3d_original_tests.md`.

---

## What this repository contains

Two novel Hybrid Machine-Learning pipelines, each implemented as a self-contained Jupyter notebook, for detecting SQL Injection (SQLi) attacks in web application traffic:

1. **`DistilBERT_Stacked_Ensemble_pipeline.ipynb`** — a DistilBERT-Stacked Ensemble (Meta-Learner) pipeline. Uses DistilBERT contextual embeddings as input to a stack of conventional ML and ensemble classifiers (Logistic Regression, XGBoost, SVM), combined under a neural-network meta-learner. Adversarial training is performed with the Fast Gradient Sign Method (FGSM); hyperparameters are tuned with Optuna.
2. **`BERT_GNN_pipeline_FINAL.ipynb`** — a BERT–Graph-Neural-Network hybrid pipeline. BERT generates contextual embeddings of SQL queries; a GNN models the graph-structured query representation to capture structural patterns. Hyperparameters tuned with Optuna.

Plus the dataset used to train and evaluate both pipelines:

3. **`SQL_Injection_Dataset.csv`** — labelled SQL queries (benign vs malicious).

## Headline results (from the dissertation)

| Pipeline | Accuracy | Adversarial accuracy (FGSM) | Notes |
|---|---|---|---|
| **DistilBERT-Stacked Ensemble** | **99.81%** | **99.77%** | Selected recommended approach; fast execution time |
| **BERT-GNN** | **99.48%** (99.67% held-out) | — | Superior structural understanding; longer execution time (23.13 s); held-out-validation retrain reaches 99.67%, see [`RESULTS.md`](RESULTS.md) |
| Best conventional baseline (Random Forest) | 99.47% | — | Benchmarked in the same study |

All four performance metrics (accuracy, precision, recall, F1-score) hit the same headline figure for both Hybrid pipelines. Full per-model tables, confusion matrices, ROC curves, learning curves and sensitivity analyses are in the notebooks and in the dissertation.

The DistilBERT-Stacked Ensemble adversarial accuracy of **99.77%** exceeds the comparable adversarial-testing result reported by Guan et al. (2023, *Future Internet* 15(4):133, DOI 10.3390/fi15040133) by **2.38%** — see the dissertation §4.4 for the full comparison.

## How to view the work

- **Notebooks** — the two `.ipynb` files in the repo root contain the full pipeline code (data loading, preprocessing, embedding, training, evaluation, adversarial robustness, sensitivity analysis). Outputs are stripped so the notebooks render fast and small on GitHub; running either notebook top-to-bottom regenerates every figure.
- **Results gallery** — [`RESULTS.md`](RESULTS.md) shows all the figures (confusion matrices, ROC curves, learning curves, sensitivity-analysis plots, per-model comparison) as a viewable gallery without needing to run anything.
- **All figures** — individual PNG exports of every result figure are in the `results/` folder, named by pipeline and section.

## How to run the notebooks locally

Tested under Python 3.10+ with a Jupyter environment. To install all dependencies:

```bash
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
.venv\Scripts\activate             # Windows
pip install -r requirements.txt
```

Then open either notebook in JupyterLab or VS Code and run cells top-to-bottom. Each pipeline is end-to-end self-contained: data loading and preprocessing → embedding extraction → model training → evaluation → adversarial-robustness check → sensitivity analysis. A GPU is recommended for the BERT-GNN training step but not required for inference or for the DistilBERT-Stacked Ensemble.

**Resource requirement.** The DistilBERT (and BERT) embedding-extraction step holds the language model and its full-dataset embeddings in memory simultaneously. End-to-end execution needs approximately **6–8 GB of free RAM** for the DistilBERT-Stacked Ensemble pipeline and **8–12 GB** for BERT-GNN. The notebooks were originally developed on Google Colab (which provides 12–16 GB and a free GPU). If running locally on a machine with 8 GB total RAM, close other applications first or run in Colab via the badge links at the top of each notebook.

## Reproducing the revision results

The scripts in the repository root regenerate the extended analysis reported in the revised BERT-GNN paper (ablation, corrected held-out evaluation, structure-aware graph, obfuscation robustness, the seven-test robustness suite, full metrics, and cross-model execution time). They read the committed `SQL_Injection_Dataset.csv`, write their outputs to `results/`, and cache intermediate artifacts (BERT embeddings, graphs, trained models) under `.structure_work/` and `.corrected_work/`. Those cache directories are intentionally not tracked; each script rebuilds them from the dataset and is resumable, so a run interrupted on a CPU-only machine can simply be started again and will continue.

The scripts form a producer→consumer chain through those caches, so run them in this order (each step only needs the dataset plus the caches written by earlier steps):

```bash
pip install -r requirements.txt

python structure_graph_gnn.py        # structure graphs + best.json (Optuna) + structure-GNN result
python corrected_bertgnn_retrain.py  # held-out-validation retrain (chain graph) -> corrected result
python extract_train_cls.py          # train-split BERT [CLS] embeddings (train_cls.npy)
python bert_only_ablation.py         # BERT-only heads on the identical test set
python obfuscation_robustness.py     # trains + caches gnn_model.pt / mlp_model.pkl; evasion recall
python robustness_1_sensitivity.py   # seven-test robustness suite, one script each
python robustness_2_adversarial.py
python robustness_3_obfuscation_extended.py
python robustness_4_adaptive.py
python robustness_5_crossdataset.py
python robustness_6_significance.py
python robustness_7_calibration.py
python metrics_summary.py            # full per-class metric tables
python complexity_breakdown.py       # accuracy by query complexity (Table 4)
python make_result_figures.py        # confusion matrices + comparison charts
python model_execution_times.py      # training + inference time across all models
```

All scripts resolve their paths relative to the repository, use a fixed seed (`random_state=42`), and require no arguments. Running on CPU is fully supported (a GPU only speeds up the embedding and GNN-training steps).

**Expected precision of reproduction.** Numbers reproduce to roughly ±0.1–0.2 percentage points rather than bit-for-bit. Minor variation comes from CPU versus GPU execution, PyTorch non-determinism, and the early-stopping epoch differing by one or two between runs. The reported conclusions (the graph adds no clean-accuracy gain but improves robustness to URL-encoding evasion, and the associated statistical tests) are stable well within that margin.

## Acknowledgements

Supervisor: Professor Atta Badii (University of Reading). Acknowledgement also to PhD candidate Ahmed Ashlam for advice during the project's execution. Both acknowledged in the dissertation.

## Citation

If you reference this work:

> Musoke, L. L. (2024). *Enhancing Web Application Firewall with Machine Learning for SQL Injection Detection.* MSc dissertation, University of Reading.

## Licence

Released under the [MIT Licence](LICENSE).

## Companion repository

This GitHub repository mirrors the original submission at the University of Reading's institutional Gitlab: `https://csgitlab.reading.ac.uk/qz820024/sql-injection-pipeline-project`.

---

*Original work declaration (from the dissertation):* "I, Lilliane Linnet Musoke, from the University of Reading's Department of Computer Science, attest that this is my original work, except for those instances where I have explicitly acknowledged the contributions of other authors."
