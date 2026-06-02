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

## What this repository contains

Two Hybrid Machine-Learning pipelines, each implemented as a self-contained Jupyter notebook, for detecting SQL Injection (SQLi) attacks in web application traffic:

1. **`DistilBERT_Stacked_Ensemble_pipeline.ipynb`** — a DistilBERT-Stacked Ensemble (Meta-Learner) pipeline. Uses DistilBERT contextual embeddings as input to a stack of conventional ML and ensemble classifiers (Logistic Regression, XGBoost, SVM), combined under a neural-network meta-learner. Adversarial training is performed with the Fast Gradient Sign Method (FGSM); hyperparameters are tuned with Optuna.
2. **`BERT_GNN_pipeline_FINAL.ipynb`** — a BERT–Graph-Neural-Network hybrid pipeline. BERT generates contextual embeddings of SQL queries; a GNN models the graph-structured query representation to capture structural patterns. Hyperparameters tuned with Optuna.

Plus the dataset used to train and evaluate both pipelines:

3. **`SQL_Injection_Dataset.csv`** — labelled SQL queries (benign vs malicious).

## Headline results (from the dissertation)

| Pipeline | Accuracy | Adversarial accuracy (FGSM) | Notes |
|---|---|---|---|
| **DistilBERT-Stacked Ensemble** | **99.81%** | **99.77%** | Selected recommended approach; fast execution time |
| **BERT-GNN** | **99.48%** | — | Superior structural understanding; longer execution time (23.13 s) |
| Best conventional baseline (Random Forest) | 94.47% | — | Benchmarked in the same study |

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
