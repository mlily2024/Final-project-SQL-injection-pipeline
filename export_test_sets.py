"""Write the exact data splits and evaluation samples of the merged paper as CSV files.

Rows are identified by their 0-based position in SQL_Injection_Dataset.csv. The samples are drawn
with the same random states as merged_phase3b_extended.py and merged_phase3c_defences.py; the
mutation-attack sample also needs the phase 3b seed-42 test probabilities (P3B_WORK cache).

Outputs (results/merged/test_sets/):
  split.csv              row, label, set (train / test), gnn_role (train / validation / -)
  obfuscation_sample.csv rows of the 1,000 + 1,000 disguise sample (phase 3b B, C; phase 3c B, C)
  padding_sample.csv     rows of the truncation sample (phase 3b J: all 2,000; phase 3c D: first 500 per class)
  mutation_sample.csv    rows of the 100 attacks of the mutation attack (phase 3b D, phase 3e)
"""
import os
import pickle

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results", "merged", "test_sets")
P3B_WORK = os.environ.get("P3B_WORK", os.path.join(HERE, ".merged_work", "phase3b")) + "_cpu"
os.makedirs(OUT, exist_ok=True)

df = pd.read_csv(os.path.join(HERE, "SQL_Injection_Dataset.csv"))
df["Query"] = df["Query"].astype(str).apply(lambda x: x.lower().strip())
train_df, test_df = train_test_split(df, test_size=0.30, random_state=42)
tr_df, val_df = train_test_split(train_df, test_size=0.15, random_state=42, stratify=train_df["Label"])
y_te = test_df["Label"].values
mal_idx, ben_idx = np.where(y_te == 1)[0], np.where(y_te == 0)[0]
rows = test_df.index.to_numpy()

split = pd.DataFrame({"row": df.index, "label": df["Label"].values, "set": "train", "gnn_role": "-"})
split.loc[test_df.index, "set"] = "test"
split.loc[tr_df.index, "gnn_role"] = "train"
split.loc[val_df.index, "gnn_role"] = "validation"
split.to_csv(os.path.join(OUT, "split.csv"), index=False)

r = np.random.RandomState(0)
bc = np.sort(np.concatenate([r.choice(mal_idx, 1000, replace=False), r.choice(ben_idx, 1000, replace=False)]))
pd.DataFrame({"row": rows[bc], "label": y_te[bc]}).to_csv(os.path.join(OUT, "obfuscation_sample.csv"), index=False)

rs = np.random.RandomState(1)
t_mal = rs.choice(mal_idx, 1000, replace=False)
t_ben = rs.choice(ben_idx, 1000, replace=False)
pad = pd.DataFrame({"row": rows[np.concatenate([t_mal, t_ben])], "label": [1] * 1000 + [0] * 1000,
                    "rank_in_class": list(range(1000)) * 2})
pad.to_csv(os.path.join(OUT, "padding_sample.csv"), index=False)

with open(os.path.join(P3B_WORK, "p_test.pkl"), "rb") as f:
    p42 = pickle.load(f)[42]
detected_all = np.all(np.stack([p42[m][mal_idx] > 0.5 for m in ("ENS", "SVM", "GNN", "BERT")]), 0)
mut = np.sort(np.random.RandomState(0).choice(mal_idx[detected_all], 100, replace=False))
pd.DataFrame({"row": rows[mut]}).to_csv(os.path.join(OUT, "mutation_sample.csv"), index=False)

print(f"train {int((split['set'] == 'train').sum())}, test {int((split['set'] == 'test').sum())}, "
      f"obfuscation {len(bc)}, padding {len(pad)}, mutation {len(mut)} -> {OUT}")
