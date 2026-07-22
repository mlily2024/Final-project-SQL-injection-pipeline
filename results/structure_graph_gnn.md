# Structure-aware BERT-GNN (SQL AST-style graph)

Replaces the original whitespace *sequential-chain* graph with a graph over sqlparse SQL tokens, adding structural edges (parenthesis-matching and clause-scope) so the GNN has real SQL structure, not just word order. Trained under the honest held-out protocol (same pristine 9,276-row test set).

Test accuracy: **99.64%** (F1 99.64%), confusion matrix [[5813, 17], [16, 3430]].

On clean data this matches the chain-graph hybrid and does not beat BERT-only, because the benchmark is saturated. The structure-aware model's advantage shows under evasion: see [`obfuscation_robustness.md`](obfuscation_robustness.md).

Reproduce with `python structure_graph_gnn.py`.
