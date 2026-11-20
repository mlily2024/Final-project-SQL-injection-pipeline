# Phase 3b: extended evaluation and timing

Same 70/30 split and models as phase 3 (test set 9276 queries: 5830 benign, 3446 malicious). Seeds [42, 1, 7, 13, 123] (mean ± std) unless stated; D, G and I use [42, 1, 7]. A query is called malicious when P(malicious) > 0.5. Reduced CPU plan: disguise tests on a stratified 1,000 + 1,000 test sample, mutation attack 100 queries x 160 tries, seed 42.

## A. Clean test set

| Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | MCC | FP / FN (seed 42) |
|---|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 99.84 ± 0.00 | 99.83 ± 0.00 | 99.74 ± 0.00 | 99.78 ± 0.00 | 0.103 ± 0.000 | 0.9965 ± 0.0000 | 6 / 9 |
| DistilBERT-SVM | 99.85 ± 0.00 | 99.85 ± 0.00 | 99.74 ± 0.00 | 99.80 ± 0.00 | 0.086 ± 0.000 | 0.9968 ± 0.0000 | 5 / 9 |
| Structure-aware BERT-GNN | 99.64 ± 0.02 | 99.53 ± 0.16 | 99.51 ± 0.15 | 99.52 ± 0.03 | 0.278 ± 0.095 | 0.9924 ± 0.0005 | 16 / 17 |
| BERT-only (MLP) | 99.74 ± 0.04 | 99.78 ± 0.03 | 99.51 ± 0.12 | 99.65 ± 0.05 | 0.127 ± 0.020 | 0.9944 ± 0.0009 | 7 / 18 |

Threshold-free metrics, detection at fixed false-alarm rates, and calibration (lower Brier and ECE are better).

| Model | ROC-AUC | PR-AUC | Detection at 0.1% FPR | at 0.5% FPR | at 1% FPR | Brier | ECE |
|---|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | 0.99985 ± 0.00000 | 0.99985 ± 0.00000 | 99.69 ± 0.01 | 99.88 ± 0.00 | 99.94 ± 0.00 | 0.00143 ± 0.00001 | 0.00094 ± 0.00006 |
| DistilBERT-SVM | 0.99989 ± 0.00000 | 0.99987 ± 0.00000 | 99.77 ± 0.00 | 99.88 ± 0.00 | 99.91 ± 0.00 | 0.00135 ± 0.00000 | 0.00145 ± 0.00010 |
| Structure-aware BERT-GNN | 0.99990 ± 0.00002 | 0.99984 ± 0.00002 | 98.57 ± 0.19 | 99.70 ± 0.06 | 99.84 ± 0.06 | 0.00289 ± 0.00009 | 0.00235 ± 0.00015 |
| BERT-only (MLP) | 0.99994 ± 0.00002 | 0.99991 ± 0.00002 | 99.37 ± 0.12 | 99.83 ± 0.03 | 99.88 ± 0.02 | 0.00235 ± 0.00027 | 0.00238 ± 0.00028 |

## B. Disguises applied to both classes

Each disguise is applied to 2000 test queries (1000 attacks, 1000 benign; stratified sample, seed 0); a query the disguise does not alter keeps its clean prediction. Groups: phase 3 (9), new (10), stacked (5), sqlmap tamper scripts (68; sqlmap 1.9.9.0).

### Detection rate (recall, %) of the malicious queries

| Disguise | Group | Changed: attacks / benign (%) | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|---|
| (clean) | | | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| url_encode | phase 3 | 99.5 / 65.8 | 99.18 ± 0.04 | 99.30 ± 0.00 | 95.92 ± 1.97 | 85.46 ± 3.67 |
| double_url_encode | phase 3 | 99.5 / 65.8 | 99.50 ± 0.00 | 99.50 ± 0.00 | 99.84 ± 0.05 | 99.36 ± 0.23 |
| inline_comment | phase 3 | 99.3 / 65.8 | 98.82 ± 0.30 | 99.40 ± 0.00 | 99.84 ± 0.05 | 99.60 ± 0.19 |
| keyword_split | phase 3 | 97.0 / 62.6 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.44 ± 0.09 | 99.40 ± 0.28 |
| mysql_versioned_comment | phase 3 | 97.0 / 62.6 | 99.70 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.58 ± 0.16 |
| case_random | phase 3 | 98.3 / 90.1 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| tab_whitespace | phase 3 | 99.3 / 65.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| mixed_whitespace | phase 3 | 99.3 / 65.8 | 99.70 ± 0.00 | 99.60 ± 0.00 | 99.46 ± 0.05 | 99.50 ± 0.19 |
| url_encode+case_random | phase 3 | 99.9 / 90.2 | 99.18 ± 0.04 | 99.30 ± 0.00 | 95.92 ± 1.97 | 85.46 ± 3.67 |
| hex_strings | new | 23.2 / 16.3 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.58 ± 0.11 | 99.36 ± 0.15 |
| char_strings | new | 23.2 / 16.3 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.56 ± 0.11 | 99.32 ± 0.13 |
| string_concat | new | 18.0 / 16.3 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.36 ± 0.11 | 99.24 ± 0.15 |
| equivalent_logic | new | 53.1 / 0.3 | 99.50 ± 0.00 | 99.50 ± 0.00 | 99.44 ± 0.05 | 99.32 ± 0.18 |
| operator_symbols | new | 62.5 / 7.5 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.12 | 99.32 ± 0.18 |
| function_synonyms | new | 1.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| fullwidth_keywords | new | 95.6 / 59.2 | 99.30 ± 0.00 | 99.30 ± 0.00 | 99.46 ± 0.11 | 99.16 ± 0.37 |
| iis_unicode | new | 99.5 / 65.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.76 ± 0.15 | 99.50 ± 0.20 |
| nested_keywords | new | 95.6 / 59.2 | 98.20 ± 0.00 | 98.60 ± 0.00 | 97.34 ± 0.45 | 98.08 ± 0.63 |
| bracket_conditions | new | 7.6 / 2.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.52 ± 0.08 | 99.30 ± 0.22 |
| hex+inline_comment+url | stacked | 99.5 / 65.8 | 98.36 ± 0.36 | 99.30 ± 0.00 | 99.84 ± 0.05 | 99.42 ± 0.35 |
| logic+versioned+case | stacked | 99.5 / 90.2 | 99.70 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.58 ± 0.16 |
| synonyms+symbols+hex+comment | stacked | 99.3 / 65.8 | 98.80 ± 0.27 | 99.50 ± 0.00 | 99.84 ± 0.05 | 99.50 ± 0.35 |
| fullwidth+inline_comment | stacked | 99.3 / 65.8 | 98.12 ± 0.22 | 99.30 ± 0.00 | 99.84 ± 0.05 | 99.64 ± 0.11 |
| concat+double_url | stacked | 99.5 / 65.8 | 99.50 ± 0.00 | 99.50 ± 0.00 | 99.84 ± 0.05 | 99.38 ± 0.19 |
| sqlmap:0eunion | sqlmap | 10.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.46 ± 0.11 | 99.32 ± 0.18 |
| sqlmap:apostrophemask | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.60 ± 0.07 | 99.38 ± 0.11 |
| sqlmap:apostrophenullencode | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.60 ± 0.07 | 99.38 ± 0.11 |
| sqlmap:appendnullbyte | sqlmap | 100.0 / 100.0 | 99.90 ± 0.00 | 99.90 ± 0.00 | 99.98 ± 0.04 | 99.96 ± 0.05 |
| sqlmap:base64encode | sqlmap | 100.0 / 100.0 | 68.10 ± 0.00 | 68.30 ± 0.00 | 67.16 ± 1.61 | 68.60 ± 11.09 |
| sqlmap:between | sqlmap | 34.5 / 0.0 | 99.50 ± 0.00 | 99.50 ± 0.00 | 99.40 ± 0.07 | 99.22 ± 0.18 |
| sqlmap:binary | sqlmap | 63.8 / 0.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:bluecoat | sqlmap | 81.5 / 14.6 | 99.34 ± 0.05 | 99.40 ± 0.00 | 99.16 ± 0.05 | 99.00 ± 0.22 |
| sqlmap:chardoubleencode | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 |
| sqlmap:charencode | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 88.14 ± 10.75 | 17.98 ± 13.35 |
| sqlmap:charunicodeencode | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.64 ± 0.80 |
| sqlmap:charunicodeescape | sqlmap | 100.0 / 100.0 | 1.40 ± 0.07 | 2.24 ± 0.09 | 65.70 ± 28.88 | 99.96 ± 0.05 |
| sqlmap:commalesslimit | sqlmap | 0.0 / 0.3 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:commentbeforeparentheses | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:concat2concatws | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:decentities | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 7.98 ± 16.45 |
| sqlmap:dunion | sqlmap | 10.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.38 ± 0.13 | 99.30 ± 0.22 |
| sqlmap:equaltolike | sqlmap | 81.5 / 14.6 | 99.34 ± 0.05 | 99.40 ± 0.00 | 99.16 ± 0.05 | 99.00 ± 0.22 |
| sqlmap:equaltorlike | sqlmap | 81.5 / 14.6 | 98.06 ± 0.05 | 98.00 ± 0.00 | 99.12 ± 0.40 | 98.94 ± 0.26 |
| sqlmap:escapequotes | sqlmap | 73.0 / 18.6 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.60 ± 0.07 | 99.38 ± 0.11 |
| sqlmap:greatest | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:halfversionedmorekeywords | sqlmap | 96.9 / 57.7 | 99.70 ± 0.00 | 99.80 ± 0.00 | 99.74 ± 0.05 | 99.42 ± 0.20 |
| sqlmap:hex2char | sqlmap | 10.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.22 ± 0.24 |
| sqlmap:hexentities | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 95.56 ± 9.76 |
| sqlmap:htmlencode | sqlmap | 99.7 / 74.3 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.82 ± 0.08 | 21.24 ± 6.51 |
| sqlmap:if2case | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:ifnull2casewhenisnull | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:ifnull2ifisnull | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:informationschemacomment | sqlmap | 2.4 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:least | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:lowercase | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:luanginx | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:misunion | sqlmap | 20.1 / 2.2 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:modsecurityversioned | sqlmap | 99.2 / 65.8 | 99.70 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.54 ± 0.11 |
| sqlmap:modsecurityzeroversioned | sqlmap | 99.2 / 65.8 | 99.70 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.54 ± 0.11 |
| sqlmap:multiplespaces | sqlmap | 96.9 / 57.7 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.52 ± 0.04 | 99.32 ± 0.18 |
| sqlmap:ord2ascii | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:overlongutf8 | sqlmap | 99.7 / 74.5 | 99.60 ± 0.00 | 99.70 ± 0.00 | 99.84 ± 0.05 | 99.56 ± 0.05 |
| sqlmap:overlongutf8more | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.78 ± 0.49 |
| sqlmap:percentage | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 96.98 ± 2.40 |
| sqlmap:plus2concat | sqlmap | 0.1 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.40 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:plus2fnconcat | sqlmap | 0.1 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.46 ± 0.09 | 99.28 ± 0.22 |
| sqlmap:randomcase | sqlmap | 98.0 / 59.4 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:randomcomments | sqlmap | 98.0 / 59.4 | 99.50 ± 0.00 | 99.60 ± 0.00 | 98.52 ± 0.61 | 98.70 ± 0.66 |
| sqlmap:schemasplit | sqlmap | 7.1 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:scientific | sqlmap | 91.2 / 62.5 | 99.52 ± 0.04 | 99.50 ± 0.00 | 99.66 ± 0.05 | 99.18 ± 0.29 |
| sqlmap:sleep2getlock | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:sp_password | sqlmap | 100.0 / 100.0 | 99.90 ± 0.00 | 99.90 ± 0.00 | 99.98 ± 0.04 | 99.64 ± 0.28 |
| sqlmap:space2comment | sqlmap | 99.3 / 65.8 | 98.82 ± 0.30 | 99.40 ± 0.00 | 99.84 ± 0.05 | 99.60 ± 0.19 |
| sqlmap:space2dash | sqlmap | 99.2 / 65.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.36 ± 0.38 | 99.48 ± 0.18 |
| sqlmap:space2hash | sqlmap | 99.2 / 65.8 | 99.50 ± 0.00 | 99.50 ± 0.00 | 99.48 ± 0.08 | 66.24 ± 15.39 |
| sqlmap:space2morecomment | sqlmap | 99.3 / 65.8 | 99.34 ± 0.05 | 99.50 ± 0.00 | 99.84 ± 0.05 | 98.94 ± 0.81 |
| sqlmap:space2morehash | sqlmap | 99.3 / 65.9 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.58 ± 0.16 | 61.80 ± 15.60 |
| sqlmap:space2mssqlblank | sqlmap | 99.3 / 65.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.74 ± 0.05 | 98.48 ± 1.29 |
| sqlmap:space2mssqlhash | sqlmap | 99.2 / 65.8 | 99.60 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 91.00 ± 7.08 |
| sqlmap:space2mysqlblank | sqlmap | 99.3 / 65.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.76 ± 0.09 | 99.10 ± 0.71 |
| sqlmap:space2mysqldash | sqlmap | 99.2 / 65.8 | 99.70 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.54 ± 0.11 |
| sqlmap:space2plus | sqlmap | 99.3 / 65.8 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.72 ± 0.08 | 99.58 ± 0.18 |
| sqlmap:space2randomblank | sqlmap | 99.3 / 65.8 | 99.70 ± 0.00 | 99.70 ± 0.00 | 99.84 ± 0.05 | 98.60 ± 1.01 |
| sqlmap:substring2leftright | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:symboliclogical | sqlmap | 62.5 / 7.5 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.52 ± 0.08 | 99.32 ± 0.18 |
| sqlmap:unionalltounion | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:unmagicquotes | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.60 ± 0.07 | 99.38 ± 0.11 |
| sqlmap:uppercase | sqlmap | 98.0 / 59.5 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:varnish | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |
| sqlmap:versionedkeywords | sqlmap | 96.9 / 57.7 | 99.60 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.42 ± 0.15 |
| sqlmap:versionedmorekeywords | sqlmap | 96.9 / 57.7 | 99.60 ± 0.00 | 99.70 ± 0.00 | 99.74 ± 0.05 | 99.42 ± 0.15 |
| sqlmap:xforwardedfor | sqlmap | 0.0 / 0.0 | 99.60 ± 0.00 | 99.60 ± 0.00 | 99.50 ± 0.07 | 99.32 ± 0.18 |

### False-alarm rate (FPR, %) on the benign queries

| Disguise | Group | Changed: attacks / benign (%) | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|---|
| (clean) | | | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| url_encode | phase 3 | 99.5 / 65.8 | 18.82 ± 1.06 | 29.12 ± 0.30 | 3.26 ± 2.27 | 35.08 ± 5.04 |
| double_url_encode | phase 3 | 99.5 / 65.8 | 53.10 ± 0.86 | 56.76 ± 0.13 | 59.82 ± 0.91 | 53.96 ± 2.77 |
| inline_comment | phase 3 | 99.3 / 65.8 | 16.60 ± 0.74 | 21.98 ± 0.48 | 36.48 ± 5.78 | 37.68 ± 8.70 |
| keyword_split | phase 3 | 97.0 / 62.6 | 14.14 ± 1.25 | 23.66 ± 0.38 | 3.38 ± 1.22 | 16.94 ± 7.69 |
| mysql_versioned_comment | phase 3 | 97.0 / 62.6 | 47.22 ± 0.40 | 50.88 ± 0.11 | 40.36 ± 2.80 | 48.60 ± 6.32 |
| case_random | phase 3 | 98.3 / 90.1 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| tab_whitespace | phase 3 | 99.3 / 65.8 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| mixed_whitespace | phase 3 | 99.3 / 65.8 | 3.30 ± 0.19 | 3.96 ± 0.09 | 2.86 ± 1.49 | 5.92 ± 2.53 |
| url_encode+case_random | phase 3 | 99.9 / 90.2 | 18.82 ± 1.06 | 29.12 ± 0.30 | 3.26 ± 2.27 | 35.08 ± 5.04 |
| hex_strings | new | 23.2 / 16.3 | 0.38 ± 0.08 | 0.64 ± 0.05 | 0.44 ± 0.17 | 0.46 ± 0.18 |
| char_strings | new | 23.2 / 16.3 | 0.80 ± 0.00 | 0.54 ± 0.05 | 4.54 ± 0.91 | 0.98 ± 0.50 |
| string_concat | new | 18.0 / 16.3 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| equivalent_logic | new | 53.1 / 0.3 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| operator_symbols | new | 62.5 / 7.5 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| function_synonyms | new | 1.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| fullwidth_keywords | new | 95.6 / 59.2 | 4.76 ± 0.15 | 6.44 ± 0.05 | 17.14 ± 3.54 | 19.92 ± 6.33 |
| iis_unicode | new | 99.5 / 65.8 | 58.52 ± 0.04 | 59.34 ± 0.05 | 54.08 ± 5.61 | 59.70 ± 1.33 |
| nested_keywords | new | 95.6 / 59.2 | 1.48 ± 0.08 | 1.58 ± 0.11 | 2.54 ± 1.19 | 4.22 ± 1.57 |
| bracket_conditions | new | 7.6 / 2.8 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| hex+inline_comment+url | stacked | 99.5 / 65.8 | 19.14 ± 0.89 | 24.54 ± 0.56 | 42.30 ± 3.69 | 37.52 ± 8.93 |
| logic+versioned+case | stacked | 99.5 / 90.2 | 47.22 ± 0.40 | 50.88 ± 0.11 | 40.36 ± 2.80 | 48.60 ± 6.32 |
| synonyms+symbols+hex+comment | stacked | 99.3 / 65.8 | 19.52 ± 0.82 | 25.30 ± 0.52 | 42.32 ± 3.99 | 37.74 ± 8.84 |
| fullwidth+inline_comment | stacked | 99.3 / 65.8 | 36.28 ± 1.67 | 42.96 ± 0.37 | 55.10 ± 1.18 | 56.42 ± 2.41 |
| concat+double_url | stacked | 99.5 / 65.8 | 53.88 ± 0.64 | 56.76 ± 0.13 | 59.82 ± 0.91 | 54.62 ± 2.63 |
| sqlmap:0eunion | sqlmap | 10.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:apostrophemask | sqlmap | 46.6 / 16.7 | 0.40 ± 0.00 | 0.64 ± 0.05 | 9.80 ± 1.19 | 0.24 ± 0.09 |
| sqlmap:apostrophenullencode | sqlmap | 46.6 / 16.7 | 0.40 ± 0.00 | 0.30 ± 0.00 | 10.08 ± 0.67 | 0.90 ± 0.22 |
| sqlmap:appendnullbyte | sqlmap | 100.0 / 100.0 | 9.02 ± 0.45 | 14.20 ± 0.31 | 23.40 ± 1.27 | 26.02 ± 4.89 |
| sqlmap:base64encode | sqlmap | 100.0 / 100.0 | 66.10 ± 0.00 | 66.30 ± 0.00 | 29.34 ± 3.24 | 44.22 ± 10.83 |
| sqlmap:between | sqlmap | 34.5 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:binary | sqlmap | 63.8 / 0.8 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:bluecoat | sqlmap | 81.5 / 14.6 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:chardoubleencode | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 |
| sqlmap:charencode | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.96 ± 0.05 | 64.40 ± 15.42 |
| sqlmap:charunicodeencode | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 |
| sqlmap:charunicodeescape | sqlmap | 100.0 / 100.0 | 23.66 ± 2.23 | 35.80 ± 0.14 | 71.38 ± 28.31 | 98.98 ± 0.86 |
| sqlmap:commalesslimit | sqlmap | 0.0 / 0.3 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:commentbeforeparentheses | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:concat2concatws | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:decentities | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 20.82 ± 24.55 |
| sqlmap:dunion | sqlmap | 10.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:equaltolike | sqlmap | 81.5 / 14.6 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:equaltorlike | sqlmap | 81.5 / 14.6 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:escapequotes | sqlmap | 73.0 / 18.6 | 0.22 ± 0.04 | 0.10 ± 0.00 | 1.38 ± 0.46 | 0.26 ± 0.18 |
| sqlmap:greatest | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:halfversionedmorekeywords | sqlmap | 96.9 / 57.7 | 38.26 ± 0.35 | 40.96 ± 0.19 | 52.18 ± 3.02 | 27.24 ± 7.15 |
| sqlmap:hex2char | sqlmap | 10.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:hexentities | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.98 ± 0.04 |
| sqlmap:htmlencode | sqlmap | 99.7 / 74.3 | 40.76 ± 0.89 | 39.88 ± 0.33 | 58.46 ± 4.21 | 1.74 ± 0.45 |
| sqlmap:if2case | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:ifnull2casewhenisnull | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:ifnull2ifisnull | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:informationschemacomment | sqlmap | 2.4 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:least | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:lowercase | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:luanginx | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:misunion | sqlmap | 20.1 / 2.2 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.16 ± 0.05 |
| sqlmap:modsecurityversioned | sqlmap | 99.2 / 65.8 | 20.70 ± 0.25 | 23.86 ± 0.32 | 34.16 ± 9.51 | 24.82 ± 5.88 |
| sqlmap:modsecurityzeroversioned | sqlmap | 99.2 / 65.8 | 19.66 ± 0.29 | 21.70 ± 0.22 | 37.20 ± 9.96 | 29.62 ± 5.57 |
| sqlmap:multiplespaces | sqlmap | 96.9 / 57.7 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:ord2ascii | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:overlongutf8 | sqlmap | 99.7 / 74.5 | 59.64 ± 0.43 | 62.12 ± 0.18 | 71.22 ± 0.76 | 64.80 ± 1.91 |
| sqlmap:overlongutf8more | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.22 ± 1.53 |
| sqlmap:percentage | sqlmap | 100.0 / 100.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 95.48 ± 2.51 |
| sqlmap:plus2concat | sqlmap | 0.1 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:plus2fnconcat | sqlmap | 0.1 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:randomcase | sqlmap | 98.0 / 59.4 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:randomcomments | sqlmap | 98.0 / 59.4 | 23.92 ± 0.95 | 30.32 ± 0.41 | 17.02 ± 5.55 | 18.84 ± 11.07 |
| sqlmap:schemasplit | sqlmap | 7.1 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:scientific | sqlmap | 91.2 / 62.5 | 0.00 ± 0.00 | 0.00 ± 0.00 | 4.26 ± 2.17 | 0.98 ± 0.45 |
| sqlmap:sleep2getlock | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:sp_password | sqlmap | 100.0 / 100.0 | 38.66 ± 0.18 | 39.52 ± 0.18 | 29.30 ± 3.90 | 14.46 ± 7.56 |
| sqlmap:space2comment | sqlmap | 99.3 / 65.8 | 16.60 ± 0.74 | 21.98 ± 0.48 | 36.34 ± 5.73 | 37.68 ± 8.70 |
| sqlmap:space2dash | sqlmap | 99.2 / 65.8 | 61.70 ± 0.00 | 62.10 ± 0.00 | 53.84 ± 5.00 | 62.42 ± 0.87 |
| sqlmap:space2hash | sqlmap | 99.2 / 65.8 | 59.22 ± 0.31 | 60.40 ± 0.00 | 51.40 ± 8.97 | 48.24 ± 4.64 |
| sqlmap:space2morecomment | sqlmap | 99.3 / 65.8 | 22.16 ± 0.52 | 25.58 ± 0.19 | 51.86 ± 3.02 | 35.74 ± 8.40 |
| sqlmap:space2morehash | sqlmap | 99.3 / 65.9 | 59.42 ± 0.16 | 60.80 ± 0.00 | 56.56 ± 4.70 | 38.74 ± 8.75 |
| sqlmap:space2mssqlblank | sqlmap | 99.3 / 65.8 | 42.92 ± 0.51 | 48.16 ± 0.13 | 48.86 ± 9.12 | 42.42 ± 5.96 |
| sqlmap:space2mssqlhash | sqlmap | 99.2 / 65.8 | 56.82 ± 0.04 | 57.84 ± 0.05 | 61.90 ± 0.92 | 53.22 ± 2.97 |
| sqlmap:space2mysqlblank | sqlmap | 99.3 / 65.8 | 56.72 ± 0.08 | 57.40 ± 0.00 | 55.16 ± 3.69 | 47.66 ± 5.48 |
| sqlmap:space2mysqldash | sqlmap | 99.2 / 65.8 | 59.76 ± 0.05 | 60.42 ± 0.04 | 60.42 ± 0.80 | 61.38 ± 1.06 |
| sqlmap:space2plus | sqlmap | 99.3 / 65.8 | 5.66 ± 1.81 | 2.32 ± 0.18 | 1.96 ± 1.72 | 18.70 ± 6.94 |
| sqlmap:space2randomblank | sqlmap | 99.3 / 65.8 | 55.82 ± 0.13 | 56.62 ± 0.04 | 55.58 ± 3.97 | 46.58 ± 5.65 |
| sqlmap:substring2leftright | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:symboliclogical | sqlmap | 62.5 / 7.5 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:unionalltounion | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:unmagicquotes | sqlmap | 46.6 / 16.7 | 3.68 ± 0.04 | 3.66 ± 0.09 | 5.48 ± 0.98 | 10.26 ± 2.05 |
| sqlmap:uppercase | sqlmap | 98.0 / 59.5 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:varnish | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |
| sqlmap:versionedkeywords | sqlmap | 96.9 / 57.7 | 22.76 ± 0.22 | 25.92 ± 0.35 | 26.22 ± 4.70 | 23.00 ± 5.08 |
| sqlmap:versionedmorekeywords | sqlmap | 96.9 / 57.7 | 21.36 ± 0.18 | 24.12 ± 0.35 | 24.00 ± 4.64 | 22.10 ± 4.61 |
| sqlmap:xforwardedfor | sqlmap | 0.0 / 0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.32 ± 0.13 | 0.06 ± 0.05 |

### Precision (%)

| Disguise | Group | Changed: attacks / benign (%) | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|---|
| (clean) | | | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| url_encode | phase 3 | 99.5 / 65.8 | 84.06 ± 0.74 | 77.32 ± 0.18 | 96.77 ± 2.09 | 70.99 ± 2.93 |
| double_url_encode | phase 3 | 99.5 / 65.8 | 65.20 ± 0.37 | 63.68 ± 0.05 | 62.53 ± 0.36 | 64.82 ± 1.16 |
| inline_comment | phase 3 | 99.3 / 65.8 | 85.62 ± 0.52 | 81.89 ± 0.32 | 73.35 ± 3.19 | 72.78 ± 4.53 |
| keyword_split | phase 3 | 97.0 / 62.6 | 87.58 ± 0.95 | 80.81 ± 0.25 | 96.72 ± 1.15 | 85.74 ± 5.51 |
| mysql_versioned_comment | phase 3 | 97.0 / 62.6 | 67.86 ± 0.18 | 66.21 ± 0.05 | 71.22 ± 1.43 | 67.31 ± 2.96 |
| case_random | phase 3 | 98.3 / 90.1 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| tab_whitespace | phase 3 | 99.3 / 65.8 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| mixed_whitespace | phase 3 | 99.3 / 65.8 | 96.80 ± 0.18 | 96.18 ± 0.08 | 97.22 ± 1.40 | 94.43 ± 2.25 |
| url_encode+case_random | phase 3 | 99.9 / 90.2 | 84.06 ± 0.74 | 77.32 ± 0.18 | 96.77 ± 2.09 | 70.99 ± 2.93 |
| hex_strings | new | 23.2 / 16.3 | 99.62 ± 0.08 | 99.36 ± 0.05 | 99.56 ± 0.17 | 99.54 ± 0.18 |
| char_strings | new | 23.2 / 16.3 | 99.20 ± 0.00 | 99.46 ± 0.05 | 95.64 ± 0.83 | 99.03 ± 0.49 |
| string_concat | new | 18.0 / 16.3 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| equivalent_logic | new | 53.1 / 0.3 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| operator_symbols | new | 62.5 / 7.5 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| function_synonyms | new | 1.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| fullwidth_keywords | new | 95.6 / 59.2 | 95.43 ± 0.14 | 93.91 ± 0.05 | 85.36 ± 2.56 | 83.48 ± 4.59 |
| iis_unicode | new | 99.5 / 65.8 | 62.99 ± 0.02 | 62.67 ± 0.02 | 64.92 ± 2.40 | 62.50 ± 0.49 |
| nested_keywords | new | 95.6 / 59.2 | 98.52 ± 0.08 | 98.42 ± 0.11 | 97.47 ± 1.15 | 95.90 ± 1.47 |
| bracket_conditions | new | 7.6 / 2.8 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| hex+inline_comment+url | stacked | 99.5 / 65.8 | 83.72 ± 0.59 | 80.19 ± 0.36 | 70.28 ± 1.86 | 72.85 ± 4.67 |
| logic+versioned+case | stacked | 99.5 / 90.2 | 67.86 ± 0.18 | 66.21 ± 0.05 | 71.22 ± 1.43 | 67.31 ± 2.96 |
| synonyms+symbols+hex+comment | stacked | 99.3 / 65.8 | 83.51 ± 0.55 | 79.73 ± 0.33 | 70.28 ± 2.01 | 72.74 ± 4.61 |
| fullwidth+inline_comment | stacked | 99.3 / 65.8 | 73.02 ± 0.87 | 69.80 ± 0.18 | 64.44 ± 0.48 | 63.86 ± 0.98 |
| concat+double_url | stacked | 99.5 / 65.8 | 64.87 ± 0.27 | 63.68 ± 0.05 | 62.53 ± 0.36 | 64.55 ± 1.09 |
| sqlmap:0eunion | sqlmap | 10.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:apostrophemask | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.36 ± 0.05 | 91.05 ± 0.99 | 99.76 ± 0.09 |
| sqlmap:apostrophenullencode | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.70 ± 0.00 | 90.81 ± 0.56 | 99.10 ± 0.22 |
| sqlmap:appendnullbyte | sqlmap | 100.0 / 100.0 | 91.72 ± 0.38 | 87.56 ± 0.24 | 81.04 ± 0.84 | 79.45 ± 3.17 |
| sqlmap:base64encode | sqlmap | 100.0 / 100.0 | 50.75 ± 0.00 | 50.74 ± 0.00 | 69.67 ± 1.88 | 61.16 ± 2.55 |
| sqlmap:between | sqlmap | 34.5 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:binary | sqlmap | 63.8 / 0.8 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:bluecoat | sqlmap | 81.5 / 14.6 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:chardoubleencode | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 |
| sqlmap:charencode | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 46.71 ± 3.27 | 19.92 ± 7.26 |
| sqlmap:charunicodeencode | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 | 49.91 ± 0.20 |
| sqlmap:charunicodeescape | sqlmap | 100.0 / 100.0 | 5.60 ± 0.26 | 5.89 ± 0.20 | 47.79 ± 4.91 | 50.25 ± 0.21 |
| sqlmap:commalesslimit | sqlmap | 0.0 / 0.3 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:commentbeforeparentheses | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:concat2concatws | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:decentities | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 | 12.74 ± 14.24 |
| sqlmap:dunion | sqlmap | 10.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:equaltolike | sqlmap | 81.5 / 14.6 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:equaltorlike | sqlmap | 81.5 / 14.6 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:escapequotes | sqlmap | 73.0 / 18.6 | 99.78 ± 0.04 | 99.90 ± 0.00 | 98.64 ± 0.45 | 99.74 ± 0.18 |
| sqlmap:greatest | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:halfversionedmorekeywords | sqlmap | 96.9 / 57.7 | 72.27 ± 0.18 | 70.90 ± 0.10 | 65.67 ± 1.33 | 78.71 ± 4.67 |
| sqlmap:hex2char | sqlmap | 10.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:hexentities | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 | 48.76 ± 2.73 |
| sqlmap:htmlencode | sqlmap | 99.7 / 74.3 | 71.00 ± 0.45 | 71.45 ± 0.17 | 63.10 ± 1.67 | 92.23 ± 1.28 |
| sqlmap:if2case | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:ifnull2casewhenisnull | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:ifnull2ifisnull | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:informationschemacomment | sqlmap | 2.4 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:least | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:lowercase | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:luanginx | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:misunion | sqlmap | 20.1 / 2.2 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.84 ± 0.06 |
| sqlmap:modsecurityversioned | sqlmap | 99.2 / 65.8 | 82.81 ± 0.18 | 80.69 ± 0.21 | 74.82 ± 5.80 | 80.20 ± 4.01 |
| sqlmap:modsecurityzeroversioned | sqlmap | 99.2 / 65.8 | 83.53 ± 0.20 | 82.13 ± 0.15 | 73.18 ± 5.87 | 77.19 ± 3.46 |
| sqlmap:multiplespaces | sqlmap | 96.9 / 57.7 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:ord2ascii | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:overlongutf8 | sqlmap | 99.7 / 74.5 | 62.55 ± 0.17 | 61.61 ± 0.07 | 58.37 ± 0.26 | 60.58 ± 0.69 |
| sqlmap:overlongutf8more | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.14 ± 0.27 |
| sqlmap:percentage | sqlmap | 100.0 / 100.0 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.00 ± 0.00 | 50.39 ± 0.22 |
| sqlmap:plus2concat | sqlmap | 0.1 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:plus2fnconcat | sqlmap | 0.1 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:randomcase | sqlmap | 98.0 / 59.4 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:randomcomments | sqlmap | 98.0 / 59.4 | 80.62 ± 0.62 | 76.66 ± 0.24 | 85.43 ± 3.83 | 84.55 ± 7.37 |
| sqlmap:schemasplit | sqlmap | 7.1 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:scientific | sqlmap | 91.2 / 62.5 | 100.00 ± 0.00 | 100.00 ± 0.00 | 95.93 ± 1.99 | 99.02 ± 0.44 |
| sqlmap:sleep2getlock | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:sp_password | sqlmap | 100.0 / 100.0 | 72.10 ± 0.09 | 71.65 ± 0.09 | 77.39 ± 2.35 | 87.64 ± 5.75 |
| sqlmap:space2comment | sqlmap | 99.3 / 65.8 | 85.62 ± 0.52 | 81.89 ± 0.32 | 73.42 ± 3.16 | 72.78 ± 4.53 |
| sqlmap:space2dash | sqlmap | 99.2 / 65.8 | 61.75 ± 0.00 | 61.60 ± 0.00 | 64.92 ± 2.11 | 61.45 ± 0.31 |
| sqlmap:space2hash | sqlmap | 99.2 / 65.8 | 62.69 ± 0.12 | 62.23 ± 0.00 | 66.12 ± 3.98 | 57.38 ± 3.71 |
| sqlmap:space2morecomment | sqlmap | 99.3 / 65.8 | 81.76 ± 0.34 | 79.55 ± 0.12 | 65.84 ± 1.33 | 73.70 ± 4.42 |
| sqlmap:space2morehash | sqlmap | 99.3 / 65.9 | 62.63 ± 0.06 | 62.09 ± 0.00 | 63.82 ± 1.89 | 61.32 ± 1.70 |
| sqlmap:space2mssqlblank | sqlmap | 99.3 / 65.8 | 69.89 ± 0.25 | 67.41 ± 0.06 | 67.34 ± 4.44 | 70.00 ± 2.78 |
| sqlmap:space2mssqlhash | sqlmap | 99.2 / 65.8 | 63.67 ± 0.02 | 63.29 ± 0.02 | 61.71 ± 0.35 | 63.06 ± 1.13 |
| sqlmap:space2mysqlblank | sqlmap | 99.3 / 65.8 | 63.72 ± 0.03 | 63.44 ± 0.00 | 64.42 ± 1.56 | 67.60 ± 2.42 |
| sqlmap:space2mysqldash | sqlmap | 99.2 / 65.8 | 62.52 ± 0.02 | 62.27 ± 0.02 | 62.28 ± 0.31 | 61.86 ± 0.40 |
| sqlmap:space2plus | sqlmap | 99.3 / 65.8 | 94.64 ± 1.61 | 97.72 ± 0.17 | 98.09 ± 1.63 | 84.44 ± 5.28 |
| sqlmap:space2randomblank | sqlmap | 99.3 / 65.8 | 64.11 ± 0.05 | 63.78 ± 0.02 | 64.27 ± 1.68 | 68.00 ± 2.56 |
| sqlmap:substring2leftright | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:symboliclogical | sqlmap | 62.5 / 7.5 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:unionalltounion | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:unmagicquotes | sqlmap | 46.6 / 16.7 | 96.44 ± 0.04 | 96.46 ± 0.08 | 94.79 ± 0.88 | 90.67 ± 1.70 |
| sqlmap:uppercase | sqlmap | 98.0 / 59.5 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:varnish | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |
| sqlmap:versionedkeywords | sqlmap | 96.9 / 57.7 | 81.40 ± 0.15 | 79.37 ± 0.22 | 79.28 ± 3.10 | 81.33 ± 3.42 |
| sqlmap:versionedmorekeywords | sqlmap | 96.9 / 57.7 | 82.34 ± 0.12 | 80.52 ± 0.23 | 80.70 ± 3.17 | 81.91 ± 3.14 |
| sqlmap:xforwardedfor | sqlmap | 0.0 / 0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.68 ± 0.13 | 99.94 ± 0.06 |

### F1 (%)

| Disguise | Group | Changed: attacks / benign (%) | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|---|
| (clean) | | | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| url_encode | phase 3 | 99.5 / 65.8 | 90.99 ± 0.43 | 86.95 ± 0.12 | 96.32 ± 0.83 | 77.50 ± 2.36 |
| double_url_encode | phase 3 | 99.5 / 65.8 | 78.78 ± 0.27 | 77.66 ± 0.04 | 76.90 ± 0.26 | 78.45 ± 0.79 |
| inline_comment | phase 3 | 99.3 / 65.8 | 91.75 ± 0.20 | 89.80 ± 0.19 | 84.54 ± 2.09 | 84.04 ± 3.01 |
| keyword_split | phase 3 | 97.0 / 62.6 | 93.20 ± 0.54 | 89.22 ± 0.15 | 98.06 ± 0.55 | 91.98 ± 3.13 |
| mysql_versioned_comment | phase 3 | 97.0 / 62.6 | 80.76 ± 0.13 | 79.58 ± 0.03 | 83.09 ± 0.96 | 80.29 ± 2.02 |
| case_random | phase 3 | 98.3 / 90.1 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| tab_whitespace | phase 3 | 99.3 / 65.8 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| mixed_whitespace | phase 3 | 99.3 / 65.8 | 98.23 ± 0.09 | 97.86 ± 0.04 | 98.32 ± 0.70 | 96.89 ± 1.15 |
| url_encode+case_random | phase 3 | 99.9 / 90.2 | 90.99 ± 0.43 | 86.95 ± 0.12 | 96.32 ± 0.83 | 77.50 ± 2.36 |
| hex_strings | new | 23.2 / 16.3 | 99.61 ± 0.04 | 99.48 ± 0.03 | 99.57 ± 0.08 | 99.45 ± 0.12 |
| char_strings | new | 23.2 / 16.3 | 99.40 ± 0.00 | 99.53 ± 0.03 | 97.56 ± 0.41 | 99.17 ± 0.23 |
| string_concat | new | 18.0 / 16.3 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.52 ± 0.04 | 99.59 ± 0.09 |
| equivalent_logic | new | 53.1 / 0.3 | 99.75 ± 0.00 | 99.75 ± 0.00 | 99.56 ± 0.07 | 99.63 ± 0.10 |
| operator_symbols | new | 62.5 / 7.5 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.07 | 99.63 ± 0.10 |
| function_synonyms | new | 1.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| fullwidth_keywords | new | 95.6 / 59.2 | 97.32 ± 0.07 | 96.53 ± 0.03 | 91.86 ± 1.46 | 90.59 ± 2.51 |
| iis_unicode | new | 99.5 / 65.8 | 77.17 ± 0.01 | 76.93 ± 0.02 | 78.63 ± 1.76 | 76.78 ± 0.32 |
| nested_keywords | new | 95.6 / 59.2 | 98.36 ± 0.04 | 98.51 ± 0.05 | 97.40 ± 0.40 | 96.97 ± 0.50 |
| bracket_conditions | new | 7.6 / 2.8 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.60 ± 0.06 | 99.62 ± 0.13 |
| hex+inline_comment+url | stacked | 99.5 / 65.8 | 90.45 ± 0.24 | 88.72 ± 0.22 | 82.48 ± 1.26 | 84.01 ± 3.03 |
| logic+versioned+case | stacked | 99.5 / 90.2 | 80.76 ± 0.13 | 79.58 ± 0.03 | 83.09 ± 0.96 | 80.29 ± 2.02 |
| synonyms+symbols+hex+comment | stacked | 99.3 / 65.8 | 90.51 ± 0.26 | 88.52 ± 0.20 | 82.48 ± 1.36 | 83.97 ± 3.00 |
| fullwidth+inline_comment | stacked | 99.3 / 65.8 | 83.72 ± 0.52 | 81.98 ± 0.13 | 78.33 ± 0.34 | 77.83 ± 0.74 |
| concat+double_url | stacked | 99.5 / 65.8 | 78.54 ± 0.20 | 77.66 ± 0.04 | 76.90 ± 0.26 | 78.26 ± 0.76 |
| sqlmap:0eunion | sqlmap | 10.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.57 ± 0.04 | 99.63 ± 0.10 |
| sqlmap:apostrophemask | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.48 ± 0.03 | 95.13 ± 0.56 | 99.57 ± 0.06 |
| sqlmap:apostrophenullencode | sqlmap | 46.6 / 16.7 | 99.60 ± 0.00 | 99.65 ± 0.00 | 95.00 ± 0.29 | 99.24 ± 0.11 |
| sqlmap:appendnullbyte | sqlmap | 100.0 / 100.0 | 95.64 ± 0.21 | 93.32 ± 0.13 | 89.52 ± 0.53 | 88.50 ± 1.93 |
| sqlmap:base64encode | sqlmap | 100.0 / 100.0 | 58.16 ± 0.00 | 58.23 ± 0.00 | 68.36 ± 0.32 | 64.12 ± 4.69 |
| sqlmap:between | sqlmap | 34.5 / 0.0 | 99.75 ± 0.00 | 99.75 ± 0.00 | 99.54 ± 0.07 | 99.58 ± 0.10 |
| sqlmap:binary | sqlmap | 63.8 / 0.8 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:bluecoat | sqlmap | 81.5 / 14.6 | 99.67 ± 0.03 | 99.70 ± 0.00 | 99.42 ± 0.08 | 99.47 ± 0.13 |
| sqlmap:chardoubleencode | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 |
| sqlmap:charencode | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 61.02 ± 5.43 | 18.46 ± 10.25 |
| sqlmap:charunicodeencode | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.51 ± 0.36 |
| sqlmap:charunicodeescape | sqlmap | 100.0 / 100.0 | 2.24 ± 0.08 | 3.25 ± 0.12 | 53.46 ± 11.21 | 66.88 ± 0.17 |
| sqlmap:commalesslimit | sqlmap | 0.0 / 0.3 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:commentbeforeparentheses | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:concat2concatws | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:decentities | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 | 8.37 ± 16.40 |
| sqlmap:dunion | sqlmap | 10.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.53 ± 0.06 | 99.62 ± 0.13 |
| sqlmap:equaltolike | sqlmap | 81.5 / 14.6 | 99.67 ± 0.03 | 99.70 ± 0.00 | 99.42 ± 0.08 | 99.47 ± 0.13 |
| sqlmap:equaltorlike | sqlmap | 81.5 / 14.6 | 99.02 ± 0.03 | 98.99 ± 0.00 | 99.40 ± 0.14 | 99.44 ± 0.14 |
| sqlmap:escapequotes | sqlmap | 73.0 / 18.6 | 99.69 ± 0.02 | 99.75 ± 0.00 | 99.11 ± 0.20 | 99.56 ± 0.06 |
| sqlmap:greatest | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:halfversionedmorekeywords | sqlmap | 96.9 / 57.7 | 83.80 ± 0.12 | 82.90 ± 0.07 | 79.19 ± 0.96 | 87.80 ± 2.78 |
| sqlmap:hex2char | sqlmap | 10.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.58 ± 0.14 |
| sqlmap:hexentities | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 | 64.54 ± 4.67 |
| sqlmap:htmlencode | sqlmap | 99.7 / 74.3 | 82.97 ± 0.31 | 83.28 ± 0.11 | 77.31 ± 1.24 | 34.14 ± 8.86 |
| sqlmap:if2case | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:ifnull2casewhenisnull | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:ifnull2ifisnull | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:informationschemacomment | sqlmap | 2.4 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:least | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:lowercase | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:luanginx | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:misunion | sqlmap | 20.1 / 2.2 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.58 ± 0.10 |
| sqlmap:modsecurityversioned | sqlmap | 99.2 / 65.8 | 90.47 ± 0.10 | 89.19 ± 0.13 | 85.40 ± 3.64 | 88.78 ± 2.37 |
| sqlmap:modsecurityzeroversioned | sqlmap | 99.2 / 65.8 | 90.90 ± 0.12 | 90.06 ± 0.09 | 84.32 ± 3.74 | 86.92 ± 2.13 |
| sqlmap:multiplespaces | sqlmap | 96.9 / 57.7 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.60 ± 0.06 | 99.63 ± 0.10 |
| sqlmap:ord2ascii | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:overlongutf8 | sqlmap | 99.7 / 74.5 | 76.84 ± 0.13 | 76.16 ± 0.05 | 73.67 ± 0.21 | 75.32 ± 0.53 |
| sqlmap:overlongutf8more | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.74 ± 0.13 |
| sqlmap:percentage | sqlmap | 100.0 / 100.0 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.67 ± 0.00 | 66.31 ± 0.59 |
| sqlmap:plus2concat | sqlmap | 0.1 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.54 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:plus2fnconcat | sqlmap | 0.1 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.57 ± 0.06 | 99.61 ± 0.13 |
| sqlmap:randomcase | sqlmap | 98.0 / 59.4 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:randomcomments | sqlmap | 98.0 / 59.4 | 89.07 ± 0.38 | 86.64 ± 0.15 | 91.46 ± 2.00 | 90.92 ± 4.17 |
| sqlmap:schemasplit | sqlmap | 7.1 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:scientific | sqlmap | 91.2 / 62.5 | 99.76 ± 0.02 | 99.75 ± 0.00 | 97.75 ± 1.02 | 99.10 ± 0.14 |
| sqlmap:sleep2getlock | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:sp_password | sqlmap | 100.0 / 100.0 | 83.75 ± 0.06 | 83.45 ± 0.06 | 87.23 ± 1.48 | 93.17 ± 3.15 |
| sqlmap:space2comment | sqlmap | 99.3 / 65.8 | 91.75 ± 0.20 | 89.80 ± 0.19 | 84.59 ± 2.07 | 84.04 ± 3.01 |
| sqlmap:space2dash | sqlmap | 99.2 / 65.8 | 76.23 ± 0.00 | 76.12 ± 0.00 | 78.51 ± 1.42 | 75.97 ± 0.22 |
| sqlmap:space2hash | sqlmap | 99.2 / 65.8 | 76.92 ± 0.09 | 76.57 ± 0.00 | 79.39 ± 2.84 | 61.14 ± 8.68 |
| sqlmap:space2morecomment | sqlmap | 99.3 / 65.8 | 89.70 ± 0.19 | 88.41 ± 0.08 | 79.34 ± 0.95 | 84.40 ± 2.65 |
| sqlmap:space2morehash | sqlmap | 99.3 / 65.9 | 76.91 ± 0.05 | 76.50 ± 0.00 | 77.77 ± 1.36 | 60.87 ± 8.11 |
| sqlmap:space2mssqlblank | sqlmap | 99.3 / 65.8 | 82.14 ± 0.17 | 80.40 ± 0.04 | 80.33 ± 3.06 | 81.79 ± 1.57 |
| sqlmap:space2mssqlhash | sqlmap | 99.2 / 65.8 | 77.69 ± 0.01 | 77.42 ± 0.02 | 76.24 ± 0.27 | 74.43 ± 3.02 |
| sqlmap:space2mysqlblank | sqlmap | 99.3 / 65.8 | 77.72 ± 0.03 | 77.51 ± 0.00 | 78.28 ± 1.14 | 80.35 ± 1.53 |
| sqlmap:space2mysqldash | sqlmap | 99.2 / 65.8 | 76.85 ± 0.02 | 76.66 ± 0.01 | 76.68 ± 0.23 | 76.30 ± 0.29 |
| sqlmap:space2plus | sqlmap | 99.3 / 65.8 | 97.05 ± 0.85 | 98.65 ± 0.09 | 98.90 ± 0.84 | 91.32 ± 2.93 |
| sqlmap:space2randomblank | sqlmap | 99.3 / 65.8 | 78.04 ± 0.04 | 77.79 ± 0.01 | 78.19 ± 1.23 | 80.46 ± 1.68 |
| sqlmap:substring2leftright | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:symboliclogical | sqlmap | 62.5 / 7.5 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.60 ± 0.06 | 99.63 ± 0.10 |
| sqlmap:unionalltounion | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:unmagicquotes | sqlmap | 46.6 / 16.7 | 97.99 ± 0.02 | 98.00 ± 0.04 | 97.13 ± 0.43 | 94.82 ± 0.88 |
| sqlmap:uppercase | sqlmap | 98.0 / 59.5 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:varnish | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |
| sqlmap:versionedkeywords | sqlmap | 96.9 / 57.7 | 89.58 ± 0.09 | 88.38 ± 0.14 | 88.31 ± 1.88 | 89.44 ± 2.02 |
| sqlmap:versionedmorekeywords | sqlmap | 96.9 / 57.7 | 90.15 ± 0.07 | 89.09 ± 0.14 | 89.19 ± 1.89 | 89.79 ± 1.84 |
| sqlmap:xforwardedfor | sqlmap | 0.0 / 0.0 | 99.80 ± 0.00 | 99.80 ± 0.00 | 99.59 ± 0.05 | 99.63 ± 0.10 |

sqlmap tamper scripts not loadable (they need a sqlmap run context): commalessmid, luanginxmore.

## C. Adaptive best-of-N

Evasion: % of attacks that at least one disguise in the group turns into a 'benign' prediction. False alarm (any): % of benign queries that at least one disguise turns into a 'malicious' prediction. Lower is better for both.

| Group (N disguises) | DistilBERT-Stacked Ensemble: evasion / false alarm | DistilBERT-SVM: evasion / false alarm | Structure-aware BERT-GNN: evasion / false alarm | BERT-only (MLP): evasion / false alarm |
|---|---|---|---|---|
| phase 3 (9) | 1.80 ± 0.32 / 58.62 ± 0.29 | 1.10 ± 0.00 / 60.90 ± 0.07 | 4.64 ± 2.02 / 62.28 ± 0.79 | 14.84 ± 3.55 / 60.92 ± 1.95 |
| new + stacked (15) | 4.28 ± 0.46 / 61.04 ± 0.09 | 2.40 ± 0.00 / 62.30 ± 0.00 | 2.86 ± 0.39 / 62.68 ± 0.69 | 2.44 ± 0.90 / 62.70 ± 0.82 |
| sqlmap (68) | 99.10 ± 0.07 / 100.00 ± 0.00 | 98.68 ± 0.04 / 100.00 ± 0.00 | 51.00 ± 13.43 / 100.00 ± 0.00 | 99.26 ± 1.22 / 100.00 ± 0.00 |
| all (92) | 99.20 ± 0.07 / 100.00 ± 0.00 | 98.78 ± 0.04 / 100.00 ± 0.00 | 52.22 ± 12.79 / 100.00 ± 0.00 | 99.32 ± 1.19 / 100.00 ± 0.00 |

## D. Score-guided mutation attack (WAF-A-MoLE style)

100 attacks detected by all four models (seed 42), sampled with seed 0. Each round creates 8 mutants of the current best candidate with one semantics-preserving operator (keyword case, whitespace substitution, comment rewriting, integer encoding, operator swap, logical invariant, string to hex, versioned comment) and keeps the one with the lowest P(malicious). Budget 20 rounds (160 model queries per attack). Seeds [42].

| Model | Evaded within budget (%) | Median model queries to evade | Mean final P(malicious) |
|---|---|---|---|
| DistilBERT-Stacked Ensemble | 10.00 | 56 | 0.903 |
| DistilBERT-SVM | 9.00 | 64 | 0.900 |
| Structure-aware BERT-GNN | 9.00 | 64 | 0.912 |
| BERT-only (MLP) | 9.00 | 40 | 0.913 |

Examples (seed 42, up to three per model): original -> evasive variant.

- DistilBERT-Stacked Ensemble: `-7416" where 7656  =  7656 order by 1--` -> `-(7416)" where 7656   like   7656 order by (1)--budja`
- DistilBERT-Stacked Ensemble: `union all select` -> `union all select and true`
- DistilBERT-Stacked Ensemble: `1%' order by 1--` -> `1%' order by0x1--ttkjjhgqszupolibnycm`
- DistilBERT-SVM: `-7416" where 7656  =  7656 order by 1--` -> `-(7416)" where 7656   like   7656order by 1--budja`
- DistilBERT-SVM: `union all select` -> `union all select and true`
- DistilBERT-SVM: `1%' order by 1--` -> `1%' orderby 1--ttkjjhgdalrsbnycmbrwr`
- Structure-aware BERT-GNN: `1'   )    )    as yqek where 1957  =  1957` -> `1'   )    )    asyqek where 0x7a5   like   1957`
- Structure-aware BERT-GNN: `union all select` -> `union all selectand true`
- Structure-aware BERT-GNN: `-2230%" union all select 3303,3303,3303--` -> `-0x8b6%" uNiONall SelecT 3303,0xce7,0xce7--ovzddrqmahfknir`
- BERT-only (MLP): `1' where 8469  =  8469` -> `1' where8469   like   8469`
- BERT-only (MLP): `1'   )    )    as yqek where 1957  =  1957` -> `1'   )    )    as yqek /*!where*/ (1957)   like   1957`
- BERT-only (MLP): `-7416" where 7656  =  7656 order by 1--` -> `-7416" where 7656   like   7656 order by 1--budja`

## E. Detection rate (%) by attack type

Rule-based categories, first match in the order shown.

| Attack type | Queries | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| time-based | 524 | 99.81 ± 0.00 | 100.00 ± 0.00 | 99.50 ± 0.22 | 99.50 ± 0.10 |
| error-based | 350 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 | 100.00 ± 0.00 |
| union-based | 620 | 100.00 ± 0.00 | 99.84 ± 0.00 | 99.84 ± 0.11 | 99.77 ± 0.14 |
| stacked | 3 | 100.00 ± 0.00 | 100.00 ± 0.00 | 66.67 ± 0.00 | 86.67 ± 18.26 |
| boolean / tautology | 1321 | 100.00 ± 0.00 | 100.00 ± 0.00 | 99.97 ± 0.04 | 100.00 ± 0.00 |
| other | 628 | 98.73 ± 0.00 | 98.73 ± 0.00 | 98.12 ± 0.47 | 98.03 ± 0.59 |

## F. Error analysis (seed 42)

46 test queries are misclassified by at least one model; 5 by all four. Wrong only for this model: DistilBERT-Stacked Ensemble 0, DistilBERT-SVM 1, Structure-aware BERT-GNN 16, BERT-only (MLP) 6. Wrong in every seed: DistilBERT-Stacked Ensemble 15, DistilBERT-SVM 14, Structure-aware BERT-GNN 20, BERT-only (MLP) 14. Full list: `phase3b_seed42_errors.csv`. Labels are as in the dataset; check by hand before quoting.

| True label | Query | ENS | SVM | GNN | BERT |
|---|---|---|---|---|---|
| attack | `#name?` | x | x | x | x |
| attack | `#name?` | x | x | x | x |
| attack | `# from wapiti` | x | x | x | x |
| attack | `update` | x | x | x | x |
| attack | `print` | x | x | x | x |
| benign | `select wp_posts.* from wp_posts left join wp_postmeta on  (  wp_posts.id  =  wp_postmeta.post_id and wp_postmeta.meta_key  =  'fave_agent_visible'  ) ...` | x | x |  | x |
| benign | `said` | x | x | x |  |
| benign | `1capa2ad*or` | x | x |  | x |
| benign | `select wp_posts.* from wp_posts where 1 = 1 and wp_posts.id in  ( 28561,30220,30322,30380,30384,30387,30390,80777,80779,80780,80782,228217,262315,2623...` | x | x |  | x |
| attack | `os` | x | x |  | x |
| attack | `select sleep  (  5  )` | x |  | x | x |
| attack | `procedure` | x | x | x |  |
| attack | `ns` | x | x |  | x |
| benign | `oblong0` |  |  | x | x |
| benign | `aa` | x |  | x |  |
| benign | `select wp_posts.id from wp_posts left join wp_postmeta on  (  wp_posts.id  =  wp_postmeta.post_id and wp_postmeta.meta_key  =  'fave_agent_visible'  )...` | x | x |  |  |
| benign | `org/?option  =  com_k2  <a href  =  "http://corfopym` |  |  | x | x |
| benign | `registrar` |  |  | x | x |
| attack | `end if` |  |  | x | x |
| attack | `)   union select * from information_schema.tables;` |  |  | x | x |
| attack | `&apos; or` |  |  | x | x |
| attack | `tz_offset` |  |  | x | x |
| attack | `select pg_sleep  (  5  )` |  |  | x | x |
| benign | `ges` |  |  | x |  |
| benign | `select floor ( rand (  ) * ( 10-5+1 ) +5 ) ;` |  |  | x |  |
| benign | `com/is?-wzx-uhylezkniylvabkl3w4oh5f749nr2kumffjzou  <email_address>  <![cdata[elwoodbuckley@freenet` |  |  | x |  |
| benign | `update native set satisfied = 'flag'where addition = 'number'` |  |  |  | x |
| benign | `25500` |  |  | x |  |
| benign | `select rand (  ) * ( 10-5 ) +5;` |  |  | x |  |
| benign | `select   coalesce ( null, null, null, 'w3schools.com', null, 'example.com' ) ;` |  |  | x |  |
| benign | `de_la` |  |  | x |  |
| benign | `1?i0l` |  |  | x |  |
| benign | `fla` |  |  | x |  |
| benign | `t!74ador` |  |  | x |  |
| benign | `8020` |  |  | x |  |
| attack | `create or replace function sleep  (  int  )   returns int as '/lib/libc.so.6','sleep' language 'c' strict` |  |  | x |  |
| attack | `*/*` |  |  |  | x |
| attack | `a` |  |  |  | x |
| attack | `select sleep  (  5  )  #` |  |  |  | x |
| attack | `; exec   (  'sel' + 'ect us' + 'er'  )` |  |  | x |  |

## G. Reverse cross-dataset: trained on HTTPParams, tested on the full Kaggle dataset

Training: all 30156 HTTPParams queries (10852 SQLi; GNN early stopping on a stratified 15% of them). Test: 30919 Kaggle queries (11382 SQLi), of which 7595 also appear in HTTPParams after whitespace normalisation. Seeds [42, 1, 7].

| Model | Test set | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) | MCC |
|---|---|---|---|---|---|---|---|
| DistilBERT-Stacked Ensemble | all | 68.57 ± 0.03 | 54.01 ± 0.03 | 98.58 ± 0.02 | 69.78 ± 0.02 | 48.90 ± 0.05 | 0.5102 ± 0.0004 |
| DistilBERT-Stacked Ensemble | without overlap | 58.35 ± 0.05 | 53.13 ± 0.03 | 98.55 ± 0.01 | 69.04 ± 0.02 | 77.48 ± 0.09 | 0.3170 ± 0.0008 |
| DistilBERT-SVM | all | 69.04 ± 0.04 | 54.39 ± 0.04 | 98.47 ± 0.01 | 70.07 ± 0.03 | 48.11 ± 0.07 | 0.5151 ± 0.0005 |
| DistilBERT-SVM | without overlap | 58.97 ± 0.06 | 53.51 ± 0.04 | 98.44 ± 0.01 | 69.34 ± 0.03 | 76.22 ± 0.11 | 0.3265 ± 0.0009 |
| Structure-aware BERT-GNN | all | 66.03 ± 1.04 | 52.04 ± 0.78 | 98.81 ± 0.06 | 68.18 ± 0.66 | 53.07 ± 1.66 | 0.4811 ± 0.0123 |
| Structure-aware BERT-GNN | without overlap | 54.98 ± 1.38 | 51.17 ± 0.78 | 98.79 ± 0.06 | 67.41 ± 0.67 | 84.07 ± 2.64 | 0.2562 ± 0.0268 |
| BERT-only (MLP) | all | 71.36 ± 0.97 | 56.34 ± 0.84 | 98.76 ± 0.03 | 71.74 ± 0.68 | 44.61 ± 1.55 | 0.5460 ± 0.0119 |
| BERT-only (MLP) | without overlap | 62.04 ± 1.29 | 55.47 ± 0.85 | 98.74 ± 0.03 | 71.03 ± 0.69 | 70.68 ± 2.46 | 0.3809 ± 0.0205 |

## H. Test set without duplicates of training queries

Exact: same query after whitespace normalisation. Template: also with every quoted string and number replaced by a placeholder.

| Test set | Queries (attacks) | DistilBERT-Stacked Ensemble F1 / FPR | DistilBERT-SVM F1 / FPR | Structure-aware BERT-GNN F1 / FPR | BERT-only (MLP) F1 / FPR |
|---|---|---|---|---|---|
| full | 9276 (3446) | 99.78 ± 0.00 / 0.10 ± 0.00 | 99.80 ± 0.00 / 0.09 ± 0.00 | 99.52 ± 0.03 / 0.28 ± 0.10 | 99.65 ± 0.05 / 0.13 ± 0.02 |
| without exact duplicates | 9228 (3413) | 99.81 ± 0.00 / 0.10 ± 0.00 | 99.84 ± 0.00 / 0.09 ± 0.00 | 99.55 ± 0.03 / 0.28 ± 0.10 | 99.67 ± 0.05 / 0.13 ± 0.02 |
| without template duplicates | 7379 (2416) | 99.73 ± 0.00 / 0.12 ± 0.00 | 99.77 ± 0.00 / 0.10 ± 0.00 | 99.45 ± 0.07 / 0.28 ± 0.12 | 99.54 ± 0.08 / 0.15 ± 0.02 |

## I. Learning curve: F1 (%) on the full test set by training-set size

Stratified samples of the training set (seeds [42, 1, 7]); 100% = main models (all seeds).

| Training share | Training queries | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| 10% | 2164 | 99.51 ± 0.07 | 99.51 ± 0.05 | 98.47 ± 0.62 | 99.28 ± 0.02 |
| 25% | 5411 | 99.64 ± 0.07 | 99.65 ± 0.05 | 99.15 ± 0.05 | 99.45 ± 0.08 |
| 50% | 10822 | 99.70 ± 0.03 | 99.72 ± 0.05 | 99.41 ± 0.01 | 99.58 ± 0.11 |
| 100% | 21643 | 99.78 ± 0.00 | 99.80 ± 0.00 | 99.52 ± 0.03 | 99.65 ± 0.05 |

## J. Query length

Length in BERT sub-word tokens (both encoders share the uncased vocabulary); inputs are cut at 128 tokens.

| Tokens | Queries (attacks) | DistilBERT-Stacked Ensemble recall / FPR | DistilBERT-SVM recall / FPR | Structure-aware BERT-GNN recall / FPR | BERT-only (MLP) recall / FPR |
|---|---|---|---|---|---|
| 1-16 | 5342 (588) | 98.47 ± 0.00 / 0.06 ± 0.00 | 98.47 ± 0.00 / 0.04 ± 0.00 | 97.45 ± 0.73 / 0.26 ± 0.09 | 97.31 ± 0.69 / 0.09 ± 0.02 |
| 17-32 | 2044 (1171) | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 99.90 ± 0.04 / 0.32 ± 0.10 | 99.91 ± 0.09 / 0.11 ± 0.00 |
| 33-64 | 1196 (1009) | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 99.94 ± 0.05 / 0.53 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 |
| 65-128 | 599 (586) | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 |
| >128 | 95 (92) | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 6.67 ± 14.91 | 100.00 ± 0.00 / 66.67 ± 0.00 |

Truncation test: 1000 attacks and 1000 benign test queries with 146 tokens of benign training text placed before the query (the query starts after the cut) or after it (benign padding: the query is still read in full, followed by benign text).

| Filler | DistilBERT-Stacked Ensemble recall / FPR | DistilBERT-SVM recall / FPR | Structure-aware BERT-GNN recall / FPR | BERT-only (MLP) recall / FPR |
|---|---|---|---|---|
| none | 99.60 ± 0.00 / 0.10 ± 0.00 | 99.60 ± 0.00 / 0.10 ± 0.00 | 99.42 ± 0.18 / 0.22 ± 0.04 | 99.44 ± 0.17 / 0.26 ± 0.05 |
| after the query | 10.50 ± 0.17 / 0.10 ± 0.00 | 10.40 ± 0.00 / 0.10 ± 0.00 | 41.14 ± 4.57 / 0.00 ± 0.00 | 7.22 ± 0.86 / 0.10 ± 0.00 |
| before the query | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 |

## K. Timing (seed 42 models, full pipeline from raw query to label)

Platform: GPU None; CPU Intel64 Family 6 Model 186 Stepping 3, GenuineIntel (12 logical cores, 10 torch threads); RAM None GB; Python 3.14.0; torch 2.10.0+cpu. Scikit-learn and XGBoost models always run on the CPU. Two warm-up passes before each measurement.

Batch size 1 (per-query latency, ms):

| Device | Model | Queries | Median | 95th percentile | Encoder | Graph build | Classifier |
|---|---|---|---|---|---|---|---|
| cpu | DistilBERT-Stacked Ensemble | 100 | 41.74 | 109.51 | 36.59 | - | 4.51 |
| cpu | DistilBERT-SVM | 100 | 33.79 | 92.19 | 32.67 | - | 1.16 |
| cpu | Structure-aware BERT-GNN | 100 | 74.66 | 208.72 | 67.75 | 2.52 | 4.38 |
| cpu | BERT-only (MLP) | 100 | 65.66 | 182.44 | 64.91 | - | 0.72 |

Batched (throughput):

| Device | Batch | Model | Queries | ms per query | Queries per second | Encoder ms/q | Graph ms/q | Classifier ms/q |
|---|---|---|---|---|---|---|---|---|
| cpu | 64 | DistilBERT-Stacked Ensemble | 1000 | 69.139 | 14 | 68.501 | - | 0.638 |
| cpu | 64 | DistilBERT-SVM | 1000 | 50.985 | 20 | 50.596 | - | 0.389 |
| cpu | 64 | Structure-aware BERT-GNN | 1000 | 136.261 | 7 | 132.839 | 3.055 | 0.367 |
| cpu | 64 | BERT-only (MLP) | 1000 | 116.453 | 9 | 116.129 | - | 0.324 |

## Notes

- Models, split and hyperparameters as phase 3; GNN hyperparameters are the phase 3 Optuna result, not re-searched.
- Transformed queries are not re-lower-cased; both tokenisers are uncased.
- sqlmap tamper scripts run as plain string functions on the test queries (no target system); random choices inside them are seeded per query.
- A disguise that leaves a query unchanged keeps the clean prediction for that query.
- GNN epochs to early stop per seed (main models): [10, 9, 10, 12, 13].

Reproduce: `python merged_phase3b_extended.py` (WORK_DIR for caches, SQLMAP_DIR for the tamper scripts).