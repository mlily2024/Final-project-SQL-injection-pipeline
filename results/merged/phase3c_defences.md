# Phase 3c: defences, obfuscation, query length and novel attacks

Models and disguises as phase 3b. Seeds [42, 1, 7] (mean ± std). Pipelines: **raw** (raw); **decode at test time only** (raw+canon); **decode + retrained** (canon); **raw + windows** (raw+window); **decode + retrained + windows** (canon+window). Decoding: URL (%XX, %uXXXX, overlong UTF-8), HTML entities, \u and \x escapes (repeated), Unicode NFKC, NUL removal, versioned comments unwrapped, block comments removed, line-comment text removed (marker kept), whitespace collapsed, lower case. Not decoded: base64, '+'. Windows (inputs over 126 tokens only): 126 tokens step 64, 32 tokens step 16; a query is malicious if any window is.

## A. Clean test set

| Pipeline | Model | Accuracy (%) | Precision (%) | Recall (%) | F1 (%) | FPR (%) |
|---|---|---|---|---|---|---|
| raw | DistilBERT-Stacked Ensemble | 99.84 ± 0.00 | 99.83 ± 0.00 | 99.74 ± 0.00 | 99.78 ± 0.00 | 0.10 ± 0.00 |
| raw | DistilBERT-SVM | 99.85 ± 0.00 | 99.85 ± 0.00 | 99.74 ± 0.00 | 99.80 ± 0.00 | 0.09 ± 0.00 |
| raw | Structure-aware BERT-GNN | 99.65 ± 0.03 | 99.62 ± 0.08 | 99.43 ± 0.11 | 99.53 ± 0.04 | 0.22 ± 0.05 |
| raw | BERT-only (MLP) | 99.75 ± 0.02 | 99.80 ± 0.03 | 99.53 ± 0.04 | 99.66 ± 0.03 | 0.12 ± 0.02 |
| decode at test time only | DistilBERT-Stacked Ensemble | 99.85 ± 0.00 | 99.77 ± 0.00 | 99.83 ± 0.00 | 99.80 ± 0.00 | 0.14 ± 0.00 |
| decode at test time only | DistilBERT-SVM | 99.86 ± 0.00 | 99.80 ± 0.00 | 99.83 ± 0.00 | 99.81 ± 0.00 | 0.12 ± 0.00 |
| decode at test time only | Structure-aware BERT-GNN | 99.67 ± 0.03 | 99.56 ± 0.08 | 99.55 ± 0.11 | 99.55 ± 0.04 | 0.26 ± 0.05 |
| decode at test time only | BERT-only (MLP) | 99.75 ± 0.03 | 99.76 ± 0.04 | 99.57 ± 0.09 | 99.67 ± 0.04 | 0.14 ± 0.03 |
| decode + retrained | DistilBERT-Stacked Ensemble | 99.83 ± 0.00 | 99.71 ± 0.00 | 99.83 ± 0.00 | 99.77 ± 0.00 | 0.17 ± 0.00 |
| decode + retrained | DistilBERT-SVM | 99.83 ± 0.00 | 99.77 ± 0.00 | 99.77 ± 0.00 | 99.77 ± 0.00 | 0.14 ± 0.00 |
| decode + retrained | Structure-aware BERT-GNN | 99.66 ± 0.04 | 99.58 ± 0.09 | 99.50 ± 0.06 | 99.54 ± 0.06 | 0.25 ± 0.06 |
| decode + retrained | BERT-only (MLP) | 99.73 ± 0.05 | 99.73 ± 0.09 | 99.56 ± 0.22 | 99.64 ± 0.07 | 0.16 ± 0.05 |

## B. Disguises (phase 3b sample: 1000 attacks, 1000 benign)

Each cell: raw pipeline → decode + retrained.

### Detection rate (recall, %)

| Disguise | Group | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| url_encode | phase 3 | 99.2 → 99.7 | 99.3 → 99.6 | 95.3 → 99.5 | 85.0 → 99.3 |
| double_url_encode | phase 3 | 99.5 → 99.7 | 99.5 → 99.6 | 99.8 → 99.5 | 99.4 → 99.3 |
| inline_comment | phase 3 | 98.8 → 99.7 | 99.4 → 99.6 | 99.8 → 99.5 | 99.6 → 99.3 |
| keyword_split | phase 3 | 99.6 → 98.4 | 99.6 → 98.5 | 99.4 → 96.6 | 99.5 → 98.4 |
| mysql_versioned_comment | phase 3 | 99.7 → 99.7 | 99.7 → 99.6 | 99.7 → 99.5 | 99.6 → 99.3 |
| case_random | phase 3 | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| tab_whitespace | phase 3 | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| mixed_whitespace | phase 3 | 99.7 → 99.6 | 99.6 → 99.5 | 99.4 → 99.5 | 99.5 → 99.2 |
| url_encode+case_random | phase 3 | 99.2 → 99.7 | 99.3 → 99.6 | 95.3 → 99.5 | 85.0 → 99.3 |
| hex_strings | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.6 | 99.4 → 99.4 |
| char_strings | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.2 |
| string_concat | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.3 → 99.3 | 99.3 → 99.2 |
| equivalent_logic | new | 99.5 → 99.6 | 99.5 → 99.5 | 99.4 → 99.5 | 99.4 → 99.3 |
| operator_symbols | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.4 | 99.4 → 99.3 |
| function_synonyms | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| fullwidth_keywords | new | 99.3 → 99.7 | 99.3 → 99.6 | 99.4 → 99.5 | 99.2 → 99.3 |
| iis_unicode | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.8 → 99.5 | 99.5 → 99.3 |
| nested_keywords | new | 98.2 → 98.3 | 98.6 → 98.7 | 97.1 → 97.0 | 98.3 → 97.1 |
| bracket_conditions | new | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| hex+inline_comment+url | stacked | 98.3 → 99.7 | 99.3 → 99.6 | 99.8 → 99.6 | 99.6 → 99.4 |
| logic+versioned+case | stacked | 99.7 → 99.6 | 99.7 → 99.5 | 99.7 → 99.5 | 99.6 → 99.3 |
| synonyms+symbols+hex+comment | stacked | 98.8 → 99.7 | 99.5 → 99.6 | 99.8 → 99.6 | 99.6 → 99.4 |
| fullwidth+inline_comment | stacked | 98.0 → 99.7 | 99.3 → 99.6 | 99.8 → 99.5 | 99.6 → 99.3 |
| concat+double_url | stacked | 99.5 → 99.7 | 99.5 → 99.6 | 99.8 → 99.3 | 99.4 → 99.2 |
| sqlmap:0eunion | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.4 → 99.5 | 99.4 → 99.3 |
| sqlmap:apostrophemask | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.6 → 99.5 | 99.4 → 99.3 |
| sqlmap:apostrophenullencode | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.6 → 99.5 | 99.4 → 99.3 |
| sqlmap:appendnullbyte | sqlmap | 99.9 → 99.7 | 99.9 → 99.6 | 100.0 → 99.5 | 100.0 → 99.3 |
| sqlmap:base64encode | sqlmap | 68.1 → 79.5 | 68.3 → 73.7 | 66.3 → 63.6 | 72.5 → 66.6 |
| sqlmap:between | sqlmap | 99.5 → 99.6 | 99.5 → 99.5 | 99.4 → 99.4 | 99.3 → 99.2 |
| sqlmap:binary | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:bluecoat | sqlmap | 99.3 → 99.6 | 99.4 → 99.4 | 99.2 → 99.2 | 99.1 → 98.7 |
| sqlmap:chardoubleencode | sqlmap | 100.0 → 99.7 | 100.0 → 99.6 | 100.0 → 99.5 | 100.0 → 99.3 |
| sqlmap:charencode | sqlmap | 100.0 → 99.7 | 100.0 → 99.6 | 93.5 → 99.5 | 19.5 → 99.3 |
| sqlmap:charunicodeencode | sqlmap | 100.0 → 99.7 | 100.0 → 99.6 | 100.0 → 99.5 | 99.4 → 99.3 |
| sqlmap:charunicodeescape | sqlmap | 1.4 → 99.7 | 2.3 → 99.6 | 80.8 → 99.5 | 100.0 → 99.3 |
| sqlmap:commalesslimit | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:commentbeforeparentheses | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:concat2concatws | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:decentities | sqlmap | 100.0 → 99.7 | 100.0 → 99.6 | 100.0 → 99.5 | 12.9 → 99.3 |
| sqlmap:dunion | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.3 → 99.4 | 99.4 → 99.2 |
| sqlmap:equaltolike | sqlmap | 99.3 → 99.6 | 99.4 → 99.4 | 99.2 → 99.2 | 99.1 → 98.7 |
| sqlmap:equaltorlike | sqlmap | 98.1 → 98.1 | 98.0 → 98.1 | 98.9 → 99.0 | 99.0 → 98.5 |
| sqlmap:escapequotes | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.6 → 99.6 | 99.4 → 99.4 |
| sqlmap:greatest | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:halfversionedmorekeywords | sqlmap | 99.7 → 99.7 | 99.8 → 99.7 | 99.7 → 99.6 | 99.5 → 99.4 |
| sqlmap:hex2char | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.3 → 99.2 |
| sqlmap:hexentities | sqlmap | 100.0 → 99.7 | 100.0 → 99.6 | 100.0 → 99.5 | 99.9 → 99.3 |
| sqlmap:htmlencode | sqlmap | 99.8 → 99.7 | 99.8 → 99.6 | 99.8 → 99.5 | 23.8 → 99.3 |
| sqlmap:if2case | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:ifnull2casewhenisnull | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:ifnull2ifisnull | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:informationschemacomment | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:least | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:lowercase | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:luanginx | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:misunion | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:modsecurityversioned | sqlmap | 99.7 → 99.7 | 99.7 → 99.6 | 99.7 → 99.5 | 99.5 → 99.3 |
| sqlmap:modsecurityzeroversioned | sqlmap | 99.7 → 99.7 | 99.7 → 99.6 | 99.7 → 99.5 | 99.5 → 99.3 |
| sqlmap:multiplespaces | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:ord2ascii | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:overlongutf8 | sqlmap | 99.6 → 99.7 | 99.7 → 99.6 | 99.8 → 99.5 | 99.6 → 99.3 |
| sqlmap:overlongutf8more | sqlmap | 100.0 → 99.7 | 100.0 → 99.6 | 100.0 → 99.5 | 99.6 → 99.3 |
| sqlmap:percentage | sqlmap | 100.0 → 100.0 | 100.0 → 100.0 | 100.0 → 100.0 | 96.5 → 52.2 |
| sqlmap:plus2concat | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.4 → 99.4 | 99.4 → 99.3 |
| sqlmap:plus2fnconcat | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.4 → 99.5 | 99.4 → 99.3 |
| sqlmap:randomcase | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:randomcomments | sqlmap | 99.5 → 97.4 | 99.6 → 97.6 | 98.5 → 91.2 | 99.1 → 93.2 |
| sqlmap:schemasplit | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:scientific | sqlmap | 99.5 → 99.7 | 99.5 → 99.4 | 99.6 → 99.7 | 99.3 → 99.4 |
| sqlmap:sleep2getlock | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:sp_password | sqlmap | 99.9 → 100.0 | 99.9 → 100.0 | 100.0 → 99.8 | 99.7 → 99.9 |
| sqlmap:space2comment | sqlmap | 98.8 → 99.7 | 99.4 → 99.6 | 99.8 → 99.5 | 99.6 → 99.3 |
| sqlmap:space2dash | sqlmap | 99.6 → 99.8 | 99.6 → 99.8 | 99.3 → 99.7 | 99.5 → 99.5 |
| sqlmap:space2hash | sqlmap | 99.5 → 99.8 | 99.5 → 99.8 | 99.5 → 99.7 | 69.1 → 99.4 |
| sqlmap:space2morecomment | sqlmap | 99.3 → 99.7 | 99.5 → 99.6 | 99.8 → 99.5 | 99.3 → 99.3 |
| sqlmap:space2morehash | sqlmap | 99.6 → 99.7 | 99.6 → 99.7 | 99.6 → 99.7 | 64.8 → 99.3 |
| sqlmap:space2mssqlblank | sqlmap | 99.6 → 99.1 | 99.6 → 99.2 | 99.7 → 98.8 | 98.8 → 98.8 |
| sqlmap:space2mssqlhash | sqlmap | 99.6 → 99.8 | 99.7 → 99.8 | 99.7 → 99.7 | 92.6 → 99.4 |
| sqlmap:space2mysqlblank | sqlmap | 99.6 → 99.6 | 99.6 → 99.5 | 99.8 → 99.4 | 99.3 → 99.2 |
| sqlmap:space2mysqldash | sqlmap | 99.7 → 99.8 | 99.7 → 99.8 | 99.7 → 99.7 | 99.5 → 99.5 |
| sqlmap:space2plus | sqlmap | 99.6 → 99.7 | 99.6 → 99.7 | 99.7 → 99.7 | 99.6 → 99.6 |
| sqlmap:space2randomblank | sqlmap | 99.7 → 99.6 | 99.7 → 99.5 | 99.8 → 99.5 | 98.7 → 99.3 |
| sqlmap:substring2leftright | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:symboliclogical | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.4 | 99.4 → 99.3 |
| sqlmap:unionalltounion | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:unmagicquotes | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.6 → 99.5 | 99.4 → 99.4 |
| sqlmap:uppercase | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:varnish | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |
| sqlmap:versionedkeywords | sqlmap | 99.6 → 99.7 | 99.7 → 99.6 | 99.7 → 99.5 | 99.4 → 99.3 |
| sqlmap:versionedmorekeywords | sqlmap | 99.6 → 99.7 | 99.7 → 99.6 | 99.7 → 99.5 | 99.4 → 99.3 |
| sqlmap:xforwardedfor | sqlmap | 99.6 → 99.7 | 99.6 → 99.6 | 99.5 → 99.5 | 99.4 → 99.3 |

### False-alarm rate (FPR, %)

| Disguise | Group | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| url_encode | phase 3 | 18.3 → 0.0 | 29.2 → 0.0 | 1.9 → 0.3 | 35.1 → 0.0 |
| double_url_encode | phase 3 | 52.6 → 0.0 | 56.8 → 0.0 | 59.4 → 0.3 | 55.3 → 0.0 |
| inline_comment | phase 3 | 16.3 → 0.0 | 22.2 → 0.0 | 35.8 → 0.3 | 42.5 → 0.0 |
| keyword_split | phase 3 | 13.5 → 1.2 | 23.8 → 0.6 | 3.0 → 0.7 | 21.6 → 0.6 |
| mysql_versioned_comment | phase 3 | 47.1 → 0.7 | 50.9 → 0.6 | 38.9 → 0.8 | 52.0 → 0.6 |
| case_random | phase 3 | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| tab_whitespace | phase 3 | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| mixed_whitespace | phase 3 | 3.3 → 0.0 | 4.0 → 0.0 | 2.1 → 0.3 | 7.4 → 0.0 |
| url_encode+case_random | phase 3 | 18.3 → 0.0 | 29.2 → 0.0 | 1.9 → 0.3 | 35.1 → 0.0 |
| hex_strings | new | 0.4 → 0.1 | 0.7 → 0.0 | 0.3 → 0.5 | 0.5 → 0.3 |
| char_strings | new | 0.8 → 0.8 | 0.6 → 0.3 | 4.1 → 4.2 | 1.3 → 0.5 |
| string_concat | new | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| equivalent_logic | new | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| operator_symbols | new | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| function_synonyms | new | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| fullwidth_keywords | new | 4.7 → 0.0 | 6.5 → 0.0 | 14.6 → 0.3 | 22.7 → 0.0 |
| iis_unicode | new | 58.5 → 0.0 | 59.4 → 0.0 | 55.6 → 0.3 | 60.3 → 0.0 |
| nested_keywords | new | 1.5 → 1.0 | 1.6 → 0.5 | 1.9 → 1.2 | 5.2 → 2.3 |
| bracket_conditions | new | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| hex+inline_comment+url | stacked | 18.7 → 0.1 | 24.8 → 0.0 | 41.4 → 0.5 | 43.0 → 0.3 |
| logic+versioned+case | stacked | 47.1 → 0.7 | 50.9 → 0.6 | 38.9 → 0.8 | 52.0 → 0.6 |
| synonyms+symbols+hex+comment | stacked | 19.1 → 0.3 | 25.5 → 0.3 | 41.4 → 0.5 | 42.9 → 0.7 |
| fullwidth+inline_comment | stacked | 35.3 → 0.0 | 43.1 → 0.0 | 55.0 → 0.3 | 57.9 → 0.0 |
| concat+double_url | stacked | 53.5 → 0.0 | 56.8 → 0.0 | 59.4 → 0.3 | 55.8 → 0.0 |
| sqlmap:0eunion | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:apostrophemask | sqlmap | 0.4 → 0.0 | 0.7 → 0.0 | 10.5 → 0.3 | 0.2 → 0.0 |
| sqlmap:apostrophenullencode | sqlmap | 0.4 → 0.0 | 0.3 → 0.0 | 10.0 → 0.3 | 0.9 → 0.0 |
| sqlmap:appendnullbyte | sqlmap | 8.9 → 0.0 | 14.3 → 0.0 | 23.1 → 0.3 | 27.0 → 0.0 |
| sqlmap:base64encode | sqlmap | 66.1 → 68.0 | 66.3 → 67.0 | 27.3 → 22.6 | 46.0 → 46.4 |
| sqlmap:between | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:binary | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:bluecoat | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:chardoubleencode | sqlmap | 100.0 → 0.0 | 100.0 → 0.0 | 100.0 → 0.2 | 100.0 → 0.0 |
| sqlmap:charencode | sqlmap | 100.0 → 0.0 | 100.0 → 0.0 | 100.0 → 0.2 | 65.1 → 0.0 |
| sqlmap:charunicodeencode | sqlmap | 100.0 → 0.0 | 100.0 → 0.0 | 100.0 → 0.3 | 100.0 → 0.0 |
| sqlmap:charunicodeescape | sqlmap | 22.3 → 0.0 | 35.9 → 0.0 | 82.9 → 0.3 | 99.0 → 0.0 |
| sqlmap:commalesslimit | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:commentbeforeparentheses | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:concat2concatws | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:decentities | sqlmap | 100.0 → 0.0 | 100.0 → 0.0 | 100.0 → 0.3 | 29.0 → 0.0 |
| sqlmap:dunion | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:equaltolike | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:equaltorlike | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:escapequotes | sqlmap | 0.2 → 0.0 | 0.1 → 0.0 | 1.2 → 1.2 | 0.2 → 0.1 |
| sqlmap:greatest | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:halfversionedmorekeywords | sqlmap | 38.2 → 31.0 | 41.0 → 30.4 | 50.9 → 47.1 | 31.5 → 22.5 |
| sqlmap:hex2char | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:hexentities | sqlmap | 100.0 → 0.0 | 100.0 → 0.0 | 100.0 → 0.3 | 100.0 → 0.0 |
| sqlmap:htmlencode | sqlmap | 40.8 → 0.0 | 40.0 → 0.0 | 58.8 → 0.3 | 2.0 → 0.0 |
| sqlmap:if2case | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:ifnull2casewhenisnull | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:ifnull2ifisnull | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:informationschemacomment | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:least | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:lowercase | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:luanginx | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:misunion | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.1 → 0.1 |
| sqlmap:modsecurityversioned | sqlmap | 20.7 → 0.0 | 24.0 → 0.0 | 30.1 → 0.3 | 28.1 → 0.0 |
| sqlmap:modsecurityzeroversioned | sqlmap | 19.7 → 0.0 | 21.8 → 0.0 | 33.8 → 0.3 | 32.7 → 0.0 |
| sqlmap:multiplespaces | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:ord2ascii | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:overlongutf8 | sqlmap | 59.4 → 0.0 | 62.2 → 0.0 | 71.3 → 0.3 | 65.1 → 0.0 |
| sqlmap:overlongutf8more | sqlmap | 100.0 → 0.0 | 100.0 → 0.0 | 100.0 → 0.3 | 98.8 → 0.0 |
| sqlmap:percentage | sqlmap | 100.0 → 92.0 | 100.0 → 94.5 | 100.0 → 99.9 | 94.9 → 27.2 |
| sqlmap:plus2concat | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:plus2fnconcat | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:randomcase | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:randomcomments | sqlmap | 23.4 → 1.0 | 30.5 → 1.5 | 17.7 → 1.6 | 24.9 → 1.1 |
| sqlmap:schemasplit | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:scientific | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 2.9 → 3.5 | 1.0 → 0.8 |
| sqlmap:sleep2getlock | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:sp_password | sqlmap | 38.6 → 14.9 | 39.6 → 16.4 | 27.3 → 3.8 | 14.7 → 17.5 |
| sqlmap:space2comment | sqlmap | 16.3 → 0.0 | 22.2 → 0.0 | 35.7 → 0.3 | 42.5 → 0.0 |
| sqlmap:space2dash | sqlmap | 61.7 → 23.7 | 62.1 → 25.4 | 51.8 → 28.7 | 62.8 → 27.7 |
| sqlmap:space2hash | sqlmap | 59.1 → 28.6 | 60.4 → 34.4 | 50.7 → 19.7 | 50.1 → 19.0 |
| sqlmap:space2morecomment | sqlmap | 21.9 → 0.0 | 25.6 → 0.0 | 50.8 → 0.3 | 39.2 → 0.0 |
| sqlmap:space2morehash | sqlmap | 59.3 → 37.0 | 60.8 → 41.9 | 56.4 → 35.4 | 41.8 → 26.8 |
| sqlmap:space2mssqlblank | sqlmap | 42.7 → 0.6 | 48.2 → 0.2 | 45.5 → 1.7 | 44.7 → 0.6 |
| sqlmap:space2mssqlhash | sqlmap | 56.8 → 28.6 | 57.9 → 34.4 | 61.8 → 19.7 | 53.8 → 19.0 |
| sqlmap:space2mysqlblank | sqlmap | 56.7 → 0.1 | 57.4 → 0.1 | 54.1 → 0.4 | 49.3 → 0.1 |
| sqlmap:space2mysqldash | sqlmap | 59.8 → 23.7 | 60.4 → 25.4 | 60.2 → 28.7 | 61.8 → 27.7 |
| sqlmap:space2plus | sqlmap | 5.3 → 3.4 | 2.4 → 1.7 | 2.4 → 2.5 | 21.7 → 27.7 |
| sqlmap:space2randomblank | sqlmap | 55.8 → 0.0 | 56.6 → 0.0 | 54.4 → 0.3 | 48.3 → 0.0 |
| sqlmap:substring2leftright | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:symboliclogical | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:unionalltounion | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:unmagicquotes | sqlmap | 3.7 → 0.7 | 3.7 → 0.7 | 5.0 → 0.4 | 10.6 → 1.5 |
| sqlmap:uppercase | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:varnish | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |
| sqlmap:versionedkeywords | sqlmap | 22.7 → 0.0 | 26.1 → 0.0 | 24.6 → 0.3 | 26.1 → 0.0 |
| sqlmap:versionedmorekeywords | sqlmap | 21.3 → 0.0 | 24.3 → 0.0 | 22.4 → 0.3 | 24.9 → 0.0 |
| sqlmap:xforwardedfor | sqlmap | 0.0 → 0.0 | 0.0 → 0.0 | 0.2 → 0.3 | 0.0 → 0.0 |

## C. Best-of-N: evasion (% of attacks) / false alarm (% of benign) by any disguise in the group

| Group | Pipeline | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|
| phase 3 (9) | raw | 1.87 ± 0.32 / 58.47 ± 0.15 | 1.10 ± 0.00 / 60.90 ± 0.10 | 5.30 ± 2.17 / 61.87 ± 0.75 | 15.20 ± 4.83 / 61.90 ± 0.46 |
| phase 3 (9) | decode at test time only | 1.80 ± 0.00 / 1.43 ± 0.06 | 1.70 ± 0.00 / 1.60 ± 0.00 | 3.13 ± 0.59 / 1.30 ± 0.36 | 1.20 ± 0.30 / 1.77 ± 0.59 |
| phase 3 (9) | decode + retrained | 1.73 ± 0.06 / 1.67 ± 0.06 | 1.60 ± 0.00 / 1.03 ± 0.06 | 3.40 ± 0.36 / 1.13 ± 0.40 | 1.70 ± 0.98 / 0.93 ± 0.65 |
| new + stacked (15) | raw | 4.40 ± 0.35 / 61.00 ± 0.00 | 2.40 ± 0.00 / 62.30 ± 0.00 | 3.07 ± 0.35 / 62.30 ± 0.53 | 2.03 ± 0.31 / 63.10 ± 0.35 |
| new + stacked (15) | decode at test time only | 1.70 ± 0.00 / 3.07 ± 0.12 | 1.30 ± 0.00 / 3.40 ± 0.17 | 3.03 ± 0.45 / 6.33 ± 0.97 | 1.73 ± 0.12 / 7.37 ± 0.57 |
| new + stacked (15) | decode + retrained | 1.70 ± 0.00 / 2.77 ± 0.06 | 1.30 ± 0.00 / 1.73 ± 0.06 | 3.10 ± 0.30 / 5.57 ± 0.76 | 3.07 ± 2.06 / 3.80 ± 1.31 |
| sqlmap (68) | raw | 99.13 ± 0.06 / 100.00 ± 0.00 | 98.67 ± 0.06 / 100.00 ± 0.00 | 43.43 ± 12.00 / 100.00 ± 0.00 | 98.90 ± 1.57 / 100.00 ± 0.00 |
| sqlmap (68) | decode at test time only | 35.00 ± 0.00 / 100.00 ± 0.00 | 34.80 ± 0.00 / 100.00 ± 0.00 | 37.87 ± 1.45 / 100.00 ± 0.00 | 33.97 ± 4.43 / 99.97 ± 0.06 |
| sqlmap (68) | decode + retrained | 23.30 ± 9.61 / 98.40 ± 0.36 | 29.13 ± 9.81 / 98.63 ± 0.06 | 40.43 ± 1.21 / 99.97 ± 0.06 | 70.63 ± 13.74 / 78.77 ± 17.65 |
| all (92) | raw | 99.23 ± 0.06 / 100.00 ± 0.00 | 98.77 ± 0.06 / 100.00 ± 0.00 | 45.03 ± 11.50 / 100.00 ± 0.00 | 98.97 ± 1.54 / 100.00 ± 0.00 |
| all (92) | decode at test time only | 35.80 ± 0.00 / 100.00 ± 0.00 | 35.50 ± 0.00 / 100.00 ± 0.00 | 38.10 ± 1.47 / 100.00 ± 0.00 | 34.20 ± 4.52 / 99.97 ± 0.06 |
| all (92) | decode + retrained | 24.10 ± 9.61 / 98.40 ± 0.36 | 29.73 ± 9.81 / 98.63 ± 0.06 | 40.60 ± 1.15 / 99.97 ± 0.06 | 70.97 ± 13.71 / 79.00 ± 17.51 |

## D. Padding attacks

500 attacks and 500 benign test queries (first 500 of each class of the phase 3b truncation sample) with 146 tokens of benign training text. Plain text before or after is the phase 3b test; the comment forms keep the SQL valid.

| Padding | Pipeline | DistilBERT-Stacked Ensemble recall / FPR | DistilBERT-SVM recall / FPR | Structure-aware BERT-GNN recall / FPR | BERT-only (MLP) recall / FPR |
|---|---|---|---|---|---|
| plain text after | raw | 10.40 ± 0.00 / 0.20 ± 0.00 | 10.40 ± 0.00 / 0.20 ± 0.00 | 42.47 ± 5.70 / 0.00 ± 0.00 | 7.93 ± 1.22 / 0.20 ± 0.00 |
| plain text after | raw + windows | 71.60 ± 0.00 / 2.40 ± 0.00 | 73.13 ± 0.23 / 2.40 ± 0.00 | 85.73 ± 0.31 / 1.13 ± 0.12 | 76.13 ± 2.08 / 6.80 ± 5.20 |
| plain text after | decode + retrained | 59.40 ± 0.00 / 0.20 ± 0.00 | 59.40 ± 0.00 / 0.20 ± 0.00 | 61.07 ± 2.04 / 0.00 ± 0.00 | 57.40 ± 1.06 / 0.20 ± 0.00 |
| plain text after | decode + retrained + windows | 86.87 ± 0.12 / 2.40 ± 0.00 | 87.07 ± 0.12 / 2.40 ± 0.00 | 86.93 ± 0.23 / 1.13 ± 0.12 | 88.73 ± 0.70 / 11.67 ± 3.23 |
| plain text before | raw | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 |
| plain text before | raw + windows | 98.00 ± 0.00 / 4.07 ± 0.46 | 98.20 ± 0.00 / 3.33 ± 0.23 | 97.13 ± 0.70 / 1.00 ± 0.00 | 98.07 ± 0.61 / 8.07 ± 3.70 |
| plain text before | decode + retrained | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 |
| plain text before | decode + retrained + windows | 97.60 ± 0.00 / 3.40 ± 0.20 | 97.60 ± 0.00 / 2.67 ± 0.12 | 97.00 ± 0.53 / 1.00 ± 0.00 | 97.13 ± 1.10 / 5.53 ± 0.81 |
| line comment after | raw | 11.20 ± 0.00 / 0.20 ± 0.00 | 11.40 ± 0.00 / 0.20 ± 0.00 | 76.47 ± 5.14 / 0.40 ± 0.35 | 9.67 ± 1.21 / 0.20 ± 0.00 |
| line comment after | raw + windows | 75.93 ± 0.23 / 6.80 ± 0.00 | 77.47 ± 0.12 / 6.80 ± 0.00 | 97.47 ± 0.12 / 3.00 ± 0.60 | 81.13 ± 1.94 / 8.80 ± 6.24 |
| line comment after | decode + retrained | 99.80 ± 0.00 / 14.27 ± 0.61 | 99.80 ± 0.00 / 16.20 ± 0.00 | 99.80 ± 0.00 / 4.07 ± 1.72 | 99.73 ± 0.12 / 17.47 ± 4.58 |
| line comment after | decode + retrained + windows | 99.80 ± 0.00 / 14.27 ± 0.61 | 99.80 ± 0.00 / 16.20 ± 0.00 | 99.80 ± 0.00 / 4.27 ± 1.72 | 99.73 ± 0.12 / 17.47 ± 4.58 |
| block comment before | raw | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 | 0.00 ± 0.00 / 0.00 ± 0.00 |
| block comment before | raw + windows | 97.80 ± 0.00 / 3.93 ± 0.23 | 97.40 ± 0.00 / 3.80 ± 0.00 | 98.00 ± 0.53 / 2.20 ± 0.92 | 98.53 ± 0.31 / 11.67 ± 2.80 |
| block comment before | decode + retrained | 99.40 ± 0.00 / 0.20 ± 0.00 | 99.40 ± 0.00 / 0.20 ± 0.00 | 98.80 ± 0.20 / 0.27 ± 0.12 | 99.27 ± 0.23 / 0.27 ± 0.12 |
| block comment before | decode + retrained + windows | 99.40 ± 0.00 / 0.20 ± 0.00 | 99.40 ± 0.00 / 0.20 ± 0.00 | 98.80 ± 0.20 / 0.47 ± 0.12 | 99.27 ± 0.23 / 0.27 ± 0.12 |

## E. Short and long queries

Length in BERT tokens of the raw query. Long queries (> 128 tokens) are also shown with windows.

| Tokens | Queries (attacks) | Pipeline | DistilBERT-Stacked Ensemble recall / FPR | DistilBERT-SVM recall / FPR | Structure-aware BERT-GNN recall / FPR | BERT-only (MLP) recall / FPR |
|---|---|---|---|---|---|---|
| 1-8 | 2059 (66) | raw | 86.36 ± 0.00 / 0.10 ± 0.00 | 86.36 ± 0.00 / 0.05 ± 0.00 | 79.29 ± 3.15 / 0.43 ± 0.10 | 78.28 ± 2.31 / 0.15 ± 0.05 |
| 1-8 | 2059 (66) | decode + retrained | 90.91 ± 0.00 / 0.20 ± 0.00 | 87.88 ± 0.00 / 0.15 ± 0.00 | 81.82 ± 2.62 / 0.47 ± 0.12 | 82.32 ± 8.34 / 0.27 ± 0.15 |
| 9-16 | 3283 (522) | raw | 100.00 ± 0.00 / 0.04 ± 0.00 | 100.00 ± 0.00 / 0.04 ± 0.00 | 99.30 ± 0.22 / 0.04 ± 0.00 | 99.68 ± 0.11 / 0.04 ± 0.04 |
| 9-16 | 3283 (522) | decode + retrained | 100.00 ± 0.00 / 0.04 ± 0.00 | 100.00 ± 0.00 / 0.04 ± 0.00 | 99.36 ± 0.11 / 0.04 ± 0.00 | 99.68 ± 0.22 / 0.02 ± 0.02 |
| 17-32 | 2044 (1171) | raw | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 99.89 ± 0.05 / 0.27 ± 0.07 | 99.97 ± 0.05 / 0.11 ± 0.00 |
| 17-32 | 2044 (1171) | decode + retrained | 100.00 ± 0.00 / 0.23 ± 0.00 | 100.00 ± 0.00 / 0.11 ± 0.00 | 99.91 ± 0.00 / 0.34 ± 0.11 | 99.83 ± 0.09 / 0.11 ± 0.00 |
| 33-64 | 1196 (1009) | raw | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 99.90 ± 0.00 / 0.53 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 |
| 33-64 | 1196 (1009) | decode + retrained | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 99.90 ± 0.00 / 0.53 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 |
| 65-128 | 599 (586) | raw | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 |
| 65-128 | 599 (586) | decode + retrained | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 |
| >128 | 95 (92) | raw | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 66.67 ± 0.00 |
| >128 | 95 (92) | decode + retrained | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 0.00 ± 0.00 | 100.00 ± 0.00 / 77.78 ± 19.25 |
| >128 | 95 (92) | raw + windows | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 |
| >128 | 95 (92) | decode + retrained + windows | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 | 100.00 ± 0.00 / 100.00 ± 0.00 |

## F. Novel attacks

### Leave one attack type out of training (seed 42, raw pipeline)

Training attacks of the type are removed; the model is tested on the test attacks of that type it never saw. Cells: detection without the type in training (with it, main model) / FPR on all benign test queries.

| Attack type | Training attacks removed | Test attacks | DistilBERT-Stacked Ensemble | DistilBERT-SVM | Structure-aware BERT-GNN | BERT-only (MLP) |
|---|---|---|---|---|---|---|
| time-based | 1061 | 524 | 97.9 (99.8) / 0.10 | 98.3 (100.0) / 0.09 | 96.9 (99.4) / 0.24 | 95.4 (99.4) / 0.05 |
| error-based | 795 | 350 | 100.0 (100.0) / 0.12 | 100.0 (100.0) / 0.09 | 100.0 (100.0) / 0.38 | 100.0 (100.0) / 0.10 |
| union-based | 1486 | 620 | 97.1 (100.0) / 0.12 | 97.7 (99.8) / 0.10 | 85.5 (99.8) / 0.26 | 96.6 (99.8) / 0.12 |
| boolean / tautology | 3136 | 1321 | 100.0 (100.0) / 0.12 | 100.0 (100.0) / 0.10 | 99.4 (99.9) / 0.38 | 98.4 (100.0) / 0.14 |
| other | 1454 | 628 | 94.4 (98.7) / 0.05 | 94.1 (98.7) / 0.05 | 93.0 (98.2) / 0.09 | 92.7 (97.8) / 0.05 |

### Curated out-of-distribution set (phase 3: 35 attacks, 34 benign)

| Pipeline | DistilBERT-Stacked Ensemble recall / FPR | DistilBERT-SVM recall / FPR | Structure-aware BERT-GNN recall / FPR | BERT-only (MLP) recall / FPR |
|---|---|---|---|---|
| raw | 100.0 ± 0.0 / 2.9 ± 0.0 | 100.0 ± 0.0 / 3.9 ± 1.7 | 100.0 ± 0.0 / 13.7 ± 3.4 | 100.0 ± 0.0 / 8.8 ± 5.1 |
| decode at test time only | 100.0 ± 0.0 / 2.9 ± 0.0 | 100.0 ± 0.0 / 2.9 ± 0.0 | 100.0 ± 0.0 / 10.8 ± 3.4 | 100.0 ± 0.0 / 8.8 ± 5.1 |
| decode + retrained | 100.0 ± 0.0 / 7.8 ± 1.7 | 100.0 ± 0.0 / 8.8 ± 0.0 | 100.0 ± 0.0 / 13.7 ± 3.4 | 100.0 ± 0.0 / 12.7 ± 1.7 |

## Notes

- Raw-pipeline disguise results are the phase 3b cached predictions for the same sample and seeds.
- 'Decode at test time only' keeps the phase 3b models; 'decode + retrained' retrains the four models on canonicalised training queries with the phase 3b procedure.
- Line-comment text is removed, so benign text after '#' (for example an invoice number) is also removed.
- Leave-one-type-out uses the rule-based categories of phase 3b section E.
- Distinct strings embedded: 63548.

Reproduce: `python merged_phase3c_defences.py` (after phase 3b; P3B_WORK, WORK_DIR, SQLMAP_DIR).