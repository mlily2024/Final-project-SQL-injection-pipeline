# Robustness test 3: extended obfuscation battery

Detection rate (recall) on 3446 malicious test queries under further WAF-bypass operators, extending the five in `obfuscation_robustness.md`. Higher is more robust to evasion.

| Obfuscation operator | Structure-GNN recall (%) | BERT-only recall (%) | GNN more robust |
|---|---|---|---|
| double_url_encode | 99.74 | 99.62 | yes |
| keyword_split(/**/) | 99.36 | 99.62 | no |
| mysql_versioned_comment | 99.65 | 99.68 | tie |
| mixed_whitespace | 99.45 | 99.56 | no |

Together with URL-encoding (test in `obfuscation_robustness.md`), this profiles the models across the common evasion families. Reproduce with `python robustness_3_obfuscation_extended.py`.
