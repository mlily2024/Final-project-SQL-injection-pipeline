# Robustness suite: overview

Seven independent robustness tests comparing the structure-aware BERT-GNN with a BERT-only classifier, on the same held-out test set. Each is reproducible from its own script; the shared harness is `robustness_common.py`.

| # | Test | Finding | GNN more robust? |
|---|---|---|---|
| 1 | Sensitivity ([node removal + feature noise](robustness_sensitivity.md)) | Feature-noise flip rate 0.66% vs 9.47% (sigma=0.5); node removal 0.19% flip at 30% | **Yes** |
| 2 | Adversarial ([FGSM / PGD](robustness_adversarial.md)) | Robust to weak attacks; under strong white-box attacks the GNN is more vulnerable (larger perturbable surface) | No (honest) |
| 3 | [Extended obfuscation](robustness_obfuscation_extended.md) | Both robust to double-encode, keyword-split, MySQL comments, mixed whitespace (99.4-99.7%) | Tie |
| 4 | [Adaptive best-of-N evasion](robustness_adaptive.md) | Evasion rate 1.25% vs 8.00% (about 6x harder to evade) | **Yes** |
| 5 | [Out-of-distribution](robustness_crossdataset.md) | Both detect 100% of novel canonical attacks; GNN half the false-alarm rate (5.9% vs 11.8%) | **Yes (precision)** |
| 6 | [Statistical significance](robustness_significance.md) | URL-encode gap 7.84 pts, 95% CI [6.76, 8.91], McNemar p=1.95e-47; clean data equivalent | Confirms |
| 7 | [Calibration under attack](robustness_calibration.md) | Under URL encoding BERT-only is twice as miscalibrated and confidently wrong (0.82 conf on 333 missed) | **Yes** |

## What the suite shows, honestly

The structure-aware model is **more robust to realistic threats**: random corruption (test 1), realistic and adaptive evasion (tests 4 and the URL-encode result, significant per test 6), out-of-distribution benign inputs (test 5, fewer false alarms), and it stays **better calibrated under attack** (test 7). It is **not** more robust to worst-case white-box gradient attacks (test 2), because the graph exposes a much larger perturbable surface than a single sentence embedding; and against most single obfuscation operators both models are already strong (test 3). On clean data the two are statistically equivalent (test 6).

The overall message for deployment is that modelling SQL structure buys resilience to the evasion and distribution-shift a web application firewall actually faces, while worst-case adversarial robustness for either model would require dedicated adversarial training. Reporting the mixed test-2 result alongside the positive ones is deliberate: the robustness claim is specific and evidence-based, not universal.
