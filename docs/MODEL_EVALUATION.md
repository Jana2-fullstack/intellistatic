# Binary PE baseline: evaluation and limits

## Purpose

The dashboard's classifier is a research baseline for triage. It does not certify that a file is safe, prove that it is malware, or identify a malware family. The displayed model score is a raw Random Forest class score, not a calibrated real-world probability.

## Dataset and preparation

- Source file: `data/MalwareDataSet.csv`.
- The bundled project README describes 137,444 PE metadata rows with a `legitimate` target (`1` legitimate, `0` malware).
- The upstream dataset URL and per-file hashes are not preserved in this project. This limits independent verification of source, collection date, duplicate files, and label quality.
- The model uses the seven dataset fields also extracted by IntelliStatic: entry point, linker version, image version, operating-system version, DLL characteristics, stack reserve size, and section count.
- The dataset's `ResourceSize` field is excluded because the current extractor does not calculate the same field.
- Identical seven-field vectors were grouped before splitting to prevent copies of the same feature vector appearing in both training and holdout sets. Groups with conflicting labels were excluded.

## Evaluation protocol

The training script uses seed 42 and a stratified 80/20 split over distinct, non-conflicting feature vectors. It trains on 20,972 unique vectors and evaluates on a holdout of 5,243 vectors. The metrics below were produced by `python ml_training/train_pe_baseline.py`.

| Metric | Holdout result |
|---|---:|
| Accuracy | 92.24% |
| Balanced accuracy | 91.70% |
| Malware precision | 83.01% |
| Malware recall | 90.50% |
| Malware ROC AUC | 97.70% |

Confusion matrix, rows = actual class and columns = predicted class (`malware`, `legitimate`):

| | Predicted malware | Predicted legitimate |
|---|---:|---:|
| Actual malware | 1,314 | 138 |
| Actual legitimate | 269 | 3,522 |

At this threshold, 269 legitimate feature vectors in the holdout were flagged as malware and 138 malware vectors were missed. The score must be interpreted with this error tradeoff in mind.

## Limitations

- The holdout is a random split of unique feature vectors, not a temporal, vendor-separated, family-separated, or campaign-separated benchmark.
- Feature vectors are only seven numeric PE header fields. Many distinct files can share the same values; malicious behavior is not represented directly.
- Source provenance, sample hashes, collection dates, and original file bytes are unavailable for the bundled CSV.
- Raw Random Forest class scores are not calibrated and must not be described as the probability that a file is malware.
- YARA hits are string-pattern indicators and may match legitimate installers. A hit is not proof; no hit is not proof of safety.
- Malware family prediction is unavailable because the labeled dataset contains only a binary legitimacy label.

For a stronger academic result, use a documented, licensed dataset with sample hashes and collection dates, split by time or source, report confidence intervals and calibration, and independently validate on samples from a separate source. Do not present the current holdout score as expected production accuracy.
