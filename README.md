# IIoT Traffic Lab

A working IIoT traffic-classification project restored from Prem Armstrong D's original ChatGPT code discussions and QMUL ECS750P dissertation. **406 messages across three relevant conversations have been recovered**, including the complete original code pastes and outputs. The archive, runnable restoration and separate controlled demo are kept distinct. See docs/RESTORATION.md.

## Try it

Open web/index.html for a standalone evidence preview. Its example replay uses recorded held-out predictions. For fresh predictions, extract the complete folder, open a terminal there and use Python 3.11 or newer:

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python server.py
```

Open http://127.0.0.1:8765. Replay a real held-out example, or download the sample CSV from the interface and upload it to run fresh inference. The server listens on localhost only. No dataset download is needed to use the bundled model. Load only the trusted bundled model; Python joblib files are executable serialization, not a safe user upload format.

## Reproduce the experiment

The full dataset is not bundled. Download `ML-EdgeIIoT-dataset.csv` from the authors' Kaggle page below and place it in data/. The raw file contains 157,800 records. The restored preprocessing removes the same 814 duplicates and reproduces the historical 156,986-row dataset.

```sh
python restored_workflow.py
python pipeline.py
python build_preview.py
```

The data/provenance.json file records the downloaded CSV's SHA-256. evidence/results.json contains measured metrics, schema, exclusions, split counts, timing, versions and limitations. evidence/holdout_predictions.csv contains every test-row prediction and its source row index (zero-based data row, excluding the CSV header). Running training replaces the bundled model and evaluation files.

## What was measured

The new run uses 40 numeric features and an 80/20 split of unique input-vector groups. Identical inputs cannot occur on both sides, although row counts need not be exactly 80/20. Numeric medians are fitted on training data only. Attack_type, hosts, timestamps, topics and payload strings are not model inputs. Conflicting input/label groups are reported, not silently removed. Random Forest is compared with a majority baseline and a TCP-only forest on the same holdout. Three-fold grouped CV is run on the training partition only; no parameter search uses the holdout.

The final holdout accuracy is about 96.75%, with attack F1 about 98.08%. These are NEW results from the separate controlled experiment. The historical restoration, in contrast, reproduces the reported 100% test accuracy and confusion matrix; its whole-dataset preprocessing and identity/capture predictors limit what that score establishes. The restoration has 87 assembled model features rather than the report's 97 preprocessing columns. Both results are kept in evidence/. The data are class-imbalanced; consult balanced accuracy and the confusion matrix alongside accuracy/F1. The test set is held out from fitting and tuning, but is used for the final comparison and displayed examples; it should not be reused for iterative tuning.

## What remains uncertain

Grouping only controls exact numeric-vector overlap, not device/session/time relationships. Capture artefacts, related traffic and protocol fingerprints can still inflate performance. One dataset does not demonstrate independent-site generalisation. This is an offline classifier, not a deployed intrusion detector. Predictions are uncalibrated scores. No watt/joule measurements exist here, and no energy-saving claim is made. Performance timing is wall-clock duration on this machine, not an energy benchmark.

## Provenance and rights

Original academic report: `DissertationandReflectiveEssayECS750P.pdf`, read from the user's supplied materials; not redistributed in this package because it contains personal academic identifiers. The original source-message text is preserved in original/. The runnable assembly, server, interface, duplicate-group validation and fresh evaluations were created with ChatGPT assistance in October 2026; original archived text was not rewritten. First-person portfolio descriptions should be reviewed by Prem before publishing.

Dataset: Mohamed Amine Ferrag, Othmane Friha, Djallel Hamouda, Leandros Maglaras and Helge Janicke (2022), Edge-IIoTset, IEEE Access, DOI 10.1109/ACCESS.2022.3165809.

- Paper: https://doi.org/10.1109/ACCESS.2022.3165809
- Authors' dataset: https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot
- Kaggle metadata retrieved 24 October 2026 lists **CC BY-NC-SA 4.0**, version 5. See data/dataset_metadata.json. The small numeric sample extracts retain that attribution and dataset licence. Do not assume commercial-use permission; review upstream terms before reuse. Full raw data are excluded from this package.

This is a local review build. It has not been published to a public website or repository. The original notebook binary and attachment images/PDFs were not exported. See evidence/verification.json for completed checks and docs/RESTORATION.md for precise scope.
