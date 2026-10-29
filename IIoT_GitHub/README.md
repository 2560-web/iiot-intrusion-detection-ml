# Industrial IoT Intrusion Detection — Machine Learning Demo

A portfolio demonstration of binary **normal vs attack** network traffic classification using the Edge-IIoTset dataset. The original MSc experiments were developed in 2024; this repository is a **2026 reconstructed implementation** using preserved code discussions and reported outputs, with a separate controlled evaluation.

## Live demo

**[Open the browser demonstration](https://YOUR-USERNAME.github.io/industrial-iot-intrusion-detection/)** — replace `YOUR-USERNAME` with your GitHub username after enabling Pages.

The static demo shows saved evaluation evidence and example predictions. **It does not run a model in the browser.** To run fresh inference locally, use the Python server below.

## Run locally (no .bat files)

Requires Python 3.11+; inspect the code and install dependencies only if you trust them.

```bash
python -m pip install -r requirements.txt
python server.py
```

Open http://127.0.0.1:8765. Use the bundled example data. The included `joblib` model is a Python serialized object: **only load this file if you trust its source**; never load untrusted joblib files.

## What's included

- `index.html`: standalone browser demo for GitHub Pages
- `web/`: original interface assets
- `server.py`: local Python inference server
- `pipeline.py`: controlled training/evaluation workflow
- `restored_workflow.py` and `Restored-IIoT-Experiment.ipynb`: reconstructed historical workflow
- `models/traffic_model.joblib`: saved model (not executable in GitHub Pages)
- `evidence/`: saved evaluation summaries and verification metadata
- `data/`: limited demonstration samples and dataset attribution; **not the full dataset**

## Results and limitations

The **original reported** Random Forest experiment achieved 100% on a random test split, but that score may be inflated by leakage/capture-specific features. The **separate reconstructed controlled experiment** reports approximately 96.75% holdout accuracy, with additional leakage precautions. These numbers describe different experiments and are not interchangeable. Independent deployment performance is unverified.

This is **network attack detection**, not a direct measurement of energy consumption; no energy savings are claimed. The original raw CSV is not included.

## Data credit

Edge-IIoTset: Ferrag et al. (2022), *IEEE Access*, DOI: https://doi.org/10.1109/ACCESS.2022.3165809. Dataset: https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot. Review dataset licence before reuse.

## Provenance

This is a **restored/reconstructed** project assembled with AI assistance from earlier code discussions and dissertation records, not a claim that the original 2024 notebook or original raw dataset was recovered intact.
