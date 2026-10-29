# Industrial IoT Intrusion Detection Using Machine Learning

**Python | Machine Learning | Cybersecurity | Industrial IoT | Scikit-learn**

[**View Live Demonstration**](https://2560-web.github.io/iiot-intrusion-detection-ml/)

## Project Overview

This project investigates how machine-learning techniques can identify normal and malicious network traffic in Industrial Internet of Things (IIoT) environments.

Industrial IoT systems connect sensors, devices and industrial infrastructure through networks. These connections improve monitoring and automation, but they also create potential cybersecurity risks.

My objective was to explore how network traffic data could be processed, analysed and classified to help distinguish legitimate activity from potential attacks.

The project formed part of my postgraduate computer science work at Queen Mary University of London.

## What I Worked On

- Exploring and preparing network traffic data from the Edge-IIoTset dataset.
- Cleaning data, handling duplicate records and preparing features for machine-learning models.
- Training and evaluating classification algorithms, including Random Forest.
- Comparing predictions against known traffic labels.
- Analysing model performance using classification metrics and visualisations.
- Developing a Python-based workflow for reproducing the experiment.
- Building a browser demonstration to make the project's outputs easier to explore.

## Technologies Used

| Area | Technologies |
|---|---|
| Programming | Python |
| Data analysis | Pandas, NumPy |
| Machine learning | Scikit-learn, Random Forest |
| Development | Jupyter Notebook |
| Evaluation | Accuracy, precision, recall, F1-score, confusion matrix |
| Demonstration | HTML, Python web server |
| Version control | GitHub |

## Dataset

The project uses the **Edge-IIoTset** dataset, which contains network traffic information associated with normal behaviour and different attack categories in IoT and IIoT environments.

The machine-learning workflow focuses on distinguishing normal traffic from attack traffic.

The original full dataset is not included in this repository. The repository contains recovered project materials and supporting example data where available.

## Machine-Learning Workflow

1. **Data exploration:** Inspect the dataset, labels, features and data quality.
2. **Preprocessing:** Clean records and prepare suitable inputs for classification.
3. **Model training:** Train machine-learning classifiers using labelled network traffic.
4. **Evaluation:** Compare predicted labels with actual labels and examine classification metrics.
5. **Demonstration:** Present the workflow and recorded outputs through a browser interface.

## Results and Evaluation

The original academic experiment reported very high classification performance, including a reported 100% Random Forest accuracy.

However, results of this kind require careful interpretation. Data leakage, duplicate records, preprocessing choices and the way training and test data are separated can affect measured performance.

A separate reconstructed evaluation reported approximately **96.75% accuracy** under its own testing procedure.

These figures come from different experimental runs and should not be treated as directly comparable. The evaluation materials are included so the methods and results can be examined.

## Live Demonstration

**[Open the IIoT Traffic Lab](https://2560-web.github.io/iiot-intrusion-detection-ml/)**

The browser demonstration presents recorded project outputs and example traffic classifications.

**Important:** The GitHub Pages demonstration is a static website. It does not run the Python machine-learning model on GitHub's servers. The Python code and saved model are provided separately for local execution.

## Repository Contents

The repository includes:

- Python source code for the machine-learning workflow.
- A restored Jupyter notebook.
- Model and supporting evaluation artifacts.
- Example data and documentation.
- A browser-based demonstration.
- Python dependency information.

## Reproducibility and Project Recovery

This repository contains a reconstruction of my earlier academic project using surviving code, reports, experimental records and related materials.

Some original files, including the complete raw dataset, were not available during recovery. Consequently, the restored workflow and its results should be distinguished from the original academic experiment.

The reconstructed materials are intended to make the available technical work easier to inspect, understand and demonstrate. They should not be interpreted as a byte-for-byte reproduction of the original environment.

## What I Learned

This project strengthened my understanding of how machine learning can be applied to cybersecurity problems, particularly the importance of preparing network data, selecting appropriate evaluation methods and interpreting results critically.

It also gave me practical experience working across data analysis, Python development, model evaluation and technical documentation.

---

**Academic background:** MSc Computer Science, Queen Mary University of London

**Project focus:** Machine Learning, Network Security and Industrial IoT
