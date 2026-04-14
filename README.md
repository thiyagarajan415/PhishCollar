# 🛡️ PhishCollar: AI-Powered Phishing Detection Microservice

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Stacking%20Ensemble-ff69b4.svg)
![Deployment](https://img.shields.io/badge/Deployed-Render-brightgreen.svg)

## 📌 Project Overview
PhishGuard (formerly PhishCollar) is an end-to-end Machine Learning microservice designed to detect zero-day phishing URLs with state-of-the-art accuracy. Moving beyond traditional Jupyter Notebook data science, this project packages advanced machine learning architecture into a high-concurrency RESTful API, complete with a responsive web dashboard and automated adversarial testing.

The system utilizes a **Dual-Tier AI Architecture** to balance real-time processing speed with maximum security, achieving a peak accuracy of **97.49%** while effectively halving the False Negative rate of baseline literature.

## ✨ Architectural Novelty

* **🧬 Evolutionary Feature Selection:** Implemented Genetic Algorithms to optimize a multi-objective fitness function. By mathematically isolating the 19 most critical URL features, the system reduces the computational payload by **36%** for high-speed edge deployment.
* **🧠 Level-1 Stacking Meta-Ensemble:** Surpassed traditional benchmark models by architecting a Stacking Titan (combining XGBoost, LightGBM, and CatBoost). A Logistic Regression meta-learner analyzes their disagreements to make the final classification.
* **🎯 Dynamic Decision Boundaries:** Utilized Isotonic Probability Calibration and threshold tuning to shift the model's decision boundary. This prioritizing security over raw accuracy, successfully dropping the False Negative (missed attack) rate to just **1.6%**.
* **🔍 Explainable AI (XAI):** Integrated SHAP (SHapley Additive exPlanations) to eliminate the "black-box" nature of neural networks, providing visual, feature-level attribution for every URL flagged as malicious.

## 🛠️ Tech Stack
* **Backend Interface:** Python, FastAPI, Uvicorn
* **Machine Learning Engine:** Scikit-Learn, XGBoost, LightGBM, CatBoost
* **Optimization:** Optuna (Bayesian Tuning), `sklearn-genetic-opt`
* **Quality Assurance:** Pytest (Adversarial Evasion Testing)
* **Frontend UI:** Vanilla JavaScript, HTML5, CSS3
* **Deployment:** Render Cloud Platform

🚀 Local Installation & Setup
1. Clone the repository

Bash
git clone [https://github.com/yourusername/PhishGuard-ML.git](https://github.com/yourusername/PhishGuard-ML.git)
cd PhishGuard-ML
2. Create a virtual environment

Bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
3. Install dependencies

Bash
pip install -r requirements.txt
4. Start the Uvicorn server

Bash
python -m uvicorn src.api:app --reload
The API and interactive dashboard will now be running at http://127.0.0.1:8000

## 📂 Repository Structure

```text
PhishGuard-ML/
│
├── data/                       # (Ignored) Raw dataset files
├── notebooks/                  
│   └── main_pipeline.ipynb     # Research, Training, and Hyperparameter Tuning
├── models/
│   ├── genetic_stacking_ensemble.pkl  # Tier 1 Edge Model (19 Features)
│   ├── academic_stacking_ensemble.pkl # Tier 2 Cloud Model (30 Features)
│   └── optimal_threshold.pkl          # Calibrated decision boundary
├── src/
│   ├── api.py                  # FastAPI Backend Application
│   ├── test_api.py             # Pytest automated test suite
│   └── static/                 
│       └── index.html          # Web Interface Dashboard
│
├── requirements.txt            # Production dependencies
├── .gitignore
└── README.md

