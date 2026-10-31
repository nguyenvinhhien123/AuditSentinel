# AuditSentinel

**ML-based database audit-log analysis with human-reviewed, offline response simulation.**

AuditSentinel is a local desktop application for training and evaluating machine-learning models on database audit logs, reviewing alerts, investigating them with a local Ollama model, and preparing response proposals. Prevention and response actions are simulations only; this project does not connect to or change a live database or firewall.

## What the agents do

The application has three sequential roles. They are workflow agents, not three independent LLMs:

1. **Detection Agent** — runs a registered scikit-learn model against audit-log records and saves suspicious/anomalous alerts.
2. **Investigation Agent** — asks a local Ollama language model to summarize evidence for a selected alert and saves the report. It does not run SQL or commands.
3. **Response Agent** — uses predefined rules to propose safe review steps from the alert and report. This role is rule-based, not a separate AI model. The operator must review/approve actions, and execution is simulation-only.

The separate **Prevention Simulation** page can simulate approved IP/user policies against later records in an offline dataset. No real account, session, network control, database, or firewall is modified.

## Work flow

<img width="975" height="576" alt="image" src="https://github.com/user-attachments/assets/83fc6c79-371f-4700-b723-e9e250744dbc" />


## Requirements

- Windows 10/11
- Python 3.11 or newer
- Ollama is optional for training/detection, but required for the Investigation Agent. The configured default model is `qwen2.5:1.5b`.

## Run from source

Open PowerShell in the cloned repository:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

To use the Investigation Agent, install Ollama, start its local service, and download the configured model:

```powershell
ollama serve
ollama pull qwen2.5:1.5b
```

If Ollama is already running as a background service, only run the `pull` command. The service should be available at `http://localhost:11434`, as configured in `config.yaml`.

## Quick start

1. Open **ML Training** and choose an audit dataset (`CSV`, `TSV`, `JSONL`, `NDJSON`, or `Parquet`).
2. Choose **Unsupervised / anomaly** when records have no labels. Choose **Supervised / labeled** when every row has a label column such as `normal` or `attack`; enter that column's name.
3. Click **Train and register**. Training requires at least 10 records.
4. Open **Model Registry**, select the new model, and click **Activate selected**.
5. Open **Detection & Alerts** (Agent 1), select an audit dataset and the matching model mode, then click **Run detection**.
6. Open **AI Investigation** (Agent 2), select an alert, and click **Investigate**. This step requires Ollama.
7. Open **Response Management** (Agent 3) and click **Propose from investigation**. Review actions; approval/simulation does not perform real containment.
8. Use **Reports** to export a local HTML or JSON operational summary.

The repository includes a synthetic labeled sample at `dataset/samples/auditsentinel_training_sample.csv`. It is only for trying the workflow; its metrics do not represent real-world performance. Use your own lawful audit data for meaningful evaluation.

## Work sessions

The session selector in the top bar lets you create a new work session or return to an existing one. Alerts, investigation reports, response actions, prevention simulation history, and selected dataset paths are isolated per session under `sessions/<session-id>/` or saved in the session index. The first entry, **Existing Data**, points to the original `logs/` and `reports/` folders so earlier records remain available. No history is deleted when switching or creating a session.

The model registry and trained models remain shared across sessions; switching work sessions does not require retraining. The selected dataset files themselves remain wherever the user stored them.

## Data formats and privacy

Training supports `CSV`, `TSV`, `JSONL`, `NDJSON`, and `Parquet`. Supervised mode requires a label on every record, at least two classes, and at least two records in each class. Unsupervised results are anomaly flags, not confirmed attacks.

Audit logs can contain credentials, personal information, SQL statements, or internal infrastructure details. Keep private datasets, trained model files, logs, and reports out of public repositories. The included `.gitignore` excludes local data/artifacts and the custom user icon; the bundled default icon is used when a custom icon is not present.

The investigation prompt treats log contents as untrusted input. Nevertheless, review sensitive-data handling and model/network configuration before using the application with production logs.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

## Current limitations

- Offline files only; no live database connector or production blocking.
- Response and prevention are manual-approval simulations.
- Investigation uses the locally running Ollama service; it is not required for training or detection.
- Detection quality depends on representative data, labels, and evaluation. A high score on synthetic data is not evidence of production accuracy.

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE).
