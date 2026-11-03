# AuditSentinel User Guide

*Database audit-log analysis, alert investigation, and offline response simulation*

This guide explains how to install and use AuditSentinel, a local desktop application for analyzing database audit logs.

> **Important safety note:** AuditSentinel analyzes local files. It does not connect to a live database, execute SQL, block database activity, modify accounts or sessions, or change a firewall. Response actions and prevention policies are human-reviewed simulations only. Treat generated alerts and model outputs as decision support, not confirmed incidents.

## Contents

1. [Project overview](#1-project-overview)
2. [Requirements and installation](#2-requirements-and-installation)
3. [Start the application and choose a session](#3-start-the-application-and-choose-a-session)
4. [Step-by-step workflow](#4-step-by-step-workflow)
5. [Optional: offline prevention simulation](#5-optional-offline-prevention-simulation)
6. [Export reports](#6-export-reports)
7. [Data handling, privacy, and limitations](#7-data-handling-privacy-and-limitations)
8. [Troubleshooting and quick reference](#8-troubleshooting-and-quick-reference)

## 1. Project overview

AuditSentinel trains and evaluates machine-learning models on database audit logs, reviews alerts, investigates selected alerts with a locally hosted Ollama language model, and prepares rule-based response proposals.

| Component | Purpose |
|---|---|
| Detection Agent | Runs an active registered scikit-learn model against records and stores suspicious or anomalous alerts. |
| Investigation Agent | Uses the configured local Ollama model to summarize evidence for a selected alert and saves a report. It does not execute SQL or system commands. |
| Response Agent | Applies predefined rules to the alert and investigation report to create proposals. A human must approve; execution is simulation-only. |
| Prevention Simulation | Evaluates explicitly approved IP/user policies against later rows in an offline dataset and records what would have been blocked. |

These are sequential workflow roles, not three independent AI models. Detection uses the registered ML model, Investigation uses Ollama, and Response is rule-based.

### Main application pages

| Page | Use |
|---|---|
| Dashboard | Review an overview of local models, alerts, and workflow status. |
| Dataset & Ingestion | Scan a local file or folder, preview a supported file, and import it into the ingestion pipeline. This is optional; training and detection pages can select files directly. |
| ML Training / Model Registry | Train a model, verify its integrity, and explicitly activate it for detection. |
| Detection & Alerts / Alert Monitoring | Analyze a dataset, review model results, acknowledge alerts, and resolve alerts with a note. |
| AI Investigation / Response Management | Run a local-model investigation and create, review, approve or reject, and simulate response proposals. |
| Prevention Simulation | Evaluate approval-gated policies against later rows in an offline dataset. |
| Reports / System Status | Export an operational summary and inspect local paths and safety settings. |

After an operation completes, its page shows a concise result summary above the full JSON details. Existing tables continue to show records such as alerts, models, proposals, and simulation runs.

## 2. Requirements and installation

- Windows 10 or Windows 11
- Python 3.11 or newer
- Ollama is optional for training and detection, but required for AI Investigation. The configured default model is `qwen2.5:1.5b`.
- Use only audit data you are authorized to process. Make a protected working copy when appropriate.

### Install from source

Open PowerShell in the cloned project folder (the folder containing `run.py`) and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

If PowerShell does not allow activating the virtual environment, you can invoke its Python directly after installing dependencies:

```powershell
.\.venv\Scripts\python.exe run.py
```

### Enable local AI investigation (optional)

Install Ollama, then make sure its local service is running and download the configured model. If the Ollama service is not already running, open a separate PowerShell window and run:

```powershell
ollama serve
```

In another PowerShell window, download the configured model:

```powershell
ollama pull qwen2.5:1.5b
```

The application is configured to contact Ollama at `http://localhost:11434`. If Ollama is already running as a background service, only the model download is needed. Training and detection do not require Ollama.

## 3. Start the application and choose a session

1. Launch the desktop app with `python run.py` from the project root.
2. The main window has a left navigation menu and a session selector in the top bar.
3. Use the existing session or choose **New session** to isolate a separate work run. Switch sessions from the selector when returning to prior work. Use the trash button beside the selector to permanently delete the selected session after confirmation. **Existing Data** cannot be deleted; deleting the active session switches to **Existing Data** first.
4. Alerts, investigation reports, response actions, prevention simulation history, and selected dataset paths are stored per session. The model registry and trained models are shared across sessions.

The **Existing Data** session points to the original `logs/` and `reports/` folders. Creating or switching sessions does not delete history. Dataset files remain at their original locations.

### Supported audit dataset formats

The workflow accepts CSV, TSV, JSONL, NDJSON, and Parquet files. Training, detection, and prevention load the selected data locally. Select files with the appropriate columns for the task; supervised training requires a label field on every record.

## 4. Step-by-step workflow

![AuditSentinel system workflow](assets/auditsentinel-workflow.svg)

### Step 1 — (Optional) inspect or import a dataset

1. Open **Dataset & Ingestion** and choose **Select File** or **Select Folder**.
2. Click **Scan Selected Path**. Review the file name, format, size, and scan status in the results table.
3. Select a supported file and click **Preview Selected File** to inspect a bounded preview.
4. If appropriate, click **Import Selected File** to pass the file through the ingestion pipeline. Alternatively, select the file directly from **ML Training** or **Detection & Alerts**.

### Step 2 — train a model

1. Open **ML Training** and click **Choose dataset**. Select a CSV, TSV, JSONL, NDJSON, or Parquet audit dataset.
2. Choose **Automatic** or **Manual** training. Automatic selects the configured training workflow; Manual offers the manual trainer. The estimator-count control is available on this page.
3. Choose **Unsupervised / anomaly** when records do not have known labels. Choose **Supervised / labeled** only when each record has a label column, for example `normal` or `attack`.
4. For supervised training, enter the exact label-column name. The default field value is `label`. Supervised training requires at least two classes and at least two records per class.
5. Click **Train and register**. Training requires at least 10 records and reads the selected dataset into memory; choose a size suitable for this computer. The progress bar shows the percentage of the dataset read; model training starts after loading completes.
6. Review the training result, including the algorithm and records loaded. A successful training run registers the model but does not automatically make it active.

An unsupervised result is an anomaly signal, not a confirmed attack. The included synthetic dataset is only for trying the workflow; its results do not demonstrate real-world accuracy.

For the Superviz25-SQL CSV, select the original `dataset.csv` directly. AuditSentinel recognizes its `full_query` and `split` columns, trains an unsupervised model on every row marked `train` (benign only), and uses that complete training split rather than making another internal holdout. After activating the new model, select the same CSV on **Detection & Alerts** and choose **Unsupervised** (or Automatic if an unsupervised model is active). Detection processes only rows marked `test`, compares predictions with `label` (`0` normal, `1` attack), and reports benchmark metrics. The table displays up to 5,000 rows; aggregate counts and metrics cover the complete test split. The test labels are used only for evaluation, never as training features.

### Step 3 — verify and activate the model

1. Open **Model Registry** and click **Refresh** if the newly trained model is not visible.
2. Select the model and click **Verify selected** to check the stored model integrity.
3. Click **Activate selected**. Activation verifies the model checksum and explicitly enables that model for its mode.
4. Confirm the model mode (supervised or unsupervised) before running detection. Use **Deactivate selected mode** if you need to disable the active model for that mode.
5. Use **Rename selected** to change the model's display name, or **Delete selected** to permanently remove it and its model files. Deleting an active model also deactivates it for that mode.

### Step 4 — detect suspicious records

1. Open **Detection & Alerts**, click **Choose file**, and select the audit-log dataset to analyze.
2. Choose **Automatic** to use the active model for the applicable mode, or explicitly select **Supervised** or **Unsupervised** to match the model you activated.
3. Click **Run detection**. Review each record’s mode, verdict, predicted label, and confidence or anomaly score.
4. Review the completion summary for the number of records analyzed and alerts created. Results are saved to the current session.

Detection analyzes the selected offline file and stores alerts; it does not block or alter database activity.

### Step 5 — review alerts

1. Open **Alert Monitoring**. Use the status filter and **Refresh** to locate alerts. Select a row to inspect its details.
2. Use **Acknowledge** to mark an alert as acknowledged.
3. To close an alert, enter a resolution note and click **Resolve**. Keep the note factual and useful for later review.
4. Refresh the page or Dashboard to see updated status counts.

### Step 6 — investigate an alert with local Ollama

1. Confirm that the Ollama service is running locally and that `qwen2.5:1.5b` (or the configured model) is available.
2. Open **AI Investigation**, click **Refresh alerts**, and select the alert to investigate.
3. Click **Investigate**. The application asks the configured local Ollama model to analyze the selected alert and saves an investigation report.
4. Review the returned status and report. Click **Refresh reports** to list saved investigations; select a report to view its details.

Investigation depends on Ollama. It does not execute SQL, scripts, or operating-system commands. Treat its narrative as analysis requiring human verification.

### Step 7 — propose and review a response

1. Open **Response Management** after investigating the alert. The response workflow needs a saved investigation report for the alert.
2. Click **Propose from investigation**. The application creates pending-approval proposals from predefined rules; this is not a separate AI model.
3. Select each proposal and review its details. Enter or confirm the operator ID (default: `operator`).
4. Click **Approve** to approve a proposal, or enter a reason and click **Reject** to reject it.
5. To test an approved proposal, select it, click **Simulate approved action**, and confirm the dialog. Review the recorded simulation status.

> Simulation is not real containment. It does not disable accounts, terminate sessions, change databases, or configure a firewall.

## 5. Optional: offline prevention simulation

This separate workflow evaluates explicitly approved policies against later records in a selected offline dataset. It never applies a real network or database control.

1. Open **Prevention Simulation** and choose a supported downloaded dataset. Select the active model mode or **Automatic active model**.
2. Choose the indicator to evaluate: **Source IP**, **Database user**, or **Source IP + DB user**.
3. Click **Analyze and propose policies**. Review the plan, trigger row, number of later matching rows, trigger count, and any alerts that lack the chosen indicator.
4. Select only the policy rows you intend to approve, enter an approver ID, and click **Approve selected and simulate**.
5. Read and confirm the dialog. Review decisions showing which later records would have been blocked and which policy triggered each result.
6. Click **View simulation history** to inspect past runs in the current session.

Only later rows in the selected dataset are affected by the simulation. No live database, account, session, network control, or firewall is modified.

## 6. Export reports

1. Open **Reports** and choose **Export HTML report** or **Export JSON report**.
2. Choose the output location in the save dialog. The application writes the selected local report and displays the saved path.
3. Open the HTML file in a browser to view, print, or save it as PDF. JSON is structured for scripts or further analysis.

Operational summaries include alerts, registered models, and offline prevention simulations. Raw IP addresses, database usernames, and SQL queries are excluded from these reports. Alert and simulation detail tables include up to the latest 100 entries; alert totals are exact.

## 7. Data handling, privacy, and limitations

- Audit logs may contain credentials, personal information, SQL statements, IP addresses, usernames, or internal infrastructure details. Store datasets, trained models, logs, and reports in appropriately protected locations; do not commit private artifacts to a public repository.
- Keep the local Ollama service and model configuration in mind when processing sensitive logs. Review organizational policy and the application’s data handling before using production data.
- The investigation prompt treats log contents as untrusted input, but this is not a substitute for privacy review or human validation.
- Training and analysis operate on files, not a live database connector. Response and prevention are manual-approval simulations only.
- Detection quality depends on representative data, labels, and evaluation. A high score on synthetic data is not evidence of production accuracy. Validate models against appropriate held-out data before relying on them operationally.
- For meaningful evaluation, use lawful, representative audit records and document your labeling assumptions.

## 8. Troubleshooting and quick reference

| Symptom | Checks / next step |
|---|---|
| Application will not start | Confirm Python 3.11+ is installed, activate the project virtual environment, install `requirements.txt`, and run `python run.py` from the repository root. |
| Dataset is rejected | Confirm the file uses CSV, TSV, JSONL, NDJSON, or Parquet and that the file path is accessible. |
| Training fails on record count | Training requires at least 10 records. Use a sufficiently sized dataset. |
| Supervised training fails | Check that the configured label-column name exactly matches the dataset and every row has a label. Provide at least two classes with at least two records in each class. |
| No model available for detection | Open Model Registry, refresh, verify the intended model, and activate it. Check that the selected detection mode matches the active model mode. |
| Investigation cannot run | Start the local Ollama service, confirm it is available at `http://localhost:11434`, and pull the configured `qwen2.5:1.5b` model. |
| No response proposals appear | Select the intended alert in AI Investigation and successfully run its investigation first; then return to Response Management. |
| Prevention approval is unavailable | Build and review a current plan, select one or more policies, ensure the dataset still exists, and enter an approver ID. |
| Cannot find prior records | Check the session selector. Alerts, reports, response actions, and simulation history are session-specific; trained models are shared. |

### Typical workflow at a glance

**Prepare dataset → Train and register model → Verify and activate model → Run detection → Review alerts → Investigate with local Ollama → Propose and review response → Optionally simulate approved action → Export report**

For project implementation details and test instructions, see `README.md` in the repository.
