SUSPICIOUS_LABELS = {
    "attack",
    "malicious",
    "intrusion",
    "intrusion_attempt",
    "anomaly",
    "threat",
    "suspicious",
    "unauthorized",
}

NORMAL_LABELS = {
    "normal",
    "benign",
    "legitimate",
    "safe",
    "clean",
}


def classify_supervised_label(label: object) -> str:
    normalized = str(label).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in SUSPICIOUS_LABELS:
        return "SUSPICIOUS"
    if normalized in NORMAL_LABELS:
        return "NORMAL"
    return "REVIEW"


def classify_result(result: dict) -> str:
    """Map detector output to a stable, user-facing classification."""
    verdict = str(result.get("verdict", "")).strip().upper()
    if verdict in {"ANOMALY", "SUSPICIOUS"}:
        return "Anomaly"
    if verdict in {"NORMAL_PATTERN", "NORMAL"}:
        return "Normal"
    label_verdict = classify_supervised_label(result.get("predicted_label", ""))
    if label_verdict == "SUSPICIOUS":
        return "Anomaly"
    if label_verdict == "NORMAL":
        return "Normal"
    return "Review"


def classification_explanation(result: dict) -> str:
    classification = classify_result(result)
    if classification == "Anomaly":
        return (
            "The active model flagged this record as anomalous or suspicious; "
            "this is a signal for review, not proof of an attack."
        )
    if classification == "Normal":
        return "The active model classified this record as normal."
    return (
        "The model output did not map to a known normal or anomaly label; "
        "review the raw prediction."
    )
