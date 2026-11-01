
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

NORMAL_BINARY_LABELS = {"0", "normal", "benign", "legitimate", "safe"}
ATTACK_BINARY_LABELS = {
    "1",
    "attack",
    "malicious",
    "intrusion",
    "intrusion_attempt",
    "anomaly",
    "threat",
    "suspicious",
    "unauthorized",
}


def normalize_binary_label(value):
    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in NORMAL_BINARY_LABELS:
        return "normal"
    if normalized in ATTACK_BINARY_LABELS:
        return "attack"
    return None


def binary_detection_metrics(counts):
    true_positive = counts["true_positive"]
    false_positive = counts["false_positive"]
    true_negative = counts["true_negative"]
    false_negative = counts["false_negative"]
    total = true_positive + false_positive + true_negative + false_negative

    return {
        "records_evaluated": total,
        "accuracy": round(
            (true_positive + true_negative) / total,
            4,
        ) if total else 0.0,
        "precision_attack": round(
            true_positive / (true_positive + false_positive),
            4,
        ) if true_positive + false_positive else 0.0,
        "recall_attack": round(
            true_positive / (true_positive + false_negative),
            4,
        ) if true_positive + false_negative else 0.0,
        "f1_attack": round(
            2 * true_positive / (2 * true_positive + false_positive + false_negative),
            4,
        ) if 2 * true_positive + false_positive + false_negative else 0.0,
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
    }


def evaluate_classifier(y_true, y_pred):
    """
    Evaluate a supervised classification model.
    Supports binary and multiclass classification.
    """

    if len(y_true) != len(y_pred):
        raise ValueError("Actual and predicted labels must have equal length")

    if len(y_true) == 0:
        raise ValueError("Evaluation data is empty")

    labels = sorted(
        set(y_true) | set(y_pred),
        key=str,
    )

    return {
        "accuracy": round(
            accuracy_score(y_true, y_pred), 4
        ),
        "precision_weighted": round(
            precision_score(
                y_true,
                y_pred,
                average="weighted",
                zero_division=0,
            ),
            4,
        ),
        "recall_weighted": round(
            recall_score(
                y_true,
                y_pred,
                average="weighted",
                zero_division=0,
            ),
            4,
        ),
        "f1_weighted": round(
            f1_score(
                y_true,
                y_pred,
                average="weighted",
                zero_division=0,
            ),
            4,
        ),
        "confusion_matrix": confusion_matrix(
            y_true,
            y_pred,
            labels=labels,
        ).tolist(),
        "labels": [str(label) for label in labels],
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=labels,
            zero_division=0,
            output_dict=True,
        ),
    }
