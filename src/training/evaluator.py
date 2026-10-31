
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


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
