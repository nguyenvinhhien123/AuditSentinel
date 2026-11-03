import math
import re


ANOMALY_MARGIN_STEPS = (0.01, 0.02, 0.03, 0.04)


def _is_finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _impact_rating(context):
    context = context if isinstance(context, dict) else {}
    evidence = []
    for key in ("sql_action", "action", "event_type", "query", "sql"):
        value = context.get(key)
        if isinstance(value, (str, int, float)):
            evidence.append(str(value)[:1000].upper())
    statement = " ".join(evidence)

    impacts = (
        (5, r"\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b"),
        (4, r"\b(DELETE|UPDATE|INSERT|MERGE|REPLACE)\b"),
        (2, r"\b(SELECT|SHOW|DESCRIBE|EXPLAIN)\b"),
    )
    for rating, pattern in impacts:
        if re.search(pattern, statement):
            return {
                "impact_rating": rating,
                "impact_basis": "observed_sql_operation",
                "impact_estimated": False,
            }

    return {
        "impact_rating": 3,
        "impact_basis": "default_missing_operation",
        "impact_estimated": True,
    }


def _likelihood_rating(confidence, anomaly_score, verdict):
    if _is_finite_number(confidence) and 0 <= confidence <= 1:
        rating = min(int(confidence * 5) + 1, 5)
        return rating, "detector_confidence"

    if _is_finite_number(anomaly_score) and anomaly_score < 0:
        magnitude = -anomaly_score
        rating = 1 + sum(
            magnitude >= threshold
            for threshold in ANOMALY_MARGIN_STEPS
        )
        return rating, "isolation_forest_decision_margin"

    verdict_rating = {
        "SUSPICIOUS": 4,
        "ANOMALY": 3,
        "REVIEW": 2,
    }.get(str(verdict or "").upper())
    if verdict_rating is not None:
        return verdict_rating, "detector_verdict_fallback"

    return None, None


def calculate_risk_score(
    confidence=None,
    anomaly_score=None,
    context=None,
    verdict=None,
):
    """Calculate a documented, NIST-style internal likelihood-impact score."""

    normalized_verdict = str(verdict or "").upper()
    if normalized_verdict in {"NORMAL", "NORMAL_PATTERN"}:
        return {
            "risk_score": None,
            "risk_score_band": "NONE",
            "risk_likelihood": None,
            "impact_rating": None,
            "impact_basis": "not_applicable_normal_result",
            "impact_estimated": False,
            "risk_likelihood_basis": None,
            "risk_score_formula": None,
            "risk_score_inputs": {"verdict": normalized_verdict},
            "risk_score_note": "No risk score is assigned to normal results.",
        }

    likelihood, likelihood_basis = _likelihood_rating(
        confidence,
        anomaly_score,
        normalized_verdict,
    )
    impact = _impact_rating(context)

    if likelihood is None:
        return {
            "risk_score": None,
            "risk_score_band": "UNKNOWN",
            "risk_likelihood": None,
            **impact,
            "risk_likelihood_basis": None,
            "risk_score_formula": "round(((likelihood × impact - 1) / 24) × 100, 1)",
            "risk_score_inputs": {
                "confidence": confidence,
                "anomaly_score": anomaly_score,
                "verdict": verdict,
                "likelihood_scale": "1–5",
                "impact_scale": "1–5",
            },
            "risk_score_note": (
                "Not calculated: no valid detector confidence, anomaly "
                "margin, or alert verdict is available."
            ),
        }

    score = round(
        ((likelihood * impact["impact_rating"] - 1) / 24) * 100,
        1,
    )
    if score < 20:
        band = "LOW"
    elif score < 40:
        band = "MEDIUM"
    elif score < 60:
        band = "HIGH"
    else:
        band = "CRITICAL"

    return {
        "risk_score": score,
        "risk_score_band": band,
        "risk_likelihood": likelihood,
        **impact,
        "risk_likelihood_basis": likelihood_basis,
        "risk_score_formula": "round(((likelihood × impact - 1) / 24) × 100, 1)",
        "risk_score_inputs": {
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "verdict": verdict,
            "likelihood": likelihood,
            "impact": impact["impact_rating"],
            "likelihood_scale": "1–5",
            "impact_scale": "1–5",
        },
        "risk_score_note": (
            "NIST-style internal risk estimate; numeric mapping is "
            "application-defined, not an official NIST or CVSS score. "
            "Detector likelihood is an uncalibrated ordinal estimate."
        ),
    }


def severity_from_risk_score(score):
    """Map the internal 0–100 matrix score to alert severity."""

    if not _is_finite_number(score) or not 0 <= score <= 100:
        return None
    if score >= 60:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
