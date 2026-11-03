import math
import re


ANOMALY_MARGIN_STEPS = (0.01, 0.02, 0.03, 0.04)
RISK_SCORE_FORMULA = "round(100 * likelihood * impact_factor, 1)"


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
        (5, 1.0, r"\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b"),
        (4, 0.65, r"\b(DELETE|UPDATE|INSERT|MERGE|REPLACE)\b"),
        (2, 0.25, r"\b(SELECT|SHOW|DESCRIBE|EXPLAIN)\b"),
    )
    for rating, factor, pattern in impacts:
        if re.search(pattern, statement):
            return {
                "impact_rating": rating,
                "impact_factor": factor,
                "impact_basis": "observed_sql_operation",
                "impact_estimated": False,
            }

    return {
        "impact_rating": 3,
        "impact_factor": 0.5,
        "impact_basis": "default_missing_operation",
        "impact_estimated": True,
    }


def _likelihood_rating(confidence, anomaly_score, verdict):
    if _is_finite_number(confidence) and 0 <= confidence <= 1:
        return confidence, "detector_confidence"

    if _is_finite_number(anomaly_score) and anomaly_score < 0:
        magnitude = -anomaly_score
        likelihood = 0.2 + 0.2 * sum(
            magnitude >= threshold
            for threshold in ANOMALY_MARGIN_STEPS
        )
        return likelihood, "isolation_forest_decision_margin"

    verdict_rating = {
        "SUSPICIOUS": 0.8,
        "ANOMALY": 0.6,
        "REVIEW": 0.3,
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
    """Return a transparent, application-defined 0-100 risk estimate."""

    normalized_verdict = str(verdict or "").upper()
    if normalized_verdict in {"NORMAL", "NORMAL_PATTERN"}:
        return {
            "risk_score": None,
            "risk_score_band": "NONE",
            "risk_likelihood": None,
            "impact_rating": None,
            "impact_factor": None,
            "impact_basis": "not_applicable_normal_result",
            "impact_estimated": False,
            "risk_likelihood_basis": None,
            "risk_score_formula": RISK_SCORE_FORMULA,
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
            "risk_score_formula": RISK_SCORE_FORMULA,
            "risk_score_inputs": {
                "confidence": confidence,
                "anomaly_score": anomaly_score,
                "verdict": verdict,
                "likelihood_scale": "0-1",
                "impact_factor_scale": "0-1",
            },
            "risk_score_note": (
                "Not calculated: no valid detector confidence, anomaly "
                "margin, or alert verdict is available."
            ),
        }

    score = round(100 * likelihood * impact["impact_factor"], 1)
    if score < 20:
        band = "LOW"
    elif score < 40:
        band = "MEDIUM"
    elif score < 70:
        band = "HIGH"
    else:
        band = "CRITICAL"

    return {
        "risk_score": score,
        "risk_score_band": band,
        "risk_likelihood": likelihood,
        **impact,
        "risk_likelihood_basis": likelihood_basis,
        "risk_score_formula": RISK_SCORE_FORMULA,
        "risk_score_inputs": {
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "verdict": verdict,
            "likelihood": likelihood,
            "impact": impact["impact_rating"],
            "impact_factor": impact["impact_factor"],
            "likelihood_scale": "0-1",
            "impact_factor_scale": "0-1",
        },
        "risk_score_note": (
            "Application-defined likelihood-impact estimate, not an official "
            "NIST or CVSS score. Confidence is an uncalibrated model signal; "
            "impact factors are heuristic and should be tuned with labeled "
            "incident data."
        ),
    }


def severity_from_risk_score(score):
    """Map the internal 0-100 score bands to alert severity."""

    if not _is_finite_number(score) or not 0 <= score <= 100:
        return None
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
