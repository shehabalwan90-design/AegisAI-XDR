"""Risk scoring based on rule confidence and asset criticality."""


def score_risk(base_score: int, asset_weight: float) -> tuple[int, str]:
    """Return bounded 0-100 risk and its severity band."""
    score = min(100, max(0, int(base_score * asset_weight)))
    if score >= 85:
        severity = "Critical"
    elif score >= 65:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    else:
        severity = "Low"
    return score, severity
