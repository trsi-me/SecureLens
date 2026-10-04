"""حساب درجة الأمان الإجمالية (Score) والتقدير الحرفي (Grade) بناءً على الملاحظات المكتشفة."""

from .finding import SEVERITY_WEIGHTS


def compute_score(findings):
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0)
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def summarize_by_severity(findings):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        summary[sev] = summary.get(sev, 0) + 1
    return summary
