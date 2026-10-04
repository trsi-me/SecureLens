"""بنية موحّدة لأي ملاحظة/ثغرة يكتشفها أي فاحص فرعي."""

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SEVERITY_LABELS_AR = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلومة",
}


def make_finding(
    check_id: str,
    title_ar: str,
    title_en: str,
    severity: str,
    description_ar: str,
    description_en: str = "",
    evidence: str = "",
    recommendation_ar: str = "",
    recommendation_en: str = "",
    category: str = "general",
):
    severity = severity if severity in SEVERITY_WEIGHTS else "info"
    return {
        "check_id": check_id,
        "category": category,
        "severity": severity,
        "severity_label_ar": SEVERITY_LABELS_AR[severity],
        "title_ar": title_ar,
        "title_en": title_en,
        "description_ar": description_ar,
        "description_en": description_en or description_ar,
        "evidence": evidence,
        "recommendation_ar": recommendation_ar,
        "recommendation_en": recommendation_en or recommendation_ar,
    }
