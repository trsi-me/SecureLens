"""فحوصات محتوى الصفحة والملفات الحساسة الشائعة (Passive)."""

from .finding import make_finding
from .http_client import safe_get

# ملفات/مسارات حساسة يتم التحقق فقط من وجودها (GET عادي بدون أي هجوم فعلي)
SENSITIVE_PATHS = [
    (".env", "critical", "ملف بيئة (.env) قد يحتوي مفاتيح API وكلمات مرور قواعد البيانات"),
    (".git/config", "critical", "مجلد Git مكشوف قد يسمح بتنزيل كامل الكود المصدري"),
    ("wp-config.php.bak", "critical", "نسخة احتياطية من إعدادات ووردبريس قد تحتوي بيانات اتصال قاعدة البيانات"),
    ("backup.zip", "high", "ملف نسخة احتياطية مكشوف للعموم"),
    ("phpinfo.php", "medium", "صفحة phpinfo تكشف تفاصيل دقيقة عن بيئة الخادم"),
    ("server-status", "medium", "صفحة حالة خادم Apache قد تكشف معلومات داخلية"),
    (".htpasswd", "high", "ملف كلمات مرور Apache مكشوف"),
]


def check_sensitive_files(base_url, timeout, max_redirects, user_agent):
    findings = []
    for path, severity, desc_ar in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"
        result = safe_get(url, timeout=timeout, max_redirects=max_redirects, user_agent=user_agent)
        if not result.ok or result.response is None:
            continue
        resp = result.response
        if resp.status_code == 200 and len(resp.content) > 0:
            # تجنّب النتائج الإيجابية الكاذبة عندما يعيد الموقع صفحة 200 موحّدة لكل الروابط غير الموجودة
            content_snippet = resp.text[:100].strip().lower()
            if content_snippet:
                findings.append(
                    make_finding(
                        check_id=f"sensitive_path_{path.replace('/', '_').replace('.', '_')}",
                        title_ar=f"مسار حساس مكشوف: /{path}",
                        title_en=f"Sensitive path exposed: /{path}",
                        severity=severity,
                        description_ar=desc_ar,
                        evidence=f"GET {url} -> HTTP {resp.status_code}",
                        recommendation_ar="امنع الوصول العام لهذا المسار عبر إعدادات الخادم (deny) أو احذفه من مجلد النشر العام.",
                        category="exposure",
                    )
                )
    return findings


def check_directory_listing(response):
    findings = []
    text = (response.text or "")[:2000].lower()
    if "index of /" in text and "<title>" in text:
        findings.append(
            make_finding(
                check_id="directory_listing_enabled",
                title_ar="سرد محتويات المجلد مفعّل (Directory Listing)",
                title_en="Directory listing enabled",
                severity="medium",
                description_ar="الخادم يعرض قائمة بملفات المجلد مباشرة بدل صفحة رئيسية، مما قد يكشف ملفات لم يكن يُقصد نشرها.",
                recommendation_ar="عطّل خاصية Directory Listing من إعدادات الخادم (مثل Options -Indexes في Apache).",
                category="exposure",
            )
        )
    return findings


def check_mixed_content(base_url, response):
    findings = []
    if not base_url.startswith("https://"):
        return findings
    text = response.text or ""
    if 'src="http://' in text or "src='http://" in text:
        findings.append(
            make_finding(
                check_id="mixed_content",
                title_ar="محتوى مختلط (Mixed Content)",
                title_en="Mixed content detected",
                severity="low",
                description_ar="الصفحة تُحمّل عبر HTTPS لكنها تستدعي بعض الموارد (صور/سكربتات) عبر HTTP غير المشفر.",
                recommendation_ar="حدّث جميع روابط الموارد الداخلية لتستخدم https:// أو روابط نسبية (protocol-relative).",
                category="content",
            )
        )
    return findings


def check_robots_and_sitemap(base_url, timeout, max_redirects, user_agent):
    findings = []
    robots_url = f"{base_url}/robots.txt"
    result = safe_get(robots_url, timeout=timeout, max_redirects=max_redirects, user_agent=user_agent)
    if result.ok and result.response is not None and result.response.status_code == 200:
        text = result.response.text.lower()
        interesting_paths = [
            line.split(":", 1)[1].strip()
            for line in text.splitlines()
            if line.strip().startswith("disallow:") and len(line.split(":", 1)) > 1
        ]
        risky_hints = [
            p for p in interesting_paths
            if any(k in p for k in ["admin", "config", "backup", "db", "private", "wp-admin", ".env"])
        ]
        if risky_hints:
            findings.append(
                make_finding(
                    check_id="robots_sensitive_hints",
                    title_ar="ملف robots.txt يشير إلى مسارات حساسة",
                    title_en="robots.txt reveals sensitive paths",
                    severity="low",
                    description_ar=(
                        "ملف robots.txt يحاول إخفاء بعض المسارات عن محركات البحث، لكنه بذلك يكشف "
                        "للمهاجمين أماكن محتملة تستحق الفحص، مثل: " + ", ".join(risky_hints[:5])
                    ),
                    evidence=", ".join(risky_hints[:10]),
                    recommendation_ar="لا تعتمد على robots.txt لإخفاء مسارات حساسة؛ استخدم صلاحيات وصول حقيقية (authentication) بدلاً من ذلك.",
                    category="exposure",
                )
            )
    return findings
