"""فحص رؤوس أمان HTTP (Security Headers)."""

from .finding import make_finding

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "high",
        "title_ar": "غياب رأس Strict-Transport-Security (HSTS)",
        "title_en": "Missing Strict-Transport-Security (HSTS) header",
        "desc_ar": "الموقع لا يفرض على المتصفح استخدام HTTPS دائماً، مما قد يعرض الزوار لهجمات إنزال الاتصال (SSL Stripping).",
        "rec_ar": "أضف الرأس: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "severity": "high",
        "title_ar": "غياب سياسة أمان المحتوى (Content-Security-Policy)",
        "title_en": "Missing Content-Security-Policy header",
        "desc_ar": "بدون CSP يصبح الموقع أكثر عرضة لهجمات حقن السكربتات (XSS) وتحميل موارد خبيثة من نطاقات غير موثوقة.",
        "rec_ar": "عرّف سياسة CSP تحدد مصادر السكربتات والأنماط والصور المسموح تحميلها، وابدأ بوضع Report-Only لتجربتها قبل التفعيل الكامل.",
    },
    "x-frame-options": {
        "severity": "medium",
        "title_ar": "غياب رأس X-Frame-Options",
        "title_en": "Missing X-Frame-Options header",
        "desc_ar": "الموقع قد يكون عرضة لهجمات النقر التصادفي (Clickjacking) عبر تضمينه داخل إطار iframe من موقع آخر.",
        "rec_ar": "أضف الرأس: X-Frame-Options: DENY أو SAMEORIGIN، أو استخدم frame-ancestors ضمن CSP.",
    },
    "x-content-type-options": {
        "severity": "low",
        "title_ar": "غياب رأس X-Content-Type-Options",
        "title_en": "Missing X-Content-Type-Options header",
        "desc_ar": "بعض المتصفحات القديمة قد 'تخمّن' نوع الملف الفعلي (MIME sniffing) بدل الالتزام بما يرسله الخادم، مما قد يُستغل لتنفيذ سكربتات ضارة.",
        "rec_ar": "أضف الرأس: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "low",
        "title_ar": "غياب رأس Referrer-Policy",
        "title_en": "Missing Referrer-Policy header",
        "desc_ar": "بدون هذا الرأس قد يُرسل المتصفح رابط الصفحة الحالية كاملاً (بما فيه معاملات حساسة) إلى مواقع خارجية عند النقر على روابط.",
        "rec_ar": "أضف الرأس: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "low",
        "title_ar": "غياب رأس Permissions-Policy",
        "title_en": "Missing Permissions-Policy header",
        "desc_ar": "لا يوجد تقييد صريح على صلاحيات المتصفح الحساسة (الكاميرا، الموقع الجغرافي، الميكروفون...) التي قد تُستغل من سكربتات طرف ثالث.",
        "rec_ar": "أضف الرأس وحدد الصلاحيات المطلوبة فقط، مثال: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def check_security_headers(response):
    findings = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in headers_lower:
            findings.append(
                make_finding(
                    check_id=f"header_missing_{header_name}",
                    title_ar=meta["title_ar"],
                    title_en=meta["title_en"],
                    severity=meta["severity"],
                    description_ar=meta["desc_ar"],
                    recommendation_ar=meta["rec_ar"],
                    category="headers",
                )
            )

    # كشف تسريب معلومات الخادم/التقنية عبر الرؤوس
    for h in INFO_LEAK_HEADERS:
        if h in headers_lower and headers_lower[h].strip():
            findings.append(
                make_finding(
                    check_id=f"info_leak_header_{h}",
                    title_ar=f"تسريب معلومات عبر رأس {h}",
                    title_en=f"Information disclosure via {h} header",
                    severity="low",
                    description_ar=(
                        f"الخادم يفصح عن تفاصيل تقنية عبر الرأس '{h}' بقيمة: "
                        f"\"{headers_lower[h][:120]}\" مما يسهّل على المهاجم معرفة "
                        "الإصدارات المستخدمة والبحث عن ثغرات معروفة لها."
                    ),
                    evidence=f"{h}: {headers_lower[h]}",
                    recommendation_ar="أخفِ أو قلّل تفاصيل هذا الرأس من إعدادات الخادم (مثل إخفاء رقم الإصدار).",
                    category="headers",
                )
            )

    return findings


def check_cookies(response):
    findings = []
    set_cookie_headers = response.raw.headers.get_all("Set-Cookie") if hasattr(response.raw, "headers") else None
    if not set_cookie_headers:
        cookie_header = response.headers.get("Set-Cookie")
        set_cookie_headers = [cookie_header] if cookie_header else []

    for raw_cookie in set_cookie_headers:
        if not raw_cookie:
            continue
        lowered = raw_cookie.lower()
        cookie_name = raw_cookie.split("=")[0].strip()

        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")

        if missing:
            findings.append(
                make_finding(
                    check_id=f"cookie_flags_{cookie_name}",
                    title_ar=f"إعدادات كوكيز غير آمنة: {cookie_name}",
                    title_en=f"Insecure cookie flags: {cookie_name}",
                    severity="medium" if "HttpOnly" in missing or "Secure" in missing else "low",
                    description_ar=(
                        f"الكوكيز '{cookie_name}' لا يحتوي على الخصائص التالية: {', '.join(missing)}. "
                        "هذا قد يعرّضه للسرقة عبر هجمات XSS أو الاعتراض على شبكات غير آمنة."
                    ),
                    evidence=raw_cookie[:200],
                    recommendation_ar=(
                        "أضف الخصائص الناقصة عند إنشاء الكوكيز، خصوصاً HttpOnly و Secure، "
                        "وحدد SameSite=Lax أو Strict حسب الحاجة."
                    ),
                    category="cookies",
                )
            )
    return findings
