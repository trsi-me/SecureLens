"""
فحص انعكاس بسيط وغير مدمّر لاحتمالية XSS المنعكس (Reflected XSS).

آلية الفحص: نضيف معامل استعلام (query parameter) عشوائي وغير مؤذٍ إلى
رابط الصفحة نفسها، ثم نتحقق هل يُعاد عرض هذه القيمة في الصفحة دون تنقية
(escaping) للرموز الخاصة مثل < و > و ". هذا لا يُنفّذ أي كود فعلي في
المتصفح ولا يرسل أي نموذج (form)؛ إنه مجرد طلب GET إضافي واحد، وبالتالي
لا يسبب أي تأثير جانبي على الموقع.

هذا الفحص استدلالي (heuristic) وليس قاطعاً: قد يُنتج نتائج إيجابية كاذبة
إذا كانت الصفحة أصلاً تعرض معاملات الاستعلام (مثل صفحة بحث)، لذلك تُعرض
النتيجة دائماً كـ 'يستدعي مراجعة يدوية' وليست تأكيداً نهائياً بوجود ثغرة.
"""

import urllib.parse as urlparse

from .finding import make_finding
from .http_client import safe_get

MARKER = "wsaiCheck1337"
PAYLOAD = f'"><{MARKER}>'


def check_reflected_marker(base_url, timeout, max_redirects, user_agent):
    findings = []
    parsed = urlparse.urlsplit(base_url)
    query = urlparse.parse_qsl(parsed.query)
    query.append(("wsai_probe", PAYLOAD))
    new_query = urlparse.urlencode(query)
    test_url = urlparse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", new_query, "")
    )

    result = safe_get(test_url, timeout=timeout, max_redirects=max_redirects, user_agent=user_agent)
    if not result.ok or result.response is None:
        return findings

    body = result.response.text or ""
    content_type = result.response.headers.get("Content-Type", "")

    if "text/html" not in content_type:
        return findings

    if PAYLOAD in body:
        findings.append(
            make_finding(
                check_id="reflected_input_unescaped",
                title_ar="احتمالية ثغرة XSS منعكس (يتطلب تأكيد يدوي)",
                title_en="Possible reflected XSS (needs manual confirmation)",
                severity="high",
                description_ar=(
                    "عند إضافة معامل استعلام تجريبي غير مؤذٍ إلى رابط الصفحة، ظهرت القيمة كما "
                    "هي في محتوى الصفحة دون أي تنقية (escaping) لرموز HTML الخاصة. هذا مؤشر "
                    "أولي على احتمال وجود ثغرة XSS منعكس، ويحتاج لتأكيد يدوي من فريق تقني."
                ),
                evidence=f"تم اختبار الرابط: {test_url}",
                recommendation_ar=(
                    "نقّ (escape) أي مدخل قادم من المستخدم قبل عرضه في HTML، واستخدم مكتبات "
                    "قوالب آمنة تقوم بذلك تلقائياً (مثل Jinja2 autoescape)، وفعّل رأس "
                    "Content-Security-Policy كطبقة حماية إضافية."
                ),
                category="injection",
            )
        )
    elif MARKER in body:
        findings.append(
            make_finding(
                check_id="reflected_input_partial",
                title_ar="انعكاس جزئي لمدخل تجريبي في الصفحة",
                title_en="Partial reflection of test input detected",
                severity="low",
                description_ar=(
                    "تم العثور على جزء من نص الاختبار داخل الصفحة، لكن يبدو أن الرموز الخاصة "
                    "تمت معالجتها (escaping). هذا مؤشر جيد، لكن يُنصح بالتحقق يدوياً من جميع "
                    "نقاط الإدخال الأخرى في الموقع (نماذج البحث، التعليقات، إلخ)."
                ),
                recommendation_ar="راجع جميع نقاط إدخال المستخدم يدوياً أو باستخدام أداة فحص أمان متخصصة (DAST) بصلاحية من مالك الموقع.",
                category="injection",
            )
        )

    return findings
