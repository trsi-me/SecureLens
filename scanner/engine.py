"""محرك تشغيل الفحص الكامل: ينسّق بين كل الفاحصات الفرعية ويجمع النتائج."""

import time
import urllib.parse as urlparse

from .checks_content import (
    check_directory_listing,
    check_mixed_content,
    check_robots_and_sitemap,
    check_sensitive_files,
)
from .checks_headers import check_cookies, check_security_headers
from .checks_ssl import check_ssl
from .checks_tech import detect_technologies
from .checks_xss import check_reflected_marker
from .finding import make_finding
from .http_client import normalize_url, safe_get
from .recommendations import build_rule_based_summary, generate_ai_summary
from .scoring import compute_score, summarize_by_severity


def run_full_scan(raw_url, config):
    started = time.monotonic()
    target_url = normalize_url(raw_url)

    parsed = urlparse.urlsplit(target_url)
    if not parsed.netloc:
        return {
            "ok": False,
            "error": "رابط غير صالح. تأكد من كتابة الرابط بشكل صحيح، مثال: example.com",
        }

    timeout = config.get("REQUEST_TIMEOUT", 10)
    max_redirects = config.get("MAX_REDIRECTS", 5)
    user_agent = config.get("USER_AGENT", "SecureLens/1.0")

    findings = []
    meta = {"target_url": target_url}

    main_result = safe_get(target_url, timeout=timeout, max_redirects=max_redirects, user_agent=user_agent)

    if not main_result.ok or main_result.response is None:
        return {
            "ok": False,
            "error": f"تعذّر الوصول إلى الموقع: {main_result.error or 'سبب غير معروف'}",
        }

    response = main_result.response
    meta["final_url"] = main_result.final_url or target_url
    meta["status_code"] = response.status_code
    meta["response_time_ms"] = main_result.elapsed_ms
    meta["used_https"] = meta["final_url"].startswith("https://")

    if main_result.error and main_result.error.startswith("ssl_error"):
        findings.append(
            make_finding(
                check_id="ssl_generic_error",
                title_ar="خطأ في شهادة SSL أثناء الاتصال",
                title_en="SSL error while connecting",
                severity="critical",
                description_ar="حدث خطأ أثناء التحقق من شهادة الأمان الخاصة بالموقع.",
                evidence=main_result.error,
                recommendation_ar="راجع إعدادات شهادة SSL على الخادم وتأكد من صلاحيتها ومطابقتها للنطاق.",
                category="ssl",
            )
        )

    # 1) رؤوس الأمان + الكوكيز
    findings += check_security_headers(response)
    findings += check_cookies(response)

    # 2) SSL/TLS (فقط إذا كان الموقع يدعم https)
    hostname = parsed.hostname or urlparse.urlsplit(meta["final_url"]).hostname
    if hostname:
        ssl_findings, ssl_meta = check_ssl(hostname)
        findings += ssl_findings
        meta["ssl"] = ssl_meta
    else:
        meta["ssl"] = {}

    if not meta["used_https"]:
        findings.append(
            make_finding(
                check_id="no_https",
                title_ar="الموقع لا يستخدم HTTPS بشكل افتراضي",
                title_en="Site does not use HTTPS by default",
                severity="critical",
                description_ar="الاتصال بالموقع غير مشفّر، مما يعرّض بيانات الزوار (بما فيها كلمات المرور) لخطر الاعتراض.",
                recommendation_ar="فعّل شهادة SSL مجانية (مثل Let's Encrypt) واجعل تحويل HTTP إلى HTTPS إجبارياً.",
                category="ssl",
            )
        )

    base_url_no_path = f"{parsed.scheme}://{parsed.netloc}"

    # 3) محتوى الصفحة (Mixed content, directory listing)
    findings += check_mixed_content(base_url_no_path, response)
    findings += check_directory_listing(response)

    # 4) ملفات ومسارات حساسة + robots.txt
    findings += check_sensitive_files(base_url_no_path, timeout, max_redirects, user_agent)
    findings += check_robots_and_sitemap(base_url_no_path, timeout, max_redirects, user_agent)

    # 5) فحص انعكاس بسيط لاحتمال XSS
    findings += check_reflected_marker(target_url, timeout, max_redirects, user_agent)

    # 6) اكتشاف التقنيات
    tech_info = detect_technologies(response)
    meta["technologies"] = tech_info

    # ترتيب النتائج حسب الخطورة
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    score, grade = compute_score(findings)
    severity_summary = summarize_by_severity(findings)

    ai_summary = build_rule_based_summary(findings, score, grade, target_url)

    ai_provider = config.get("AI_PROVIDER")
    ai_api_key = config.get("AI_API_KEY")
    if ai_provider and ai_api_key:
        real_ai = generate_ai_summary(findings, score, grade, target_url, ai_provider, ai_api_key)
        if real_ai.get("ai_generated"):
            ai_summary["ai_text"] = real_ai["text"]

    duration_ms = int((time.monotonic() - started) * 1000)

    return {
        "ok": True,
        "target_url": target_url,
        "findings": findings,
        "meta": meta,
        "score": score,
        "grade": grade,
        "severity_summary": severity_summary,
        "summary": ai_summary,
        "duration_ms": duration_ms,
    }
