"""فحص شهادة SSL/TLS الخاصة بالموقع."""

import socket
import ssl
from datetime import datetime

from .finding import make_finding


def _parse_cert_date(value):
    # صيغة قياسية تعيدها مكتبة ssl، مثال: 'Jun  1 12:00:00 2025 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def check_ssl(hostname: str, port: int = 443, timeout: int = 8):
    findings = []
    meta = {}

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                meta["tls_version"] = ssock.version()

                not_after = _parse_cert_date(cert["notAfter"])
                not_before = _parse_cert_date(cert["notBefore"])
                days_left = (not_after - datetime.utcnow()).days
                meta["cert_expires"] = not_after.isoformat()
                meta["cert_issued"] = not_before.isoformat()
                meta["days_until_expiry"] = days_left

                issuer = dict(x[0] for x in cert.get("issuer", []))
                meta["issuer"] = issuer.get("organizationName", issuer.get("commonName", "غير معروف"))

                if days_left < 0:
                    findings.append(
                        make_finding(
                            check_id="ssl_expired",
                            title_ar="شهادة SSL منتهية الصلاحية",
                            title_en="Expired SSL certificate",
                            severity="critical",
                            description_ar="شهادة الأمان (SSL/TLS) الخاصة بالموقع منتهية الصلاحية، وهذا يُظهر تحذيراً مخيفاً لكل الزوار ويكسر الثقة بالموقع.",
                            evidence=f"انتهت في: {not_after.isoformat()}",
                            recommendation_ar="جدّد شهادة SSL فوراً، ويُفضّل تفعيل التجديد التلقائي (مثل Let's Encrypt + certbot).",
                            category="ssl",
                        )
                    )
                elif days_left < 14:
                    findings.append(
                        make_finding(
                            check_id="ssl_expiring_soon",
                            title_ar="شهادة SSL قاربت على الانتهاء",
                            title_en="SSL certificate expiring soon",
                            severity="high",
                            description_ar=f"شهادة الموقع ستنتهي خلال {days_left} يوم فقط.",
                            recommendation_ar="جدّد الشهادة قبل انتهائها، وفعّل التجديد التلقائي لتفادي تكرار المشكلة.",
                            category="ssl",
                        )
                    )

                if meta["tls_version"] in ("TLSv1", "TLSv1.1"):
                    findings.append(
                        make_finding(
                            check_id="ssl_old_protocol",
                            title_ar="استخدام إصدار قديم وغير آمن من TLS",
                            title_en="Outdated/insecure TLS version in use",
                            severity="high",
                            description_ar=f"الاتصال تم عبر {meta['tls_version']} وهو إصدار قديم يحتوي على ثغرات معروفة.",
                            recommendation_ar="عطّل TLS 1.0 و1.1 من إعدادات الخادم واجعل الحد الأدنى TLS 1.2 (ويُفضّل TLS 1.3).",
                            category="ssl",
                        )
                    )

    except ssl.SSLCertVerificationError as exc:
        findings.append(
            make_finding(
                check_id="ssl_verification_failed",
                title_ar="فشل التحقق من شهادة SSL",
                title_en="SSL certificate verification failed",
                severity="critical",
                description_ar="شهادة الموقع غير موثوقة أو غير مطابقة للنطاق، مما يعني أن اتصال الزوار قد لا يكون مشفراً بشكل موثوق.",
                evidence=str(exc),
                recommendation_ar="تأكد أن الشهادة صادرة من جهة موثوقة (CA) ومطابقة للنطاق المستخدم، وأنها مثبتة بشكل صحيح على الخادم.",
                category="ssl",
            )
        )
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        findings.append(
            make_finding(
                check_id="ssl_connection_failed",
                title_ar="تعذّر الاتصال عبر HTTPS للتحقق من الشهادة",
                title_en="Could not establish HTTPS connection to verify certificate",
                severity="medium",
                description_ar="لم تتمكن الأداة من فتح اتصال TLS مباشر بالمنفذ 443 للتحقق من شهادة الموقع.",
                evidence=str(exc),
                recommendation_ar="تأكد أن المنفذ 443 مفتوح للجميع وأن HTTPS مفعّل بشكل صحيح على الخادم.",
                category="ssl",
            )
        )

    return findings, meta
