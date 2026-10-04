"""اكتشاف التقنيات المستخدمة في الموقع (Technology Fingerprinting) عبر الرؤوس والـ meta tags."""

import re

TECH_SIGNATURES = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"joomla", "Joomla"),
    (r"drupal", "Drupal"),
    (r"shopify", "Shopify"),
    (r"wix\.com", "Wix"),
    (r"laravel_session", "Laravel"),
    (r"django", "Django"),
    (r"csrftoken", "Django"),
    (r"asp\.net", "ASP.NET"),
    (r"jsessionid", "Java (JSP/Servlet)"),
    (r"react", "React"),
    (r"next\.js|__next", "Next.js"),
    (r"vue", "Vue.js"),
]


def detect_technologies(response):
    detected = set()
    haystack_parts = []

    for k, v in response.headers.items():
        haystack_parts.append(f"{k}: {v}")

    haystack_parts.append(response.text[:5000] if response.text else "")

    haystack = " ".join(haystack_parts).lower()

    for pattern, name in TECH_SIGNATURES:
        if re.search(pattern, haystack, re.IGNORECASE):
            detected.add(name)

    server_header = response.headers.get("Server", "")
    powered_by = response.headers.get("X-Powered-By", "")

    return {
        "detected": sorted(detected),
        "server": server_header,
        "powered_by": powered_by,
    }
