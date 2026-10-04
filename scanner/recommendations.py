"""
محرك التوصيات "الذكي".

بشكل افتراضي (بدون أي مفتاح API) يعمل هذا المحرك كنظام خبير قائم على قواعد
(rule-based expert system): يرتّب الملاحظات حسب الخطورة، يجمّعها حسب
الفئة، ويولّد ملخصاً تنفيذياً وخطة عمل مقترحة بالعربية والإنجليزية.

إذا رغب المستخدم لاحقاً بربط نموذج ذكاء اصطناعي حقيقي (OpenAI أو Anthropic)
لتوليد توصيات أكثر تخصيصاً بلغة طبيعية، يكفي تعبئة AI_PROVIDER و AI_API_KEY
في ملف .env، وستُستخدم الدالة generate_ai_summary تلقائياً بدلاً من القواعد
الثابتة. هذا يبقي الأداة تعمل بالكامل دون اتصال بالإنترنت أو تكلفة إضافية
عند عدم توفر مفتاح API.
"""

from collections import defaultdict

CATEGORY_LABELS_AR = {
    "headers": "رؤوس الأمان",
    "cookies": "إعدادات الكوكيز",
    "ssl": "شهادة SSL/TLS",
    "exposure": "كشف ملفات ومسارات حساسة",
    "content": "محتوى الصفحة",
    "injection": "ثغرات الحقن (XSS)",
    "general": "عام",
}

PRIORITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_rule_based_summary(findings, score, grade, target_url):
    if not findings:
        return {
            "headline_ar": f"لم يتم العثور على مشاكل أمان واضحة في {target_url}. النتيجة: {score}/100 ({grade}).",
            "headline_en": f"No obvious security issues found on {target_url}. Score: {score}/100 ({grade}).",
            "action_plan_ar": [
                "حافظ على تحديث البرمجيات والمكتبات المستخدمة بشكل دوري.",
                "أعد فحص الموقع بشكل دوري (شهرياً) خصوصاً بعد أي تحديث كبير.",
            ],
        }

    by_category = defaultdict(list)
    for f in findings:
        by_category[f.get("category", "general")].append(f)

    critical_high = [f for f in findings if f["severity"] in ("critical", "high")]

    headline_ar = (
        f"تم اكتشاف {len(findings)} ملاحظة أمنية في {target_url}، منها "
        f"{len(critical_high)} ذات أولوية عالية أو حرجة. الدرجة الإجمالية: {score}/100 ({grade})."
    )
    headline_en = (
        f"Found {len(findings)} security findings on {target_url}, including "
        f"{len(critical_high)} high/critical priority issues. Overall score: {score}/100 ({grade})."
    )

    action_plan_ar = []
    sorted_findings = sorted(
        findings, key=lambda f: PRIORITY_ORDER.index(f.get("severity", "info"))
    )
    for f in sorted_findings[:5]:
        if f.get("recommendation_ar"):
            action_plan_ar.append(f"[{f['severity_label_ar']}] {f['title_ar']}: {f['recommendation_ar']}")

    category_breakdown_ar = {
        CATEGORY_LABELS_AR.get(cat, cat): len(items) for cat, items in by_category.items()
    }

    return {
        "headline_ar": headline_ar,
        "headline_en": headline_en,
        "action_plan_ar": action_plan_ar,
        "category_breakdown_ar": category_breakdown_ar,
    }


def generate_ai_summary(findings, score, grade, target_url, provider, api_key):
    """
    نقطة ربط اختيارية بنموذج ذكاء اصطناعي حقيقي.
    تُترك بسيطة عمداً حتى لا تفرض تبعية على مكتبات خارجية غير مثبتة افتراضياً.
    """
    if provider == "openai" and api_key:
        try:
            from openai import OpenAI  # مكتبة اختيارية، ثبّتها فقط إذا فعّلت هذا الخيار

            client = OpenAI(api_key=api_key)
            findings_text = "\n".join(
                f"- ({f['severity']}) {f['title_ar']}: {f['description_ar']}" for f in findings[:15]
            )
            prompt = (
                f"أنت خبير أمن سيبراني. إليك نتائج فحص الموقع {target_url} "
                f"(الدرجة: {score}/100):\n{findings_text}\n\n"
                "اكتب ملخصاً تنفيذياً موجزاً بالعربية (3-4 جمل) وخطة عمل من 3 نقاط."
            )
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=400,
            )
            return {"ai_generated": True, "text": completion.choices[0].message.content}
        except Exception as exc:  # noqa: BLE001
            return {"ai_generated": False, "error": str(exc)}

    return {"ai_generated": False, "error": "لم يتم تهيئة مزوّد ذكاء اصطناعي (AI_PROVIDER)."}
