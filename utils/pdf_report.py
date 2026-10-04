"""
توليد تقرير PDF لنتائج الفحص.

ملاحظة: توليد PDF يدعم اللغة العربية بشكل كامل (مع اتصال الحروف واتجاه
الكتابة الصحيح) يتطلب خطوطاً خاصة ومكتبات تشكيل إضافية (arabic-reshaper
و python-bidi). لتبسيط الإعداد وتقليل الاعتماديات، يُولَّد تقرير الـ PDF
بالمحتوى الإنجليزي لكل ملاحظة (المتوفر أصلاً في كل نتيجة عبر title_en و
description_en)، بينما تبقى واجهة الويب والتقرير التفاعلي يعرضان اللغة
العربية بشكل كامل وصحيح. يمكن لاحقاً إضافة خط عربي (مثل Amiri أو Cairo)
وتفعيل التشكيل لدعم PDF عربي كامل إذا احتاج المستخدم ذلك.
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos

SEVERITY_COLORS = {
    "critical": (192, 57, 43),
    "high": (230, 126, 34),
    "medium": (241, 196, 15),
    "low": (52, 152, 219),
    "info": (149, 165, 166),
}


class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(20, 30, 60)
        self.cell(0, 12, "WebScan AI - Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(90, 90, 90)
        self.cell(0, 6, "AI-assisted passive web security checkup", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


PLACEHOLDER_NON_LATIN = (
    "(Full details are in Arabic - see the online report in your browser for this text.)"
)


def _pdf_safe(text: str) -> str:
    """
    يضمن أن النص قابل للعرض بخط Helvetica القياسي (Latin-1 فقط).
    بعض الحقول (خصوصاً description/recommendation) قد ترث نصاً عربياً حين
    لا تتوفر نسخة إنجليزية صريحة لها (راجع finding.py)، وخط PDF الأساسي لا
    يدعم رسم الحروف العربية، لذا نستبدل أي نص كهذا بعبارة توضيحية آمنة
    بدلاً من تعطّل توليد الـ PDF بالكامل.
    """
    if not text:
        return ""
    try:
        text.encode("latin-1")
        return text
    except UnicodeEncodeError:
        return PLACEHOLDER_NON_LATIN


def build_pdf_report(scan_result: dict) -> bytes:
    pdf = ReportPDF()
    pdf.add_page()

    target_url = scan_result.get("target_url", "")
    score = scan_result.get("score", 0)
    grade = scan_result.get("grade", "F")
    findings = scan_result.get("findings", [])
    severity_summary = scan_result.get("severity_summary", {})
    meta = scan_result.get("meta", {})

    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 8, f"Target: {_pdf_safe(target_url)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.multi_cell(0, 8, f"Overall Score: {score}/100   Grade: {grade}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.multi_cell(
        0,
        8,
        f"Scanned at status code {meta.get('status_code', '-')}, "
        f"HTTPS: {'Yes' if meta.get('used_https') else 'No'}, "
        f"Response time: {meta.get('response_time_ms', '-')} ms",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Findings by severity:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_summary.get(sev, 0)
        pdf.cell(0, 6, f"  - {sev.capitalize()}: {count}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Detailed findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    for f in findings:
        color = SEVERITY_COLORS.get(f.get("severity", "info"), (100, 100, 100))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(
            0,
            7,
            _pdf_safe(f" [{f.get('severity', 'info').upper()}] {f.get('title_en', '')}"),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            fill=True,
        )

        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(
            0, 5, f"Description: {_pdf_safe(f.get('description_en', ''))}", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        if f.get("evidence"):
            pdf.multi_cell(0, 5, f"Evidence: {_pdf_safe(f.get('evidence', ''))}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if f.get("recommendation_en"):
            pdf.multi_cell(
                0,
                5,
                f"Recommendation: {_pdf_safe(f.get('recommendation_en', ''))}",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
        pdf.ln(2)

    if not findings:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, "No security issues were detected.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())
