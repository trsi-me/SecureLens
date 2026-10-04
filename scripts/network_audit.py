"""
أداة سطر أوامر داخلية (لا تُستخدم إلا محلياً من قِبل فريق الأمن) تُكمّل SecureLens
بفحوصات شبكة نشطة عبر Nmap، واختيارياً التقاط حزم عبر tshark (نسخة سطر الأوامر من Wireshark).

هذه الأداة مقصودة للاستخدام اليدوي من طرف فريق تقني على أصول يملكها الفريق فعلياً،
ولا يتم استدعاؤها أبداً من تطبيق الويب العام في app.py، لأن الفحص النشط (Active Scanning)
يختلف عن الفحص السلبي (Passive) الذي يعتمده SecureLens بواجهة الويب.

الاستخدام:
    python scripts/network_audit.py example.com --i-own-this
    python scripts/network_audit.py example.com --i-own-this --capture 15
"""

import argparse
import re
import shutil
import subprocess
import sys

HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$")


def validate_target(target):
    """يمنع حقن أوامر عبر قبول أسماء مضيفين/عناوين IP صحيحة الصيغة فقط."""
    if not HOSTNAME_PATTERN.match(target):
        raise ValueError("الهدف غير صالح، استخدم اسم نطاق أو عنوان IP فقط بدون رموز إضافية.")
    return target


def run_nmap(target):
    if not shutil.which("nmap"):
        print("تحذير: أداة nmap غير مثبتة على هذا الجهاز، تخطي فحص المنافذ.")
        return
    print(f"==> تشغيل Nmap (فحص منافذ أساسي) على {target} ...")
    try:
        subprocess.run(["nmap", "-sV", "--top-ports", "100", target], check=True)
    except subprocess.CalledProcessError as exc:
        print(f"فشل تشغيل nmap: {exc}")


def run_tshark_capture(target, seconds):
    if not shutil.which("tshark"):
        print("تحذير: أداة tshark (Wireshark) غير مثبتة على هذا الجهاز، تخطي التقاط الحزم.")
        return
    print(f"==> التقاط حزم لمدة {seconds} ثانية متعلقة بـ {target} ...")
    try:
        subprocess.run(
            ["tshark", "-a", f"duration:{seconds}", "-f", f"host {target}", "-w", "capture.pcapng"],
            check=True,
        )
        print("==> تم حفظ الالتقاط في capture.pcapng، افتحه بـ Wireshark لتحليله يدوياً.")
    except subprocess.CalledProcessError as exc:
        print(f"فشل تشغيل tshark: {exc}")


def main():
    parser = argparse.ArgumentParser(description="أداة فحص شبكة نشطة داخلية مكمّلة لـ SecureLens.")
    parser.add_argument("target", help="اسم النطاق أو عنوان IP للأصل الذي تملكه.")
    parser.add_argument(
        "--i-own-this",
        action="store_true",
        required=True,
        help="تأكيد إلزامي بأنك تملك هذا الأصل أو لديك تصريح رسمي بفحصه.",
    )
    parser.add_argument(
        "--capture",
        type=int,
        default=0,
        help="عدد ثواني التقاط الحزم عبر tshark (اختياري، صفر يعني تعطيل الالتقاط).",
    )
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
    except ValueError as exc:
        print(f"خطأ: {exc}")
        sys.exit(1)

    run_nmap(target)

    if args.capture > 0:
        run_tshark_capture(target, args.capture)


if __name__ == "__main__":
    main()
