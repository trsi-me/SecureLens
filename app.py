import io
import os

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for
from flask_wtf import CSRFProtect

from config import Config
from models import Scan, db
from scanner import run_full_scan
from utils.arabic_datetime import format_arabic_datetime
from utils.pdf_report import build_pdf_report

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)

    csrf.init_app(app)

    db.init_app(app)
    with app.app_context():
        db.create_all()

    app.jinja_env.filters["ar_datetime"] = format_arabic_datetime

    register_routes(app)
    register_security_headers(app)
    return app


def register_security_headers(app: Flask):
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "script-src 'self'"
        )
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response


def get_scanner_config(app):
    return {
        "REQUEST_TIMEOUT": app.config["REQUEST_TIMEOUT"],
        "MAX_REDIRECTS": app.config["MAX_REDIRECTS"],
        "USER_AGENT": app.config["USER_AGENT"],
        "AI_PROVIDER": app.config["AI_PROVIDER"],
        "AI_API_KEY": app.config["AI_API_KEY"],
    }


def register_routes(app: Flask):

    @app.route("/")
    def index():
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(8).all()
        return render_template("index.html", recent_scans=recent_scans)

    @app.route("/scan", methods=["POST"])
    def scan():
        target_url = (request.form.get("url") or "").strip()
        confirmed_ownership = request.form.get("confirm_ownership")

        if not target_url:
            return render_template("index.html", error="الرجاء إدخال رابط صحيح للفحص.", recent_scans=[])

        if not confirmed_ownership:
            return render_template(
                "index.html",
                error="يجب تأكيد أنك تملك الموقع أو لديك تصريح رسمي بفحصه قبل المتابعة.",
                recent_scans=[],
            )

        result = run_full_scan(target_url, get_scanner_config(app))

        if not result.get("ok"):
            return render_template(
                "index.html",
                error=result.get("error", "حدث خطأ غير متوقع أثناء الفحص."),
                recent_scans=Scan.query.order_by(Scan.created_at.desc()).limit(8).all(),
            )

        scan_record = Scan(
            target_url=result["target_url"],
            score=result["score"],
            grade=result["grade"],
            duration_ms=result["duration_ms"],
        )
        scan_record.set_findings(result["findings"])
        combined_meta = dict(result["meta"])
        combined_meta["severity_summary"] = result["severity_summary"]
        combined_meta["summary"] = result["summary"]
        scan_record.set_meta(combined_meta)

        db.session.add(scan_record)
        db.session.commit()

        return redirect(url_for("report", scan_id=scan_record.id))

    @app.route("/report/<int:scan_id>")
    def report(scan_id):
        scan_record = Scan.query.get_or_404(scan_id)
        meta = scan_record.get_meta()
        return render_template(
            "report.html",
            scan=scan_record,
            findings=scan_record.get_findings(),
            meta=meta,
            severity_summary=meta.get("severity_summary", {}),
            summary=meta.get("summary", {}),
        )

    @app.route("/report/<int:scan_id>/pdf")
    def report_pdf(scan_id):
        scan_record = Scan.query.get_or_404(scan_id)
        result = {
            "target_url": scan_record.target_url,
            "score": scan_record.score,
            "grade": scan_record.grade,
            "findings": scan_record.get_findings(),
            "severity_summary": scan_record.get_meta().get("severity_summary", {}),
            "meta": scan_record.get_meta(),
        }
        pdf_bytes = build_pdf_report(result)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"securelens_report_{scan_id}.pdf",
        )

    @app.route("/history")
    def history():
        all_scans = Scan.query.order_by(Scan.created_at.desc()).all()
        return render_template("history.html", scans=all_scans)

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/how-it-works")
    def how_it_works():
        return render_template("how_it_works.html")

    @app.route("/api/scan", methods=["POST"])
    @csrf.exempt
    def api_scan():
        """واجهة برمجية (JSON) لتشغيل الفحص برمجياً، مفيدة للتكامل مع أدوات أخرى."""
        data = request.get_json(silent=True) or {}
        target_url = (data.get("url") or "").strip()
        if not target_url:
            return jsonify({"ok": False, "error": "url is required"}), 400

        result = run_full_scan(target_url, get_scanner_config(app))
        status = 200 if result.get("ok") else 400
        return jsonify(result), status

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404


app = create_app()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_mode)
