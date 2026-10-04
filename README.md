# SecureLens

أداة ويب عربية لفحص أمني سلبي لموقع يملكه المشغّل أو يملك تصريحاً بفحصه. الواجهة تسجّل درجة أمان وتقديراً حرفياً وتقرير نتائج، مع إمكانية تنزيل PDF.

## 1. ما هو المشروع

SecureLens تطبيق Flask يعرض صفحة عربية يطلب فيها رابط الموقع وتأكيداً بأن المشغّل يملك الموقع أو لديه تصريح رسمي. بعد الفحص تُحفظ النتيجة في قاعدة بيانات وتُعرض في تقرير. الفحص المدمج في الواجهة سلبي: يقرأ استجابة الخادم كما يراها زائر عادي، ويراجع رؤوس HTTP والكوكيز وشهادة TLS ومحتوى الصفحة وملفات عامة مثل `robots.txt`.

يوجد سكربت منفصل `scripts/network_audit.py` لفحص شبكة محلي لا يستدعيه تطبيق الويب. هذا السكربت يطلب علماً صريحاً بالملكية قبل أن يشغّل أدوات مثبتة محلياً.

## 2. لماذا يوجد هذا المشروع

الواجهة والنصوص في القوالب تقدّم الأداة كفحص أمان لموقع الويب مع توصيات إصلاح عربية. المحرك في `scanner/engine.py` يجمع ملاحظات مصنّفة الخطورة ثم يحسب درجة من 100 وتقديراً من `A+` إلى `F`.

## 3. من يستخدمه

| الدور الظاهر في الملفات | ما يستطيع فعله |
| --- | --- |
| زائر الواجهة | إدخال رابط، تأكيد الملكية، مشاهدة التقرير والسجل وتنزيل PDF |
| مستدعٍ لواجهة JSON | إرسال رابط إلى `POST /api/scan` واستلام JSON |
| مشغّل محلي لسكربت الشبكة | تشغيل `scripts/network_audit.py` على جهازه مع علم الملكية |

حسابات مستخدمين وأدوار داخل التطبيق: «غير موجود في الملفات الحالية».

## 4. ماذا يستطيع النظام أن يفعل

| الوحدة | الوظيفة الحالية |
| --- | --- |
| `check_security_headers` | يلاحظ غياب HSTS وCSP وX-Frame-Options وX-Content-Type-Options وReferrer-Policy وPermissions-Policy، ويلاحظ رؤوس تكشف نوع الخادم |
| `check_cookies` | يراجع أعلام الكوكيز الظاهرة في الاستجابة |
| `check_ssl` | يفحص الشهادة على المنفذ 443: الانتهاء، القرب من الانتهاء، إصدارات TLS القديمة، وفشل التحقق |
| `check_mixed_content` | يلاحظ موارد غير مشفّرة داخل صفحة HTTPS |
| `check_directory_listing` | يلاحظ تفعيل سرد المجلد |
| `check_sensitive_files` | يطلب قائمة مسارات ثابتة داخل الكود ويبلّغ إن استجاب الخادم |
| `check_robots_and_sitemap` | يقرأ `robots.txt` ويبلّغ إن ظهرت فيه إشارات لمسارات حساسة |
| `check_reflected_marker` | يرسل علامة تجريبية ويبلّغ إن انعكست في الصفحة دون تهريب. النتيجة معلّمة بأنها تحتاج تأكيداً يدوياً |
| `detect_technologies` | يطابق بصمات نصية شائعة مثل WordPress وLaravel وDjango وغيرها |
| `compute_score` | يبدأ من 100 ويخصم أوزاناً: حرجة 25، عالية 15، متوسطة 8، منخفضة 3، معلومة 0 |
| `build_rule_based_summary` | ملخص عربي/إنجليزي مبني على القواعد |
| `generate_ai_summary` | مسار اختياري لمزوّد `openai` فقط إذا وُجد المفتاح والمكتبة |
| `build_pdf_report` | يبني ملف PDF من نتيجة محفوظة |
| `scripts/network_audit.py` | فحص منافذ أساسي عبر `nmap` إن وُجد، والتقاط اختياري عبر `tshark` |

التقدير الحرفي: `A+` من 90، `A` من 80، `B` من 70، `C` من 55، `D` من 40، ودون ذلك `F`.

## 5. كيف يعمل النظام

```
المتصفح
  -> نموذج POST /scan مع الرابط وتأكيد الملكية
  -> run_full_scan
  -> طلب HTTP للصفحة ثم فحوصات الرؤوس وTLS والمحتوى
  -> درجة + تقدير + ملخص
  -> حفظ صف في جدول scans
  -> تحويل إلى /report/<id>
  -> عرض HTML أو تنزيل PDF
```

إن تعذّر الوصول إلى الرابط تبقى الصفحة الرئيسية مع رسالة خطأ ولا يُنشأ سجل.

## 6. أمثلة واقعية

1. المشغّل يفتح `/` ويرى آخر 8 فحوصات.
2. يرسل الرابط مع مربع التأكيد. المحرك يطبع الرابط ويطلب الصفحة.
3. إن نجح الطلب تُحفظ الدرجة والمدة والنتائج في `scans` ثم يفتح `/report/<id>`.
4. من التقرير يمكن تنزيل `securelens_report_<id>.pdf`.
5. صفحة `/history` تعرض كل الصفوف بترتيب الأحدث.
6. `POST /api/scan` بجسم JSON فيه الحقل `url` يعيد نتيجة الفحص دون حفظها في قاعدة البيانات. استنتاج من الكود: مسار API لا يستدعي `Scan` ولا `db.session.add`.

## 7. رحلة المستخدم

التطبيق بلا تسجيل دخول. الرحلة الحالية:

1. فتح `/`.
2. كتابة الرابط.
3. تأكيد الملكية. بدون هذا المربع تُرفض العملية برسالة عربية.
4. انتظار الفحص.
5. قراءة التقرير: الدرجة، التقدير، الملخص، الملاحظات.
6. تنزيل PDF أو الرجوع إلى السجل.

صفحتا `/about` و`/how-it-works` شرح ثابت داخل القوالب.

## 8. الوحدات والأقسام

| الملف | الوظيفة | علاقته بالنظام |
| --- | --- | --- |
| `app.py` | إنشاء التطبيق والمسارات ورؤوس الأمان | يستدعي `run_full_scan` ويحفظ `Scan` |
| `config.py` | قراءة البيئة | يمرَّر جزء منها إلى المحرك |
| `models.py` | نموذج `Scan` | جدول `scans` |
| `scanner/engine.py` | تنسيق الفحص | يجمع كل الفاحصات |
| `scanner/http_client.py` | `normalize_url` و`safe_get` | كل الطلبات الصادرة |
| `scanner/finding.py` | شكل الملاحظة الموحّد | كل الفاحصات |
| `scanner/scoring.py` | الدرجة والتقدير | بعد جمع الملاحظات |
| `scanner/recommendations.py` | الملخص القاعدي ومسار OpenAI | نهاية الفحص |
| `utils/pdf_report.py` | PDF عبر `fpdf2` | مسار التنزيل |
| `utils/arabic_datetime.py` | مرشّح قالب `ar_datetime` | عرض وقت الفحص |
| `templates/` | الصفحات العربية | واجهة المستخدم |
| `static/` | CSS وJS وشعار | التنسيق |
| `deploy/` | gunicorn وnginx وApache وsystemd ونماذج سحابة | تشغيل الإنتاج |
| `scripts/setup_linux.sh` و`setup_windows.ps1` | إعداد بيئة محلي | خارج دورة الطلب |
| `security-tools/` | نموذج OpenVPN وقواعد Snort باسم `securelens.rules` | ملفات مرافقة، التطبيق لا يحمّلها |

## 9. الشركات والكيانات

«غير موجود في الملفات الحالية». المشروع أحادي ولا يفرّق بين شركات أو فروع.

## 10. الصلاحيات

لا أدوار مستخدمين. الفرق الوحيد الظاهر:

- نموذج الويب يشترط حقل `confirm_ownership`.
- `POST /api/scan` معفى من CSRF ولا يفحص هذا الحقل.
- سكربت الشبكة يرفض الهدف إن لم يُمرَّر علم الملكية الموجود في السكربت، ويقبل اسم نطاق أو عنواناً يطابق النمط في `validate_target`.

## 11. الأتمتة ومسارات العمل

«غير موجود في الملفات الحالية» داخل تطبيق الويب. لا طوابير ولا مهام مجدولة. ملف `deploy/securelens.service` يعرّف خدمة systemd لإبقاء عملية gunicorn تعمل وإعادة تشغيلها عند الفشل.

## 12. التكامل بين الوحدات

`run_full_scan` يمرر الاستجابة نفسها إلى فاحصات الرؤوس والمحتوى والتقنيات، ويمرر اسم المضيف إلى فحص TLS. الملخص القاعدي يُبنى دائماً. إن وُجد `AI_PROVIDER` و`AI_API_KEY` ونجح استدعاء OpenAI يُستبدل نص الملخص بالنص الراجع. الحفظ في `Scan` يجمع `meta` مع `severity_summary` و`summary`.

## 13. المصطلحات

| المصطلح | المعنى في هذا المشروع |
| --- | --- |
| فحص سلبي | قراءة استجابات عامة دون تعديل الموقع |
| Finding | قاموس ملاحظة فيه `check_id` و`severity` ونص عربي |
| Score | رقم من 0 إلى 100 |
| Grade | `A+` أو `A` أو `B` أو `C` أو `D` أو `F` |
| CSRF | حماية نماذج Flask-WTF. مسار API معفى منها |
| HSTS / CSP | رأسا أمان يبحث عنهما `checks_headers.py` |

## 14. الأسئلة الشائعة

**هل يُحفظ كل فحص؟** فحص النموذج نعم. فحص `POST /api/scan` يعيد JSON فقط.

**ماذا لو الموقع لا يفتح؟** تُعاد رسالة «تعذّر الوصول إلى الموقع» ولا يُحفظ صف.

**هل توصيات الذكاء الاصطناعي إلزامية؟** المسار القاعدي هو الافتراضي. OpenAI يُستدعى فقط عند تعبئة المزوّد والمفتاح. تعليق `config.py` يذكر `anthropic`، والدالة `generate_ai_summary` لا تحتوي فرعاً لهذا المزوّد.

**أين قاعدة البيانات؟** الافتراضي ملف `instance/scans.db`. يمكن تغيير `DATABASE_URL`.

## 15. Architecture

```
+------------------+     +-------------------+     +------------------+
| templates/static | --> | Flask app.py      | --> | scanner/engine   |
| Jinja RTL        |     | CSRF + headers    |     | checks + scoring |
+------------------+     +---------+---------+     +--------+---------+
                                   |                        |
                                   v                        v
                            SQLite scans.db          requests + TLS
                            أو MySQL/PostgreSQL      موقع الهدف
                                   |
                                   v
                            utils/pdf_report.py
```

## 16. Tech Stack

| الطبقة | التقنية |
| --- | --- |
| اللغة | Python |
| إطار الويب | Flask 3.0.3 |
| النماذج وCSRF | Flask-WTF 1.2.1 |
| قاعدة البيانات | Flask-SQLAlchemy 3.1.1، الافتراضي SQLite |
| HTTP | requests 2.32.3 |
| HTML | beautifulsoup4 4.12.3 |
| النطاقات | tldextract 5.1.2 |
| PDF | fpdf2 2.7.9 |
| البيئة | python-dotenv 1.0.1 |
| إنتاج | gunicorn 22.0.0 |
| واجهة | Jinja2 وقوالب HTML و`static/css/style.css` و`static/js/main.js` |
| خطوط الواجهة | IBM Plex Sans Arabic من Google Fonts، وأيقونات Font Awesome من CDN |

قواعد البيانات الاختيارية في `requirements-db.txt`: `psycopg2-binary==2.9.9` و`PyMySQL==1.1.1`. مكتبة `openai` غير مذكورة في `requirements.txt`.

## 17. Project Structure

```
SecureLens/
  app.py
  config.py
  models.py
  requirements.txt
  requirements-db.txt
  .env.example
  scanner/
  utils/
  templates/
  static/
  deploy/
  scripts/
  security-tools/
  instance/scans.db
```

## 18. Frontend

تطبيق متعدد الصفحات (MPA) عبر قوالب Jinja، الاتجاه `rtl` واللغة `ar`.

| القالب | المسار |
| --- | --- |
| `index.html` | `/` ونموذج الفحص |
| `report.html` | `/report/<scan_id>` |
| `history.html` | `/history` |
| `about.html` | `/about` |
| `how_it_works.html` | `/how-it-works` |
| `404.html` | خطأ 404 |
| `base.html` | الهيكل والقائمة وأيقونة التبويب `static/img/logo.jpeg` |

`static/js/main.js` يتحكم بالقائمة في الشاشات الضيقة. تحميل البيانات يتم على الخادم قبل الرسم، بلا SPA.

## 19. Backend

- `create_app` يجهّز Flask وCSRF وSQLAlchemy وينشئ الجداول بـ `db.create_all`.
- المنطق في حزمة `scanner` وليس في طبقة controllers منفصلة.
- الاستعلامات عبر SQLAlchemy على نموذج `Scan`.
- التشغيل المباشر: المضيف `0.0.0.0` والمنفذ من `PORT` أو 5000. وضع التصحيح يعمل عندما `FLASK_DEBUG=1`.

## 20. Request Flow

مثال فحص من النموذج:

```
المتصفح
  -> POST /scan
  -> التحقق من url و confirm_ownership
  -> run_full_scan
  -> safe_get ثم الفاحصات
  -> INSERT في scans
  -> 302 إلى /report/<id>
  -> SELECT وعرض report.html
```

مثال API:

```
POST /api/scan
  JSON { "url": "..." }
  -> run_full_scan
  -> 200 أو 400 مع JSON
```

## 21. Database

| البند | القيمة |
| --- | --- |
| النوع الافتراضي | SQLite |
| الملف | `instance/scans.db` |
| الاتصال | `DATABASE_URL` أو مسار SQLite في `config.py` |
| الاستعلامات | SQLAlchemy ORM |
| migrations | «غير موجود في الملفات الحالية». الإنشاء عبر `db.create_all` |
| seeds | «غير موجود في الملفات الحالية» |

جدول `scans`:

| العمود | الدور |
| --- | --- |
| `id` | مفتاح أساسي |
| `target_url` | الرابط، حتى 512 حرفاً |
| `created_at` | وقت الإنشاء |
| `score` | الدرجة |
| `grade` | التقدير، طول 2 |
| `findings_json` | نص JSON للملاحظات |
| `meta_json` | نص JSON للبيانات الوصفية |
| `duration_ms` | مدة الفحص |

العلاقات: «غير موجود في الملفات الحالية». جدول واحد.

## 22. API

| Method | Path | الغرض | المدخلات | المصادقة | الاستجابة |
| --- | --- | --- | --- | --- | --- |
| GET | `/` | الصفحة الرئيسية | - | لا | HTML |
| POST | `/scan` | فحص وحفظ | نموذج: `url` و`confirm_ownership` ورمز CSRF | لا | تحويل أو HTML خطأ |
| GET | `/report/<scan_id>` | عرض تقرير | رقم الفحص | لا | HTML أو 404 |
| GET | `/report/<scan_id>/pdf` | تنزيل PDF | رقم الفحص | لا | ملف PDF |
| GET | `/history` | كل الفحوصات | - | لا | HTML |
| GET | `/about` | عن المشروع | - | لا | HTML |
| GET | `/how-it-works` | شرح | - | لا | HTML |
| POST | `/api/scan` | فحص JSON بلا حفظ | JSON: `url` | لا، ومعفى من CSRF | JSON وحالة 200 أو 400 |

## 23. Authentication & Authorization

تسجيل دخول وجلسات مستخدمين: «غير موجود في الملفات الحالية».

الحماية الموجودة على النماذج هي CSRF من Flask-WTF. مسار `/api/scan` موسوم بـ `csrf.exempt`.

## 24. Security

الموجود فعلياً:

- رؤوس الاستجابة: `X-Content-Type-Options: nosniff` و`X-Frame-Options: DENY` و`Referrer-Policy` و`Permissions-Policy` و`Content-Security-Policy`، مع إزالة رأسي `Server` و`X-Powered-By`.
- CSRF على نماذج Flask.
- اشتراط تأكيد الملكية في نموذج الويب.
- `validate_target` في سكربت الشبكة يقبل نمطاً محدوداً قبل تمرير النص إلى عملية خارجية.
- المهلة وعدد التحويلات من الإعدادات.
- وكيل المستخدم الافتراضي يعرّف الأداة كفاحص سلبي.

النقاط الظاهرة في الكود وتحتاج قرار تشغيل:

- مفتاح سري احتياطي داخل `config.py` إذا خلا `SECRET_KEY`.
- تقارير PDF والسجل و`/api/scan` بلا مصادقة.
- مسار API معفى من CSRF.

كلمات مرور وتجزئة: «غير موجود في الملفات الحالية». تحديد معدل الطلبات: «غير موجود في الملفات الحالية». سجل تدقيق منفصل: «غير موجود في الملفات الحالية».

## 25. Configuration

انسخ `.env.example` إلى `.env`. الأسماء فقط:

| المتغير | الدور |
| --- | --- |
| `SECRET_KEY` | مفتاح الجلسة/CSRF |
| `DATABASE_URL` | سلسلة الاتصال |
| `AI_PROVIDER` | المزوّد الاختياري |
| `AI_API_KEY` | مفتاح المزوّد |
| `REQUEST_TIMEOUT` | مهلة الطلب، الافتراضي 10 |
| `MAX_REDIRECTS` | الافتراضي 5 |
| `SCANNER_USER_AGENT` | وكيل المستخدم |
| `FLASK_DEBUG` | `1` يفعّل وضع التصحيح عند التشغيل المباشر |
| `PORT` | منفذ التشغيل المباشر، الافتراضي 5000 |

لا تُنسخ قيم الأسرار إلى هذا الملف. `.gitignore` موجود.

## 26. Integrations

| الخدمة | الحالة في الكود |
| --- | --- |
| OpenAI | استدعاء اختياري في `generate_ai_summary` بالنموذج `gpt-4o-mini` |
| Anthropic | مذكور في تعليق الإعداد فقط |
| Google Fonts وFont Awesome CDN | روابط في `base.html` ومسموحة في CSP |
| nmap وtshark | يستدعيهما سكربت الشبكة إن وُجدا في مسار النظام |
| OpenVPN وSnort | ملفات نموذجية في `security-tools/` ولا يستدعيها `app.py` |
| بريد أو رسائل | «غير موجود في الملفات الحالية» |

## 27. Scheduled Jobs

«غير موجود في الملفات الحالية».

## 28. File Storage

التخزين الدائم الظاهر هو ملف SQLite داخل `instance/`. مجلد `instance` يُنشأ عند الإقلاع. PDF يُولَّد في الذاكرة ويُرسل مباشرة بلا حفظ نسخة على القرص. رفع ملفات من المستخدم: «غير موجود في الملفات الحالية».

## 29. Logging & Monitoring

معالج أخطاء 404 يعيد قالباً. تسجيل تطبيقي منظم ومراقبة وتنبيهات: «غير موجود في الملفات الحالية». أخطاء الفحص تُعاد كنص للمستخدم في الصفحة أو في حقل `error` داخل JSON.

## 30. Installation

1. تثبيت Python.
2. من جذر المشروع: `pip install -r requirements.txt`.
3. إن كانت القاعدة MySQL أو PostgreSQL: تثبيت السطر المناسب من `requirements-db.txt` وضبط `DATABASE_URL`.
4. نسخ `.env.example` إلى `.env` وتعيين `SECRET_KEY`.
5. التشغيل: `python app.py` ثم فتح `http://127.0.0.1:5000`.
6. سكربتا `scripts/setup_windows.ps1` و`scripts/setup_linux.sh` موجودان لإعداد البيئة. تفاصيل أوامرهما داخل الملفين.

فحص الشبكة الاختياري يحتاج `nmap`، والتقاط الحزم يحتاج `tshark`. الواجهة تعمل بدونهما.

## 31. Development Guide

فاحص جديد يُضاف كدالة تُرجع قائمة ملاحظات عبر `make_finding` ثم تُستدعى من `run_full_scan`. صفحة جديدة تُضاف كقالب يرث `base.html` ومسار في `register_routes`. عمود جديد في `Scan` يحتاج تعديل `models.py` ثم إعادة إنشاء الجدول، لأن migrations غير موجودة. صلاحيات المستخدمين غير موجودة، لذلك لا مسار جاهز لإضافة دور.

## 32. Deployment

| الملف | ما يعرّفه |
| --- | --- |
| `deploy/wsgi.py` | نقطة gunicorn: `app` |
| `deploy/securelens.service` | خدمة systemd، المستخدم `securelens`، المجلد `/opt/securelens`، الربط `127.0.0.1:8000`، 3 عمال |
| `deploy/nginx.conf` | نموذج وكيل عكسي |
| `deploy/apache.conf` | نموذج Apache |
| `deploy/cloud/aws_user_data.sh` | سكربت بيانات مستخدم |
| `deploy/cloud/azure_cloud_init.yaml` | نموذج cloud-init |

الإنتاج حسب وحدة systemd يقرأ `/opt/securelens/.env`. ربط الواجهة خلف الوكيل على 127.0.0.1:8000، بينما `python app.py` يربط `0.0.0.0`.

## 33. Backup & Recovery

«غير موجود في الملفات الحالية». النسخ العملي هو الاحتفاظ بملف `instance/scans.db` أو بقاعدة `DATABASE_URL`.

## 34. Troubleshooting

| العرض | ما يظهر في الكود |
| --- | --- |
| رسالة رابط غير صالح | `netloc` فارغ بعد `normalize_url` |
| تعذّر الوصول | `safe_get` لم يعد استجابة |
| رفض النموذج | حقل التأكيد غير مرسل |
| PDF لا يفتح | مراجعة استثناءات `build_pdf_report` على الخادم |
| OpenAI لا يعمل | المزوّد ليس `openai`، أو المفتاح فارغ، أو المكتبة غير مثبتة |
| nmap متخطى | الأداة غير موجودة في PATH |

## 35. Dependencies

من `requirements.txt`:

```
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
Flask-WTF==1.2.1
requests==2.32.3
beautifulsoup4==4.12.3
python-dotenv==1.0.1
tldextract==5.1.2
fpdf2==2.7.9
gunicorn==22.0.0
```

اختيارية: `psycopg2-binary==2.9.9` و`PyMySQL==1.1.1`. مكتبة OpenAI تُستورد داخل الدالة فقط عند التفعيل.

## 36. Known Limitations

- الفحص في الواجهة سلبي. ملاحظة XSS معلّمة بأنها تحتاج تأكيداً يدوياً.
- `grade` عمود بطول حرفين، والقيمة `A+` حرفان فتتسع.
- مسار API بلا تأكيد ملكية وبلا حفظ.
- لا مصادقة على التقارير.
- `AI_PROVIDER=anthropic` لا يملك فرع تنفيذ.
- سكربت الشبكة منفصل ويشغّل أدوات النظام إن وُجدت.

## 37. Current System State

| الحالة | البنود |
| --- | --- |
| موجود في الكود | الفحص السلبي، الحفظ، التقرير، PDF، السجل، API JSON، نماذج النشر |
| يعمل حسب مسار الكود | دورة النموذج حتى قاعدة SQLite المحلية `instance/scans.db` |
| غير مكتمل | مزوّد Anthropic، مصادقة المستخدمين، migrations |
| غير موثق خارج الكود | سياسة استخدام رسمية، جهة الاتصال، مالك المنتج |

## 38. Architecture Decisions

- الفحص السلبي معزول عن سكربت الشبكة حتى لا يمر فحص المنافذ عبر الواجهة العامة. السبب مكتوب في تعليق `scripts/network_audit.py`.
- النتائج تُخزَّن JSON داخل صف واحد بدل جداول ملاحظات منفصلة.
- الملخص القاعدي هو المسار الافتراضي حتى يبقى التشغيل بلا مفتاح خارجي.
- رؤوس الأمان تُضبط في `after_request` على تطبيق Flask نفسه.

## 39. سجل التغييرات

ملف إصدارات أو تاريخ إصدارات: «غير موجود في الملفات الحالية». وكيل المستخدم الافتراضي يحمل النص `SecureLens/1.0`. هذا معرف داخل الإعداد وليس سجل تغييرات.

## System Overview

```
[زائر]
   |  رابط + تأكيد ملكية
   v
[Flask SecureLens] --حفظ--> [scans]
   |
   +-- رؤوس وكوكيز
   +-- شهادة TLS
   +-- محتوى وملفات عامة
   +-- علامة انعكاس
   +-- بصمة تقنية
   |
   v
[درجة وتقرير HTML/PDF]

[مشغّل محلي] --> [network_audit.py] --> nmap / tshark
```

## Quick Reference

| الجزء | التقنية | الموقع | الوظيفة |
| --- | --- | --- | --- |
| واجهة | Jinja / CSS / JS | `templates/` و`static/` | الصفحات العربية |
| تطبيق | Flask | `app.py` | المسارات والحفظ |
| محرك | Python | `scanner/engine.py` | تنسيق الفحص |
| بيانات | SQLite | `instance/scans.db` | سجل الفحوصات |
| تقارير | fpdf2 | `utils/pdf_report.py` | تنزيل PDF |
| نشر | gunicorn | `deploy/` | خدمة وإنتاج |
| شبكة | nmap / tshark | `scripts/network_audit.py` | فحص محلي منفصل |

## Quick Start

```
pip install -r requirements.txt
copy .env.example .env
python app.py
```

ثم افتح `http://127.0.0.1:5000` وأدخل موقعاً تملكه أو تملك تصريحاً بفحصه مع تأكيد الملكية.

## For Non-Technical Users

SecureLens صفحة عربية تفحص موقعاً أنت مخوّل بفحصه وتعطيك درجة وتقديراً وقائمة ملاحظات مع نص إصلاح، ويمكنك تنزيل التقرير. ابدأ من الصفحة الرئيسية، اكتب الرابط، أكّد الملكية، ثم اقرأ التقرير. السجل يعيد الفحوصات السابقة.

أهم الأقسام: الرئيسية، كيف يعمل، سجل الفحوصات، عن المشروع، وصفحة التقرير.

## For Developers

- التقنيات: Flask وSQLAlchemy وJinja وSQLite، مع gunicorn للنشر.
- المعمارية: تطبيق واحد يستدعي حزمة `scanner` ويحفظ نموذجاً واحداً.
- قاعدة البيانات: جدول `scans` وJSON داخل عمودين نصيين.
- الواجهة البرمجية: `POST /api/scan` بلا حفظ وبلا CSRF.
- أهم الملفات: `app.py` و`scanner/engine.py` و`models.py` و`config.py`.
- التطوير: أضف الفاحص في `scanner/` ثم اربطه من `run_full_scan`. اضبط الأسرار في `.env` فقط.
