# سكربت أتمتة تجهيز SecureLens على Windows Server.
# الاستخدام (PowerShell كمسؤول): .\scripts\setup_windows.ps1

$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir

Write-Host "==> تجهيز SecureLens في: $ProjectDir"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "خطأ: لم يتم العثور على Python. ثبّت Python 3.10 أو أحدث من python.org أولاً."
    exit 1
}

python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "==> تم إنشاء ملف .env من .env.example، عدّل القيم قبل التشغيل بالإنتاج."
}

Write-Host "==> التجهيز اكتمل. للتشغيل المحلي: .\.venv\Scripts\Activate.ps1 ; python app.py"
Write-Host "==> للتشغيل بالإنتاج على IIS، استخدم wfastcgi أو استضف Gunicorn داخل WSL."
