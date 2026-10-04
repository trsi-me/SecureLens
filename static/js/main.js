// تحسينات بسيطة لتجربة المستخدم في واجهة أداة فحص الويب

document.addEventListener('DOMContentLoaded', () => {
  // تطبيع الرابط المُدخل تلقائياً (إزالة مسافات زائدة)
  const urlInput = document.getElementById('urlInput');
  if (urlInput) urlInput.addEventListener('blur', () => { urlInput.value = urlInput.value.trim(); });

  // فتح/إغلاق كل الملاحظات دفعة واحدة في صفحة التقرير (إن وُجد زر لاحقاً)
  const findingCards = document.querySelectorAll('.finding-card');
  // فتح الملاحظات الحرجة والعالية تلقائياً لجذب الانتباه
  if (findingCards.length > 0) findingCards.forEach((card) => { if (card.classList.contains('sev-border-critical') || card.classList.contains('sev-border-high')) card.setAttribute('open', 'true'); });

  // القائمة المتنقلة (الهيدر المتجاوب) للشاشات الصغيرة
  const navToggle = document.getElementById('navToggle');
  const navLinks = document.getElementById('navLinks');
  const navClose = document.getElementById('navClose');
  if (navToggle && navLinks) navToggle.addEventListener('click', () => {
    navLinks.classList.add('is-open');
    navToggle.setAttribute('aria-expanded', 'true');
  });
  if (navClose && navLinks && navToggle) navClose.addEventListener('click', () => {
    navLinks.classList.remove('is-open');
    navToggle.setAttribute('aria-expanded', 'false');
  });
  if (navLinks && navToggle) navLinks.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
    navLinks.classList.remove('is-open');
    navToggle.setAttribute('aria-expanded', 'false');
  }));
});
