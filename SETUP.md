# إعداد YASJOY (Cloudflare + Firebase)

1. ارفع `admin.html` و `index.html` ومجلد `functions/` إلى جذر المستودع (functions بجانب index.html) ثم أعد النشر على Cloudflare Pages.
2. Cloudflare Pages > Settings > Variables and Secrets: أضف `FIREBASE_SERVICE_ACCOUNT` = ملف JSON لحساب الخدمة (Firebase Console > Project settings > Service accounts > Generate new private key). اختياري: `ADMIN_UID`.
3. قواعد Firestore: اسمح للمستخدم بتحديث حقوله (balance عبر عملية السحب فقط، وip, previousIp, ipAt, countryCode, country, countryAt, lastCountryCode, lastCountry, previousCountryCode, banned, banReason, bannedBy, bannedAt, wallEntries). اسمح للمسؤول بالقراءة على transactions و postbackLogs وبالحذف على users/withdrawals/transactions.
4. جدار العروض: من لوحة المسؤول > جدران العروض أضف الجدار + المفتاح السري، احفظ، انسخ رابط Postback وضعه في لوحة المزوّد (بدّل المتغيرات حسب مزوّدك).
