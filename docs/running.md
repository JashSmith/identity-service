# راهنمای اجرا

این راهنما اجرای کامل سامانه روی سیستم توسعه، بررسی سلامت، تست‌ها و افزودن سازمان جدید را توضیح می‌دهد.

- [پیش‌نیازها](#پیشنیازها)
- [اجرا](#اجرا)
- [بررسی سلامت](#بررسی-سلامت)
- [اولین ورود](#اولین-ورود)
- [تست‌ها](#تستها)
- [توقف](#توقف)
- [افزودن سازمان جدید](#افزودن-سازمان-جدید)
- [عیب‌یابی](#عیبیابی)

## پیش‌نیازها

- ‏.NET 10 SDK
- ‏Docker Desktop در حال اجرا
- آزاد بودن پورت‌های `18080` (Keycloak)، ‏`5080` (درگاه)، ‏`5081` (سرویس نمونه) و `5090` (کنسول)

پورت 8080 روی سیستم مالک پروژه در اختیار Apache است؛ به همین دلیل Keycloak روی 18080 و با گواهی توسعه HTTPS اجرا می‌شود.

## اجرا

```bash
bash scripts/build-keycloak-extensions.sh      # یک بار و پس از هر تغییر در keycloak/extensions (فقط Docker لازم است)
dotnet build IdentityService.slnx
dotnet run --project src/Identity.AppHost --launch-profile http
```

بدون ساخت افزونه هم سامانه کار می‌کند، ولی برنامه زمانی روی صفحه ورود خود Keycloak اعمال نمی‌شود و درگاه در لاگ هشدار می‌دهد.

‏Aspire این منابع را بالا می‌آورد:

| منبع | توضیح |
|---|---|
| ‏`postgres` | پایگاه داده Keycloak؛ ظرف ماندگار است و با توقف Stack پاک نمی‌شود |
| ‏`keycloak` | ‏Import دو Realm نمونه (`company` و `acme`) و تم فارسی `avash` |
| ‏`redis` | ‏Cache |
| ‏`identity-gateway` | درگاه هویت |
| ‏`identity-admin` | کنسول مدیریت |
| ‏`order-service` | سرویس نمونه که دسترسی‌هایش را ثبت می‌کند |

رمزهای Clientها و رمز مدیر Keycloak به‌صورت پارامتر Aspire ساخته و در User Secrets پروژه AppHost نگه داشته می‌شوند و در مخزن ذخیره نمی‌شوند.

## بررسی سلامت

```bash
curl http://localhost:5080/health        # Healthy پس از پایان Bootstrap کلیدکول برای همه سازمان‌ها
curl http://localhost:5090/alive         # کنسول
```

اولین اجرا به خاطر دریافت Imageها چند دقیقه طول می‌کشد و اجراهای بعدی حدود ۱۵ ثانیه.

## اولین ورود

1. ‏`http://localhost:5090` را باز کنید و سازمان «شرکت» را انتخاب کنید.
2. در صفحه ورود فارسی با `admin` و رمز `admin` وارد شوید. این کاربر فقط برای محیط توسعه است.
3. از بخش «نقش‌ها» یک نقش بسازید و از بخش «کاربران» کاربری با آن نقش و محدوده دلخواه ایجاد کنید.

ورود مستقیم از طریق API:

```bash
curl -X POST http://localhost:5080/api/identity/auth/login \
  -H "X-Tenant-Id: company" \
  -d "grant_type=password&username=admin&password=admin"
```

## تست‌ها

```bash
dotnet test IdentityService.slnx                       # بدون نیاز به Stack
bash scripts/smoke-test.sh                             # روی Stack در حال اجرا
IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests    # Stack را خودش بالا می‌آورد؛ Stack توسعه باید خاموش باشد
```

## توقف

با `Ctrl+C` در پنجره AppHost همه منابع متوقف می‌شوند. اگر پردازه AppHost را مستقیم ببندید، ظرف‌های `keycloak-*` و `redis-*` باقی می‌مانند و باید حذفشان کنید:

```bash
docker ps --format '{{.Names}}' | grep -E '^(keycloak|redis)-' | xargs -r docker rm -f
```

ظرف `postgres-*` عمداً ماندگار است.

## افزودن سازمان جدید

هر سازمان یک Realm است و ساخت خودکار Realm هنوز پیاده‌سازی نشده است. مراحل:

1. ‏Realm را با فایل Import یا با کنسول مدیریت Keycloak بسازید. فایل `src/Identity.AppHost/Keycloak/Realms/realm-acme.json` الگوی کاملی است: کلاینت‌های `identity-gateway-admin` (Service Account با نقش‌های realm-management) و `identity-gateway`، گروه‌های `super-admins` و `iam-scope-registry`، و Client Scopeهای `iam-access`، ‏`authz-scopes` و `iam-permissions`.
2. سازمان را در تنظیمات درگاه اضافه کنید؛ رمزها را از پیکربندی امن بدهید، نه در فایل:

   ```text
   Identity__Tenants__1__Id=branch-north
   Identity__Tenants__1__DisplayName=شعبه شمال
   Identity__Tenants__1__Realm=branch-north
   Identity__Tenants__1__AdminClientSecret=<secret>
   Identity__Tenants__1__ClientSecret=<secret>
   ```

3. سازمان را در تنظیمات کنسول (`Console__Tenants__N__*`) اضافه کنید.
4. درگاه را دوباره اجرا کنید. ‏Bootstrap برای Realm جدید رجیستری محدوده، Mapperها، گروه `super-admins`، دسترسی‌های درگاه و کلاینت کنسول را می‌سازد.

## عیب‌یابی

| نشانه | علت و راه‌حل |
|---|---|
| ‏`/health` مدت طولانی Unhealthy است | پیام وضعیت Bootstrap را در پاسخ `/health` یا لاگ درگاه ببینید؛ معمولاً Keycloak هنوز بالا نیامده یا رمز Service Account با Realm یکی نیست. |
| خطای SSL روی آدرس Keycloak | پورت در اختیار برنامه دیگری است یا گواهی توسعه معتبر نیست (`dotnet dev-certs https --trust`). |
| ‏`403 tenant.mismatch` | توکن از Realm سازمان دیگری است؛ سرآیند `X-Tenant-Id` را با سازمانی که توکن را صادر کرده یکی کنید. |
| ‏`403 access.outside_schedule` | کاربر خارج از برنامه زمانی است؛ برنامه مؤثر را در صفحه کاربر در کنسول ببینید. |
| کنسول پس از راه‌اندازی دوباره به صفحه ورود می‌رود | رفتار طراحی‌شده است: توکن‌ها فقط در حافظه کنسول نگه داشته می‌شوند. |
| ‏Realm جدید Import نمی‌شود | ‏Keycloak فقط Realmهایی را Import می‌کند که هنوز وجود ندارند؛ برای بازسازی، Realm را حذف و Stack را دوباره اجرا کنید. |
