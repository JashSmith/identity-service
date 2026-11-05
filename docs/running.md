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
- آزاد بودن پورت‌های `18080` (Keycloak)، ‏`5080` (درگاه) و `5090` (کنسول)

پورت 8080 روی سیستم مالک پروژه در اختیار Apache است؛ به همین دلیل Keycloak روی 18080 و با گواهی توسعه HTTPS اجرا می‌شود.

## اجرا

```bash
bash scripts/build-keycloak-extensions.sh      # یک بار و پس از هر تغییر در keycloak/extensions (فقط Docker لازم است)
dotnet build IdentityService.slnx
dotnet run --project src/Hosts/Identity.AppHost --launch-profile http
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

رمزهای Clientها و رمز مدیر Keycloak به‌صورت پارامتر Aspire ساخته و در User Secrets پروژه AppHost نگه داشته می‌شوند و در مخزن ذخیره نمی‌شوند.

## بررسی سلامت

```bash
curl http://localhost:5080/health        # Healthy پس از پایان Bootstrap کلیدکول برای همه سازمان‌ها (تا آن موقع Degraded با کد 503)
curl http://localhost:5080/health/live   # زنده بودن پردازه؛ از همان ابتدا 200
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
IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests --filter "FullyQualifiedName~Ui"   # فقط تست‌های مرورگری
```

تست‌های E2E همه‌ی سامانه را با `Aspire.Hosting.Testing` روی همان پورت‌های توسعه (5080، 5090، 18080) بالا می‌آورند؛ به همین دلیل Stack توسعه باید خاموش باشد.

تست‌های مرورگری (`tests/Identity.E2E.Tests/Ui`) با Playwright و همان Google Chrome نصب‌شده روی سیستم اجرا می‌شوند و دانلود مرورگر لازم ندارند. این تست‌ها مثل یک مدیر واقعی کار می‌کنند:

- ورود از صفحه فارسی Keycloak و باز کردن همه‌ی بخش‌های کنسول بدون خطا و بدون اسکرول افقی
- چند بار ورود و خروج پشت سر هم، با کنترل اندازه‌ی سرآیند Cookie (جلوگیری از بازگشت خطای 431)
- ورود در کنار Cookieهای بزرگ برنامه‌های دیگر روی `localhost` (حدود ۱۲ کیلوبایت)
- تغییر پوسته و ماندن آن پس از بارگذاری دوباره
- ساخت صفحه ورود اختصاصی برای یک اپلیکیشن و باز کردن صفحه واقعی Keycloak با همان برند
- تنظیم پیامک با سرویس آزمایشی و ارسال پیامک آزمایشی
- ورود بدون رمز با شماره موبایل و کد پیامکی روی صفحه Keycloak، ورود با عامل دوم پیامکی، و ثبت شماره موبایل و روشن و خاموش کردن ورود با پیامک از کنسول
- مدیری که فقط دسترسی خواندن کاربران دارد و فقط بخش‌های مجاز را می‌بیند
- کار با کنسول فقط با صفحه‌کلید و نمای موبایل

هر پاسخ HTTP با کد 400 یا بیشتر و هر خطای کنسول مرورگر در طول تست، حتی اگر تست مستقیماً آن را بررسی نکند، تست را رد می‌کند. هنگام شکست، تصویر صفحه در `tests/Identity.E2E.Tests/bin/Debug/net10.0/TestResults/ui` ذخیره می‌شود.

| متغیر | کاربرد |
|---|---|
| ‏`PLAYWRIGHT_CHANNEL` | مرورگر: پیش‌فرض `chrome`؛ ‏`msedge` هم پشتیبانی می‌شود |
| ‏`PLAYWRIGHT_HEADED=1` | نمایش پنجره مرورگر هنگام اجرای تست |

## توقف

با `Ctrl+C` در پنجره AppHost همه منابع متوقف می‌شوند. اگر پردازه AppHost را مستقیم ببندید، ظرف‌های `keycloak-*` و `redis-*` باقی می‌مانند و باید حذفشان کنید:

```bash
docker ps --format '{{.Names}}' | grep -E '^(keycloak|redis)-' | xargs -r docker rm -f
```

ظرف `identity-postgres` (با volume به نام `identity-postgres-data`) عمداً ماندگار است.

## افزودن سازمان جدید

هر سازمان یک Realm است. ابزار `tools/Identity.TenantProvisioning` آن را از الگو می‌سازد. این ابزار را اپراتور با حساب Realm اصلی (`master`) اجرا می‌کند و خود درگاه هیچ‌وقت به Realm اصلی دسترسی ندارد.

1. ابزار را اجرا کنید. رمز حساب master از متغیر محیطی `KEYCLOAK_MASTER_PASSWORD` یا به‌صورت پنهان از ورودی خوانده می‌شود و هیچ‌وقت در خط فرمان نوشته نمی‌شود:

   ```powershell
   dotnet run --project tools/Identity.TenantProvisioning -- `
     --keycloak https://keycloak.example --realm branch-north --display-name "شعبه شمال" --admin admin
   ```

   به‌جای کاربر master می‌توان از یک Service Account در master با نقش `create-realm` استفاده کرد (`--master-client-id` و رمز در `KEYCLOAK_MASTER_CLIENT_SECRET`). در Git Bash روی ویندوز نام‌های فارسی در آرگومان‌ها خراب می‌شوند؛ ابزار را در PowerShell اجرا کنید.

2. ابزار Realm را با کلاینت‌های درگاه، گروه‌های `super-admins` و `iam-scope-registry`، ‏Client Scopeهای لازم و یک مدیر عضو `super-admins` می‌سازد. رمزهای تصادفی و رمز موقت مدیر را در فایل `branch-north.tenant.env` می‌نویسد. اگر Realm از قبل وجود داشته باشد یا فایل خروجی موجود باشد، کاری انجام نمی‌دهد.
3. تنظیمات این فایل را به پیکربندی درگاه (`Identity__Tenants__N__*`) و کنسول (`Console__Tenants__N__*`) اضافه کنید و N را با شماره آزاد بعدی جایگزین کنید. رمزها را در محل امن نگه دارید و فایل را پاک کنید.
4. درگاه و کنسول را دوباره اجرا کنید. ‏Bootstrap درگاه برای Realm جدید رجیستری محدوده، Mapperها، دسترسی‌های درگاه و کلاینت کنسول را می‌سازد.
5. مدیر جدید با رمز موقت وارد می‌شود و Keycloak او را به تغییر رمز وادار می‌کند.

## عیب‌یابی

| نشانه | علت و راه‌حل |
|---|---|
| ‏`/health` مدت طولانی Degraded است | ‏Bootstrap هنوز منتظر Keycloak است؛ پیام وضعیت را در پاسخ `/health` ببینید. ‏`/health/live` در همین مدت 200 برمی‌گرداند. |
| ‏`/health` مدت طولانی Unhealthy است | یکی از مراحل Bootstrap شکست خورده است؛ نام مرحله در پاسخ `/health` و لاگ درگاه آمده است. معمولاً رمز Service Account با Realm یکی نیست. |
| ‏`Port(s) ... already in use` هنگام اجرای AppHost | یک Stack دیگر (اجرای دوم AppHost یا تست‌های E2E که همین پورت‌ها را می‌گیرند) در حال اجراست. آن را متوقف کنید و ظرف‌های `keycloak-*` و `redis-*` باقی‌مانده را حذف کنید. پیش از این بررسی، همین وضعیت پس از دو دقیقه با `TimeoutRejectedException` و `The JSON-RPC connection with the remote party was lost` تمام می‌شد. |
| ‏`TimeoutRejectedException` پس از دو دقیقه، بدون اشغال بودن پورت‌ها | پروکسی سیستمی ویندوز درخواست‌های `localhost` را هم به پروکسی می‌فرستاد. AppHost و سرویس‌ها اکنون `localhost` و `127.0.0.1` را همیشه مستقیم صدا می‌زنند (`LoopbackProxyBypass`)؛ در تنظیمات پروکسی ویندوز هم بهتر است «برای نشانی‌های محلی از پروکسی استفاده نشود» روشن باشد. |
| ‏`/health` با `schedule-authenticator failed: auth_flow.not_found` | فایل افزونه Keycloak از شاخه‌ای قدیمی‌تر از پایگاه داده ساخته شده است (مثلاً مراحل ورود با پیامک در Realm هست ولی در jar نیست). در شاخه فعلی `bash scripts/build-keycloak-extensions.sh` را اجرا و Stack را دوباره راه‌اندازی کنید. |
| خطای 431 هنگام ورود | سرآیند Cookie از حد Keycloak بزرگ‌تر شده است. مرورگر Cookieهای همه‌ی پورت‌های یک نام میزبان (مثلاً `localhost`، از جمله داشبورد Aspire و پروژه‌های دیگر) را به Keycloak هم می‌فرستد. مرورگر روی HTTPS با Keycloak از HTTP/2 استفاده می‌کند و Keycloak در HTTP/2 به‌طور پیش‌فرض بیش از 8192 بایت سرآیند نمی‌پذیرد (`quarkus.http.limits.max-header-list-size`). ‏AppHost این حد را با `QUARKUS_HTTP_LIMITS_MAX_HEADER_LIST_SIZE=32768` بالا می‌برد؛ در محیط عملیاتی همین متغیر را روی Keycloak تنظیم کنید. کنسول و بسته `AddAvashWebSso` هم نشست را سمت سرور نگه می‌دارند و در Cookie فقط یک کلید کوتاه می‌گذارند. اگر باز هم دیدید، Cookieهای `localhost` را از مرورگر پاک کنید. |
| «سرویس ورود موقتاً در دسترس نیست» در صفحه ورود کنسول | کنسول به Keycloak وصل نشد؛ وضعیت Keycloak را در داشبورد Aspire ببینید. |
| خطاهای `ERR_NO_BUFFER_SPACE`، ‏`ERR_ADDRESS_IN_USE` یا `WSAENOBUFS` | پورت‌های موقت ویندوز تمام شده‌اند. با `netstat -ano` پردازه‌ای را که هزاران اتصال باز دارد پیدا و دوباره اجرا کنید (معمولاً `com.docker.backend`، یعنی Docker Desktop). |
| خطای SSL روی آدرس Keycloak | پورت در اختیار برنامه دیگری است یا گواهی توسعه معتبر نیست (`dotnet dev-certs https --trust`). |
| ‏`403 tenant.mismatch` | توکن از Realm سازمان دیگری است؛ سرآیند `X-Tenant-Id` را با سازمانی که توکن را صادر کرده یکی کنید. |
| ‏`403 access.outside_schedule` | کاربر خارج از برنامه زمانی است؛ برنامه مؤثر را در صفحه کاربر در کنسول ببینید. |
| کنسول پس از راه‌اندازی دوباره به صفحه ورود می‌رود | رفتار طراحی‌شده است: توکن‌ها فقط در حافظه کنسول نگه داشته می‌شوند. |
| ‏Realm جدید Import نمی‌شود | ‏Keycloak فقط Realmهایی را Import می‌کند که هنوز وجود ندارند؛ برای بازسازی، Realm را حذف و Stack را دوباره اجرا کنید. |
