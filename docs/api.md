# خلاصه API درگاه هویت

همه مسیرها زیر `/api/identity` هستند. درخواست‌ها با `Authorization: Bearer <token>` و برای سازمان غیرپیش‌فرض با `X-Tenant-Id` ارسال می‌شوند. خطاها قالب ProblemDetails با `code` دارند. نمونه درخواست‌ها در `src/Identity.Gateway/Identity.Gateway.http` است و مستند OpenAPI در محیط توسعه از `/scalar` در دسترس است.

- [ورود و توکن](#ورود-و-توکن)
- [کاربران](#کاربران)
- [نقش‌ها](#نقشها)
- [اپلیکیشن‌ها و دسترسی‌ها](#اپلیکیشنها-و-دسترسیها)
- [محدوده‌ها](#محدودهها)
- [برنامه زمانی](#برنامه-زمانی)
- [تنظیمات احراز هویت](#تنظیمات-احراز-هویت)
- [سازمان‌ها](#سازمانها)

## ورود و توکن

| مسیر | توضیح |
|---|---|
| ‏`POST /auth/login` | ورود با `password` یا `client_credentials` (فرم)؛ برنامه زمانی بررسی می‌شود |
| ‏`POST /auth/refresh` | تمدید توکن؛ برنامه زمانی دوباره بررسی می‌شود |
| ‏`POST /auth/logout` | پایان نشست |
| ‏`POST /auth/introspect` | بررسی توکن |
| ‏`GET /.well-known/openid-configuration` | سند Discovery سازمان (با `?tenant=` برای سازمان دیگر) |
| ‏`GET /access-context` | دسترسی‌ها و تخصیص‌های کاربر جاری |
| ‏`GET /access-schedule` | برنامه زمانی مؤثر کاربر جاری (برای سرویس‌ها) |

## کاربران

| مسیر | دسترسی لازم |
|---|---|
| ‏`GET /users`، ‏`GET /users/{id}` | ‏`Users:User:Read` |
| ‏`POST /users`، ‏`PUT /users/{id}`، ‏`DELETE /users/{id}` | ‏`Users:User:Manage` |
| ‏`PUT /users/{id}/reset-password` | ‏`Users:User:Manage` |
| ‏`GET` و `PUT /users/{id}/scoped-access` | ‏`Scopes:Scope:Read` و `Scopes:Scope:Manage` |
| ‏`GET` و `DELETE /users/{id}/lockout` | خواندن و رفع قفل |
| ‏`GET /users/{id}/credentials`، ‏`DELETE .../credentials/{credentialId}` | اعتبارنامه‌ها، مثلاً حذف OTP |
| ‏`GET` و `PUT /users/{id}/required-actions` | اقدامات الزامی ورود بعدی |
| ‏`POST /users/{id}/execute-actions-email` | ایمیل انجام اقدامات (نیازمند SMTP) |
| ‏`GET /users/{id}/sessions`، ‏`POST /users/{id}/revoke` | نشست‌ها |
| ‏`GET /required-actions` | فهرست اقدامات فعال سازمان |

همه مسیرهای یک کاربر مشخص برای مدیر تفویضی فقط درباره کاربران محدوده خودش کار می‌کند.

## نقش‌ها

| مسیر | توضیح |
|---|---|
| ‏`GET /business-roles`، ‏`GET /business-roles/{name}` | فهرست و جزئیات |
| ‏`POST /business-roles` | ایجاد با `permissions`، ‏`requiredScopes` و `allowedScopes` |
| ‏`PUT /business-roles/{name}` | تغییر توضیح، مجموعه کامل دسترسی‌ها یا سیاست محدوده |
| ‏`POST /business-roles/{name}/permissions` | افزودن دسترسی |
| ‏`DELETE /business-roles/{name}` | حذف (اگر عضو نداشته باشد) |

## اپلیکیشن‌ها و دسترسی‌ها

| مسیر | توضیح |
|---|---|
| ‏`GET` و `POST /applications`، ‏`PUT` و `DELETE /applications/{clientId}` | مدیریت اپلیکیشن‌ها |
| ‏`POST /applications/{clientId}/secret` | کلید محرمانه جدید (فقط یک بار نمایش داده می‌شود) |
| ‏`GET` و `POST /applications/{clientId}/permissions` | دسترسی‌های یک اپلیکیشن، افزودن دستی |
| ‏`PUT` و `DELETE /applications/{clientId}/permissions/{name}` | تغییر یا منسوخ کردن، حذف |
| ‏`GET /permissions`، ‏`GET /permissions/tree` | فهرست و درخت دسترسی‌ها |
| ‏`POST /permissions/register` | ثبت دسترسی‌ها توسط خود سرویس |

## محدوده‌ها

| مسیر | توضیح |
|---|---|
| ‏`GET` و `POST /scopes`، ‏`PUT` و `DELETE /scopes/{key}` | کلیدهای محدوده با والد |
| ‏`GET` و `PUT /scopes/{key}/values` | فهرست مقادیر مجاز با عنوان و مقدار والد |
| ‏`GET` و `PUT /scopes/{key}/resources` | منابعی که محدوده آن‌ها را فیلتر می‌کند |

## برنامه زمانی

| مسیر | توضیح |
|---|---|
| ‏`GET`، ‏`PUT` و `DELETE /schedules/realm` | برنامه پیش‌فرض سازمان |
| ‏`GET`، ‏`PUT` و `DELETE /schedules/roles/{name}` | برنامه نقش |
| ‏`GET`، ‏`PUT` و `DELETE /schedules/permissions/{permission}` | برنامه دسترسی (نام کامل) |
| ‏`GET`، ‏`PUT` و `DELETE /schedules/users/{id}` | برنامه اختصاصی کاربر |
| ‏`GET /schedules/users/{id}/effective` | برنامه مؤثر کاربر |

قالب بدنه: `{"unrestricted": false, "days": {"sat": ["08:00-16:00"]}}`.

## تنظیمات احراز هویت

| مسیر | توضیح |
|---|---|
| ‏`GET` و `PUT /settings/tokens` | عمر توکن و نشست |
| ‏`GET` و `PUT /settings/password-policy` | سیاست رمز عبور |
| ‏`GET` و `PUT /settings/brute-force` | قفل حساب |
| ‏`GET` و `PUT /settings/otp` | ورود دومرحله‌ای |
| ‏`GET` و `PUT /settings/login` | گزینه‌ها و قالب صفحه ورود |
| ‏`/settings/identity-providers` | سرویس‌های ورود خارجی (OIDC، ‏SAML، ‏Google، ‏Microsoft، ‏GitHub) |
| ‏`/settings/ldap` | ‏LDAP و Active Directory؛ ‏`POST /settings/ldap/test` و `POST /settings/ldap/{id}/sync` |

## سازمان‌ها

| مسیر | توضیح |
|---|---|
| ‏`GET /tenants` | فهرست سازمان‌ها بدون اطلاعات محرمانه |
