/**
 * Identity Service Dashboard - Interactive Logic
 * Single Page Application for Keycloak Gateway Administration
 */

(function () {
  'use strict';

  // State Management
  const state = {
    token: sessionStorage.getItem('identity_admin_token') || '',
    currentUser: null,
    users: [],
    roles: [],
    scopes: [],
    resources: [],
    permissions: [],
    currentView: 'view-overview',
    refreshInterval: null,
    lang: localStorage.getItem('dashboard_lang') || 'en',
    theme: localStorage.getItem('dashboard_theme') || 'dark'
  };

  // DOM Elements Cache
  const elements = {
    sidebar: document.getElementById('sidebar'),
    pageHeading: document.getElementById('page-heading'),
    profileContainer: document.getElementById('profile-container'),
    headerAvatar: document.getElementById('header-avatar'),
    headerUsername: document.getElementById('header-username'),
    headerRole: document.getElementById('header-role'),
    onlineUsersBadge: document.getElementById('online-users-badge'),
    
    // Metrics
    statTotalUsers: document.getElementById('stat-total-users'),
    statOnlineUsers: document.getElementById('stat-online-users'),
    statBusinessRoles: document.getElementById('stat-business-roles'),
    statScopes: document.getElementById('stat-scopes'),
    scopesCountBadge: document.getElementById('scopes-count-badge'),
    statPermissions: document.getElementById('stat-permissions'),
    statDbProvider: document.getElementById('stat-db-provider'),
    statDbSub: document.getElementById('stat-db-sub'),
    cardDbMetric: document.getElementById('card-db-metric'),
    btnHeaderDb: document.getElementById('btn-header-db'),
    headerDbTitle: document.getElementById('header-db-title'),
    headerDbStatusBadge: document.getElementById('header-db-status-badge'),
    btnSidebarDb: document.getElementById('btn-sidebar-db'),
    sidebarDbLabel: document.getElementById('sidebar-db-label'),
    sidebarDbSub: document.getElementById('sidebar-db-sub'),
    sidebarDbDot: document.getElementById('sidebar-db-dot'),
    modalDbInfo: document.getElementById('modal-db-info'),
    modalDbProvider: document.getElementById('modal-db-provider'),
    modalDbHealth: document.getElementById('modal-db-health'),
    modalDbHost: document.getElementById('modal-db-host'),
    modalDbName: document.getElementById('modal-db-name'),

    // Users View
    usersTableBody: document.getElementById('users-table-body'),
    userSearchInput: document.getElementById('user-search-input'),
    userStatusFilter: document.getElementById('user-status-filter'),

    // Roles View
    businessRolesGrid: document.getElementById('business-roles-grid'),

    // Scopes View
    scopesTableBody: document.getElementById('scopes-table-body'),
    inlineFormCreateScope: document.getElementById('inline-form-create-scope'),
    btnRefreshScopes: document.getElementById('btn-refresh-scopes'),

    // Permissions View
    permissionsTableBody: document.getElementById('permissions-table-body'),
    permSearchInput: document.getElementById('perm-search-input'),

    // Token Playground
    tokenMintForm: document.getElementById('token-mint-form'),
    tokenTestUsername: document.getElementById('token-test-username'),
    tokenTestPassword: document.getElementById('token-test-password'),
    tokenOutputConsole: document.getElementById('token-output-console'),
    btnTestMe: document.getElementById('btn-test-me'),
    btnTestContext: document.getElementById('btn-test-context'),

    // Modals
    modalLogin: document.getElementById('modal-login'),
    formLogin: document.getElementById('form-login'),
    modalCreateUser: document.getElementById('modal-create-user'),
    formCreateUser: document.getElementById('form-create-user'),
    cuRoleSelect: document.getElementById('cu-role-select'),
    cuScopesContainer: document.getElementById('cu-scopes-container'),
    btnModalAddScope: document.getElementById('btn-modal-add-scope'),
    modalUserScopes: document.getElementById('modal-user-scopes'),
    formUserScopes: document.getElementById('form-user-scopes'),
    usUserId: document.getElementById('us-user-id'),
    usUsernameDisplay: document.getElementById('us-username-display'),
    usRoleSelect: document.getElementById('us-role-select'),
    usScopesContainer: document.getElementById('us-scopes-container'),
    modalEditUser: document.getElementById('modal-edit-user'),
    formEditUser: document.getElementById('form-edit-user'),
    euUsernameDisplay: document.getElementById('eu-username-display'),
    euUsername: document.getElementById('eu-username'),
    euEmailVerified: document.getElementById('eu-email-verified'),
    euBtnResetPwShortcut: document.getElementById('eu-btn-reset-pw-shortcut'),
    euBtnDeleteShortcut: document.getElementById('eu-btn-delete-shortcut'),
    modalResetPassword: document.getElementById('modal-reset-password'),
    formResetPassword: document.getElementById('form-reset-password'),
    rpUserId: document.getElementById('rp-user-id'),
    rpUsername: document.getElementById('rp-username'),
    rpUsernameLabel: document.getElementById('rp-username-label'),
    rpPassword: document.getElementById('rp-password'),
    rpPasswordConfirm: document.getElementById('rp-password-confirm'),
    rpTemporary: document.getElementById('rp-temporary'),
    modalConfirmDeleteUser: document.getElementById('modal-confirm-delete-user'),
    deleteUserId: document.getElementById('delete-user-id'),
    deleteUserUsername: document.getElementById('delete-user-username'),
    btnExecuteDeleteUser: document.getElementById('btn-execute-delete-user'),
    modalCreateRole: document.getElementById('modal-create-role'),
    formCreateRole: document.getElementById('form-create-role'),
    modalCreateScope: document.getElementById('modal-create-scope'),
    formCreateScope: document.getElementById('form-create-scope'),
    modalEditScope: document.getElementById('modal-edit-scope'),
    formEditScope: document.getElementById('form-edit-scope'),
    modalConfirmRevoke: document.getElementById('modal-confirm-revoke'),
    revokeTargetId: document.getElementById('revoke-target-id'),
    revokeTargetUsername: document.getElementById('revoke-target-username'),
    btnExecuteRevoke: document.getElementById('btn-execute-revoke'),
    modalConfirmDeleteScope: document.getElementById('modal-confirm-delete-scope'),
    deleteScopeKey: document.getElementById('delete-scope-key'),
    deleteScopeTargetKey: document.getElementById('delete-scope-target-key'),
    btnExecuteDeleteScope: document.getElementById('btn-execute-delete-scope'),
    modalEditRole: document.getElementById('modal-edit-role'),
    formEditRole: document.getElementById('form-edit-role'),
    erName: document.getElementById('er-name'),
    erDesc: document.getElementById('er-desc'),
    erPermsSelector: document.getElementById('er-perms-selector'),
    modalConfirmDeleteRole: document.getElementById('modal-confirm-delete-role'),
    deleteRoleName: document.getElementById('delete-role-name'),
    deleteRoleNameDisplay: document.getElementById('delete-role-name-display'),
    btnExecuteDeleteRole: document.getElementById('btn-execute-delete-role'),
    btnOpenCreatePermission: document.getElementById('btn-open-create-permission'),
    modalCreatePermission: document.getElementById('modal-create-permission'),
    formCreatePermission: document.getElementById('form-create-permission'),
    cpName: document.getElementById('cp-name'),
    cpDesc: document.getElementById('cp-desc'),
    cpService: document.getElementById('cp-service'),
    toastContainer: document.getElementById('toast-container'),
    loginAlert: document.getElementById('login-alert'),
    loginAlertMsg: document.getElementById('login-alert-msg'),

    // Preferences & Toggles
    btnLangToggle: document.getElementById('btn-lang-toggle'),
    currentLangLabel: document.getElementById('current-lang-label'),
    btnThemeToggle: document.getElementById('btn-theme-toggle'),
    currentThemeIcon: document.getElementById('current-theme-icon'),
    radioLangFa: document.getElementById('radio-lang-fa'),
    radioLangEn: document.getElementById('radio-lang-en'),
    radioThemeDark: document.getElementById('radio-theme-dark'),
    radioThemeLight: document.getElementById('radio-theme-light'),
    btnResetPreferences: document.getElementById('btn-reset-preferences'),
    cardLangFa: document.getElementById('card-lang-fa'),
    cardLangEn: document.getElementById('card-lang-en'),
    cardThemeDark: document.getElementById('card-theme-dark'),
    cardThemeLight: document.getElementById('card-theme-light')
  };

  // ==========================================
  // Multilingual Dictionary (i18n)
  // Default language: Persian ('fa')
  // ==========================================
  const i18n = {
    fa: {
      // Sidebar & Navigation
      navCategoryGeneral: 'مدیریت و دسترسی',
      navOverview: 'داشبورد مدیریتی',
      navUsers: 'کاربران و Scopeها',
      navRoles: 'نقش‌های سازمانی',
      navScopes: 'تعریف Attribute Scopeها',
      badgeRegistry: 'رجیستری',
      navPermissions: 'کاتالوگ مجوزها',
      navCategoryDev: 'توسعه و اعتبارسنجی',
      navTokenTest: 'آزمایشگاه توکن (Playground)',
      navScalar: 'مستندات API (Scalar)',
      navCategoryPreferences: 'شخصی‌سازی',
      navSettings: 'تنظیمات و زبان',
      keycloakDbOnline: 'ارتباط با Keycloak و DB برقرار است',
      realmSub: 'realm: company · postgres',
      refresh: 'بروزرسانی',
      signOut: 'خروج از حساب',
      adminRole: 'مدیر ارشد سامانه',
      
      // Overview
      metricTotalUsers: 'کل کاربران',
      metricTotalUsersTrend: 'ثبت شده در Keycloak',
      metricOnlineUsers: 'کاربران آنلاین',
      metricOnlineUsersTrend: 'نشست‌های فعال جاری',
      metricRoles: 'نقش‌های بیزینس',
      metricRolesTrend: 'گروه‌ها و رول‌های فعال',
      metricScopes: 'ابعاد Scope',
      metricScopesTrend: 'اسکوپ‌های ثبت‌شده در رجیستری',
      metricDb: 'موتور پایگاه داده',
      metricDbSub: 'آنلاین (پورت ۵۴۳۲)',
      quickActionsTitle: 'اقدامات سریع مدیریتی',
      quickActionsSubtitle: 'ایجاد کاربر با اسکوپ و نقش، تعریف نقش‌های سازمانی و اسکوپ‌های ابعادی',
      btnNewUser: '➕ ساخت کاربر جدید',
      btnAddRole: '➕ ایجاد نقش سازمانی',
      btnNewScope: '➕ اسکوپ جدید',
      btnPlayground: 'آزمایشگاه توکن JWT',
      archTitle: 'معماری احراز هویت و کنترل دسترسی چندسطحی',
      archStatus: 'سیستم فعال و عملیاتی',
      arch1Title: '۱. هویت و حساب کاربران',
      arch1Desc: 'کاربران در کی‌کلوک تعریف شده و دارای اطلاعات هویتی، نقش و محدودیت‌های اسکوپ ابعادی در پروفایل هستند.',
      arch2Title: '۲. نقش‌های سازمانی و گروه‌ها',
      arch2Desc: 'نقش‌های بیزینس (مانند مدیر، حسابدار) به‌صورت گروه‌های Keycloak مدل‌سازی شده و مجوزهای میکروسرویس‌ها را تجمیع می‌کنند.',
      arch3Title: '۳. اسکوپ‌های پویا (Attribute Scopes)',
      arch3Desc: 'ابعاد دسترسی (مانند شعبه، منطقه، مرکز هزینه) در رجیستری iam-scope-registry تعریف و به هر کاربر مقادیر مجاز اختصاص می‌یابد.',
      arch4Title: '۴. ادعاهای توکن و فیلترینگ داده',
      arch4Desc: 'اسکوپ‌های کاربر در کلیم‌های authz.scope.<key> توکن JWT درج شده و میکروسرویس‌ها بر اساس آن داده‌ها را در سطح ردیف فیلتر می‌کنند.',

      // Users
      usersTitle: 'مدیریت کاربران و دسترسی‌های مبتنی بر Scope',
      usersSubtitle: 'تعریف حساب‌های کاربری، انتساب نقش سازمانی، تنظیم مقادیر اسکوپ ابعادی، تغییر رمز و لغو نشست‌ها',
      searchUsersPlaceholder: 'جستجوی کاربر بر اساس نام کاربری، ایمیل یا نام...',
      filterAllUsers: 'همه کاربران',
      filterOnlineUsers: 'فقط آنلاین',
      filterOfflineUsers: 'فقط آفلاین',
      btnCreateUser: '+ ساخت کاربر',
      thUser: 'کاربر',
      thNameEmail: 'نام و ایمیل',
      thStatus: 'وضعیت',
      thRoleScopes: 'نقش و مقادیر Scope',
      thActions: 'عملیات',
      loadingUsers: 'در حال دریافت اطلاعات کاربران از Keycloak...',
      noUsersFound: 'هیچ کاربری با این مشخصات یافت نشد.',
      noRole: 'بدون نقش',
      noScopes: 'بدون اسکوپ محدودکننده (دسترسی نامحدود یا پیش‌فرض)',
      activeStatus: 'آنلاین',
      offlineStatus: 'آفلاین',
      disabledBadge: 'غیرفعال',
      btnEditUser: 'ویرایش',
      btnManageScopes: 'نقش و اسکوپ‌ها',
      btnRevokeSessions: 'لغو نشست‌ها',

      // Roles
      rolesTitle: 'مدیریت نقش‌های سازمانی',
      rolesSubtitle: 'مدیریت نقش‌های ترکیبی و مجوزهای مرتبط با گروه‌های Keycloak',
      btnCreateRole: '+ ایجاد نقش جدید',
      loadingRoles: 'در حال بارگذاری نقش‌های سازمانی...',
      noRolesFound: 'هیچ نقش سازمانی ثبت نشده است.',
      permissionsCount: 'مجوز',
      btnEditRole: 'ویرایش نقش',
      btnDeleteRole: 'حذف',

      // Scopes
      scopeRegisterTitle: 'ثبت اسکوپ ابعادی جدید',
      scopeRegisterSubtitle: 'تعریف بعد دسترسی برای کنترل دسترسی در سطح ردیف (مانند branch، region، cost_center)',
      scopeKeyLabel: 'کلید اسکوپ (Scope Key) *',
      scopeKeyHint: 'حروف کوچک انگلیسی، عدد، خط تیره و زیرخط (مانند branch, region)',
      displayNameLabel: 'نام نمایشی *',
      descriptionLabel: 'توضیحات',
      targetResourcesLabel: 'منابع تحت پوشش (Target Resources - جدا شده با کاما)',
      quickSuggestions: 'پیشنهاد سریع:',
      btnRegisterScope: 'ثبت اسکوپ در رجیستری',
      scopesRegistryTitle: 'اسکوپ‌های ابعادی ثبت‌شده',
      scopesRegistrySubtitle: 'اسکوپ‌های فعال در گروه iam-scope-registry قابل انتساب به کاربران',
      refreshList: 'بروزرسانی لیست',
      thScopeKey: 'کلید اسکوپ',
      thDisplayName: 'نام نمایشی',
      thDescription: 'توضیحات',
      thTargetResources: 'منابع تحت پوشش',
      loadingScopes: 'در حال بارگذاری اسکوپ‌ها از رجیستری Keycloak...',
      noScopesFound: 'هیچ اسکوپی ثبت نشده است. از فرم بالا برای ثبت اسکوپ جدید استفاده کنید.',
      unboundResources: '(عمومی / نامشخص)',
      btnEdit: 'ویرایش',
      btnActivate: 'فعال‌سازی',
      btnDeactivate: 'غیرفعال‌سازی',
      btnDelete: '🗑️ حذف',
      scopeActiveLabel: 'اسکوپ فعال باشد',
      btnUpdateScope: 'بروزرسانی اسکوپ',
      modalCreateScopeTitle: 'ثبت اسکوپ ابعادی جدید',
      modalEditScopeTitle: 'ویرایش اسکوپ ابعادی',
      modalDeleteScopeTitle: 'حذف اسکوپ از رجیستری',
      deleteScopeWarning: 'آیا از حذف دائمی اسکوپ ابعادی مطمئن هستید؟',
      fromRegistry: 'از رجیستری Keycloak',
      deleteScopeWarningDesc: '⚠️ هشدار: حذف این اسکوپ تعاریف آن را از گروه iam-scope-registry و تمامی ارتباطات منابع پاک خواهد کرد.',
      btnDeleteScopeConfirm: 'حذف دائمی اسکوپ',

      // Permissions
      permsCatalogTitle: 'کاتالوگ مجوزهای پلتفرم',
      permsCatalogSubtitle: 'مجوزهای ثبت‌شده توسط میکروسرویس‌ها جهت ترکیب در نقش‌های سازمانی',
      searchPermsPlaceholder: 'جستجوی مجوز (مثال: Orders.Read)...',
      btnRegisterPerm: '+ ثبت دستی مجوز',
      thPermName: 'نام مجوز (Permission)',
      thOriginService: 'سرویس مبدا',
      loadingPermissions: 'در حال بارگذاری کاتالوگ مجوزها...',
      noPermsFound: 'هیچ مجوزی مطابق با جستجو یافت نشد.',
      modalCreatePermTitle: 'ثبت دستی مجوز جدید',
      permNameLabel: 'نام مجوز * (مانند Orders.Export, Reports.View)',
      permNameHint: 'فرمت استاندارد: Resource.Action (مثال: Orders.Read, Orders.Manage)',
      originServiceLabel: 'شناسه سرویس مبدا (Client ID)',
      originServiceHint: 'کلاینت مورد نظر در Keycloak که رول در آن ایجاد می‌شود',

      // Token Playground
      tokenPlaygroundTitle: 'آزمایشگاه توکن و اعتبارسنجی دسترسی',
      tokenPlaygroundSubtitle: 'ورود به عنوان هر کاربر، صدور توکن زنده JWT کی‌کلوک و بررسی کلیم‌های authz.scope.*',
      tokenStep1Title: '۱. احراز هویت و صدور توکن JWT',
      usernameLabel: 'نام کاربری',
      passwordLabel: 'رمز عبور',
      btnAuthenticateMint: 'احراز هویت و صدور توکن',
      tokenStep2Title: '۲. اعتبارسنجی کانتکست دسترسی توکن',
      tokenOutputTitle: 'محتوای دیکود شده توکن (Claims و Scopes)',

      // Settings
      settingsTitle: 'تنظیمات و شخصی‌سازی داشبورد',
      settingsSubtitle: 'تنظیم زبان، جهت صفحه (راست‌چین/چپ‌چین) و تم ظاهری. تنظیمات در LocalStorage ذخیره می‌شوند.',
      settingLangTitle: 'زبان و جهت صفحه (Language & Direction)',
      settingLangDesc: 'انتخاب زبان رابط کاربری و جهت نوشتاری',
      settingThemeTitle: 'تم ظاهری داشبورد (Dashboard Theme)',
      settingThemeDesc: 'انتخاب بین تم دارک مدرن شیشه‌ای یا تم روشن مینیمال',
      badgeDefault: 'پیش‌فرض',
      langFaTitle: 'فارسی (Persian)',
      langFaDesc: 'چیدمان کاملاً راست‌به‌چپ برای سایدبار، هدر، جداول و مودال‌ها',
      langEnTitle: 'English (Left-to-Right)',
      langEnDesc: 'چیدمان استاندارد چپ‌به‌راست (LTR)',
      themeDarkTitle: 'Dark Glassmorphism (دارک مدرن شیشه‌ای)',
      themeDarkDesc: 'طراحی تیره و شفاف با جلوه‌های نئونی و کنتراست بالا',
      themeLightTitle: 'Clean Light (روشن مینیمال)',
      themeLightDesc: 'طراحی سفید با کنتراست بالا مناسب برای محیط‌های پرنور',
      storageNotice: '💾 تنظیمات شما بلافاصله در LocalStorage مرورگر ذخیره و در مراجعات بعدی حفظ می‌شوند.',
      resetSettings: 'بازنشانی به پیش‌فرض (انگلیسی / دارک)',

      // Modals General
      cancel: 'انصراف',
      save: 'ذخیره',
      close: 'بستن',
      modalCreateUserTitle: 'ساخت کاربر جدید',
      modalCreateUserSubtitle: 'تعریف کاربر در Keycloak با مشخصات ورود، نقش سازمانی و محدودیت‌های اسکوپ ابعادی',
      secIdentityCredentials: '۱. هویت و مشخصات ورود',
      initialPasswordLabel: 'رمز عبور اولیه *',
      firstNameLabel: 'نام',
      lastNameLabel: 'نام خانوادگی',
      emailLabel: 'آدرس ایمیل',
      roleLabel: 'نقش سازمانی',
      selectRole: '(یک نقش سازمانی انتخاب کنید)',
      tempPasswordLabel: 'رمز عبور موقت (الزام تغییر در اولین ورود)',
      accountEnabledLabel: 'حساب کاربری فعال باشد',
      secAttributeScopes: '۲. اسکوپ‌های ابعادی (محدودیت‌های دسترسی پویا)',
      btnNewScopePlus: '+ اسکوپ جدید',
      scopesDescription: 'اسکوپ‌های مرتبط با این کاربر را تیک بزنید و مقادیر مجاز را وارد کنید (چندین مقدار با کاما جدا شوند، مثلاً: tehran-north, CC-9080):',
      
      modalUserScopesTitle: 'مدیریت نقش و اسکوپ‌های کاربر',
      userPrefix: 'کاربر:',
      businessRoleRequired: 'نقش سازمانی *',
      secScopesCheckAndEnter: 'اسکوپ‌های ابعادی (انتخاب و مقداردهی)',
      scopesCheckDesc: 'اسکوپ‌های انتخاب‌شده دسترسی کاربر به داده‌ها را به مقادیر تعیین‌شده محدود می‌کنند:',
      btnSaveRoleScopes: 'ذخیره نقش و اسکوپ‌ها',

      modalEditUserTitle: 'ویرایش مشخصات کاربر',
      emailVerifiedLabel: 'ایمیل تایید شده باشد',
      btnDeleteUser: '🗑️ حذف کاربر',
      btnResetPassword: '🔑 تغییر رمز عبور',
      btnSaveChanges: 'ذخیره تغییرات',

      modalResetPasswordTitle: 'تغییر رمز عبور کاربر',
      settingPwFor: 'تنظیم رمز جدید برای کاربر:',
      newPasswordLabel: 'رمز عبور جدید *',
      confirmPasswordLabel: 'تکرار رمز عبور جدید *',
      tempPasswordNext: 'رمز موقت (باید در ورود بعدی تغییر کند)',

      modalDeleteUserTitle: 'حذف کاربر از Keycloak',
      deleteUserWarning: 'آیا از حذف دائمی کاربر مطمئن هستید؟',
      deleteUserWarningDesc: '⚠️ هشدار: این عملیات غیرقابل بازگشت است. حساب کاربر، نشست‌های فعال و اسکوپ‌های اختصاص داده شده به طور کامل پاک می‌شوند.',
      btnDeleteUserConfirm: 'حذف دائمی کاربر',

      modalCreateRoleTitle: 'ایجاد نقش سازمانی جدید',
      roleNameLabel: 'نام نقش * (مثال: Manager, Accountant, Clerk)',
      selectPermissionsLabel: 'انتخاب مجوزها (Permissions)',
      modalEditRoleTitle: 'ویرایش نقش سازمانی',
      assignedPermsLabel: 'مجوزهای تخصیص داده شده',
      btnSaveRoleChanges: 'ذخیره تغییرات نقش',

      modalDeleteRoleTitle: 'حذف نقش سازمانی',
      deleteRoleWarning: 'آیا از حذف دائمی نقش سازمانی مطمئن هستید؟',
      deleteRoleWarningDesc: '⚠️ حذف ایمن: در صورتی که کاربری به این نقش اختصاص داده شده باشد، Keycloak اجازه حذف نخواهد داد.',
      btnDeleteRoleConfirm: 'حذف نقش',

      modalRevokeTitle: 'لغو نشست‌های فعال کاربر',
      revokeWarning: 'آیا از لغو تمامی نشست‌های فعال کاربر مطمئن هستید؟',
      revokeWarningDesc: 'این اقدام تمامی توکن‌های صادر شده قبلی را بلافاصله باطل کرده و ارتباط کاربر را قطع می‌کند.',
      btnRevokeConfirm: 'لغو نشست‌ها',

      modalDbTitle: 'وضعیت زیرساخت پایگاه داده',
      dbActiveEngine: 'موتور فعال',
      dbConnectionHealth: 'سلامت اتصال',
      dbHostTarget: 'آدرس هاست',
      dbName: 'نام دیتابیس',

      modalLoginTitle: 'ورود به پنل مدیریت هویت',
      modalLoginSubtitle: 'ورود با نام کاربری و رمز عبور مدیریتی Keycloak',
      defaultCredentials: 'اطلاعات پیش‌فرض: admin / admin',
      btnSignIn: 'ورود به پنل'
    },
    en: {
      // Sidebar & Navigation
      navCategoryGeneral: 'Management',
      navOverview: 'Overview',
      navUsers: 'Users & Scopes',
      navRoles: 'Business Roles',
      navScopes: 'Attribute Scopes',
      badgeRegistry: 'Registry',
      navPermissions: 'Permissions',
      navCategoryDev: 'Developer & Verification',
      navTokenTest: 'Token Playground',
      navScalar: 'API Docs (Scalar)',
      navCategoryPreferences: 'Preferences',
      navSettings: 'Settings',
      keycloakDbOnline: 'Keycloak & DB Online',
      realmSub: 'company realm · postgres',
      refresh: 'Refresh',
      signOut: 'Sign Out',
      adminRole: 'Super Admin',

      // Overview
      metricTotalUsers: 'Total Users',
      metricTotalUsersTrend: 'Registered in Keycloak',
      metricOnlineUsers: 'Online Users',
      metricOnlineUsersTrend: 'Active online sessions',
      metricRoles: 'Business Roles',
      metricRolesTrend: 'Configured business roles',
      metricScopes: 'Attribute Scopes',
      metricScopesTrend: 'Active registry scopes',
      metricDb: 'Database Engine',
      metricDbSub: 'Online (5432)',
      quickActionsTitle: 'Administrative Quick Actions',
      quickActionsSubtitle: 'Create users with roles and scopes, define business roles, and register new attribute scopes',
      btnNewUser: '➕ New User',
      btnAddRole: '➕ Add Business Role',
      btnNewScope: '➕ New Scope',
      btnPlayground: 'Token Playground',
      archTitle: 'Identity & Access Control Architecture',
      archStatus: 'System Operational',
      arch1Title: '1. User Identity & Provisioning',
      arch1Desc: 'Users are defined in Keycloak with credential validation, business role mapping, and dynamic attribute scope restrictions stored on the user profile.',
      arch2Title: '2. Business Roles & Groups',
      arch2Desc: 'Composite business roles (e.g., Manager, Accountant) are modeled as Keycloak groups bundling granular service permissions.',
      arch3Title: '3. Dynamic Attribute Scopes',
      arch3Desc: 'Scope dimensions (e.g., branch, region, cost center) are registered in iam-scope-registry and assigned with specific authorized values per user.',
      arch4Title: '4. Token Claims & Data Filtering',
      arch4Desc: 'Scoped permissions propagate into authz.scope.<key> claims in minted JWT tokens, allowing microservices to enforce row-level filtering.',

      // Users
      usersTitle: 'Users & Scoped Access Management',
      usersSubtitle: 'Manage user accounts, assign business roles, configure dynamic attribute scopes, reset passwords, and revoke sessions',
      searchUsersPlaceholder: 'Search users by username, email, name...',
      filterAllUsers: 'All Users',
      filterOnlineUsers: 'Online Only',
      filterOfflineUsers: 'Offline Only',
      btnCreateUser: '+ Create User',
      thUser: 'User',
      thNameEmail: 'Name & Email',
      thStatus: 'Status',
      thRoleScopes: 'Role & Assigned Scopes',
      thActions: 'Actions',
      loadingUsers: 'Loading users from Keycloak...',
      noUsersFound: 'No users found matching your search.',
      noRole: 'No Role Assigned',
      noScopes: 'No Scopes (Full/Default Access)',
      activeStatus: 'Active',
      offlineStatus: 'Offline',
      disabledBadge: 'Disabled',
      btnEditUser: 'Edit',
      btnManageScopes: 'Role & Scopes',
      btnRevokeSessions: 'Revoke Sessions',

      // Roles
      rolesTitle: 'Business Roles',
      rolesSubtitle: 'Manage composite roles and permissions connected to Keycloak groups',
      btnCreateRole: '+ Create Role',
      loadingRoles: 'Loading business roles...',
      noRolesFound: 'No business roles configured yet.',
      permissionsCount: 'permissions',
      btnEditRole: 'Edit Role',
      btnDeleteRole: 'Delete',

      // Scopes
      scopeRegisterTitle: 'Register New Attribute Scope',
      scopeRegisterSubtitle: 'Define a new scope dimension for row-level and multi-tenant access control (e.g., branch, region, cost center)',
      scopeKeyLabel: 'Scope Key *',
      scopeKeyHint: 'Lowercase letters, numbers, hyphens, and underscores',
      displayNameLabel: 'Display Name *',
      descriptionLabel: 'Description',
      targetResourcesLabel: 'Target Resources (comma separated)',
      quickSuggestions: 'Quick Suggestions:',
      btnRegisterScope: 'Register Scope',
      scopesRegistryTitle: 'Registered Attribute Scopes',
      scopesRegistrySubtitle: 'Active scopes in the iam-scope-registry group available for user assignment',
      refreshList: 'Refresh List',
      thScopeKey: 'Scope Key',
      thDisplayName: 'Display Name',
      thDescription: 'Description',
      thTargetResources: 'Target Resources',
      loadingScopes: 'Loading scopes from Keycloak registry...',
      noScopesFound: 'No attribute scopes registered yet. Use the form above to register a new scope.',
      unboundResources: '(Unbound / Global)',
      btnEdit: 'Edit',
      btnActivate: 'Activate',
      btnDeactivate: 'Deactivate',
      btnDelete: '🗑️ Delete',
      scopeActiveLabel: 'Scope Active',
      btnUpdateScope: 'Update Scope',
      modalCreateScopeTitle: 'Register New Attribute Scope',
      modalEditScopeTitle: 'Edit Attribute Scope',
      modalDeleteScopeTitle: 'Delete Attribute Scope',
      deleteScopeWarning: 'Are you sure you want to permanently delete attribute scope',
      fromRegistry: 'from the registry',
      deleteScopeWarningDesc: '⚠️ Warning: Deleting this scope will remove its definition from the iam-scope-registry group in Keycloak.',
      btnDeleteScopeConfirm: 'Delete Scope',

      // Permissions
      permsCatalogTitle: 'Platform Permissions Catalog',
      permsCatalogSubtitle: 'Permissions registered by microservices available for role composition',
      searchPermsPlaceholder: 'Search permissions (e.g. Orders.Read)...',
      btnRegisterPerm: '+ Register Permission',
      thPermName: 'Permission Name',
      thOriginService: 'Origin Service',
      loadingPermissions: 'Loading permissions catalog...',
      noPermsFound: 'No matching permissions found.',
      modalCreatePermTitle: 'Register New Permission',
      permNameLabel: 'Permission Name * (e.g. Orders.Export, Reports.View)',
      permNameHint: 'Standard format: Resource.Action (e.g. Orders.Read, Orders.Manage)',
      originServiceLabel: 'Origin Service ID',
      originServiceHint: 'Service client in Keycloak where the client role will be provisioned',

      // Token Playground
      tokenPlaygroundTitle: 'Token Playground & Access Verification',
      tokenPlaygroundSubtitle: 'Sign in as any user, mint live Keycloak JWT tokens, and inspect authz.scope.* claims',
      tokenStep1Title: '1. Sign In & Mint JWT Token',
      usernameLabel: 'Username',
      passwordLabel: 'Password',
      btnAuthenticateMint: 'Authenticate & Mint Token',
      tokenStep2Title: '2. Verify Token & Access Context',
      tokenOutputTitle: 'Decoded Token Content (Claims & Scopes)',

      // Settings
      settingsTitle: 'Dashboard Settings & Preferences',
      settingsSubtitle: 'Customize language, interface direction (RTL/LTR), and theme. Settings are automatically saved to LocalStorage.',
      settingLangTitle: 'Language & Direction',
      settingLangDesc: 'Select interface language and text layout direction',
      settingThemeTitle: 'Dashboard Theme',
      settingThemeDesc: 'Choose dark glassmorphism or clean light appearance',
      badgeDefault: 'Default',
      langFaTitle: 'فارسی (Persian)',
      langFaDesc: 'Right-to-Left (RTL) interface for sidebar, headers, and modals',
      langEnTitle: 'English (Left-to-Right)',
      langEnDesc: 'Standard Left-to-Right (LTR) layout and typography',
      themeDarkTitle: 'Dark Glassmorphism',
      themeDarkDesc: 'Modern dark glassmorphic styling with neon accents and high contrast',
      themeLightTitle: 'Clean Light',
      themeLightDesc: 'High contrast, clean light background for bright working environments',
      storageNotice: '💾 Preferences are saved to LocalStorage and persist across visits.',
      resetSettings: 'Reset to Defaults (English / Dark)',

      // Modals General
      cancel: 'Cancel',
      save: 'Save',
      close: 'Close',
      modalCreateUserTitle: 'Create New User',
      modalCreateUserSubtitle: 'Provision user in Keycloak with credentials, business role, and attribute scopes',
      secIdentityCredentials: '1. Identity & Credentials',
      initialPasswordLabel: 'Initial Password *',
      firstNameLabel: 'First Name',
      lastNameLabel: 'Last Name',
      emailLabel: 'Email Address',
      roleLabel: 'Business Role',
      selectRole: '(Select a Business Role)',
      tempPasswordLabel: 'Temporary Password (must change on first sign-in)',
      accountEnabledLabel: 'Account Enabled',
      secAttributeScopes: '2. Attribute Scopes (Dynamic Access Restrictions)',
      btnNewScopePlus: '+ New Scope',
      scopesDescription: 'Check the scopes that apply to this user and specify authorized values (comma-separated for multiple values, e.g. tehran-north, CC-9080):',

      modalUserScopesTitle: 'Manage Role & Scopes',
      userPrefix: 'User:',
      businessRoleRequired: 'Business Role *',
      secScopesCheckAndEnter: 'Attribute Scopes (Check and enter values)',
      scopesCheckDesc: 'Checked scopes restrict the user\'s data access to the specified values:',
      btnSaveRoleScopes: 'Save Role & Scopes',

      modalEditUserTitle: 'Edit User Profile',
      emailVerifiedLabel: 'Email Verified',
      btnDeleteUser: '🗑️ Delete User',
      btnResetPassword: '🔑 Reset Password',
      btnSaveChanges: 'Save Changes',

      modalResetPasswordTitle: 'Reset User Password',
      settingPwFor: 'Setting a new password for:',
      newPasswordLabel: 'New Password *',
      confirmPasswordLabel: 'Confirm New Password *',
      tempPasswordNext: 'Temporary Password (must change on next sign-in)',

      modalDeleteUserTitle: 'Delete User from Keycloak',
      deleteUserWarning: 'Are you sure you want to permanently delete user',
      deleteUserWarningDesc: '⚠️ Warning: This action is permanent and cannot be undone. The user account, active sessions, and assigned scopes will be completely deleted from Keycloak.',
      btnDeleteUserConfirm: 'Delete User',

      modalCreateRoleTitle: 'Create Business Role',
      roleNameLabel: 'Role Name * (e.g. Manager, Accountant, Clerk)',
      selectPermissionsLabel: 'Select Permissions',
      modalEditRoleTitle: 'Edit Business Role',
      assignedPermsLabel: 'Assigned Permissions',
      btnSaveRoleChanges: 'Save Role Changes',

      modalDeleteRoleTitle: 'Delete Business Role',
      deleteRoleWarning: 'Are you sure you want to permanently delete business role',
      deleteRoleWarningDesc: '⚠️ Safe Deletion: Keycloak will block deletion if any user accounts are currently assigned to this role.',
      btnDeleteRoleConfirm: 'Delete Role',

      modalRevokeTitle: 'Revoke User Sessions',
      revokeWarning: 'Are you sure you want to revoke all active sessions for user',
      revokeWarningDesc: 'This will invalidate all issued tokens immediately and disconnect the user.',
      btnRevokeConfirm: 'Revoke Sessions',

      modalDbTitle: 'Database Infrastructure Status',
      dbActiveEngine: 'Active Engine',
      dbConnectionHealth: 'Connection Health',
      dbHostTarget: 'Host Target',
      dbName: 'Database Name',

      modalLoginTitle: 'Admin Sign In',
      modalLoginSubtitle: 'Sign in with your Keycloak administrative credentials',
      defaultCredentials: 'Default credentials: admin / admin',
      btnSignIn: 'Sign In'
    }
  };

  // Translation lookup helper
  function t(key, fallback = '') {
    const langObj = i18n[state.lang] || i18n.en;
    if (langObj && langObj[key] !== undefined) {
      return langObj[key];
    }
    const enObj = i18n.en || {};
    if (enObj[key] !== undefined) {
      return enObj[key];
    }
    return fallback;
  }

  // Parse comma-separated Target Resources
  function parseTargetResources(val) {
    if (!val || typeof val !== 'string') return [];
    return val
      .split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0);
  }

  // Apply Language & Direction
  function applyLanguage(lang) {
    state.lang = lang === 'en' ? 'en' : 'fa';
    localStorage.setItem('dashboard_lang', state.lang);
    document.documentElement.setAttribute('lang', state.lang);
    document.documentElement.setAttribute('dir', state.lang === 'fa' ? 'rtl' : 'ltr');

    if (elements.currentLangLabel) {
      elements.currentLangLabel.textContent = state.lang === 'fa' ? 'EN' : 'FA';
    }

    if (elements.radioLangFa && elements.radioLangEn) {
      elements.radioLangFa.checked = (state.lang === 'fa');
      elements.radioLangEn.checked = (state.lang === 'en');
      elements.cardLangFa?.classList.toggle('active', state.lang === 'fa');
      elements.cardLangEn?.classList.toggle('active', state.lang === 'en');
    }

    // Translate DOM elements with data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val) {
        el.textContent = val;
      }
    });

    // Translate placeholders with data-i18n-placeholder
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = t(key);
      if (val) el.placeholder = val;
    });

    // Translate titles
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      const val = t(key);
      if (val) el.title = val;
    });

    // Re-title the current page
    switchView(state.currentView);

    // Re-render active view components
    renderUsersTable();
    renderBusinessRoles();
    renderScopesTable();
    renderPermissionsTable();
    updateMetrics();
  }

  // Apply Theme (Dark / Light)
  function applyTheme(theme) {
    state.theme = theme === 'light' ? 'light' : 'dark';
    localStorage.setItem('dashboard_theme', state.theme);
    document.documentElement.setAttribute('data-theme', state.theme);

    if (elements.currentThemeIcon) {
      elements.currentThemeIcon.textContent = state.theme === 'light' ? '☀️' : '🌙';
    }

    if (elements.radioThemeDark && elements.radioThemeLight) {
      elements.radioThemeDark.checked = (state.theme === 'dark');
      elements.radioThemeLight.checked = (state.theme === 'light');
      elements.cardThemeDark?.classList.toggle('active', state.theme === 'dark');
      elements.cardThemeLight?.classList.toggle('active', state.theme === 'light');
    }
  }

  // ==========================================
  // Helper: API Fetch with Bearer Auth
  // ==========================================
  async function apiFetch(url, options = {}) {
    const headers = options.headers || {};
    if (state.token) {
      headers['Authorization'] = `Bearer ${state.token}`;
    }
    if (!headers['Content-Type'] && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, { ...options, headers });
    if (response.status === 401) {
      promptLogin();
      throw new Error('Unauthorized');
    }
    return response;
  }

  // ==========================================
  // Helper: UI Toast Notifications
  // ==========================================
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = type === 'success' ? '✓' : (type === 'error' ? '✕' : (type === 'warning' ? '⚠' : 'ℹ'));
    toast.innerHTML = `<span style="font-weight:700;">${icon}</span><span>${escapeHtml(message)}</span>`;
    
    elements.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ==========================================
  // Modal Helpers (<dialog> API)
  // ==========================================
  function openModal(dialogElement) {
    if (!dialogElement) return;
    if (typeof dialogElement.showModal === 'function') {
      dialogElement.showModal();
    } else {
      dialogElement.setAttribute('open', '');
    }
  }

  function closeModal(dialogElement) {
    if (!dialogElement) return;
    if (typeof dialogElement.close === 'function') {
      dialogElement.close();
    } else {
      dialogElement.removeAttribute('open');
    }
  }

  // Bind close buttons with [data-close-modal]
  document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => {
      const modalId = btn.getAttribute('data-close-modal');
      const targetModal = document.getElementById(modalId);
      if (targetModal) closeModal(targetModal);
    });
  });

  // ==========================================
  // Authentication & Session
  // ==========================================
  function promptLogin() {
    state.token = '';
    state.currentUser = null;
    sessionStorage.removeItem('identity_admin_token');
    hideLoginAlert();
    openModal(elements.modalLogin);
  }

  function showLoginAlert(message) {
    if (elements.loginAlert && elements.loginAlertMsg) {
      elements.loginAlertMsg.textContent = message;
      elements.loginAlert.style.display = 'flex';
    }
  }

  function hideLoginAlert() {
    if (elements.loginAlert) {
      elements.loginAlert.style.display = 'none';
    }
  }

  async function handleLogin(username, password) {
    hideLoginAlert();
    try {
      const form = new URLSearchParams();
      form.append('grant_type', 'password');
      form.append('client_id', 'identity-gateway');
      form.append('username', username);
      form.append('password', password);

      const res = await fetch('/api/identity/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });

      const body = await res.json();
      if (!res.ok) {
        showLoginAlert(body.detail || body.message || body.error_description || 'Sign in failed: invalid credentials');
        return;
      }

      state.token = body.access_token || body.accessToken;
      sessionStorage.setItem('identity_admin_token', state.token);
      closeModal(elements.modalLogin);
      showToast('Signed in successfully!', 'success');

      await loadCurrentUserProfile();
      await refreshAllData();
    } catch (err) {
      showLoginAlert(`Connection error: ${err.message}`);
    }
  }

  async function loadCurrentUserProfile() {
    if (!state.token) return;
    try {
      const res = await apiFetch('/api/identity/me');
      if (res.ok) {
        state.currentUser = await res.json();
        elements.headerUsername.textContent = state.currentUser.username || 'Admin';
        elements.headerAvatar.textContent = (state.currentUser.username || 'A').charAt(0).toUpperCase();
        elements.headerRole.textContent = state.currentUser.roles && state.currentUser.roles.length > 0
          ? state.currentUser.roles.slice(0, 2).join(', ')
          : 'Administrator';
      }
    } catch {
      elements.headerUsername.textContent = 'Admin User';
    }
  }

  // ==========================================
  // View Routing
  // ==========================================
  function switchView(viewId) {
    state.currentView = viewId;
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const targetPanel = document.getElementById(viewId);
    if (targetPanel) targetPanel.classList.add('active');

    const activeNav = document.querySelector(`[data-view="${viewId}"]`);
    if (activeNav) activeNav.classList.add('active');

    const titles = {
      'view-overview': t('navOverview', 'Dashboard Overview'),
      'view-users': t('navUsers', 'Users & Scoped Access Management'),
      'view-roles': t('navRoles', 'Business Roles'),
      'view-scopes': t('navScopes', 'Attribute Scope Registry'),
      'view-permissions': t('navPermissions', 'Platform Permissions Catalog'),
      'view-token-test': t('navTokenTest', 'Token Playground & Access Verification'),
      'view-settings': t('navSettings', 'Dashboard Settings & Preferences')
    };
    elements.pageHeading.textContent = titles[viewId] || t('navOverview', 'Dashboard Overview');
  }

  // ==========================================
  // Data Loaders
  // ==========================================
  async function refreshAllData() {
    await Promise.all([
      loadScopes(),
      loadBusinessRoles(),
      loadUsers(),
      loadPermissions(),
      loadDatabaseInfo()
    ]);
    updateMetrics();
  }

  // 0. Database Diagnostics Loader
  async function loadDatabaseInfo() {
    if (!state.token) return;
    try {
      const res = await apiFetch('/api/system/database-info');
      if (res.ok) {
        const db = await res.json();
        const rawProvider = db.provider || 'postgres';
        const providerName = rawProvider === 'mssql' ? 'SQL Server' : (rawProvider === 'oracle' ? 'Oracle' : 'PostgreSQL');
        const isHealthy = !!db.isHealthy;
        const latency = db.latencyMs != null ? `${db.latencyMs} ms` : 'N/A';
        const statusText = isHealthy ? `Online (${latency})` : 'Unreachable';

        if (elements.statDbProvider) elements.statDbProvider.textContent = providerName;
        if (elements.statDbSub) {
          elements.statDbSub.textContent = statusText;
          elements.statDbSub.className = isHealthy ? 'metric-trend online' : 'metric-trend';
        }

        if (elements.sidebarDbLabel) {
          elements.sidebarDbLabel.textContent = `Keycloak & ${providerName}`;
        }
        if (elements.sidebarDbSub) {
          elements.sidebarDbSub.textContent = isHealthy ? `Online (${latency})` : 'Unreachable';
        }
        if (elements.sidebarDbDot) {
          elements.sidebarDbDot.style.background = isHealthy ? '#10b981' : '#f43f5e';
        }

        if (elements.modalDbProvider) elements.modalDbProvider.textContent = providerName;
        if (elements.modalDbHealth) {
          elements.modalDbHealth.textContent = `${db.status || 'Unknown'} (${latency})`;
          elements.modalDbHealth.style.color = isHealthy ? 'var(--success)' : 'var(--danger)';
        }
        if (elements.modalDbHost) elements.modalDbHost.textContent = `${db.host || '-'}:${db.port || '-'}`;
        if (elements.modalDbName) elements.modalDbName.textContent = db.databaseName || 'keycloak';
      }
    } catch (err) {
      console.warn('Failed to load database diagnostics:', err);
    }
  }

  // 1. Users Loader
  async function loadUsers() {
    try {
      const res = await apiFetch('/api/identity/users?page=1&pageSize=100&includeSessions=true');
      if (res.ok) {
        const paged = await res.json();
        state.users = paged.items || [];
        renderUsersTable();
      }
    } catch (err) {
      elements.usersTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger); padding: 24px;">Failed to load users from Keycloak.</td></tr>`;
    }
  }

  function renderUsersTable() {
    const search = (elements.userSearchInput.value || '').toLowerCase().trim();
    const filter = elements.userStatusFilter.value;

    let filtered = state.users.filter(u => {
      const matchSearch = !search ||
        (u.username && u.username.toLowerCase().includes(search)) ||
        (u.displayName && u.displayName.toLowerCase().includes(search)) ||
        (u.attributes && Object.values(u.attributes).flat().some(v => String(v).toLowerCase().includes(search)));

      let matchFilter = true;
      if (filter === 'online') matchFilter = !!u.isOnline;
      if (filter === 'offline') matchFilter = !u.isOnline;

      return matchSearch && matchFilter;
    });

    if (filtered.length === 0) {
      elements.usersTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-faint); padding: 32px;">${t('noUsersFound', 'No matching users found.')}</td></tr>`;
      return;
    }

    elements.usersTableBody.innerHTML = filtered.map(u => {
      const isOnline = !!u.isOnline;
      const sessionCount = u.activeSessionsCount || (isOnline ? 1 : 0);
      const statusBadge = isOnline
        ? `<span class="badge badge-online"><span class="badge-dot"></span> ${t('activeStatus', 'Online')} (${sessionCount})</span>`
        : `<span class="badge badge-offline"><span class="badge-dot"></span> ${t('offlineStatus', 'Offline')}</span>`;

      // 1. Business role (from iam.business_role OR iam.scoped_access)
      let roleName = '';
      if (u.attributes && u.attributes['iam.business_role'] && u.attributes['iam.business_role'].length > 0) {
        roleName = u.attributes['iam.business_role'][0];
      }

      // 2. Extract scopes
      let scopesDisplay = [];
      if (u.attributes && u.attributes['iam.scoped_access']) {
        try {
          const doc = JSON.parse(u.attributes['iam.scoped_access'][0]);
          if (Array.isArray(doc)) {
            doc.forEach(a => {
              if (a.role && !roleName) roleName = a.role;
              if (a.scopes) {
                Object.entries(a.scopes).forEach(([k, vals]) => {
                  const valStr = Array.isArray(vals) ? vals.join(', ') : vals;
                  scopesDisplay.push(`<span class="scope-chip" title="Scope: ${escapeHtml(k)}">${escapeHtml(k)}: ${escapeHtml(valStr)}</span>`);
                });
              }
            });
          }
        } catch {}
      }

      // Also check authz.scope.* attributes
      if (u.attributes) {
        Object.entries(u.attributes).forEach(([k, v]) => {
          if (k.startsWith('authz.scope.')) {
            const scopeKey = k.substring('authz.scope.'.length);
            const valStr = Array.isArray(v) ? v.join(', ') : v;
            const chip = `<span class="scope-chip" title="Scope: ${escapeHtml(scopeKey)}">${escapeHtml(scopeKey)}: ${escapeHtml(valStr)}</span>`;
            if (!scopesDisplay.some(s => s.includes(`${escapeHtml(scopeKey)}:`))) {
              scopesDisplay.push(chip);
            }
          }
        });
      }

      const roleBadge = roleName
        ? `<span class="role-badge">🛡️ ${escapeHtml(roleName)}</span>`
        : `<span style="color: var(--text-faint); font-size: 0.78rem;">${t('noRole', '(No Role)')}</span>`;

      const scopesHtml = scopesDisplay.length > 0
        ? `<div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 5px;">${scopesDisplay.join('')}</div>`
        : `<div style="color: var(--text-faint); font-size: 0.75rem; margin-top: 3px;">${t('noScopes', 'No Scopes Assigned')}</div>`;

      return `
        <tr data-user-id="${escapeHtml(u.id)}">
          <td>
            <div class="user-cell">
              <div class="avatar-circle">${escapeHtml(u.username.charAt(0).toUpperCase())}</div>
              <div class="user-cell-meta">
                <span class="user-cell-name">${escapeHtml(u.username)}</span>
                <span class="user-cell-sub">ID: ${escapeHtml(u.id.substring(0, 8))}...</span>
              </div>
            </div>
          </td>
          <td>
            <div style="font-weight: 500;">${escapeHtml(u.displayName || '-')}</div>
            ${u.attributes && u.attributes.email ? `<div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(u.attributes.email[0])}</div>` : ''}
          </td>
          <td>${statusBadge}</td>
          <td>
            <div>${roleBadge}</div>
            ${scopesHtml}
          </td>
          <td style="text-align: right;">
            <div style="display: flex; gap: 6px; justify-content: flex-end; align-items: center; flex-wrap: wrap;">
              <button class="btn btn-sm btn-primary btn-manage-scopes" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="Manage Role & Scopes">
                ${t('btnManageScopes', 'Role & Scopes')}
              </button>
              <button class="btn btn-sm btn-secondary btn-edit-user" data-user='${JSON.stringify(u).replace(/'/g, "&apos;")}' title="Edit User Profile">
                ${t('btnEditUser', 'Edit')}
              </button>
              <button class="btn btn-sm btn-secondary btn-reset-password" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="Reset Password">
                ${t('btnResetPassword', '🔑 Reset Password')}
              </button>
              <button class="btn btn-sm btn-ghost btn-revoke-tokens" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="Revoke Sessions">
                ${t('btnRevokeSessions', 'Revoke')}
              </button>
              <button class="btn btn-sm btn-outline-danger btn-delete-user" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="Delete User">
                ${t('btnDelete', '🗑️ Delete')}
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach Event Listeners
    elements.usersTableBody.querySelectorAll('.btn-manage-scopes').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const username = btn.getAttribute('data-username');
        openUserScopesModal(id, username);
      });
    });

    elements.usersTableBody.querySelectorAll('.btn-edit-user').forEach(btn => {
      btn.addEventListener('click', () => {
        const user = JSON.parse(btn.getAttribute('data-user'));
        openEditUserModal(user);
      });
    });

    elements.usersTableBody.querySelectorAll('.btn-reset-password').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const username = btn.getAttribute('data-username');
        openResetPasswordModal(id, username);
      });
    });

    elements.usersTableBody.querySelectorAll('.btn-revoke-tokens').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const username = btn.getAttribute('data-username');
        elements.revokeTargetId.value = id;
        elements.revokeTargetUsername.textContent = username;
        openModal(elements.modalConfirmRevoke);
      });
    });

    elements.usersTableBody.querySelectorAll('.btn-delete-user').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const username = btn.getAttribute('data-username');
        openDeleteUserModal(id, username);
      });
    });
  }

  function openEditUserModal(user) {
    document.getElementById('eu-id').value = user.id;
    if (elements.euUsernameDisplay) elements.euUsernameDisplay.textContent = user.username;
    if (elements.euUsername) elements.euUsername.value = user.username;
    document.getElementById('eu-email').value = (user.attributes && user.attributes.email ? user.attributes.email[0] : '') || '';
    document.getElementById('eu-firstname').value = (user.attributes && user.attributes.firstName ? user.attributes.firstName[0] : '') || '';
    document.getElementById('eu-lastname').value = (user.attributes && user.attributes.lastName ? user.attributes.lastName[0] : '') || '';
    document.getElementById('eu-enabled').checked = !!user.enabled;
    if (elements.euEmailVerified) {
      elements.euEmailVerified.checked = user.attributes && user.attributes.emailVerified && user.attributes.emailVerified[0] === 'true';
    }
    openModal(elements.modalEditUser);
  }

  function openResetPasswordModal(id, username) {
    elements.rpUserId.value = id;
    elements.rpUsername.value = username;
    elements.rpUsernameLabel.textContent = username;
    elements.rpPassword.value = '';
    elements.rpPasswordConfirm.value = '';
    elements.rpTemporary.checked = false;
    openModal(elements.modalResetPassword);
  }

  function openDeleteUserModal(id, username) {
    elements.deleteUserId.value = id;
    elements.deleteUserUsername.textContent = username;
    openModal(elements.modalConfirmDeleteUser);
  }

  // 2. Business Roles Loader
  async function loadBusinessRoles() {
    try {
      const res = await apiFetch('/api/identity/business-roles');
      if (res.ok) {
        state.roles = await res.json();
        renderBusinessRoles();
        populateRoleSelectors();
      }
    } catch (err) {
      elements.businessRolesGrid.innerHTML = `<div style="grid-column: 1 / -1; text-align: center; color: var(--danger); padding: 24px;">Failed to load business roles.</div>`;
    }
  }

  function renderBusinessRoles() {
    if (state.roles.length === 0) {
      elements.businessRolesGrid.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; color: var(--text-faint); padding: 32px;">
          No business roles registered yet. Create one like 'Manager' or 'Accountant'.
        </div>`;
      return;
    }

    elements.businessRolesGrid.innerHTML = state.roles.map(r => {
      const perms = r.permissions || [];
      const permsPreview = perms.slice(0, 4).map(p => `<span class="badge" style="background: rgba(148,163,184,0.1); color: var(--text-muted); font-size: 0.72rem;">${escapeHtml(p)}</span>`).join(' ');
      const moreCount = perms.length > 4 ? `+${perms.length - 4} more` : '';

      return `
        <div class="role-card">
          <div class="role-card-header">
            <div class="role-card-title">${escapeHtml(r.name)}</div>
            <span class="badge badge-role">${perms.length} Permissions</span>
          </div>
          <p class="role-card-desc">${escapeHtml(r.description || 'No description provided')}</p>
          <div style="margin-top: 12px; display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
            ${permsPreview}
            ${moreCount ? `<span style="font-size: 0.72rem; color: var(--text-faint);">${moreCount}</span>` : ''}
          </div>
          <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.07); display: flex; justify-content: flex-end; gap: 8px;">
            <button class="btn btn-sm btn-secondary btn-edit-role" data-role='${JSON.stringify(r)}'>
              Edit Role
            </button>
            <button class="btn btn-sm btn-ghost btn-delete-role" data-name="${escapeHtml(r.name)}" style="color: var(--danger);">
              🗑️ Delete
            </button>
          </div>
        </div>
      `;
    }).join('');

    // Attach role card action listeners
    elements.businessRolesGrid.querySelectorAll('.btn-edit-role').forEach(btn => {
      btn.addEventListener('click', () => {
        const r = JSON.parse(btn.getAttribute('data-role'));
        elements.erName.value = r.name;
        elements.erDesc.value = r.description || '';
        const currentPerms = new Set(r.permissions || []);
        elements.erPermsSelector.innerHTML = state.permissions.map(p => `
          <label class="checkbox-label" style="font-size: 0.85rem;">
            <input type="checkbox" name="edit_role_perms" value="${escapeHtml(p.name)}" ${currentPerms.has(p.name) ? 'checked' : ''}>
            <span style="font-family: monospace; color: #e2e8f0;">${escapeHtml(p.name)}</span>
            <span style="color: var(--text-faint); font-size: 0.75rem;">(${escapeHtml(p.declaringService)})</span>
          </label>
        `).join('');
        openModal(elements.modalEditRole);
      });
    });

    elements.businessRolesGrid.querySelectorAll('.btn-delete-role').forEach(btn => {
      btn.addEventListener('click', () => {
        const name = btn.getAttribute('data-name');
        elements.deleteRoleName.value = name;
        elements.deleteRoleNameDisplay.textContent = name;
        openModal(elements.modalConfirmDeleteRole);
      });
    });
  }

  function populateRoleSelectors() {
    const options = [
      '<option value="">(Select a Business Role)</option>',
      ...state.roles.map(r => `<option value="${escapeHtml(r.name)}">${escapeHtml(r.name)}</option>`)
    ].join('');

    if (elements.cuRoleSelect) elements.cuRoleSelect.innerHTML = options;
    if (elements.usRoleSelect) elements.usRoleSelect.innerHTML = options;
  }

  // 3. Attribute Scopes Loader & Management
  async function loadScopes() {
    try {
      const [resScopes, resResources] = await Promise.all([
        apiFetch('/api/identity/scopes'),
        apiFetch('/api/identity/scopes/resources/list')
      ]);

      if (resScopes.ok) {
        state.scopes = await resScopes.json();
      }
      if (resResources.ok) {
        state.resources = await resResources.json();
      }

      renderScopesTable();
      renderScopeCheckboxes('cu-scopes-container', {});
      updateMetrics();
    } catch (err) {
      if (elements.scopesTableBody) {
        elements.scopesTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--danger); padding: 24px;">Failed to load attribute scopes registry.</td></tr>`;
      }
    }
  }

  function renderScopesTable() {
    if (!elements.scopesTableBody) return;
    if (!state.scopes || state.scopes.length === 0) {
      elements.scopesTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-faint); padding: 32px;">${t('noScopesFound', 'No attribute scopes registered yet. Use the form above to register a new scope.')}</td></tr>`;
      return;
    }

    elements.scopesTableBody.innerHTML = state.scopes.map(s => {
      const boundRes = (state.resources || [])
        .filter(r => r.scopes && r.scopes.some(sc => sc.toLowerCase() === s.key.toLowerCase()))
        .map(r => `<span class="resource-pill">${escapeHtml(r.key)}</span>`)
        .join(' ');

      const statusBadge = s.isActive
        ? `<span class="badge badge-online"><span class="badge-dot"></span> ${t('activeStatus', 'Active')}</span>`
        : `<span class="badge badge-offline"><span class="badge-dot"></span> ${t('disabledBadge', 'Inactive')}</span>`;

      return `
        <tr>
          <td><span class="scope-chip">${escapeHtml(s.key)}</span></td>
          <td style="font-weight: 600; color: var(--text-main);">${escapeHtml(s.displayName || s.key)}</td>
          <td style="color: var(--text-muted); font-size: 0.85rem;">${escapeHtml(s.description || '-')}</td>
          <td>${boundRes || `<span style="color: var(--text-faint); font-size: 0.78rem;">${t('unboundResources', '(Unbound)')}</span>`}</td>
          <td>${statusBadge}</td>
          <td style="text-align: right;">
            <div style="display: flex; gap: 6px; justify-content: flex-end;">
              <button class="btn btn-sm btn-secondary btn-edit-scope" data-scope='${JSON.stringify(s)}'>
                ${t('btnEdit', 'Edit')}
              </button>
              <button class="btn btn-sm btn-ghost btn-toggle-scope" data-key="${escapeHtml(s.key)}" data-active="${!!s.isActive}">
                ${s.isActive ? t('btnDeactivate', 'Deactivate') : t('btnActivate', 'Activate')}
              </button>
              <button class="btn btn-sm btn-ghost btn-delete-scope" data-key="${escapeHtml(s.key)}" style="color: var(--danger);">
                ${t('btnDelete', '🗑️ Delete')}
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach listeners
    elements.scopesTableBody.querySelectorAll('.btn-edit-scope').forEach(btn => {
      btn.addEventListener('click', () => {
        const s = JSON.parse(btn.getAttribute('data-scope'));
        document.getElementById('es-key').value = s.key;
        document.getElementById('es-display').value = s.displayName || s.key;
        document.getElementById('es-desc').value = s.description || '';
        document.getElementById('es-active').checked = !!s.isActive;

        // Populate Target Resources for editing!
        const currentResources = (state.resources || [])
          .filter(r => r.scopes && r.scopes.some(sc => sc.toLowerCase() === s.key.toLowerCase()))
          .map(r => r.key);
        const esRes = document.getElementById('es-resources');
        if (esRes) {
          esRes.value = currentResources.join(', ');
        }
        openModal(elements.modalEditScope);
      });
    });

    elements.scopesTableBody.querySelectorAll('.btn-delete-scope').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-key');
        elements.deleteScopeTargetKey.value = key;
        elements.deleteScopeKey.textContent = key;
        openModal(elements.modalConfirmDeleteScope);
      });
    });

    elements.scopesTableBody.querySelectorAll('.btn-toggle-scope').forEach(btn => {
      btn.addEventListener('click', async () => {
        const key = btn.getAttribute('data-key');
        const currentActive = btn.getAttribute('data-active') === 'true';
        const target = state.scopes.find(x => x.key === key);
        if (!target) return;

        try {
          const res = await apiFetch(`/api/identity/scopes/${encodeURIComponent(key)}`, {
            method: 'PUT',
            body: JSON.stringify({
              displayName: target.displayName,
              description: target.description,
              isActive: !currentActive
            })
          });
          if (res.ok) {
            showToast(`Scope '${key}' ${!currentActive ? 'activated' : 'deactivated'} successfully.`, 'success');
            await loadScopes();
          } else {
            showToast('Failed to toggle scope status.', 'error');
          }
        } catch {
          showToast('Network error while toggling scope status.', 'error');
        }
      });
    });
  }

  // Render Scope Checkboxes with Dynamic Value Inputs for Create/Edit User
  function renderScopeCheckboxes(containerId, initialScopes = {}) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!state.scopes || state.scopes.length === 0) {
      container.innerHTML = `
        <div style="font-size: 0.85rem; color: var(--text-faint); padding: 12px; text-align: center;">
          No attribute scopes defined yet. Register a new scope from the Attribute Scopes tab.
        </div>`;
      return;
    }

    container.innerHTML = state.scopes.map(s => {
      const isSelected = initialScopes && initialScopes[s.key] != null;
      let initialValues = '';
      if (isSelected) {
        const raw = initialScopes[s.key];
        initialValues = Array.isArray(raw) ? raw.join(', ') : String(raw);
      }

      return `
        <div class="scope-select-card ${isSelected ? 'selected' : ''}" data-scope-key="${escapeHtml(s.key)}">
          <div class="scope-header-row">
            <label class="checkbox-label" style="margin: 0; cursor: pointer; display: flex; align-items: flex-start; gap: 8px;">
              <input type="checkbox" class="scope-toggle-cb" data-target-key="${escapeHtml(s.key)}" ${isSelected ? 'checked' : ''} style="margin-top: 3px;">
              <div>
                <div class="scope-name-title">
                  ${escapeHtml(s.displayName || s.key)}
                  <span style="font-size: 0.75rem; color: var(--secondary); font-family: monospace;">(${escapeHtml(s.key)})</span>
                </div>
                ${s.description ? `<div class="scope-desc-text">${escapeHtml(s.description)}</div>` : ''}
              </div>
            </label>
          </div>
          <div class="scope-values-input-box" style="display: ${isSelected ? 'flex' : 'none'}; margin-top: 10px;">
            <label style="font-size: 0.74rem; color: var(--secondary); font-weight: 600;">
              Authorized value(s) for this user:
            </label>
            <input type="text" class="form-control scope-values-input"
              data-scope-input="${escapeHtml(s.key)}"
              value="${escapeHtml(initialValues)}"
              placeholder="e.g. tehran-north or comma-separated: tehran-1, tehran-2"
              style="padding: 7px 12px; font-size: 0.85rem;">
          </div>
        </div>
      `;
    }).join('');

    // Attach checkbox toggle handlers
    container.querySelectorAll('.scope-toggle-cb').forEach(cb => {
      cb.addEventListener('change', () => {
        const card = cb.closest('.scope-select-card');
        const inputContainer = card.querySelector('.scope-values-input-box');
        const input = card.querySelector('.scope-values-input');
        if (cb.checked) {
          card.classList.add('selected');
          inputContainer.style.display = 'flex';
          input.focus();
        } else {
          card.classList.remove('selected');
          inputContainer.style.display = 'none';
        }
      });
    });
  }

  function getScopesFromContainer(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return { scopes: {}, missingValueKey: null };
    const scopes = {};
    let missingValueKey = null;

    container.querySelectorAll('.scope-select-card').forEach(card => {
      const cb = card.querySelector('.scope-toggle-cb');
      if (cb && cb.checked) {
        const key = card.getAttribute('data-scope-key');
        const input = card.querySelector('.scope-values-input');
        const rawVal = input ? input.value : '';
        const values = rawVal.split(',').map(v => v.trim()).filter(Boolean);
        if (values.length > 0) {
          scopes[key] = values;
        } else {
          missingValueKey = key;
        }
      }
    });

    return { scopes, missingValueKey };
  }

  // Manage Role & Scopes Modal for Existing User
  async function openUserScopesModal(userId, username) {
    elements.usUserId.value = userId;
    elements.usUsernameDisplay.textContent = username;
    populateRoleSelectors();

    let initialRole = '';
    let initialScopes = {};

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(userId)}/scoped-access`);
      if (res.ok) {
        const data = await res.json();
        if (data.assignments && data.assignments.length > 0) {
          initialRole = data.assignments[0].role || '';
          initialScopes = data.assignments[0].scopes || {};
        }
      }
    } catch (err) {
      console.warn('Could not load user scoped access:', err);
    }

    // Fallback: If user had no scoped-access entry but had a business_role attribute
    if (!initialRole) {
      const userObj = state.users.find(u => u.id === userId);
      if (userObj && userObj.attributes && userObj.attributes['iam.business_role']) {
        initialRole = userObj.attributes['iam.business_role'][0];
      }
    }

    elements.usRoleSelect.value = initialRole;
    renderScopeCheckboxes('us-scopes-container', initialScopes);
    openModal(elements.modalUserScopes);
  }

  // 4. Permissions Loader
  async function loadPermissions() {
    try {
      const res = await apiFetch('/api/identity/permissions');
      if (res.ok) {
        state.permissions = await res.json();
        renderPermissionsTable();
        renderPermissionsSelector();
      }
    } catch (err) {
      elements.permissionsTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--danger); padding: 24px;">Failed to load permissions catalog.</td></tr>`;
    }
  }

  function renderPermissionsTable() {
    const search = (elements.permSearchInput.value || '').toLowerCase().trim();
    let filtered = state.permissions.filter(p => {
      return !search ||
        (p.name && p.name.toLowerCase().includes(search)) ||
        (p.description && p.description.toLowerCase().includes(search)) ||
        (p.declaringService && p.declaringService.toLowerCase().includes(search));
    });

    if (filtered.length === 0) {
      elements.permissionsTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-faint); padding: 32px;">${t('noPermsFound', 'No matching permissions found.')}</td></tr>`;
      return;
    }

    elements.permissionsTableBody.innerHTML = filtered.map(p => `
      <tr>
        <td style="font-family: monospace; font-weight: 600; color: #38bdf8;">${escapeHtml(p.name)}</td>
        <td>${escapeHtml(p.description || '-')}</td>
        <td><span class="badge" style="background: rgba(168,85,247,0.15); color: #c084fc;">${escapeHtml(p.declaringService)}</span></td>
        <td><span class="badge badge-online"><span class="badge-dot"></span> ${t('activeStatus', 'Active')}</span></td>
      </tr>
    `).join('');
  }

  function renderPermissionsSelector() {
    const container = document.getElementById('cr-perms-selector');
    if (!container) return;

    if (state.permissions.length === 0) {
      container.innerHTML = `<span style="font-size: 0.82rem; color: var(--text-faint);">No permissions available.</span>`;
      return;
    }

    container.innerHTML = state.permissions.map(p => `
      <label class="checkbox-label" style="font-size: 0.85rem;">
        <input type="checkbox" name="role_perms" value="${escapeHtml(p.name)}">
        <span style="font-family: monospace; color: #e2e8f0;">${escapeHtml(p.name)}</span>
        <span style="color: var(--text-faint); font-size: 0.75rem;">(${escapeHtml(p.declaringService)})</span>
      </label>
    `).join('');
  }

  function updateMetrics() {
    if (elements.statTotalUsers) elements.statTotalUsers.textContent = state.users.length;
    const online = state.users.filter(u => u.isOnline).length;
    if (elements.statOnlineUsers) elements.statOnlineUsers.textContent = online;
    if (elements.onlineUsersBadge) elements.onlineUsersBadge.textContent = `${online} Online`;
    if (elements.statBusinessRoles) elements.statBusinessRoles.textContent = state.roles.length;
    if (elements.statScopes) elements.statScopes.textContent = state.scopes.length;
    if (elements.scopesCountBadge) elements.scopesCountBadge.textContent = `${state.scopes.length} Scopes`;
    if (elements.statPermissions) elements.statPermissions.textContent = state.permissions.length;
  }

  // ==========================================
  // Form Actions & Handlers
  // ==========================================

  // 1. Create User with Business Role & Dynamic Scopes
  elements.formCreateUser.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('cu-username').value.trim();
    const email = document.getElementById('cu-email').value.trim() || null;
    const firstName = document.getElementById('cu-firstname').value.trim() || null;
    const lastName = document.getElementById('cu-lastname').value.trim() || null;
    const password = document.getElementById('cu-password').value;
    const temporary = document.getElementById('cu-temporary').checked;
    const enabled = document.getElementById('cu-enabled').checked;
    const role = elements.cuRoleSelect.value;

    const { scopes, missingValueKey } = getScopesFromContainer('cu-scopes-container');
    if (missingValueKey) {
      showToast(`Please enter at least one value for checked scope '${missingValueKey}'.`, 'warning');
      return;
    }

    const hasScopes = Object.keys(scopes).length > 0;
    if (hasScopes && !role) {
      showToast('Selecting a Business Role is required when assigning scopes.', 'warning');
      elements.cuRoleSelect.focus();
      return;
    }

    const assignments = [];
    if (role) {
      assignments.push({ role, scopes });
    }

    const payload = {
      username,
      email,
      firstName,
      lastName,
      enabled,
      credentials: { password, temporary },
      assignments: assignments.length > 0 ? assignments : null
    };

    try {
      const res = await apiFetch('/api/identity/users', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        showToast(`User '${username}' created successfully in Keycloak with assigned scopes!`, 'success');
        closeModal(elements.modalCreateUser);
        elements.formCreateUser.reset();
        await loadUsers();
        updateMetrics();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to create user: ${err.detail || err.message || 'Validation error'}`, 'error');
      }
    } catch {
      showToast('Error sending create user request.', 'error');
    }
  });

  // 2. Manage Existing User Role & Scopes
  elements.formUserScopes.addEventListener('submit', async (e) => {
    e.preventDefault();
    const userId = elements.usUserId.value;
    const role = elements.usRoleSelect.value;
    if (!role) {
      showToast('Please select a business role for the user.', 'warning');
      return;
    }

    const { scopes, missingValueKey } = getScopesFromContainer('us-scopes-container');
    if (missingValueKey) {
      showToast(`Please enter a value for checked scope '${missingValueKey}'.`, 'warning');
      return;
    }

    const payload = {
      assignments: [{ role, scopes }]
    };

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(userId)}/scoped-access`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        showToast('User role and scopes saved successfully in Keycloak!', 'success');
        closeModal(elements.modalUserScopes);
        await loadUsers();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to update scopes: ${err.detail || err.message || 'Validation error'}`, 'error');
      }
    } catch {
      showToast('Error updating user scopes.', 'error');
    }
  });

  // 3. Edit User Profile
  elements.formEditUser.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('eu-id').value;
    const username = elements.euUsername ? elements.euUsername.value.trim() : null;
    const email = document.getElementById('eu-email').value.trim() || null;
    const firstName = document.getElementById('eu-firstname').value.trim() || null;
    const lastName = document.getElementById('eu-lastname').value.trim() || null;
    const enabled = document.getElementById('eu-enabled').checked;
    const emailVerified = elements.euEmailVerified ? elements.euEmailVerified.checked : null;

    const payload = { username, email, firstName, lastName, enabled, emailVerified };

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        showToast('User profile updated successfully in Keycloak!', 'success');
        closeModal(elements.modalEditUser);
        await loadUsers();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to update user: ${err.detail || err.message || 'Update failed'}`, 'error');
      }
    } catch {
      showToast('Error updating user profile.', 'error');
    }
  });

  if (elements.euBtnResetPwShortcut) {
    elements.euBtnResetPwShortcut.addEventListener('click', () => {
      const id = document.getElementById('eu-id').value;
      const username = elements.euUsernameDisplay ? elements.euUsernameDisplay.textContent : '';
      closeModal(elements.modalEditUser);
      openResetPasswordModal(id, username);
    });
  }

  if (elements.euBtnDeleteShortcut) {
    elements.euBtnDeleteShortcut.addEventListener('click', () => {
      const id = document.getElementById('eu-id').value;
      const username = elements.euUsernameDisplay ? elements.euUsernameDisplay.textContent : '';
      closeModal(elements.modalEditUser);
      openDeleteUserModal(id, username);
    });
  }

  // 3.1 Reset User Password
  elements.formResetPassword.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = elements.rpUserId.value;
    const password = elements.rpPassword.value;
    const confirm = elements.rpPasswordConfirm.value;
    const temporary = elements.rpTemporary.checked;

    if (password !== confirm) {
      showToast('Passwords do not match.', 'warning');
      return;
    }

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(id)}/reset-password`, {
        method: 'POST',
        body: JSON.stringify({ password, temporary })
      });

      if (res.ok) {
        showToast('User password reset successfully in Keycloak!', 'success');
        closeModal(elements.modalResetPassword);
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to reset password: ${err.detail || err.message || 'Server error'}`, 'error');
      }
    } catch {
      showToast('Error sending password reset request.', 'error');
    }
  });

  // 3.2 Delete User
  elements.btnExecuteDeleteUser.addEventListener('click', async () => {
    const id = elements.deleteUserId.value;
    if (!id) return;

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(id)}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        showToast('User deleted successfully from Keycloak!', 'success');
        closeModal(elements.modalConfirmDeleteUser);
        await loadUsers();
        updateMetrics();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to delete user: ${err.detail || err.message || res.statusText}`, 'error');
      }
    } catch {
      showToast('Error sending delete user request.', 'error');
    }
  });

  // 4. Revoke User Tokens & Sessions
  elements.btnExecuteRevoke.addEventListener('click', async () => {
    const id = elements.revokeTargetId.value;
    if (!id) return;

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(id)}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'Admin dashboard manual session revocation' })
      });

      if (res.ok) {
        showToast('All active user sessions revoked successfully!', 'success');
        closeModal(elements.modalConfirmRevoke);
        await loadUsers();
        updateMetrics();
      } else {
        showToast('Failed to revoke user sessions.', 'error');
      }
    } catch {
      showToast('Error sending session revocation request.', 'error');
    }
  });

  // 5. Create Business Role
  elements.formCreateRole.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('cr-name').value.trim();
    const description = document.getElementById('cr-desc').value.trim() || null;
    
    const selectedPerms = [];
    document.querySelectorAll('input[name="role_perms"]:checked').forEach(cb => {
      selectedPerms.push(cb.value);
    });

    const payload = {
      name,
      description,
      permissions: selectedPerms
    };

    try {
      const res = await apiFetch('/api/identity/business-roles', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        showToast(`Business role '${name}' created successfully in Keycloak!`, 'success');
        closeModal(elements.modalCreateRole);
        elements.formCreateRole.reset();
        await loadBusinessRoles();
        updateMetrics();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to create role: ${err.detail || err.message || 'Already exists'}`, 'error');
      }
    } catch {
      showToast('Error creating business role.', 'error');
    }
  });

  // 6. Create Attribute Scope (Inline Form directly on Scope page!)
  if (elements.inlineFormCreateScope) {
    elements.inlineFormCreateScope.addEventListener('submit', async (e) => {
      e.preventDefault();
      const key = document.getElementById('inline-cs-key').value.trim().toLowerCase();
      const displayName = document.getElementById('inline-cs-display').value.trim();
      const description = document.getElementById('inline-cs-desc').value.trim() || null;
      const targetResources = parseTargetResources(document.getElementById('inline-cs-resources')?.value);

      try {
        const res = await apiFetch('/api/identity/scopes', {
          method: 'POST',
          body: JSON.stringify({ key, displayName, description, targetResources })
        });

        if (res.ok) {
          showToast(state.lang === 'fa' ? `اسکوپ '${displayName}' (${key}) با موفقیت ثبت شد!` : `Scope '${displayName}' (${key}) registered successfully!`, 'success');
          elements.inlineFormCreateScope.reset();
          await loadScopes();
          updateMetrics();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast(`Failed to register scope: ${err.detail || err.message || 'Already exists'}`, 'error');
        }
      } catch {
        showToast('Error registering scope.', 'error');
      }
    });
  }

  // Fallback modal scope form
  if (elements.formCreateScope) {
    elements.formCreateScope.addEventListener('submit', async (e) => {
      e.preventDefault();
      const key = document.getElementById('cs-key').value.trim().toLowerCase();
      const displayName = document.getElementById('cs-display').value.trim();
      const description = document.getElementById('cs-desc').value.trim() || null;
      const targetResources = parseTargetResources(document.getElementById('cs-resources')?.value);

      try {
        const res = await apiFetch('/api/identity/scopes', {
          method: 'POST',
          body: JSON.stringify({ key, displayName, description, targetResources })
        });

        if (res.ok) {
          showToast(state.lang === 'fa' ? `اسکوپ '${key}' با موفقیت ثبت شد!` : `Scope '${key}' registered successfully!`, 'success');
          closeModal(elements.modalCreateScope);
          elements.formCreateScope.reset();
          await loadScopes();
          updateMetrics();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast(`Failed to register scope: ${err.detail || err.message || 'Already exists'}`, 'error');
        }
      } catch {
        showToast('Error registering scope.', 'error');
      }
    });
  }

  // 7. Edit Attribute Scope
  elements.formEditScope.addEventListener('submit', async (e) => {
    e.preventDefault();
    const key = document.getElementById('es-key').value;
    const displayName = document.getElementById('es-display').value.trim();
    const description = document.getElementById('es-desc').value.trim() || null;
    const isActive = document.getElementById('es-active').checked;
    const targetResources = parseTargetResources(document.getElementById('es-resources')?.value);

    try {
      const res = await apiFetch(`/api/identity/scopes/${encodeURIComponent(key)}`, {
        method: 'PUT',
        body: JSON.stringify({ displayName, description, isActive, targetResources })
      });

      if (res.ok) {
        showToast(state.lang === 'fa' ? `اسکوپ '${key}' با موفقیت بروزرسانی شد!` : `Scope '${key}' updated successfully!`, 'success');
        closeModal(elements.modalEditScope);
        await loadScopes();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Failed to update scope: ${err.detail || err.message || 'Error'}`, 'error');
      }
    } catch {
      showToast('Error updating scope.', 'error');
    }
  });

  // 7.1 Delete Attribute Scope
  if (elements.btnExecuteDeleteScope) {
    elements.btnExecuteDeleteScope.addEventListener('click', async () => {
      const key = elements.deleteScopeTargetKey.value;
      if (!key) return;

      try {
        const res = await apiFetch(`/api/identity/scopes/${encodeURIComponent(key)}`, {
          method: 'DELETE'
        });

        if (res.ok) {
          showToast(`Attribute scope '${key}' deleted successfully from registry.`, 'success');
          closeModal(elements.modalConfirmDeleteScope);
          await loadScopes();
          updateMetrics();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast(`Failed to delete scope: ${err.detail || err.message || 'Deletion error'}`, 'error');
        }
      } catch {
        showToast('Error sending delete scope request.', 'error');
      }
    });
  }

  // 7.2 Edit Business Role
  if (elements.formEditRole) {
    elements.formEditRole.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = elements.erName.value.trim();
      const description = elements.erDesc.value.trim() || null;
      const checkedBoxes = elements.erPermsSelector.querySelectorAll('input[name="edit_role_perms"]:checked');
      const permissions = Array.from(checkedBoxes).map(cb => cb.value);

      try {
        const res = await apiFetch(`/api/identity/business-roles/${encodeURIComponent(name)}`, {
          method: 'PUT',
          body: JSON.stringify({ description, permissions })
        });

        if (res.ok) {
          showToast(`Business role '${name}' updated successfully in Keycloak!`, 'success');
          closeModal(elements.modalEditRole);
          await loadBusinessRoles();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast(`Failed to update role: ${err.detail || err.message || 'Validation error'}`, 'error');
        }
      } catch {
        showToast('Error updating business role.', 'error');
      }
    });
  }

  // 7.3 Delete Business Role
  if (elements.btnExecuteDeleteRole) {
    elements.btnExecuteDeleteRole.addEventListener('click', async () => {
      const name = elements.deleteRoleName.value;
      if (!name) return;

      try {
        const res = await apiFetch(`/api/identity/business-roles/${encodeURIComponent(name)}`, {
          method: 'DELETE'
        });

        if (res.ok) {
          showToast(`Business role '${name}' deleted successfully from Keycloak!`, 'success');
          closeModal(elements.modalConfirmDeleteRole);
          await loadBusinessRoles();
          updateMetrics();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast(`Failed to delete role: ${err.detail || err.message || 'Role cannot be deleted while assigned to users.'}`, 'error');
        }
      } catch {
        showToast('Error deleting business role.', 'error');
      }
    });
  }

  // 7.4 Create Permission Manually
  if (elements.formCreatePermission) {
    elements.formCreatePermission.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = elements.cpName.value.trim();
      const description = elements.cpDesc.value.trim() || null;
      const serviceId = elements.cpService.value.trim() || null;

      try {
        const res = await apiFetch('/api/identity/permissions', {
          method: 'POST',
          body: JSON.stringify({ name, description, serviceId })
        });

        if (res.ok) {
          showToast(`Permission '${name}' registered successfully in Keycloak!`, 'success');
          closeModal(elements.modalCreatePermission);
          elements.formCreatePermission.reset();
          await loadPermissions();
          updateMetrics();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast(`Failed to register permission: ${err.detail || err.message || 'Validation error'}`, 'error');
        }
      } catch {
        showToast('Error registering permission.', 'error');
      }
    });
  }

  // 8. Token Playground
  elements.tokenMintForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = elements.tokenTestUsername.value.trim();
    const password = elements.tokenTestPassword.value;

    elements.tokenOutputConsole.textContent = 'Sending authentication request to Keycloak...';

    try {
      const form = new URLSearchParams();
      form.append('grant_type', 'password');
      form.append('client_id', 'identity-gateway');
      form.append('username', username);
      form.append('password', password);

      const res = await fetch('/api/identity/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });

      const body = await res.json();
      if (!res.ok) {
        elements.tokenOutputConsole.textContent = `// Error: ${(body.detail || body.message || body.error_description || 'Authentication failed')}\n` + JSON.stringify(body, null, 2);
        elements.btnTestMe.disabled = true;
        elements.btnTestContext.disabled = true;
        return;
      }

      const token = body.access_token || body.accessToken;
      let decodedPayload = {};
      try {
        const parts = token.split('.');
        if (parts.length === 3) {
          decodedPayload = JSON.parse(atob(parts[1]));
        }
      } catch { /* best effort */ }

      elements.tokenOutputConsole.textContent = 
        `// ================= Token Minted Successfully =================\n` +
        `Token Type: ${body.token_type || 'Bearer'}\n` +
        `Expires In: ${body.expires_in} seconds\n\n` +
        `// ================= Decoded JWT Claims & Scopes =================\n` +
        JSON.stringify(decodedPayload, null, 2);

      window._lastMintedTestToken = token;
      elements.btnTestMe.disabled = false;
      elements.btnTestContext.disabled = false;
      showToast(`Token minted successfully for user '${username}'.`, 'success');
    } catch (err) {
      elements.tokenOutputConsole.textContent = `// Network exception: ${err.message}`;
    }
  });

  elements.btnTestMe.addEventListener('click', async () => {
    if (!window._lastMintedTestToken) return;
    elements.tokenOutputConsole.textContent = 'Calling GET /api/identity/me with Bearer token...';
    try {
      const res = await fetch('/api/identity/me', {
        headers: { 'Authorization': `Bearer ${window._lastMintedTestToken}` }
      });
      const data = await res.json();
      elements.tokenOutputConsole.textContent = 
        `// Response: GET /api/identity/me [HTTP ${res.status}]\n` + JSON.stringify(data, null, 2);
    } catch (err) {
      elements.tokenOutputConsole.textContent = `// Error: ${err.message}`;
    }
  });

  elements.btnTestContext.addEventListener('click', async () => {
    if (!window._lastMintedTestToken) return;
    elements.tokenOutputConsole.textContent = 'Calling GET /api/identity/access-context with Bearer token...';
    try {
      const res = await fetch('/api/identity/access-context', {
        headers: { 'Authorization': `Bearer ${window._lastMintedTestToken}` }
      });
      const data = await res.json();
      elements.tokenOutputConsole.textContent = 
        `// Response: GET /api/identity/access-context [HTTP ${res.status}]\n` + JSON.stringify(data, null, 2);
    } catch (err) {
      elements.tokenOutputConsole.textContent = `// Error: ${err.message}`;
    }
  });

  // Login Form Submission
  elements.formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    const u = document.getElementById('login-username').value.trim();
    const p = document.getElementById('login-password').value;
    await handleLogin(u, p);
  });

  document.getElementById('login-username')?.addEventListener('input', hideLoginAlert);
  document.getElementById('login-password')?.addEventListener('input', hideLoginAlert);

  // ==========================================
  // Global Event Listeners & Navigation
  // ==========================================
  document.querySelectorAll('.nav-item[data-view]').forEach(item => {
    item.addEventListener('click', () => {
      const viewId = item.getAttribute('data-view');
      switchView(viewId);
    });
  });

  document.getElementById('btn-global-refresh').addEventListener('click', async () => {
    await refreshAllData();
    showToast('Data refreshed successfully from Keycloak.', 'info');
  });

  if (elements.btnRefreshScopes) {
    elements.btnRefreshScopes.addEventListener('click', async () => {
      await loadScopes();
      showToast('Scopes list refreshed.', 'info');
    });
  }

  document.getElementById('btn-logout').addEventListener('click', () => {
    promptLogin();
  });

  elements.userSearchInput.addEventListener('input', () => renderUsersTable());
  elements.userStatusFilter.addEventListener('change', () => renderUsersTable());
  elements.permSearchInput.addEventListener('input', () => renderPermissionsTable());

  // Quick Action Buttons
  const openCreateUserHandler = () => {
    populateRoleSelectors();
    renderScopeCheckboxes('cu-scopes-container', {});
    openModal(elements.modalCreateUser);
  };
  document.getElementById('btn-quick-create-user').addEventListener('click', openCreateUserHandler);
  document.getElementById('btn-open-create-user').addEventListener('click', openCreateUserHandler);

  if (elements.btnModalAddScope) {
    elements.btnModalAddScope.addEventListener('click', () => {
      openModal(elements.modalCreateScope);
    });
  }

  document.getElementById('btn-quick-create-role').addEventListener('click', () => {
    openModal(elements.modalCreateRole);
  });
  document.getElementById('btn-open-create-role').addEventListener('click', () => {
    openModal(elements.modalCreateRole);
  });
  document.getElementById('btn-quick-create-scope')?.addEventListener('click', () => {
    switchView('view-scopes');
    document.getElementById('inline-cs-key')?.focus();
  });
  document.getElementById('btn-quick-test-token').addEventListener('click', () => {
    switchView('view-token-test');
  });
  if (elements.btnOpenCreatePermission) {
    elements.btnOpenCreatePermission.addEventListener('click', () => {
      openModal(elements.modalCreatePermission);
    });
  }

  // Database Engine Info Modal
  if (elements.btnHeaderDb) {
    elements.btnHeaderDb.addEventListener('click', () => openModal(elements.modalDbInfo));
  }
  if (elements.btnSidebarDb) {
    elements.btnSidebarDb.addEventListener('click', () => openModal(elements.modalDbInfo));
  }
  if (elements.cardDbMetric) {
    elements.cardDbMetric.addEventListener('click', () => openModal(elements.modalDbInfo));
  }

  // Chip suggestions for Target Resources
  document.querySelectorAll('.chip-clickable[data-suggest]').forEach(btn => {
    btn.addEventListener('click', () => {
      const suggest = btn.getAttribute('data-suggest');
      const targetId = btn.getAttribute('data-target');
      const targetInput = document.getElementById(targetId);
      if (!targetInput) return;

      const current = parseTargetResources(targetInput.value);
      if (!current.includes(suggest)) {
        current.push(suggest);
        targetInput.value = current.join(', ');
      }
    });
  });

  // Header Quick Toggles
  if (elements.btnLangToggle) {
    elements.btnLangToggle.addEventListener('click', () => {
      const nextLang = state.lang === 'fa' ? 'en' : 'fa';
      applyLanguage(nextLang);
      showToast(state.lang === 'fa' ? 'زبان داشبورد به فارسی تغییر کرد' : 'Switched language to English', 'info');
    });
  }

  if (elements.btnThemeToggle) {
    elements.btnThemeToggle.addEventListener('click', () => {
      const nextTheme = state.theme === 'dark' ? 'light' : 'dark';
      applyTheme(nextTheme);
      const isDark = state.theme === 'dark';
      const msg = isDark
        ? (state.lang === 'fa' ? 'تم تیره (Dark) فعال شد' : 'Dark theme activated')
        : (state.lang === 'fa' ? 'تم روشن (Light) فعال شد' : 'Light theme activated');
      showToast(msg, 'info');
    });
  }

  // Settings Radio Listeners
  if (elements.radioLangFa) {
    elements.radioLangFa.addEventListener('change', () => {
      if (elements.radioLangFa.checked) {
        applyLanguage('fa');
        showToast('زبان داشبورد به فارسی تغییر کرد.', 'info');
      }
    });
  }
  if (elements.radioLangEn) {
    elements.radioLangEn.addEventListener('change', () => {
      if (elements.radioLangEn.checked) {
        applyLanguage('en');
        showToast('Switched language to English.', 'info');
      }
    });
  }

  if (elements.radioThemeDark) {
    elements.radioThemeDark.addEventListener('change', () => {
      if (elements.radioThemeDark.checked) {
        applyTheme('dark');
        showToast(state.lang === 'fa' ? 'تم دارک فعال شد.' : 'Dark theme activated.', 'info');
      }
    });
  }
  if (elements.radioThemeLight) {
    elements.radioThemeLight.addEventListener('change', () => {
      if (elements.radioThemeLight.checked) {
        applyTheme('light');
        showToast(state.lang === 'fa' ? 'تم روشن فعال شد.' : 'Light theme activated.', 'info');
      }
    });
  }

  if (elements.btnResetPreferences) {
    elements.btnResetPreferences.addEventListener('click', () => {
      applyLanguage('en');
      applyTheme('dark');
      showToast(state.lang === 'fa' ? 'تنظیمات به حالت پیش‌فرض (انگلیسی و تم دارک) بازنشانی شدند.' : 'Preferences reset to defaults (English / Dark).', 'success');
    });
  }

  // Auto-refresh online statuses every 20 seconds
  state.refreshInterval = setInterval(() => {
    if (state.token && state.currentView === 'view-users') {
      loadUsers();
      updateMetrics();
    }
  }, 20000);

  // App Startup
  window.addEventListener('DOMContentLoaded', async () => {
    applyLanguage(state.lang);
    applyTheme(state.theme);
    await loadDatabaseInfo();
    if (!state.token) {
      promptLogin();
    } else {
      await loadCurrentUserProfile();
      await refreshAllData();
    }
  });

})();
