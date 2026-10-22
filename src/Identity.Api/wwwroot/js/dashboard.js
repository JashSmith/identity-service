/**
 * Identity Service Dashboard - Interactive Logic
 * Single Page Application for Keycloak Facade Administration
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
    refreshInterval: null
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
    toastContainer: document.getElementById('toast-container'),
    loginAlert: document.getElementById('login-alert'),
    loginAlertMsg: document.getElementById('login-alert-msg')
  };

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
      form.append('client_id', 'identity-facade');
      form.append('client_secret', 'facade-development-only');
      form.append('username', username);
      form.append('password', password);

      const res = await fetch('/api/identity/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });

      const body = await res.json();
      if (!res.ok) {
        showLoginAlert(body.message || body.error_description || 'Sign in failed: invalid credentials');
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
      'view-overview': 'Overview (داشبورد مدیریت)',
      'view-users': 'Users & Scoped Access (مدیریت کاربران و اسکوپ‌ها)',
      'view-roles': 'Business Roles (نقش‌های کسب‌وکاری)',
      'view-scopes': 'Attribute Scope Registry (ساخت و مدیریت Scopeها)',
      'view-permissions': 'Platform Permissions Catalog (دسترسی‌ها)',
      'view-token-test': 'Token Playground & Access Verification'
    };
    elements.pageHeading.textContent = titles[viewId] || 'Identity Management';
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
    try {
      const res = await fetch('/api/system/database-info');
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
      const res = await apiFetch('/api/identity/users?page=1&pageSize=100');
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
      elements.usersTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-faint); padding: 32px;">No matching users found.</td></tr>`;
      return;
    }

    elements.usersTableBody.innerHTML = filtered.map(u => {
      const isOnline = !!u.isOnline;
      const sessionCount = u.activeSessionsCount || (isOnline ? 1 : 0);
      const statusBadge = isOnline
        ? `<span class="badge badge-online"><span class="badge-dot"></span> Online (${sessionCount})</span>`
        : `<span class="badge badge-offline"><span class="badge-dot"></span> Offline</span>`;

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
        : `<span style="color: var(--text-faint); font-size: 0.78rem;">(بدون نقش)</span>`;

      const scopesHtml = scopesDisplay.length > 0
        ? `<div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 5px;">${scopesDisplay.join('')}</div>`
        : `<div style="color: var(--text-faint); font-size: 0.75rem; margin-top: 3px;">بدون محدودیت Scope</div>`;

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
            <div style="display: flex; gap: 6px; justify-content: flex-end;">
              <button class="btn btn-sm btn-primary btn-manage-scopes" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="مدیریت نقش و محدودیت‌های Scope">
                نقش و Scopeها
              </button>
              <button class="btn btn-sm btn-secondary btn-edit-user" data-user='${JSON.stringify(u)}' title="ویرایش پروفایل">
                ویرایش
              </button>
              <button class="btn btn-sm btn-ghost btn-revoke-tokens" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="ابطال نشست‌ها">
                ابطال
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

    elements.usersTableBody.querySelectorAll('.btn-revoke-tokens').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const username = btn.getAttribute('data-username');
        elements.revokeTargetId.value = id;
        elements.revokeTargetUsername.textContent = username;
        openModal(elements.modalConfirmRevoke);
      });
    });

    elements.usersTableBody.querySelectorAll('.btn-edit-user').forEach(btn => {
      btn.addEventListener('click', () => {
        const user = JSON.parse(btn.getAttribute('data-user'));
        document.getElementById('eu-id').value = user.id;
        document.getElementById('eu-email').value = (user.attributes && user.attributes.email ? user.attributes.email[0] : '') || '';
        document.getElementById('eu-firstname').value = (user.attributes && user.attributes.firstName ? user.attributes.firstName[0] : '') || '';
        document.getElementById('eu-lastname').value = (user.attributes && user.attributes.lastName ? user.attributes.lastName[0] : '') || '';
        document.getElementById('eu-enabled').checked = !!user.enabled;
        openModal(elements.modalEditUser);
      });
    });
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
          No business roles registered yet. Create one like 'Manager' (مدیر) or 'Accountant' (حسابدار).
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
        </div>
      `;
    }).join('');
  }

  function populateRoleSelectors() {
    const options = [
      '<option value="">(انتخاب نقش کاربری)</option>',
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
      elements.scopesTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-faint); padding: 32px;">هیچ اسکوپی در سیستم ثبت نشده است. از فرم بالا برای ساخت اسکوپ استفاده کنید.</td></tr>`;
      return;
    }

    elements.scopesTableBody.innerHTML = state.scopes.map(s => {
      const boundRes = (state.resources || [])
        .filter(r => r.scopes && r.scopes.some(sc => sc.toLowerCase() === s.key.toLowerCase()))
        .map(r => `<span class="badge" style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; font-size: 0.72rem;">${escapeHtml(r.key)}</span>`)
        .join(' ');

      const statusBadge = s.isActive
        ? `<span class="badge badge-online"><span class="badge-dot"></span> Active (فعال)</span>`
        : `<span class="badge badge-offline"><span class="badge-dot"></span> Inactive (غیرفعال)</span>`;

      return `
        <tr>
          <td><span class="scope-chip">${escapeHtml(s.key)}</span></td>
          <td style="font-weight: 600; color: var(--text-main);">${escapeHtml(s.displayName || s.key)}</td>
          <td style="color: var(--text-muted); font-size: 0.85rem;">${escapeHtml(s.description || '-')}</td>
          <td>${boundRes || '<span style="color: var(--text-faint); font-size: 0.78rem;">(Unbound)</span>'}</td>
          <td>${statusBadge}</td>
          <td style="text-align: right;">
            <div style="display: flex; gap: 6px; justify-content: flex-end;">
              <button class="btn btn-sm btn-secondary btn-edit-scope" data-scope='${JSON.stringify(s)}'>
                ویرایش
              </button>
              <button class="btn btn-sm btn-ghost btn-toggle-scope" data-key="${escapeHtml(s.key)}" data-active="${!!s.isActive}">
                ${s.isActive ? 'غیرفعال‌سازی' : 'فعال‌سازی'}
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
        openModal(elements.modalEditScope);
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
            showToast(`اسکوپ '${key}' ${!currentActive ? 'فعال' : 'غیرفعال'} شد.`, 'success');
            await loadScopes();
          } else {
            showToast('خطا در تغییر وضعیت اسکوپ.', 'error');
          }
        } catch {
          showToast('خطای شبکه در تغییر وضعیت اسکوپ.', 'error');
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
          هنوز هیچ اسکوپی در سیستم تعریف نشده است. از بخش "ساخت Scope جدید" اسکوپ بسازید.
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
              مقدار / Value مجاز برای این کاربر:
            </label>
            <input type="text" class="form-control scope-values-input"
              data-scope-input="${escapeHtml(s.key)}"
              value="${escapeHtml(initialValues)}"
              placeholder="مثال: tehran-1 یا مقادیر با کاما: tehran-1, tehran-2"
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
      elements.permissionsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger); padding: 24px;">Failed to load permissions catalog.</td></tr>`;
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
      elements.permissionsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-faint); padding: 32px;">No matching permissions found.</td></tr>`;
      return;
    }

    elements.permissionsTableBody.innerHTML = filtered.map(p => `
      <tr>
        <td style="font-family: monospace; font-weight: 600; color: #38bdf8;">${escapeHtml(p.name)}</td>
        <td>${escapeHtml(p.description || '-')}</td>
        <td><span class="badge" style="background: rgba(168,85,247,0.15); color: #c084fc;">${escapeHtml(p.declaringService)}</span></td>
        <td>v${escapeHtml(p.version || '1')}</td>
        <td><span class="badge badge-online"><span class="badge-dot"></span> Active</span></td>
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
      showToast(`لطفاً برای اسکوپ تیک‌خورده '${missingValueKey}' مقدار (Value) وارد کنید.`, 'warning');
      return;
    }

    const hasScopes = Object.keys(scopes).length > 0;
    if (hasScopes && !role) {
      showToast('برای تخصیص اسکوپ به کاربر، انتخاب "نقش سازمانی" الزامی است.', 'warning');
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
        showToast(`کاربر '${username}' با موفقیت در Keycloak ایجاد و اسکوپ‌ها ثبت شد!`, 'success');
        closeModal(elements.modalCreateUser);
        elements.formCreateUser.reset();
        await loadUsers();
        updateMetrics();
      } else {
        const err = await res.json();
        showToast(`خطا در ایجاد کاربر: ${err.message || 'Validation error'}`, 'error');
      }
    } catch {
      showToast('خطا در ارسال درخواست ایجاد کاربر.', 'error');
    }
  });

  // 2. Manage Existing User Role & Scopes
  elements.formUserScopes.addEventListener('submit', async (e) => {
    e.preventDefault();
    const userId = elements.usUserId.value;
    const role = elements.usRoleSelect.value;
    if (!role) {
      showToast('لطفاً نقش سازمانی کاربر را انتخاب کنید.', 'warning');
      return;
    }

    const { scopes, missingValueKey } = getScopesFromContainer('us-scopes-container');
    if (missingValueKey) {
      showToast(`لطفاً برای اسکوپ تیک‌خورده '${missingValueKey}' مقدار وارد کنید.`, 'warning');
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
        showToast('نقش و اسکوپ‌های کاربر با موفقیت در Keycloak ذخیره شد!', 'success');
        closeModal(elements.modalUserScopes);
        await loadUsers();
      } else {
        const err = await res.json();
        showToast(`خطا در بروزرسانی اسکوپ‌ها: ${err.message || 'Validation error'}`, 'error');
      }
    } catch {
      showToast('خطا در بروزرسانی اسکوپ‌های کاربر.', 'error');
    }
  });

  // 3. Edit User Profile
  elements.formEditUser.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('eu-id').value;
    const email = document.getElementById('eu-email').value.trim() || null;
    const firstName = document.getElementById('eu-firstname').value.trim() || null;
    const lastName = document.getElementById('eu-lastname').value.trim() || null;
    const enabled = document.getElementById('eu-enabled').checked;

    const payload = { email, firstName, lastName, enabled };

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        showToast('مشخصات کاربر با موفقیت ذخیره شد!', 'success');
        closeModal(elements.modalEditUser);
        await loadUsers();
      } else {
        const err = await res.json();
        showToast(`خطا: ${err.message || 'Update failed'}`, 'error');
      }
    } catch {
      showToast('خطا در ویرایش مشخصات کاربر.', 'error');
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
        showToast(`تمامی نشست‌ها و توکن‌های کاربر با موفقیت ابطال شد!`, 'success');
        closeModal(elements.modalConfirmRevoke);
        await loadUsers();
        updateMetrics();
      } else {
        showToast('خطا در ابطال نشست‌های کاربر.', 'error');
      }
    } catch {
      showToast('خطا در ارسال درخواست ابطال.', 'error');
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
        showToast(`نقش '${name}' با موفقیت در Keycloak ایجاد شد!`, 'success');
        closeModal(elements.modalCreateRole);
        elements.formCreateRole.reset();
        await loadBusinessRoles();
        updateMetrics();
      } else {
        const err = await res.json();
        showToast(`خطا در ایجاد نقش: ${err.message || 'Already exists'}`, 'error');
      }
    } catch {
      showToast('خطا در ارتباط با سرور.', 'error');
    }
  });

  // 6. Create Attribute Scope (Inline Form directly on Scope page!)
  if (elements.inlineFormCreateScope) {
    elements.inlineFormCreateScope.addEventListener('submit', async (e) => {
      e.preventDefault();
      const key = document.getElementById('inline-cs-key').value.trim().toLowerCase();
      const displayName = document.getElementById('inline-cs-display').value.trim();
      const description = document.getElementById('inline-cs-desc').value.trim() || null;

      try {
        const res = await apiFetch('/api/identity/scopes', {
          method: 'POST',
          body: JSON.stringify({ key, displayName, description })
        });

        if (res.ok) {
          showToast(`اسکوپ جدید '${displayName}' (${key}) با موفقیت ثبت شد!`, 'success');
          elements.inlineFormCreateScope.reset();
          await loadScopes();
          updateMetrics();
        } else {
          const err = await res.json();
          showToast(`خطا در ساخت اسکوپ: ${err.message || 'Already exists'}`, 'error');
        }
      } catch {
        showToast('خطا در ثبت اسکوپ.', 'error');
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

      try {
        const res = await apiFetch('/api/identity/scopes', {
          method: 'POST',
          body: JSON.stringify({ key, displayName, description })
        });

        if (res.ok) {
          showToast(`اسکوپ '${key}' با موفقیت ساخته شد!`, 'success');
          closeModal(elements.modalCreateScope);
          elements.formCreateScope.reset();
          await loadScopes();
          updateMetrics();
        } else {
          const err = await res.json();
          showToast(`خطا: ${err.message || 'Already exists'}`, 'error');
        }
      } catch {
        showToast('خطا در ایجاد اسکوپ.', 'error');
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

    try {
      const res = await apiFetch(`/api/identity/scopes/${encodeURIComponent(key)}`, {
        method: 'PUT',
        body: JSON.stringify({ displayName, description, isActive })
      });

      if (res.ok) {
        showToast(`اسکوپ '${key}' با موفقیت بروزرسانی شد!`, 'success');
        closeModal(elements.modalEditScope);
        await loadScopes();
      } else {
        const err = await res.json();
        showToast(`خطا: ${err.message || 'Error'}`, 'error');
      }
    } catch {
      showToast('خطا در بروزرسانی اسکوپ.', 'error');
    }
  });

  // 8. Token Playground
  elements.tokenMintForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = elements.tokenTestUsername.value.trim();
    const password = elements.tokenTestPassword.value;

    elements.tokenOutputConsole.textContent = 'در حال ارسال درخواست به Keycloak...';

    try {
      const form = new URLSearchParams();
      form.append('grant_type', 'password');
      form.append('client_id', 'identity-facade');
      form.append('client_secret', 'facade-development-only');
      form.append('username', username);
      form.append('password', password);

      const res = await fetch('/api/identity/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });

      const body = await res.json();
      if (!res.ok) {
        elements.tokenOutputConsole.textContent = `// Error: ${(body.message || body.error_description || 'Authentication failed')}\n` + JSON.stringify(body, null, 2);
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
      showToast(`توکن برای کاربر '${username}' با موفقیت صادر شد.`, 'success');
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
    showToast('اطلاعات با موفقیت از Keycloak بروزرسانی شد.', 'info');
  });

  if (elements.btnRefreshScopes) {
    elements.btnRefreshScopes.addEventListener('click', async () => {
      await loadScopes();
      showToast('لیست اسکوپ‌ها بروزرسانی شد.', 'info');
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

  // Auto-refresh online statuses every 20 seconds
  state.refreshInterval = setInterval(() => {
    if (state.token && state.currentView === 'view-users') {
      loadUsers();
      updateMetrics();
    }
  }, 20000);

  // App Startup
  window.addEventListener('DOMContentLoaded', async () => {
    await loadDatabaseInfo();
    if (!state.token) {
      promptLogin();
    } else {
      await loadCurrentUserProfile();
      await refreshAllData();
    }
  });

})();
