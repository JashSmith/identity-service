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
    statPermissions: document.getElementById('stat-permissions'),

    // Users View
    usersTableBody: document.getElementById('users-table-body'),
    userSearchInput: document.getElementById('user-search-input'),
    userStatusFilter: document.getElementById('user-status-filter'),

    // Roles View
    businessRolesGrid: document.getElementById('business-roles-grid'),

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
    modalEditUser: document.getElementById('modal-edit-user'),
    formEditUser: document.getElementById('form-edit-user'),
    modalCreateRole: document.getElementById('modal-create-role'),
    formCreateRole: document.getElementById('form-create-role'),
    modalConfirmRevoke: document.getElementById('modal-confirm-revoke'),
    revokeTargetId: document.getElementById('revoke-target-id'),
    revokeTargetUsername: document.getElementById('revoke-target-username'),
    btnExecuteRevoke: document.getElementById('btn-execute-revoke'),
    toastContainer: document.getElementById('toast-container')
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

    try {
      const response = await fetch(url, { ...options, headers });
      if (response.status === 401) {
        showToast('Authentication required or session expired. Please sign in.', 'error');
        promptLogin();
        throw new Error('Unauthorized');
      }
      return response;
    } catch (err) {
      if (err.message !== 'Unauthorized') {
        console.error('API Fetch Error:', err);
      }
      throw err;
    }
  }

  // ==========================================
  // Toast Notifications
  // ==========================================
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    } else {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
    }

    toast.innerHTML = `${iconSvg} <span>${escapeHtml(message)}</span>`;
    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
  }

  // ==========================================
  // Modal Utilities (Native Dialog + Light-Dismiss Fallback)
  // ==========================================
  function openModal(modal) {
    if (modal && typeof modal.showModal === 'function') {
      modal.showModal();
    }
  }

  function closeModal(modal) {
    if (modal && typeof modal.close === 'function') {
      modal.close();
    }
  }

  // Setup Light-Dismiss Fallback for modern dialogs
  document.querySelectorAll('dialog').forEach(dialog => {
    // Light-dismiss click outside fallback
    dialog.addEventListener('click', (event) => {
      if (dialog.getAttribute('closedby') === 'none') return;
      if (event.target !== dialog) return;

      const rect = dialog.getBoundingClientRect();
      const isContent = (
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width
      );

      if (!isContent) {
        dialog.close();
      }
    });

    // Close buttons inside dialog
    dialog.querySelectorAll('[data-close-modal]').forEach(btn => {
      btn.addEventListener('click', () => dialog.close());
    });
  });

  // ==========================================
  // Authentication & Session
  // ==========================================
  function promptLogin() {
    state.token = '';
    sessionStorage.removeItem('identity_admin_token');
    openModal(elements.modalLogin);
  }

  async function handleLogin(username, password) {
    try {
      const form = new URLSearchParams();
      form.append('grant_type', 'password');
      form.append('client_id', 'admin-cli');
      form.append('username', username);
      form.append('password', password);

      const res = await fetch('/api/identity/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });

      if (!res.ok) {
        const errText = await res.text();
        showToast(`Login failed: Invalid credentials or rejected by Keycloak`, 'error');
        return false;
      }

      const data = await res.json();
      state.token = data.access_token || data.accessToken;
      sessionStorage.setItem('identity_admin_token', state.token);

      closeModal(elements.modalLogin);
      showToast(`Welcome back, ${username}! Authenticated successfully.`, 'success');
      
      await loadCurrentUserProfile();
      await refreshAllData();
      return true;
    } catch (err) {
      showToast('Network error contacting Identity Service', 'error');
      return false;
    }
  }

  async function loadCurrentUserProfile() {
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

    // Update Heading
    const titles = {
      'view-overview': 'Dashboard Overview',
      'view-users': 'Users & Session Management',
      'view-roles': 'Business Roles (نقش‌های کسب‌وکاری)',
      'view-permissions': 'Platform Permissions Catalog',
      'view-token-test': 'Token Minting & Service Verification'
    };
    elements.pageHeading.textContent = titles[viewId] || 'Identity Management';
  }

  // ==========================================
  // Data Loaders
  // ==========================================
  async function refreshAllData() {
    await Promise.all([
      loadUsers(),
      loadBusinessRoles(),
      loadPermissions()
    ]);
    updateMetrics();
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
        (u.attributes && Object.values(u.attributes).flat().some(v => v.toLowerCase().includes(search)));

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
        ? `<span class="badge badge-online"><span class="badge-dot"></span> Online (${sessionCount} ${sessionCount === 1 ? 'session' : 'sessions'})</span>`
        : `<span class="badge badge-offline"><span class="badge-dot"></span> Offline</span>`;

      // Business role & scope badges
      const roles = (u.attributes && u.attributes['iam.business_role']) || [];
      const rolesHtml = roles.map(r => `<span class="badge badge-role">${escapeHtml(r)}</span>`).join(' ');

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
          <td>${escapeHtml(u.displayName || '-')}</td>
          <td>${statusBadge}</td>
          <td>${rolesHtml || '<span style="color: var(--text-faint); font-size: 0.8rem;">(No Role Assigned)</span>'}</td>
          <td style="text-align: right;">
            <div style="display: flex; gap: 8px; justify-content: flex-end;">
              <button class="btn btn-sm btn-secondary btn-edit-user" data-user='${JSON.stringify(u)}' title="Edit user profile">
                Edit
              </button>
              <button class="btn btn-sm btn-outline-danger btn-revoke-tokens" data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}" title="Revoke all active tokens & sessions in Keycloak">
                Revoke Tokens
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach Event Listeners to Action Buttons
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
      const permPills = perms.slice(0, 8).map(p => `<span class="perm-pill">${escapeHtml(p)}</span>`).join('');
      const moreCount = perms.length > 8 ? `<span class="perm-pill">+${perms.length - 8} more</span>` : '';

      return `
        <div class="business-role-card">
          <div class="role-card-header">
            <div>
              <div class="role-name">${escapeHtml(r.name)}</div>
              <div class="role-desc">${escapeHtml(r.description || 'Custom composite business role')}</div>
            </div>
            <span class="badge badge-role">${perms.length} Permissions</span>
          </div>

          <div style="font-size: 0.78rem; font-weight: 600; color: var(--text-faint);">Effective Permissions:</div>
          <div class="role-perms-list">
            ${permPills || '<span style="color: var(--text-faint); font-size: 0.8rem;">(No permissions added yet)</span>'}
            ${moreCount}
          </div>

          <div class="role-card-footer">
            <button class="btn btn-sm btn-outline-danger btn-delete-role" data-role-name="${escapeHtml(r.name)}">
              Delete
            </button>
            <span style="font-size: 0.75rem; color: var(--text-faint);">Keycloak Composite Group</span>
          </div>
        </div>
      `;
    }).join('');

    elements.businessRolesGrid.querySelectorAll('.btn-delete-role').forEach(btn => {
      btn.addEventListener('click', async () => {
        const name = btn.getAttribute('data-role-name');
        if (confirm(`Are you sure you want to delete business role '${name}'?`)) {
          try {
            const res = await apiFetch(`/api/identity/business-roles/${encodeURIComponent(name)}`, { method: 'DELETE' });
            if (res.ok) {
              showToast(`Business role '${name}' deleted successfully.`, 'success');
              await loadBusinessRoles();
              updateMetrics();
            } else {
              showToast(`Failed to delete role '${name}'.`, 'error');
            }
          } catch {
            showToast('Error deleting business role.', 'error');
          }
        }
      });
    });
  }

  function populateRoleSelectors() {
    const cuRoleSelect = document.getElementById('cu-role-select');
    if (!cuRoleSelect) return;
    
    let options = '<option value="">(None - Assign Later)</option>';
    state.roles.forEach(r => {
      options += `<option value="${escapeHtml(r.name)}">${escapeHtml(r.name)}</option>`;
    });
    cuRoleSelect.innerHTML = options;

    // Populate permissions selector in create role modal
    const permsSelector = document.getElementById('cr-perms-selector');
    if (permsSelector && state.permissions.length > 0) {
      permsSelector.innerHTML = state.permissions.map(p => `
        <label class="checkbox-label" style="font-size: 0.82rem;">
          <input type="checkbox" name="role_perms" value="${escapeHtml(p.name)}">
          <span><strong>${escapeHtml(p.name)}</strong> - <small style="color: var(--text-faint);">${escapeHtml(p.description)}</small></span>
        </label>
      `).join('');
    }
  }

  // 3. Permissions Loader
  async function loadPermissions() {
    try {
      const res = await apiFetch('/api/identity/permissions');
      if (res.ok) {
        state.permissions = await res.json();
        renderPermissionsTable();
        populateRoleSelectors();
      }
    } catch {
      elements.permissionsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger); padding: 24px;">Failed to load permissions catalog.</td></tr>`;
    }
  }

  function renderPermissionsTable() {
    const search = (elements.permSearchInput.value || '').toLowerCase().trim();
    let filtered = state.permissions.filter(p => !search || p.name.toLowerCase().includes(search) || p.description.toLowerCase().includes(search));

    if (filtered.length === 0) {
      elements.permissionsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-faint); padding: 32px;">No permissions found matching search.</td></tr>`;
      return;
    }

    elements.permissionsTableBody.innerHTML = filtered.map(p => `
      <tr>
        <td style="font-weight: 600; color: #a5b4fc;">${escapeHtml(p.name)}</td>
        <td>${escapeHtml(p.description || '-')}</td>
        <td><span class="badge badge-scope">${escapeHtml(p.serviceId || 'system')}</span></td>
        <td style="color: var(--text-faint); font-family: monospace;">${escapeHtml(p.serviceVersion || '1.0')}</td>
        <td>
          ${p.deprecated 
            ? '<span class="badge" style="background: rgba(244,63,94,0.12); color: var(--danger);">Deprecated</span>' 
            : '<span class="badge badge-online"><span class="badge-dot"></span> Active</span>'}
        </td>
      </tr>
    `).join('');
  }

  // 4. Metrics Updater
  function updateMetrics() {
    const total = state.users.length;
    const online = state.users.filter(u => !!u.isOnline).length;
    elements.statTotalUsers.textContent = total;
    elements.statOnlineUsers.textContent = online;
    elements.statBusinessRoles.textContent = state.roles.length;
    elements.statPermissions.textContent = state.permissions.length;
    elements.onlineUsersBadge.textContent = `${online} Online`;
  }

  // ==========================================
  // Form Submission Handlers
  // ==========================================

  // 1. Create User
  elements.formCreateUser.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('cu-username').value.trim();
    const email = document.getElementById('cu-email').value.trim() || null;
    const firstName = document.getElementById('cu-firstname').value.trim() || null;
    const lastName = document.getElementById('cu-lastname').value.trim() || null;
    const password = document.getElementById('cu-password').value;
    const temporary = document.getElementById('cu-temporary').checked;
    const role = document.getElementById('cu-role-select').value;
    const scopeCity = document.getElementById('cu-scope-city').value.trim();

    const assignments = [];
    if (role) {
      const scopes = {};
      if (scopeCity) {
        scopes['city'] = [scopeCity];
      }
      assignments.push({ role, scopes });
    }

    const payload = {
      username,
      email,
      firstName,
      lastName,
      enabled: true,
      credentials: { password, temporary },
      assignments: assignments.length > 0 ? assignments : null
    };

    try {
      const res = await apiFetch('/api/identity/users', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        showToast(`User '${username}' created in Keycloak successfully!`, 'success');
        closeModal(elements.modalCreateUser);
        elements.formCreateUser.reset();
        await loadUsers();
        updateMetrics();
      } else {
        const err = await res.json();
        showToast(`Creation failed: ${err.message || 'Validation error'}`, 'error');
      }
    } catch {
      showToast('Error sending user creation request', 'error');
    }
  });

  // 2. Edit User
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
        showToast('User profile updated successfully.', 'success');
        closeModal(elements.modalEditUser);
        await loadUsers();
      } else {
        showToast('Failed to update user profile.', 'error');
      }
    } catch {
      showToast('Error updating user', 'error');
    }
  });

  // 3. Revoke Tokens
  elements.btnExecuteRevoke.addEventListener('click', async () => {
    const id = elements.revokeTargetId.value;
    const username = elements.revokeTargetUsername.textContent;

    try {
      const res = await apiFetch(`/api/identity/users/${encodeURIComponent(id)}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'Admin dashboard forced session logout & token revocation' })
      });

      if (res.ok) {
        const result = await res.json();
        showToast(`Tokens and sessions revoked for '${username}'. User must log in again.`, 'success');
        closeModal(elements.modalConfirmRevoke);
        await loadUsers();
        updateMetrics();
      } else {
        showToast('Failed to revoke user tokens.', 'error');
      }
    } catch {
      showToast('Error executing token revocation.', 'error');
    }
  });

  // 4. Create Business Role
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
        showToast(`Business role '${name}' created successfully!`, 'success');
        closeModal(elements.modalCreateRole);
        elements.formCreateRole.reset();
        await loadBusinessRoles();
        updateMetrics();
      } else {
        const err = await res.json();
        showToast(`Role creation error: ${err.message || 'Already exists'}`, 'error');
      }
    } catch {
      showToast('Error creating business role.', 'error');
    }
  });

  // 5. Token Playground
  elements.tokenMintForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = elements.tokenTestUsername.value.trim();
    const password = elements.tokenTestPassword.value;

    elements.tokenOutputConsole.textContent = 'Authenticating against Keycloak token proxy...';

    try {
      const form = new URLSearchParams();
      form.append('grant_type', 'password');
      form.append('client_id', 'identity-facade');
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
      // Decode JWT payload
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

      // Store test token for live testing buttons
      window._lastMintedTestToken = token;
      elements.btnTestMe.disabled = false;
      elements.btnTestContext.disabled = false;
      showToast(`Token generated for user '${username}'`, 'success');
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

  // ==========================================
  // Global Event Listeners & Initialization
  // ==========================================
  document.querySelectorAll('.nav-item[data-view]').forEach(item => {
    item.addEventListener('click', () => {
      const viewId = item.getAttribute('data-view');
      switchView(viewId);
    });
  });

  document.getElementById('btn-global-refresh').addEventListener('click', async () => {
    await refreshAllData();
    showToast('Data refreshed from Keycloak.', 'info');
  });

  document.getElementById('btn-logout').addEventListener('click', () => {
    promptLogin();
  });

  elements.userSearchInput.addEventListener('input', () => renderUsersTable());
  elements.userStatusFilter.addEventListener('change', () => renderUsersTable());
  elements.permSearchInput.addEventListener('input', () => renderPermissionsTable());

  // Quick Action Buttons
  document.getElementById('btn-quick-create-user').addEventListener('click', () => {
    openModal(elements.modalCreateUser);
  });
  document.getElementById('btn-open-create-user').addEventListener('click', () => {
    openModal(elements.modalCreateUser);
  });
  document.getElementById('btn-quick-create-role').addEventListener('click', () => {
    openModal(elements.modalCreateRole);
  });
  document.getElementById('btn-open-create-role').addEventListener('click', () => {
    openModal(elements.modalCreateRole);
  });
  document.getElementById('btn-quick-test-token').addEventListener('click', () => {
    switchView('view-token-test');
  });

  // Auto-refresh online statuses every 15 seconds
  state.refreshInterval = setInterval(() => {
    if (state.token && state.currentView === 'view-users') {
      loadUsers();
      updateMetrics();
    }
  }, 15000);

  // App Startup
  window.addEventListener('DOMContentLoaded', async () => {
    if (!state.token) {
      promptLogin();
    } else {
      await loadCurrentUserProfile();
      await refreshAllData();
    }
  });

})();
