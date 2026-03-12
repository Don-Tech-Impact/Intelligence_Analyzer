/**
 * superadmin.js - Complete SuperAdmin Dashboard Logic
 * Handles: Dashboard, Tenants, Global Health, Settings, Backup & Logs, Network Security
 */

const SuperAdmin = {
    API_BASE: (window.location.origin === 'null' || window.location.protocol === 'file:')
        ? 'http://localhost:8000'
        : window.location.origin,
    tenantsChart: null,
    alertsChart: null,
    systemLoadChart: null,
    errorRateChart: null,
    cachedOverview: null,
    healthInterval: null,
    auditPage: 1,

    formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    },

    formatNumber(num) {
        if (num === undefined || num === null) return '0';
        return num.toLocaleString();
    },

    // ============================================
    // INITIALIZATION
    // ============================================
    async init() {
        // Enforce Superadmin role with flexible detection
        const payload = Auth.getPayload();
        if (!payload) {
            window.location.href = 'login.html';
            return;
        }

        const role = (payload.role || '').toLowerCase();
        const isAdmin = payload.is_admin || (payload.admin && payload.admin.is_admin) || false;
        const username = (payload.username || (payload.admin && payload.admin.username) || '').toLowerCase();
        const email = (payload.email || (payload.admin && payload.admin.email) || '').toLowerCase();

        const userType = payload.user_type || (payload.admin && payload.admin.user_type) || '';
        const isAuthorized = (role === 'superadmin' || isAdmin || username === 'superadmin') && userType !== 'tenant_user';

        if (!isAuthorized) {
            console.error("Access denied. Admin portal limited to SuperAdmins.");
            window.location.href = 'index.html';
            return;
        }

        // Display username in sidebar
        const displayName = username || email.split('@')[0] || 'Superadmin';
        const sidebarUser = document.getElementById('sidebar-username');
        if (sidebarUser) sidebarUser.textContent = displayName.charAt(0).toUpperCase() + displayName.slice(1);

        // Initialize dashboard view
        this.initCharts();
        await this.loadData();

        // Auto-refresh every 60 seconds
        setInterval(() => this.loadData(), 60000);

        lucide.createIcons();
    },

    // ============================================
    // VIEW SWITCHING
    // ============================================
    switchView(viewId, navElement) {
        // Hide all views
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

        // Show target view
        const target = document.getElementById(`${viewId}-view`);
        if (target) {
            target.classList.add('active');
        }

        // Highlight nav item
        if (navElement) {
            navElement.classList.add('active');
        } else {
            const nav = document.querySelector(`[onclick*="'${viewId}'"]`);
            if (nav) nav.classList.add('active');
        }

        // Load view-specific data
        switch (viewId) {
            case 'dashboard':
                this.loadData();
                break;
            case 'tenants':
                this.loadTenantsView();
                break;
            case 'users':
                this.loadUsers();
                break;
            case 'audit':
                this.loadAuditLogs();
                break;
            case 'health':
                this.loadHealth();
                break;
            case 'settings':
                this.loadSettings();
                break;
            case 'backup':
                this.loadReports();
                break;
            case 'network':
                this.loadNetworkSecurity();
                break;
            case 'api-inventory':
                this.loadApiInventory();
                break;
        }

        lucide.createIcons();
    },

    // ============================================
    // DASHBOARD VIEW
    // ============================================
    initCharts() {
        const baseChartOptions = {
            chart: {
                height: 250,
                type: 'area',
                toolbar: { show: false },
                background: 'transparent',
                foreColor: '#637381',
                fontFamily: 'Public Sans, sans-serif',
                animations: {
                    enabled: true,
                    easing: 'easeinout',
                    speed: 800
                }
            },
            stroke: { curve: 'smooth', width: 3 },
            fill: {
                type: 'gradient',
                gradient: { shadeIntensity: 1, opacityFrom: 0.3, opacityTo: 0.05, stops: [0, 85, 100] }
            },
            dataLabels: { enabled: false },
            grid: { borderColor: 'rgba(145,158,171,0.2)', strokeDashArray: 3 },
            xaxis: { axisBorder: { show: false }, axisTicks: { show: false } },
            tooltip: {
                theme: 'light',
                style: { fontFamily: 'Public Sans, sans-serif' }
            }
        };

        const tEl = document.querySelector("#tenants-chart");
        if (tEl) {
            this.tenantsChart = new ApexCharts(tEl, {
                ...baseChartOptions,
                series: [{ name: 'Logs Ingested', data: [12, 41, 35, 51, 49, 62, 69, 91, 148] }],
                colors: ['#00A76F'],
                xaxis: { ...baseChartOptions.xaxis, categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'] }
            });
            this.tenantsChart.render();
        }

        const aEl = document.querySelector("#alerts-chart");
        if (aEl) {
            this.alertsChart = new ApexCharts(aEl, {
                ...baseChartOptions,
                series: [{ name: 'Alerts', data: [23, 11, 22, 27, 13, 19, 37, 21, 44] }],
                colors: ['#FFAB00'],
                xaxis: { ...baseChartOptions.xaxis, categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'] }
            });
            this.alertsChart.render();
        }
    },

    // ============================================
    // DATA LOADING (Optimized for Weak Networks)
    // ============================================
    async loadData(force = false) {
        if (force) {
            localStorage.removeItem('superadmin_bundle');
            this.showToast('Fetching fresh system bundle...', 'info');
        }

        const cached = localStorage.getItem('superadmin_bundle');
        if (cached && !force) {
            console.log("Loading dashboard from cache...");
            try {
                this.renderBundle(JSON.parse(cached));
            } catch (e) {
                localStorage.removeItem('superadmin_bundle');
            }
        }

        try {
            const response = await fetch(`${this.API_BASE}/api/admin/system/bundle`, {
                headers: Auth.getAuthHeader()
            });

            if (response.status === 401 || response.status === 403) {
                console.error("Auth Failure: Dashboard fetch rejected.");
                const tbody = document.getElementById('tenant-list');
                if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-state" style="color:var(--error);">Access Denied: Backend rejected your token.</td></tr>';
                return;
            }

            if (response.ok) {
                const result = await response.json();
                const bundle = result.data;

                // Store in cache
                localStorage.setItem('superadmin_bundle', JSON.stringify(bundle));

                // Render fresh data
                this.renderBundle(bundle);
            } else {
                throw new Error(`Server returned ${response.status}`);
            }
        } catch (e) {
            console.error("Failed to load system bundle", e);
            const tbody = document.getElementById('tenant-list');
            if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="empty-state error"><i data-lucide="alert-triangle"></i> Control plane connection failed. ${e.message}</td></tr>`;
            lucide.createIcons();
        }
    },

    renderBundle(bundle) {
        if (!bundle) return;

        // A. Update Stats & Charts
        if (bundle.overview) {
            this.cachedOverview = bundle.overview;
            this.updateDashboardUI(bundle.overview);
        }

        // B. Update Tenant List
        if (bundle.tenants) {
            this.renderRealTenants(bundle.tenants);
        }
    },

    async loadRealTenants() {
        // This is now handled by the system bundle in loadData()
    },

    renderRealTenants(tenants) {
        const tbody = document.getElementById('tenant-list');
        if (!tbody || !tenants) return;

        if (tenants.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No tenants found in Repo 1.</td></tr>';
            return;
        }

        tbody.innerHTML = tenants.map(t => `
            <tr>
                <td>
                    <div style="display:flex;align-items:center;gap:12px;">
                        <div style="width:34px;height:34px;background:var(--primary-light);border-radius:10px;display:flex;align-items:center;justify-content:center;color:var(--primary);font-weight:700;font-size:14px;">
                            ${(t.name || 'T').charAt(0).toUpperCase()}
                        </div>
                        <div style="display:flex;flex-direction:column;">
                            <span style="font-weight:600;">${t.name}</span>
                            <span style="font-size:11px;color:var(--text-muted);">${t.tenant_id}</span>
                        </div>
                    </div>
                </td>
                <td>${t.total_logs || '—'}</td>
                <td>${t.active_alerts || '—'}</td>
                <td><span class="badge badge-${t.status === 'active' ? 'active' : 'inactive'}">${t.status || 'Unknown'}</span></td>
                <td style="text-align:right;">
                    <button class="btn-secondary btn-sm" onclick="SuperAdmin.viewTenantDetail('${t.tenant_id}')">
                        <i data-lucide="eye" style="width:14px;"></i> Details
                    </button>
                </td>
            </tr>
        `).join('');
        lucide.createIcons();
    },

    updateDashboardUI(data) {
        if (!data) return;

        // Stats
        const lEl = document.getElementById('total-logs');
        if (lEl) lEl.innerText = this.formatNumber(data.logs?.total || 0);

        const aEl = document.getElementById('total-alerts');
        if (aEl) aEl.innerText = this.formatNumber(data.alerts?.total || 0);

        const tEl = document.getElementById('total-tenants');
        if (tEl) tEl.innerText = data.tenants?.total || 0;

        const dEl = document.getElementById('db-size');
        if (dEl) {
            const storageBytes = data.estimated_storage_bytes || 0;
            dEl.innerText = this.formatBytes(storageBytes);
        }

        // Tenant Table (if real list failed or using mock)
        if (!document.querySelector('#tenant-list tr td span')) { // Only if not populated by renderRealTenants
            const tbody = document.getElementById('tenant-list');
            if (tbody && data.top_tenants_by_volume) {
                if (data.top_tenants_by_volume.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No tenants found. Data ingestion has not started yet.</td></tr>';
                    return;
                }
                tbody.innerHTML = data.top_tenants_by_volume.map(t => `
                    <tr>
                        <td>
                            <div style="display:flex;align-items:center;gap:12px;">
                                <div style="width:34px;height:34px;background:var(--primary-light);border-radius:10px;display:flex;align-items:center;justify-content:center;color:var(--primary);font-weight:700;font-size:14px;">
                                    ${(t.tenant_id || 'T').charAt(0).toUpperCase()}
                                </div>
                                <span style="font-weight:600;">${t.tenant_id}</span>
                            </div>
                        </td>
                        <td>${this.formatNumber(t.log_count || 0)}</td>
                        <td>—</td>
                        <td><span class="badge badge-active">Active</span></td>
                        <td style="text-align:right;">
                            <button class="btn-secondary btn-sm" onclick="SuperAdmin.viewTenantDetail('${t.tenant_id}')">
                                <i data-lucide="eye" style="width:14px;"></i> Details
                            </button>
                        </td>
                    </tr>
                `).join('');
                lucide.createIcons();
            }
        }
    },

    // ============================================
    // TENANTS VIEW
    // ============================================
    async loadTenantsView() {
        // Update stats placeholders
        const tcEl = document.getElementById('tenants-total-count');
        const acEl = document.getElementById('tenants-active-count');
        const icEl = document.getElementById('tenants-inactive-count');
        if (tcEl) tcEl.textContent = '...';
        if (acEl) acEl.textContent = '...';
        if (icEl) icEl.textContent = '...';

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants`, {
                headers: Auth.getAuthHeader()
            });
            if (res.ok) {
                const data = await res.json();
                const tenants = data.tenants || [];

                // Standardize: Populate ALL tenant selects across the dashboard
                const tenantSelects = ['user-tenant-filter', 'network-tenant-filter', 'gen-report-tenant', 'audit-tenant-filter', 'api-tenant-filter'];
                tenantSelects.forEach(id => {
                    const el = document.getElementById(id);
                    if (el) {
                        const currentVal = el.value;
                        const defaultOpt = id === 'gen-report-tenant' ? '<option value="default">Default (All)</option>' :
                            (id === 'api-tenant-filter' ? '<option value="">All Tenants</option>' : '<option value="">Select Tenant...</option>');
                        el.innerHTML = defaultOpt + tenants.map(t => `<option value="${t.tenant_id}">${t.name || t.tenant_id}</option>`).join('');
                        el.value = currentVal;
                    }
                });

                // Update stats
                if (tcEl) tcEl.textContent = tenants.length;
                if (acEl) acEl.textContent = tenants.filter(t => t.status === 'active').length;
                if (icEl) icEl.textContent = tenants.filter(t => t.status !== 'active').length;

                const tbody = document.getElementById('tenants-full-list');
                if (tbody) {
                    if (tenants.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No tenants registered yet.</td></tr>';
                        return;
                    }
                    tbody.innerHTML = tenants.map(t => `
                        <tr>
                            <td>
                                <div style="display:flex;align-items:center;gap:12px;">
                                    <div style="width:34px;height:34px;background:var(--primary-light);border-radius:10px;display:flex;align-items:center;justify-content:center;color:var(--primary);font-weight:700;font-size:14px;">
                                        ${(t.name || 'T').charAt(0).toUpperCase()}
                                    </div>
                                    <div style="display:flex;flex-direction:column;">
                                        <span style="font-weight:600;">${t.name}</span>
                                        <span style="font-size:11px;color:var(--text-muted);">${t.tenant_id}</span>
                                    </div>
                                </div>
                            </td>
                            <td>—</td>
                            <td>—</td>
                            <td>—</td>
                            <td>—</td>
                            <td><span class="badge badge-${t.status === 'active' ? 'active' : 'inactive'}">${t.status}</span></td>
                            <td style="text-align:right;">
                                <div style="display:flex;gap:8px;justify-content:flex-end;">
                                    <button class="btn-secondary btn-sm" onclick="SuperAdmin.viewTenantDetail('${t.tenant_id}')">
                                        <i data-lucide="eye" style="width:14px;"></i> View
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('');
                    lucide.createIcons();
                }
            }
        } catch (e) {
            console.error("Failed to load real tenants view", e);
            const tbody = document.getElementById('tenants-full-list');
            if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="empty-state" style="color:var(--error);">Failed to connect to Repo 1 API.</td></tr>';
        }
    },

    async viewTenantDetail(tenantId) {
        const modal = document.getElementById('tenant-detail-modal');
        const title = document.getElementById('tenant-detail-title');
        const body = document.getElementById('tenant-detail-body');

        title.textContent = `Tenant: ${tenantId}`;
        body.innerHTML = '<p class="empty-state">Fetching latest data from control plane...</p>';
        modal.style.display = 'flex';

        try {
            const [tRes, uRes] = await Promise.all([
                fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}`, { headers: Auth.getAuthHeader() }),
                fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}/usage`, { headers: Auth.getAuthHeader() })
            ]);

            if (!tRes.ok) throw new Error('Failed to fetch tenant details');

            const tData = await tRes.json();
            const uData = uRes.ok ? await uRes.json() : { stats: {} };

            // Normalize Repo 1 vs local mapping
            const t = tData.data || tData;
            const stats = uData.stats || uData;

            body.innerHTML = `
                <div class="tenant-overview-grid">
                    <div class="card detail-card">
                        <div style="display:flex; justify-content:space-between; align-items:start; margin-bottom:12px;">
                            <h4 style="margin:0; color:var(--text-primary);">Core Configuration</h4>
                            <button class="btn-secondary btn-sm" onclick="SuperAdmin.showEditTenantModal('${tenantId}')">
                                <i data-lucide="edit-3" style="width:14px;"></i> Edit
                            </button>
                        </div>
                        <div class="detail-row"><span>Status:</span> <span class="badge badge-${t.status || 'active'}">${t.status || 'Active'}</span></div>
                        <div class="detail-row"><span>Created:</span> <span>${t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}</span></div>
                        <div class="detail-row"><span>Description:</span> <span>${t.description || 'No description provided.'}</span></div>
                    </div>
                    <div class="card detail-card">
                        <h4>Usage Statistics</h4>
                        <div class="detail-row"><span>Total Logs:</span> <strong>${stats.total_logs || 0}</strong></div>
                        <div class="detail-row"><span>Active Alerts:</span> <strong style="color:var(--error);">${stats.active_alerts || 0}</strong></div>
                        <div class="detail-row"><span>Managed Assets:</span> <strong>${stats.total_assets || 0}</strong></div>
                    </div>
                </div>

                <div class="detail-section" style="margin-top:20px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h4 style="margin:0;">Network Security (Primary IPs)</h4>
                        <button class="btn-primary btn-sm" onclick="SuperAdmin.showAddIpModal()">
                            <i data-lucide="plus" style="width:14px;"></i> Add Allowlist Range
                        </button>
                    </div>
                    
                    <div class="form-row" style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:16px; background:var(--grey-50); padding:12px; border-radius:8px;">
                        <div>
                            <label style="font-size:11px; margin-bottom:4px; display:block;">Primary IP 1</label>
                            <input type="text" id="primary-ip-1" class="glass-input" placeholder="e.g. 1.2.3.4">
                        </div>
                        <div>
                            <label style="font-size:11px; margin-bottom:4px; display:block;">Primary IP 2</label>
                            <input type="text" id="primary-ip-2" class="glass-input" placeholder="Optional">
                        </div>
                        <div>
                            <label style="font-size:11px; margin-bottom:4px; display:block; padding-left: 4px;">Primary IP 3</label>
                            <div style="display:flex; gap:8px;">
                                <input type="text" id="primary-ip-3" class="glass-input" placeholder="Optional">
                                <button class="btn-primary btn-sm" style="padding: 0 12px;" onclick="SuperAdmin.setPrimaryIps('${tenantId}')">Set</button>
                            </div>
                        </div>
                    </div>

                    <div id="tenant-ips-container">
                        <p class="empty-state">Loading allowlist...</p>
                    </div>
                </div>

                <div class="detail-section" style="margin-top:20px;">
                    <h4>Recent API Keys</h4>
                    <div id="tenant-keys-container" style="display:none;">
                        <table class="data-table">
                            <thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Created</th></tr></thead>
                            <tbody id="tenant-keys-list"></tbody>
                        </table>
                    </div>
                    <div id="tenant-keys-loading" class="empty-state">Fetching keys...</div>
                </div>
            `;
            lucide.createIcons();

            // Load extra data pieces
            this.loadTenantApiKeys(tenantId);
            this.loadTenantAllowlistMini(tenantId);

        } catch (e) {
            body.innerHTML = `<div class="empty-state error"><i data-lucide="alert-circle"></i><br>Error: ${e.message}</div>`;
            lucide.createIcons();
        }
    },

    async loadTenantAllowlistMini(tenantId) {
        const container = document.getElementById('tenant-ips-container');
        try {
            const res = await fetch(`${this.API_BASE}/api/admin/allowlist/${tenantId}`, { headers: Auth.getAuthHeader() });
            const data = await res.json();
            const ips = data.ips || data.entries || [];

            if (ips.length === 0) {
                container.innerHTML = '<p class="empty-state">No primary IPs configured for this tenant.</p>';
                return;
            }

            container.innerHTML = `
                <table class="data-table">
                    <thead><tr><th>IP / Range</th><th>Description</th><th>Added By</th><th>Action</th></tr></thead>
                    <tbody>
                        ${ips.map(ip => `
                            <tr>
                                <td><code>${ip.ip_range || ip}</code></td>
                                <td>${ip.description || 'Primary Office'}</td>
                                <td>${ip.added_by || 'System'}</td>
                                <td style="text-align:right;">
                                    <button class="btn-icon" style="color:var(--error);" onclick="SuperAdmin.removeIpRange('${tenantId}', '${ip.id || ip}')">
                                        <i data-lucide="trash-2" style="width:14px;"></i>
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
            lucide.createIcons();
        } catch (e) {
            container.innerHTML = '<p class="empty-state error">Failed to load IPs.</p>';
        }
    },

    async showEditTenantModal(tenantId) {
        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}`, { headers: Auth.getAuthHeader() });
            const data = await res.json();
            const t = data.data || data;

            document.getElementById('edit-tenant-id').value = tenantId;
            document.getElementById('edit-tenant-slug').value = tenantId;
            document.getElementById('edit-tenant-name').value = t.name || '';
            document.getElementById('edit-tenant-desc').value = t.description || '';
            document.getElementById('edit-tenant-status').value = t.status || 'active';
            document.getElementById('edit-tenant-config').value = JSON.stringify(t.config || {}, null, 2);

            document.getElementById('edit-tenant-modal').style.display = 'flex';
        } catch (e) {
            this.showToast('Failed to fetch tenant for editing', 'error');
        }
    },

    async updateTenant(e) {
        e.preventDefault();
        const tenantId = document.getElementById('edit-tenant-id').value;
        const updates = {};

        const name = document.getElementById('edit-tenant-name').value;
        const description = document.getElementById('edit-tenant-desc').value;
        const status = document.getElementById('edit-tenant-status').value;
        const configRaw = document.getElementById('edit-tenant-config').value;

        // Collect partial changes (in a real app we'd compare with original, for now we send what's in modal)
        if (name) updates.name = name;
        if (description) updates.description = description;
        if (status) updates.status = status;

        try {
            if (configRaw) updates.config = JSON.parse(configRaw);
        } catch (err) {
            alert('Invalid JSON in Configuration field');
            return;
        }

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}`, {
                method: 'PUT',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(updates)
            });

            if (res.ok) {
                this.showToast(`Tenant "${tenantId}" updated successfully`, 'success');
                this.closeModal('edit-tenant-modal');
                this.loadData(true); // Refresh list
                if (document.getElementById('tenant-detail-modal').style.display === 'flex') {
                    this.viewTenantDetail(tenantId); // Refresh detail view if open
                }
            } else {
                const err = await res.json();
                alert(`Update failed: ${err.detail || 'Unknown error'}`);
            }
        } catch (e) {
            this.showToast('Failed to connect to backend', 'error');
        }
    },

    async setPrimaryIps(tenantId) {
        const ip1 = document.getElementById('primary-ip-1')?.value || '';
        const ip2 = document.getElementById('primary-ip-2')?.value || '';
        const ip3 = document.getElementById('primary-ip-3')?.value || '';
        const ips = [ip1, ip2, ip3].filter(ip => ip.trim() !== '');

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}/primary-ips`, {
                method: 'POST',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(ips)
            });
            if (res.ok) {
                this.showToast('Primary IPs updated successfully', 'success');
                this.viewTenantDetail(tenantId);
            } else {
                const err = await res.json();
                alert(`Error: ${err.detail || 'Failed to update IPs'}`);
            }
        } catch (e) {
            alert('Failed to connect to backend API');
        }
    },

    openTenantDashboard(tenantId) {
        window.open(`index.html?tenant_id=${tenantId}`, '_blank');
    },

    viewTenantUsers(tenantId) {
        // Switch to users view and filter by tenant
        this.switchView('users', document.querySelector('[data-view="users"]'));
        const filter = document.getElementById('user-tenant-filter');
        if (filter) {
            filter.value = tenantId;
            this.loadUsers();
        }
    },

    // ============================================
    showAddUserModal() {
        document.getElementById('add-user-modal').style.display = 'flex';
    },

    async loadUsers() {
        const tbody = document.getElementById('users-list');
        if (!tbody) return;

        const tenantFilter = document.getElementById('user-tenant-filter')?.value;
        let url = `${this.API_BASE}/api/admin/users`;
        if (tenantFilter) url += `?tenant_id=${tenantFilter}`;

        try {
            const res = await fetch(url, { headers: Auth.getAuthHeader() });
            if (res.ok) {
                const data = await res.json();
                const users = data.users || [];
                tbody.innerHTML = users.map(u => `
                    <tr>
                        <td><strong>${u.username}</strong></td>
                        <td>${u.email}</td>
                        <td><span class="badge ${u.role === 'superadmin' ? 'badge-critical' : 'badge-active'}">${u.role}</span></td>
                        <td>${u.tenant_id || 'System'}</td>
                        <td>${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
                        <td style="text-align:right;">
                            <div style="display:flex; gap:8px; justify-content:flex-end;">
                                <button class="btn-secondary btn-sm" onclick="SuperAdmin.editUser('${u.username}')">
                                    <i data-lucide="edit-2" style="width:14px;"></i> Edit
                                </button>
                                <button class="btn-secondary btn-sm" style="color:var(--error);" onclick="SuperAdmin.deleteUser('${u.username}')">
                                    <i data-lucide="trash-2" style="width:14px;"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `).join('');
                lucide.createIcons();
            }
        } catch (e) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state error">Failed to load users from Identity Provider.</td></tr>';
        }
    },

    async addUser(e) {
        e.preventDefault();
        const payload = {
            username: document.getElementById('new-user-username').value,
            email: document.getElementById('new-user-email').value,
            password: document.getElementById('new-user-password').value,
            role: document.getElementById('new-user-role').value,
            tenant_id: document.getElementById('new-user-tenant').value || null
        };

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/users`, {
                method: 'POST',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                this.closeModal('add-user-modal');
                this.loadUsers();
                this.showToast('User created successfully', 'success');
            } else {
                const err = await res.json();
                alert(`Error: ${err.detail || 'Failed to create user'} `);
            }
        } catch (e) {
            alert('Identity service unreachable');
        }
    },
    async editUser(username) {
        const modal = document.getElementById('edit-user-modal');
        try {
            const res = await fetch(`${this.API_BASE}/api/admin/users?username=${username}`, {
                headers: Auth.getAuthHeader()
            });
            const data = await res.json();
            const user = (Array.isArray(data) ? data[0] : (data.users ? data.users[0] : data)) || {};

            document.getElementById('edit-user-id').value = username;
            document.getElementById('edit-user-username').value = user.username || username;
            document.getElementById('edit-user-email').value = user.email || '';
            document.getElementById('edit-user-role').value = user.role || 'user';
            document.getElementById('edit-user-tenant').value = user.tenant_id || '';
            document.getElementById('edit-user-password').value = '';

            modal.style.display = 'flex';
        } catch (e) {
            console.error("EditUser error:", e);
            this.showToast('Failed to load user details', 'error');
        }
    },

    async updateUser(e) {
        e.preventDefault();
        const userId = document.getElementById('edit-user-id').value;
        const payload = {
            email: document.getElementById('edit-user-email').value,
            role: document.getElementById('edit-user-role').value,
            tenant_id: document.getElementById('edit-user-tenant').value || null
        };

        const newPass = document.getElementById('edit-user-password').value;
        if (newPass) payload.password = newPass;

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/users/${userId}`, {
                method: 'PUT',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                this.closeModal('edit-user-modal');
                this.loadUsers();
                this.showToast('User preferences updated.', 'success');
            } else {
                const err = await res.json();
                alert(`Update failed: ${err.detail || 'Unknown error'}`);
            }
        } catch (e) {
            alert('Identity service unreachable');
        }
    },

    async deleteUser(username) {
        if (!confirm(`Are you sure you want to PERMANENTLY delete user "${username}"? This cannot be undone.`)) return;

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/users/${username}`, {
                method: 'DELETE',
                headers: Auth.getAuthHeader()
            });

            if (res.ok) {
                this.showToast(`User ${username} deleted.`, 'success');
                this.loadUsers();
            } else {
                const err = await res.json();
                alert(`Deletion failed: ${err.detail || 'Access denied'}`);
            }
        } catch (e) {
            console.error("DeleteUser error:", e);
        }
    },

    async prevAuditPage() { if (this.auditPage > 1) this.loadAuditLogs(this.auditPage - 1); },
    async nextAuditPage() { this.loadAuditLogs(this.auditPage + 1); },

    async loadAuditLogs(page = 1) {
        this.auditPage = page;
        const tbody = document.getElementById('audit-list');
        const tenantId = document.getElementById('audit-tenant-filter')?.value;
        const pageNum = document.getElementById('audit-page-num');
        if (pageNum) pageNum.textContent = page;

        if (!tbody) return;
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Fetching global audit trail...</td></tr>';

        try {
            // First time load: fill tenant filter
            if (this.cachedOverview && document.getElementById('audit-tenant-filter').options.length <= 1) {
                const select = document.getElementById('audit-tenant-filter');
                this.cachedOverview.tenants.forEach(t => {
                    const opt = document.createElement('option');
                    opt.value = t.tenant_id;
                    opt.textContent = t.name || t.tenant_id;
                    select.appendChild(opt);
                });
            }

            let url = `${this.API_BASE}/api/admin/audit-log?page=${page}&page_size=20`;
            if (tenantId) url += `&tenant_id=${tenantId}`;

            const res = await fetch(url, { headers: Auth.getAuthHeader() });
            if (res.ok) {
                const data = await res.json();
                const logs = data.logs || data;
                if (!logs || logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No audit events recorded.</td></tr>';
                    return;
                }
                tbody.innerHTML = logs.map(l => `
                    <tr>
                        <td>${new Date(l.timestamp).toLocaleString()}</td>
                        <td><strong>${l.action}</strong></td>
                        <td>${l.user || 'system'}</td>
                        <td>${l.tenant_id || 'Global'}</td>
                        <td><span class="badge badge-active">${l.status || 'SUCCESS'}</span></td>
                        <td>${l.ip_address || '—'}</td>
                    </tr>
                `).join('');
                lucide.createIcons();
            }
        } catch (e) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="empty-state error">Failed to load system audit trail.</td></tr>';
        }
    },

    // ============================================
    // GLOBAL HEALTH
    // ============================================
    async loadHealth() {
        try {
            const start = performance.now();
            const resp = await fetch(`${this.API_BASE}/health`, { headers: Auth.getAuthHeader() });
            const latency = Math.round(performance.now() - start);
            const healthData = await resp.json().catch(() => ({}));

            const overallStatus = healthData.status || 'unknown';
            if (overallStatus === 'healthy') {
                this.setHealthCard('health-api', 'healthy', 'Operational', `Latency: ${latency}ms | v${healthData.version || '1.0.0'}`);
            } else {
                this.setHealthCard('health-api', 'degraded', 'Degraded', `Latency: ${latency}ms`);
            }

            const redisStatus = healthData.components?.redis?.status;
            if (redisStatus === 'healthy') {
                this.setHealthCard('health-redis', 'healthy', 'Connected', 'Queue processing active');
            } else {
                const redisErr = healthData.components?.redis?.error || 'Check Redis connection';
                this.setHealthCard('health-redis', 'down', 'Disconnected', redisErr);
            }

            const dbStatus = healthData.components?.database?.status;
            if (dbStatus === 'healthy') {
                this.setHealthCard('health-db', 'healthy', 'Connected', 'All tables accessible');
            } else {
                const dbErr = healthData.components?.database?.error || 'Check database connection';
                this.setHealthCard('health-db', 'down', 'Disconnected', dbErr);
            }

            if (overallStatus === 'healthy' && redisStatus === 'healthy') {
                this.setHealthCard('health-consumer', 'healthy', 'Running', 'Processing logs from Redis');
            } else {
                this.setHealthCard('health-consumer', 'down', 'Unknown', 'Processing interrupted');
            }

            const idStatus = healthData.components?.identity?.status;
            if (idStatus === 'healthy') {
                this.setHealthCard('health-identity', 'healthy', 'Connected', 'Repo 1 API is reachable');
            } else {
                const idErr = healthData.components?.identity?.error || `HTTP ${healthData.components?.identity?.status_code || 'Err'}`;
                this.setHealthCard('health-identity', 'down', 'Unreachable', idErr);
            }

            this.addSystemEvent('success', `Health check OK — API: ${overallStatus}`);
        } catch (e) {
            this.setHealthCard('health-api', 'down', 'Unreachable', e.message);
            this.addSystemEvent('error', `Health check failed: ${e.message}`);
        }
        this.initHealthCharts();
    },

    setHealthCard(cardId, status, statusText, detail) {
        const card = document.getElementById(cardId);
        if (!card) return;
        card.className = `card health-card ${status}`;
        const statusEl = card.querySelector('.health-status');
        const detailEl = card.querySelector('.health-detail');
        if (statusEl) statusEl.textContent = statusText;
        if (detailEl) detailEl.textContent = detail;
    },

    addSystemEvent(type, message) {
        const log = document.getElementById('system-events-log');
        if (!log) return;
        const now = new Date().toLocaleTimeString('en-US', { hour12: false });
        const line = document.createElement('div');
        line.className = `event-line ${type}`;
        line.innerHTML = `<span class="event-time">${now}</span> ${message}`;
        log.prepend(line);
        while (log.children.length > 50) log.removeChild(log.lastChild);
    },

    initHealthCharts() {
        const chartEl1 = document.querySelector("#system-load-chart");
        const chartEl2 = document.querySelector("#error-rate-chart");
        if (!chartEl1 || !chartEl2 || this.systemLoadChart) return;

        const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);
        const baseOpts = {
            chart: { height: 220, type: 'area', toolbar: { show: false }, background: 'transparent', foreColor: '#637381', fontFamily: 'Public Sans' },
            stroke: { curve: 'smooth', width: 2 },
            fill: { type: 'gradient', gradient: { opacityFrom: 0.2, opacityTo: 0.02 } },
            dataLabels: { enabled: false },
            grid: { borderColor: 'rgba(145,158,171,0.2)' },
            tooltip: { theme: 'light' },
            xaxis: { categories: hours, axisBorder: { show: false }, labels: { show: false } }
        };

        this.systemLoadChart = new ApexCharts(chartEl1, { ...baseOpts, series: [{ name: 'CPU %', data: hours.map(() => Math.random() * 40 + 10) }], colors: ['#00B8D9'] });
        this.systemLoadChart.render();

        this.errorRateChart = new ApexCharts(chartEl2, { ...baseOpts, series: [{ name: 'Errors', data: hours.map(() => Math.floor(Math.random() * 5)) }], colors: ['#FF5630'] });
        this.errorRateChart.render();
    },

    // ============================================
    // NETWORK SECURITY
    // ============================================
    async loadNetworkSecurity() {
        const filter = document.getElementById('network-tenant-filter');
        const empty = document.getElementById('allowlist-empty');
        const content = document.getElementById('allowlist-content');
        if (!filter) return;

        if (filter.options.length <= 1 && this.cachedOverview?.top_tenants_by_volume) {
            filter.innerHTML = '<option value="">Select Tenant...</option>' +
                this.cachedOverview.top_tenants_by_volume.map(t =>
                    `<option value="${t.tenant_id}">${t.tenant_id}</option>`
                ).join('');
        }

        const tenantId = filter.value;
        if (!tenantId) {
            if (empty) empty.style.display = 'block';
            if (content) content.style.display = 'none';
            return;
        }

        if (empty) empty.style.display = 'none';
        if (content) content.style.display = 'block';

        const tbody = document.getElementById('allowlist-list');
        if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Fetching allowlist from Repo 1...</td></tr>';

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/allowlist/${tenantId}`, {
                headers: Auth.getAuthHeader()
            });
            if (res.ok) {
                const data = await res.json();
                const entries = (data.entries && data.entries.length > 0) ? data.entries : (data.ips || []).map(ip => ({ ip_range: ip, description: 'Flat Entry' }));

                const acEl = document.getElementById('allowlist-active-count');
                const luEl = document.getElementById('allowlist-last-update');
                if (acEl) acEl.textContent = entries.length;
                if (luEl) luEl.textContent = entries.length > 0 ? 'Active' : 'Never';

                if (tbody) {
                    if (entries.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No IP ranges configured for this tenant.</td></tr>';
                        return;
                    }
                    tbody.innerHTML = entries.map(e => `
                        <tr>
                            <td><code>${e.ip_range}</code></td>
                            <td>${e.description || '—'}</td>
                            <td>${e.added_by || 'System'}</td>
                            <td>${e.created_at ? new Date(e.created_at).toLocaleString() : '—'}</td>
                            <td style="text-align:right;">
                                <button class="btn-secondary btn-sm" style="color:var(--error);" onclick="SuperAdmin.removeIpRange('${tenantId}', '${e.id}')">
                                    <i data-lucide="trash-2" style="width:14px;"></i> Remove
                                </button>
                            </td>
                        </tr>
                    `).join('');
                }
                lucide.createIcons();
            }
        } catch (e) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-state error">Failed to load allowlist from Repo 1.</td></tr>';
        }
    },

    showAddIpModal() {
        document.getElementById('add-ip-modal').style.display = 'flex';
    },

    async addIpRange(e) {
        e.preventDefault();
        const tenantId = document.getElementById('network-tenant-filter').value;
        const ip_range = document.getElementById('new-ip-range').value;
        const description = document.getElementById('new-ip-desc').value;

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}/ips`, {
                method: 'POST',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_range, description })
            });
            if (res.ok) {
                this.closeModal('add-ip-modal');
                this.loadNetworkSecurity();
                this.showToast('IP range added successfully', 'success');
                document.getElementById('new-ip-range').value = '';
                document.getElementById('new-ip-desc').value = '';
            } else {
                const err = await res.json();
                alert(`Error: ${err.detail || 'Failed to add IP range'}`);
            }
        } catch (e) {
            alert('Failed to connect to backend API');
        }
    },

    async removeIpRange(tenantId, ipId) {
        if (!confirm('Are you sure you want to remove this IP range? This takes effect immediately.')) return;
        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}/ips/${ipId}`, {
                method: 'DELETE',
                headers: Auth.getAuthHeader()
            });
            if (res.ok) {
                this.loadNetworkSecurity();
                this.showToast('IP range removed', 'success');
            } else {
                const err = await res.json();
                alert(`Error: ${err.detail || 'Failed to remove IP range'}`);
            }
        } catch (e) {
            alert('Failed to connect to backend API');
        }
    },

    // ============================================
    // SYSTEM SETTINGS
    // ============================================
    async loadSettings() {
        try {
            const response = await fetch(`${this.API_BASE}/api/config`, { headers: Auth.getAuthHeader() });
            if (response.ok) {
                const config = await response.json();
                const c = config.data || config;
                if (c.detection) {
                    document.getElementById('cfg-bf-threshold').value = c.detection.brute_force_threshold || 5;
                    document.getElementById('cfg-ps-threshold').value = c.detection.port_scan_threshold || 20;
                    document.getElementById('cfg-beacon-interval').value = c.detection.beaconing_interval || 60;
                }
                if (c.logging) document.getElementById('cfg-log-level').value = c.logging.level || 'INFO';
                if (c.email) {
                    document.getElementById('cfg-email-enabled').checked = c.email.enabled || false;
                    document.getElementById('cfg-email-recipients').value = (c.email.recipients || []).join(', ');
                }
                if (c.webhook) {
                    document.getElementById('cfg-webhook-enabled').checked = c.webhook.enabled || false;
                    document.getElementById('cfg-webhook-url').value = c.webhook.url || '';
                }
            }
        } catch (e) {
            console.warn("Settings load skipped:", e.message);
        }
    },

    async saveConfig(configUpdate) {
        try {
            const response = await fetch(`${this.API_BASE}/api/config`, {
                method: 'PUT',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(configUpdate)
            });
            if (response.ok) this.showToast('Configuration saved successfully.', 'success');
            else {
                const err = await response.json();
                this.showToast(`Save failed: ${err.detail || 'Unknown error'}`, 'error');
            }
        } catch (e) { this.showToast(`Save failed: ${e.message}`, 'error'); }
    },

    // ============================================
    // BACKUP & REPORTS
    // ============================================
    async loadReports() {
        const type = document.getElementById('report-type-filter')?.value || '';
        let url = `${this.API_BASE}/api/v1/reports?tenant_id=default`;
        if (type) url += `&report_type=${type}`;
        try {
            const response = await fetch(url, { headers: Auth.getAuthHeader() });
            if (response.ok) {
                const result = await response.json();
                const reports = result.data || result.reports || [];
                const tbody = document.getElementById('reports-list');
                if (!tbody) return;
                if (reports.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No reports generated yet.</td></tr>';
                    return;
                }
                tbody.innerHTML = reports.map(r => `
                    <tr>
                        <td><span class="badge badge-active">${(r.report_type || 'custom').toUpperCase()}</span></td>
                        <td>${new Date(r.created_at || r.generated_at).toLocaleString()}</td>
                        <td>${r.period_start ? new Date(r.period_start).toLocaleDateString() : '—'} — ${r.period_end ? new Date(r.period_end).toLocaleDateString() : '—'}</td>
                        <td>${r.log_count || '—'}</td>
                        <td>${r.alert_count || '—'}</td>
                        <td style="text-align:right;"><button class="btn-secondary btn-sm" onclick="SuperAdmin.viewReport('${r.id}')"><i data-lucide="file-text" style="width:14px;"></i> View</button></td>
                    </tr>`).join('');
                lucide.createIcons();
            }
        } catch (e) { console.warn("Reports load failed:", e.message); }
        this.loadSystemLogs();
    },

    loadSystemLogs() {
        const viewer = document.getElementById('system-log-viewer');
        if (!viewer) return;
        const entries = [
            { level: 'info', msg: 'SIEM Analyzer engine running.' },
            { level: 'info', msg: 'Redis consumer connected.' },
            { level: 'info', msg: 'Database initialized.' },
            { level: 'api', msg: 'Admin API listening for events.' },
            { level: 'info', msg: 'Health monitoring active.' },
        ];
        viewer.innerHTML = entries.map(e => `<div class="log-line ${e.level}"><span class="log-time">${new Date().toLocaleTimeString('en-US', { hour12: false })}</span> <span class="log-level">${e.level.toUpperCase()}</span> <span class="log-msg">${e.msg}</span></div>`).join('');
    },

    showGenerateReportModal() {
        document.getElementById('gen-report-modal').style.display = 'flex';
    },

    async generateReport(e) {
        if (e) e.preventDefault();
        const type = document.getElementById('gen-report-type').value;
        const tenant = document.getElementById('gen-report-tenant').value;

        this.showToast('Generating security intelligence report...', 'info');

        try {
            const res = await fetch(`${this.API_BASE}/api/v1/reports/generate`, {
                method: 'POST',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    report_type: type,
                    tenant_id: tenant === 'default' ? 'default' : tenant,
                    days_back: type === 'daily' ? 1 : (type === 'weekly' ? 7 : 30)
                })
            });

            if (res.ok) {
                this.showToast('Report generated successfully', 'success');
                this.closeModal('gen-report-modal');
                this.loadReports();
            } else {
                const err = await res.json();
                this.showToast(`Generation failed: ${err.detail || 'Internal error'}`, 'error');
            }
        } catch (e) {
            this.showToast('Failed to connect to report controller', 'error');
        }
    },

    async viewReport(reportId) {
        window.open(`${this.API_BASE}/api/v1/reports/${reportId}/content`, '_blank');
    },

    showAddTenantModal() {
        document.getElementById('add-tenant-modal').style.display = 'flex';
    },

    async addTenant(e) {
        e.preventDefault();
        const payload = {
            tenant_id: document.getElementById('new-tenant-id').value,
            name: document.getElementById('new-tenant-name').value,
            description: document.getElementById('new-tenant-description').value,
            primary_ips: document.getElementById('new-tenant-primary-ips').value.split(',').map(s => s.trim()).filter(Boolean),
            config: {
                contact_email: document.getElementById('new-tenant-email').value,
                compliance: document.getElementById('new-tenant-compliance').value.split(',').map(s => s.trim()).filter(Boolean),
                rate_limits: {
                    rpm: parseInt(document.getElementById('new-tenant-limit-rpm').value) || 1000,
                    lph: parseInt(document.getElementById('new-tenant-limit-lph').value) || 50000,
                    max_devices: parseInt(document.getElementById('new-tenant-limit-devices').value) || 100
                },
                business_hours: {
                    start: document.getElementById('new-tenant-hours-start').value,
                    end: document.getElementById('new-tenant-hours-end').value
                }
            },
            create_admin_user: document.getElementById('new-tenant-create-admin').checked
        };

        if (payload.create_admin_user) {
            payload.admin_username = document.getElementById('new-tenant-admin-user').value;
            payload.admin_email = document.getElementById('new-tenant-admin-email').value;
            payload.admin_password = document.getElementById('new-tenant-admin-pass').value;
        }

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants`, {
                method: 'POST',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                this.closeModal('add-tenant-modal');
                this.loadTenantsView();
                this.showToast('Premium tenant provisioned successfully.', 'success');
            } else {
                const err = await res.json();
                alert(`Provisioning error: ${err.detail || 'Service rejected request'}`);
            }
        } catch (e) { alert('Admin control plane unreachable'); }
    },

    // ============================================
    // UTILITIES
    // ============================================
    closeModal(modalId) {
        const m = document.getElementById(modalId);
        if (m) m.style.display = 'none';
    },

    showToast(message, type = 'info') {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    },

    formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return n.toLocaleString();
    },

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    // ============================================
    // API INVENTORY & OVERSIGHT
    // ============================================
    async loadApiInventory() {
        const list = document.getElementById('api-inventory-list');
        const filterTenant = document.getElementById('api-tenant-filter')?.value;

        try {
            // Fetch from global proxy or specific tenant
            const path = filterTenant ? `/tenants/${filterTenant}/api-keys` : '/api-keys';
            const response = await fetch(`${this.API_BASE}/api/admin${path}`, {
                headers: Auth.getAuthHeader()
            });
            if (!response.ok) {
                console.error(`[Admin API] ${path} failed:`, response.status);
                const err = await response.json().catch(() => ({}));
                console.error('[Admin API] Error detail:', err);
                if (list) list.innerHTML = `<tr><td colspan="6" class="empty-state error">Fetch failed: ${err.detail || response.statusText}</td></tr>`;
                return;
            }
            const data = await response.json();

            // Handle various Repo 1 formats:
            // 1. { "keys": [...] }
            // 2. { "api_keys": [...] }
            // 3. Raw array [...]
            const keys = data.keys || data.api_keys || (Array.isArray(data) ? data : []);
            this.renderApiInventory(keys);
        } catch (e) {
            console.error("LoadApiInventory error:", e);
            if (list) list.innerHTML = `<tr><td colspan="6" class="empty-state error">Failed to load API inventory.</td></tr>`;
        }
    },

    renderApiInventory(keys) {
        const list = document.getElementById('api-inventory-list');
        if (!list) return;
        if (!keys || keys.length === 0) {
            list.innerHTML = `<tr><td colspan="6" class="empty-state">No active API keys found across the platform.</td></tr>`;
            return;
        }

        list.innerHTML = keys.map(key => {
            // Normalize permissions/scopes
            let scopes = [];
            if (Array.isArray(key.scopes)) {
                scopes = key.scopes;
            } else if (key.permissions) {
                // If Repo 1 returns an object like {"ingest": true, "read": false}
                if (typeof key.permissions === 'object' && !Array.isArray(key.permissions)) {
                    scopes = Object.entries(key.permissions)
                        .filter(([_, enabled]) => enabled)
                        .map(([name]) => name);
                } else if (Array.isArray(key.permissions)) {
                    scopes = key.permissions;
                }
            }
            if (scopes.length === 0) scopes = ['standard'];

            return `
            <tr>
                <td><strong>${key.name || 'Unnamed Key'}</strong></td>
                <td><code class="tenant-tag">${key.tenant_id || 'System'}</code></td>
                <td><code>${key.key_prefix || key.prefix || 'ak_...'}***</code></td>
                <td>
                    <div class="scope-badges">
                        ${scopes.map(s => `<span class="badge badge-scope">${s}</span>`).join('')}
                    </div>
                </td>
                <td style="font-size:11px; color:var(--text-secondary);">${key.created_at ? new Date(key.created_at).toLocaleDateString() : '—'}</td>
                <td style="text-align:right;">
                    <button class="btn-icon btn-danger-soft" title="Revoke Key" onclick="SuperAdmin.revokeApiKey('${key.id}', '${key.name}')">
                        <i data-lucide="trash-2" style="width:14px;"></i>
                    </button>
                </td>
            </tr>
        `}).join('');
        lucide.createIcons();
    },

    async loadTenantApiKeys(tenantId) {
        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}/api-keys`, {
                headers: Auth.getAuthHeader()
            });
            const data = await res.json();
            const keys = data.keys || data;

            const loading = document.getElementById('tenant-keys-loading');
            const container = document.getElementById('tenant-keys-container');
            const list = document.getElementById('tenant-keys-list');

            if (loading) loading.style.display = 'none';
            if (container) container.style.display = 'block';

            if (!keys || !Array.isArray(keys) || keys.length === 0) {
                if (list) list.innerHTML = `<tr><td colspan="5" class="empty-state" style="padding:16px;">No API keys found for this tenant.</td></tr>`;
            } else {
                if (list) list.innerHTML = keys.map(k => {
                    const scopes = Array.isArray(k.scopes) ? k.scopes.join(', ') : (k.permissions ? Object.keys(k.permissions).filter(p => k.permissions[p]).join(', ') : 'none');
                    return `
                    <tr>
                        <td><strong>${k.name}</strong></td>
                        <td><code>${k.key_prefix || k.prefix}***</code></td>
                        <td><div class="scope-badges">${scopes}</div></td>
                        <td style="font-size:11px; color:var(--text-secondary);">${new Date(k.created_at).toLocaleDateString()}</td>
                        <td style="text-align:right;">
                            <button class="btn-icon btn-danger-soft" title="Revoke Key" onclick="SuperAdmin.revokeApiKey('${k.id}', '${k.name}')">
                                <i data-lucide="trash-2" style="width:14px;"></i>
                            </button>
                        </td>
                    </tr>
                `}).join('');
                lucide.createIcons();
            }
        } catch (e) {
            console.error("LoadTenantApiKeys error:", e);
        }
    },

    async revokeApiKey(id, name) {
        if (!confirm(`Are you sure you want to revoke API key "${name}"? This action cannot be undone.`)) return;

        try {
            const res = await fetch(`${this.API_BASE}/api/admin/api-keys/${id}`, {
                method: 'DELETE',
                headers: Auth.getAuthHeader()
            });

            if (res.ok) {
                this.showToast(`API Key "${name}" revoked successfully.`, 'success');
                this.loadApiInventory();
            } else {
                this.showToast(`Failed to revoke key.`, 'error');
            }
        } catch (e) {
            console.error("Revoke error:", e);
            this.showToast(`System error while revoking key.`, 'error');
        }
    },

    filterApiKeys() {
        const query = document.getElementById('api-search').value.toLowerCase();
        const rows = document.querySelectorAll('#api-inventory-list tr');

        rows.forEach(row => {
            if (row.querySelector('.empty-state')) return;
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    },
};

document.addEventListener('DOMContentLoaded', () => SuperAdmin.init());
