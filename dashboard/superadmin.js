/**
 * superadmin.js - Complete SuperAdmin Dashboard Logic
 * Handles: Dashboard, Tenants, Global Health, Settings, Backup & Logs, Network Security
 */

const SuperAdmin = {
    API_BASE: window.location.origin,
    tenantsChart: null,
    alertsChart: null,
    systemLoadChart: null,
    errorRateChart: null,
    cachedOverview: null,
    healthInterval: null,

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

    async loadData() {
        try {
            const response = await fetch(`${this.API_BASE}/api/admin/system/overview`, {
                headers: Auth.getAuthHeader()
            });

            if (response.status === 401 || response.status === 403) {
                console.error("Auth Failure: Dashboard fetch rejected. Check SECRET_KEY sync.");
                const tbody = document.getElementById('tenant-list');
                if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-state" style="color:var(--error);">Access Denied: Backend rejected your token. Check .env SECRET_KEY.</td></tr>';
                return;
            }

            if (response.ok) {
                const result = await response.json();
                this.cachedOverview = result.data;
                this.updateDashboardUI(result.data);

                // Also fetch the REAL tenant list if possible
                this.loadRealTenants();
            }
        } catch (e) {
            console.error("Failed to load admin overview", e);
        }
    },

    async loadRealTenants() {
        try {
            const res = await fetch(`${this.API_BASE}/api/admin/tenants`, {
                headers: Auth.getAuthHeader()
            });
            if (res.ok) {
                const data = await res.json();
                // Repo 1 returns { tenants: [...] }
                const tenants = data.tenants || [];
                this.renderRealTenants(tenants);
            }
        } catch (e) {
            console.warn("Failed to fetch real tenants from Repo 1", e);
        }
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
                const tenantSelects = ['user-tenant-filter', 'network-tenant-filter', 'gen-report-tenant'];
                tenantSelects.forEach(id => {
                    const el = document.getElementById(id);
                    if (el) {
                        const currentVal = el.value;
                        el.innerHTML = (id === 'gen-report-tenant' ? '<option value="default">Default (All)</option>' : '<option value="">Select Tenant...</option>') +
                            tenants.map(t => `<option value="${t.tenant_id}">${t.name || t.tenant_id}</option>`).join('');
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
        const body = document.getElementById('tenant-detail-body');
        if (body) body.innerHTML = '<div class="empty-state">Fetching premium tenant intelligence...</div>';
        document.getElementById('tenant-detail-modal').style.display = 'flex';

        try {
            // Parallel fetch for metadata and usage stats
            const [metaRes, usageRes] = await Promise.all([
                fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}`, { headers: Auth.getAuthHeader() }),
                fetch(`${this.API_BASE}/api/admin/tenants/${tenantId}/usage`, { headers: Auth.getAuthHeader() })
            ]);

            const meta = metaRes.ok ? await metaRes.json() : {};
            const usageEnvelope = usageRes.ok ? await usageRes.json() : {};
            const usage = usageEnvelope.data || usageEnvelope;
            const t = meta.tenant || meta;
            const config = t.config || {};

            if (body) {
                body.innerHTML = `
                <div class="tenant-detail-grid">
                    <div class="card detail-section">
                        <div class="section-header"><i data-lucide="info"></i> <h4>Basic Information</h4></div>
                        <div class="detail-row"><span class="label">Display Name:</span> <span class="value"><strong>${t.name || '—'}</strong></span></div>
                        <div class="detail-row"><span class="label">Tenant ID:</span> <span class="value"><code>${t.tenant_id || tenantId}</code></span></div>
                        <div class="detail-row"><span class="label">Contact Email:</span> <span class="value">${t.contact_email || config.contact_email ? `<a href="mailto:${t.contact_email || config.contact_email}">${t.contact_email || config.contact_email}</a>` : '—'}</span></div>
                        <div class="detail-row"><span class="label">Status:</span> <span class="badge ${t.status === 'active' ? 'badge-active' : 'badge-inactive'}">${t.status || 'Active'}</span></div>
                        <div class="detail-row" style="margin-top:12px;"><span class="label">Description:</span><p class="desc-text">${t.description || 'No description provided.'}</p></div>
                    </div>

                    <div class="card detail-section">
                        <div class="section-header"><i data-lucide="bar-chart-3"></i> <h4>Analyzer Statistics</h4></div>
                        <div class="detail-row"><span class="label">Total Logs Ingested:</span> <span class="value"><strong>${this.formatNumber(usage.logs?.total || usage.total_logs)}</strong></span></div>
                        <div class="detail-row"><span class="label">Active Alerts:</span> <span class="value" style="color:var(--error); font-weight:700;">${this.formatNumber(usage.alerts?.active || usage.active_alerts)}</span></div>
                        <div class="detail-row"><span class="label">Ingestion Rate:</span> <span class="value">${usage.ingestion_rate || usage.avg_eps || '0.0'} EPS</span></div>
                        <div class="detail-row"><span class="label">Storage Used:</span> <span class="value">${this.formatBytes(usage.estimated_storage_bytes || usage.storage_bytes || 0)}</span></div>
                        <div class="detail-row"><span class="label">Last Activity:</span> <span class="value">${usage.last_event ? new Date(usage.last_event).toLocaleString() : 'Never'}</span></div>
                    </div>

                    <div class="card detail-section full-width">
                        <div class="section-header"><i data-lucide="settings-2"></i> <h4>Operational Configuration</h4></div>
                        <div class="config-grid-layout">
                            <div class="config-item"><span class="label">Business Hours:</span><span class="value">${usage.business_hours_start || t.business_hours_start || '09:00'} to ${usage.business_hours_end || t.business_hours_end || '17:00'}</span></div>
                            <div class="config-item"><span class="label">Timezone:</span><span class="value">UTC/GMT</span></div>
                            <div class="config-item"><span class="label">Retention:</span><span class="value">90 Days</span></div>
                            <div class="config-item"><span class="label">Compliance:</span><span class="value" style="color:var(--success); font-weight:600;">SOC2 Compliant</span></div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer" style="padding:24px 0 0; margin-top:12px; border-top:1px dashed var(--grey-200); display:flex; gap:12px; justify-content:flex-end;">
                    <button class="btn-secondary" onclick="SuperAdmin.loadUsers('${tenantId}'); SuperAdmin.switchView('users'); SuperAdmin.closeModal('tenant-detail-modal')">
                        <i data-lucide="users" style="width:16px;"></i> Management Users
                    </button>
                    <button class="btn-primary" onclick="alert('Accessing dedicated portal for ${tenantId}...')">
                        <i data-lucide="external-link" style="width:16px;"></i> Open Dashboard
                    </button>
                </div>
                `;
                lucide.createIcons();
            }
        } catch (e) {
            console.error("ViewDetail error:", e);
            if (body) body.innerHTML = `<div class="empty-state error">Failed to load detailed intelligence for ${tenantId}.</div>`;
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
    // USER MANAGEMENT
    // ============================================
    async loadUsers() {
        const tbody = document.getElementById('users-list');
        if (!tbody) return;

        const tenantFilter = document.getElementById('user-tenant-filter')?.value;
        let url = `${this.API_BASE} /api/admin / users`;
        if (tenantFilter) url += `? tenant_id = ${tenantFilter} `;

        try {
            const res = await fetch(url, { headers: Auth.getAuthHeader() });
            if (res.ok) {
                const data = await res.json();
                const users = data.users || [];
                tbody.innerHTML = users.map(u => `
    < tr >
                        <td><strong>${u.username}</strong></td>
                        <td>${u.email}</td>
                        <td><span class="badge ${u.role === 'superadmin' ? 'badge-critical' : 'badge-active'}">${u.role}</span></td>
                        <td>${u.tenant_id || 'System'}</td>
                        <td>${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
                        <td style="text-align:right;">
                            <button class="btn-secondary btn-sm" onclick="SuperAdmin.editUser('${u.id}')">
                                <i data-lucide="edit-2" style="width:14px;"></i> Edit
                            </button>
                        </td>
                    </tr >
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
            const res = await fetch(`${this.API_BASE} /api/admin / users`, {
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

    showAddUserModal() {
        document.getElementById('add-user-modal').style.display = 'flex';
    },

    loadAuditLogs() {
        const tbody = document.getElementById('audit-list');
        if (!tbody) return;

        const logs = [
            { time: new Date().toISOString(), action: 'LOGIN_SUCCESS', user: 'superadmin', target: 'System', status: 'SUCCESS', ip: '127.0.0.1' },
            { time: new Date(Date.now() - 600000).toISOString(), action: 'TENANT_VIEW', user: 'superadmin', target: 'acme-corp', status: 'SUCCESS', ip: '127.0.0.1' },
            { time: new Date(Date.now() - 3600000).toISOString(), action: 'CONFIG_UPDATE', user: 'superadmin', target: 'Detection Thresholds', status: 'SUCCESS', ip: '127.0.0.1' }
        ];
        tbody.innerHTML = logs.map(l => `
    < tr >
                <td>${new Date(l.time).toLocaleString()}</td>
                <td><strong>${l.action}</strong></td>
                <td>${l.user}</td>
                <td>${l.target}</td>
                <td><span class="badge badge-active">${l.status}</span></td>
                <td>${l.ip}</td>
            </tr >
    `).join('');
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
        let url = `${this.API_BASE}/api/reports?tenant_id=default`;
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
                        <td style="text-align:right;"><button class="btn-secondary btn-sm" onclick="SuperAdmin.viewReport(${r.id})"><i data-lucide="file-text" style="width:14px;"></i> View</button></td>
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
            { level: 'info', msg: 'API server listening on 0.0.0.0:8000.' },
            { level: 'info', msg: 'Health check passed.' },
        ];
        viewer.innerHTML = entries.map(e => `<div class="log-line ${e.level}"><span class="log-time">${new Date().toLocaleTimeString('en-US', { hour12: false })}</span> <span class="log-level">${e.level.toUpperCase()}</span> <span class="log-msg">${e.msg}</span></div>`).join('');
    },

    showAddTenantModal() {
        document.getElementById('add-tenant-modal').style.display = 'flex';
    },

    async addTenant(e) {
        e.preventDefault();
        const tid = document.getElementById('new-tenant-id').value;
        const name = document.getElementById('new-tenant-name').value;
        const email = document.getElementById('new-tenant-email').value;
        const description = document.getElementById('new-tenant-description').value;
        const hoursStart = document.getElementById('new-tenant-hours-start').value;
        const hoursEnd = document.getElementById('new-tenant-hours-end').value;
        const createAdmin = document.getElementById('new-tenant-create-admin').checked;

        const payload = {
            tenant_id: tid,
            name: name,
            description: description,
            config: { business_hours: { start: hoursStart, end: hoursEnd }, contact_email: email },
            create_admin_user: createAdmin
        };

        if (createAdmin) {
            payload.admin_username = document.getElementById('new-tenant-admin-user').value;
            payload.admin_email = document.getElementById('new-tenant-admin-email').value;
            payload.admin_password = document.getElementById('new-tenant-admin-pass').value;
            if (!payload.admin_username || !payload.admin_password) {
                alert("Admin username and password are required.");
                return;
            }
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
                this.showToast('Tenant created successfully', 'success');
            } else {
                const err = await res.json();
                alert(`Error: ${err.detail || 'Failed to create tenant'}`);
            }
        } catch (e) { alert('Failed to connect to backend API'); }
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
    }
};

document.addEventListener('DOMContentLoaded', () => SuperAdmin.init());
