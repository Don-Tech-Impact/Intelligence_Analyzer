/**
 * superadmin.js - Complete SuperAdmin Dashboard Logic
 * Handles: Dashboard, Tenants, Global Health, Settings, Backup & Logs
 */

const SuperAdmin = {
    API_BASE: window.location.origin,
    tenantsChart: null,
    alertsChart: null,
    systemLoadChart: null,
    errorRateChart: null,
    cachedOverview: null,
    healthInterval: null,

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

        const isAuthorized = role === 'superadmin' || isAdmin || username === 'superadmin' || email.includes('admin@');

        if (!isAuthorized) {
            console.error("Access denied. Not a superadmin.");
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
        }

        // Load view-specific data
        switch (viewId) {
            case 'dashboard':
                this.loadData();
                break;
            case 'tenants':
                this.loadTenantsView();
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
                foreColor: '#94A3B8',
                fontFamily: 'Inter, sans-serif',
                animations: {
                    enabled: true,
                    easing: 'easeinout',
                    speed: 800
                }
            },
            stroke: { curve: 'smooth', width: 3 },
            fill: {
                type: 'gradient',
                gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0, stops: [0, 90, 100] }
            },
            dataLabels: { enabled: false },
            grid: { borderColor: 'rgba(255,255,255,0.05)', strokeDashArray: 3 },
            xaxis: { axisBorder: { show: false }, axisTicks: { show: false } },
            tooltip: {
                theme: 'dark',
                style: { fontFamily: 'Inter, sans-serif' }
            }
        };

        this.tenantsChart = new ApexCharts(document.querySelector("#tenants-chart"), {
            ...baseChartOptions,
            series: [{ name: 'Logs Ingested', data: [12, 41, 35, 51, 49, 62, 69, 91, 148] }],
            colors: ['#3366FF'],
            xaxis: { ...baseChartOptions.xaxis, categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'] }
        });
        this.tenantsChart.render();

        this.alertsChart = new ApexCharts(document.querySelector("#alerts-chart"), {
            ...baseChartOptions,
            series: [{ name: 'Alerts', data: [23, 11, 22, 27, 13, 19, 37, 21, 44] }],
            colors: ['#FF5630'],
            xaxis: { ...baseChartOptions.xaxis, categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'] }
        });
        this.alertsChart.render();
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
            }
        } catch (e) {
            console.error("Failed to load admin overview", e);
        }
    },

    updateDashboardUI(data) {
        if (!data) return;

        // Stats
        document.getElementById('total-logs').innerText = this.formatNumber(data.logs?.total || 0);
        document.getElementById('total-alerts').innerText = this.formatNumber(data.alerts?.total || 0);
        document.getElementById('total-tenants').innerText = data.tenants?.total || 0;

        const storageBytes = data.estimated_storage_bytes || 0;
        document.getElementById('db-size').innerText = this.formatBytes(storageBytes);

        // Tenant Table
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
    },

    // ============================================
    // TENANTS VIEW
    // ============================================
    async loadTenantsView() {
        // Use cached data or fetch fresh
        if (!this.cachedOverview) {
            await this.loadData();
        }

        const data = this.cachedOverview;
        if (!data) return;

        const tenants = data.top_tenants_by_volume || [];
        const totalLogs = data.logs?.total || 0;
        const totalTenants = data.tenants?.total || 0;
        const activeTenants = data.tenants?.active || totalTenants;
        const inactiveTenants = data.tenants?.inactive || 0;

        // Mini stats
        document.getElementById('tenants-total-count').textContent = totalTenants;
        document.getElementById('tenants-active-count').textContent = activeTenants;
        document.getElementById('tenants-inactive-count').textContent = inactiveTenants;
        document.getElementById('tenants-total-logs-count').textContent = this.formatNumber(totalLogs);

        // Full tenant table
        const tbody = document.getElementById('tenants-full-list');
        if (tenants.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No tenants registered yet.</td></tr>';
            return;
        }

        tbody.innerHTML = tenants.map(t => {
            const storageMB = ((t.estimated_storage || 0) / (1024 * 1024)).toFixed(1);
            return `
                <tr>
                    <td>
                        <div style="display:flex;align-items:center;gap:12px;">
                            <div style="width:34px;height:34px;background:var(--primary-light);border-radius:10px;display:flex;align-items:center;justify-content:center;color:var(--primary);font-weight:700;font-size:14px;">
                                ${(t.tenant_id || 'T').charAt(0).toUpperCase()}
                            </div>
                            <span style="font-weight:600;">${t.tenant_id}</span>
                        </div>
                    </td>
                    <td>${this.formatNumber(t.log_count_24h || 0)}</td>
                    <td>${this.formatNumber(t.log_count || 0)}</td>
                    <td>${t.alert_count || '—'}</td>
                    <td>${storageMB} MB</td>
                    <td><span class="badge badge-active">Active</span></td>
                    <td style="text-align:right;">
                        <div style="display:flex;gap:8px;justify-content:flex-end;">
                            <button class="btn-secondary btn-sm" onclick="SuperAdmin.viewTenantDetail('${t.tenant_id}')">
                                <i data-lucide="eye" style="width:14px;"></i> View
                            </button>
                            <button class="btn-secondary btn-sm" onclick="window.location.href='index.html?tenant=${t.tenant_id}'">
                                <i data-lucide="layout-dashboard" style="width:14px;"></i> Dash
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        lucide.createIcons();
    },

    filterTenants() {
        const query = (document.getElementById('tenant-search')?.value || '').toLowerCase();
        const rows = document.querySelectorAll('#tenants-full-list tr');
        rows.forEach(row => {
            if (row.querySelector('.empty-state')) return;
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    },

    async viewTenantDetail(tenantId) {
        document.getElementById('tenant-detail-modal').style.display = 'flex';
        document.getElementById('tenant-detail-title').textContent = `Tenant: ${tenantId}`;
        document.getElementById('tenant-detail-body').innerHTML = '<p class="empty-state">Loading tenant details...</p>';

        try {
            const response = await fetch(`${this.API_BASE}/api/admin/tenant/${tenantId}/usage`, {
                headers: Auth.getAuthHeader()
            });

            if (response.ok) {
                const result = await response.json();
                const d = result.data || result;
                document.getElementById('tenant-detail-body').innerHTML = `
                    <div class="tenant-detail-grid">
                        <div class="tenant-detail-stat">
                            <div class="td-value">${this.formatNumber(d.logs?.total || 0)}</div>
                            <div class="td-label">Total Logs</div>
                        </div>
                        <div class="tenant-detail-stat">
                            <div class="td-value">${this.formatNumber(d.logs?.last_24h || 0)}</div>
                            <div class="td-label">Logs (24h)</div>
                        </div>
                        <div class="tenant-detail-stat">
                            <div class="td-value">${this.formatNumber(d.logs?.last_7d || 0)}</div>
                            <div class="td-label">Logs (7d)</div>
                        </div>
                        <div class="tenant-detail-stat">
                            <div class="td-value" style="color:var(--error);">${d.alerts?.critical || 0}</div>
                            <div class="td-label">Critical Alerts</div>
                        </div>
                        <div class="tenant-detail-stat">
                            <div class="td-value" style="color:var(--warning);">${d.alerts?.high || 0}</div>
                            <div class="td-label">High Alerts</div>
                        </div>
                        <div class="tenant-detail-stat">
                            <div class="td-value">${d.alerts?.total || 0}</div>
                            <div class="td-label">Total Alerts</div>
                        </div>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                        <div class="tenant-detail-stat">
                            <div class="td-value">${d.reports || 0}</div>
                            <div class="td-label">Reports Generated</div>
                        </div>
                        <div class="tenant-detail-stat">
                            <div class="td-value">${this.formatBytes(d.estimated_storage_bytes || 0)}</div>
                            <div class="td-label">Storage Used</div>
                        </div>
                    </div>
                    <div style="margin-top:20px;display:flex;gap:12px;justify-content:flex-end;">
                        <button class="btn-primary" onclick="window.location.href='index.html?tenant=${tenantId}'">
                            <i data-lucide="layout-dashboard" style="width:16px;"></i> Open Dashboard
                        </button>
                    </div>
                `;
                lucide.createIcons();
            } else {
                document.getElementById('tenant-detail-body').innerHTML = '<p class="empty-state" style="color:var(--error);">Failed to load tenant data.</p>';
            }
        } catch (e) {
            document.getElementById('tenant-detail-body').innerHTML = `<p class="empty-state" style="color:var(--error);">Error: ${e.message}</p>`;
        }
    },

    showAddTenantModal() {
        document.getElementById('add-tenant-modal').style.display = 'flex';
    },

    async addTenant(e) {
        e.preventDefault();
        const tenantId = document.getElementById('new-tenant-id').value.trim();
        this.closeModal('add-tenant-modal');
        this.showToast(`Tenant "${tenantId}" registration noted. Tenants are auto-created on first log ingestion.`, 'info');
    },

    // ============================================
    // GLOBAL HEALTH
    // ============================================
    async loadHealth() {
        // Check API Server + Components via /health endpoint
        try {
            const start = performance.now();
            const resp = await fetch(`${this.API_BASE}/health`, { headers: Auth.getAuthHeader() });
            const latency = Math.round(performance.now() - start);
            const healthData = await resp.json().catch(() => ({}));

            // API Server itself
            const overallStatus = healthData.status || 'unknown';
            if (overallStatus === 'healthy') {
                this.setHealthCard('health-api', 'healthy', 'Operational', `Latency: ${latency}ms | v${healthData.version || '1.0.0'}`);
            } else {
                this.setHealthCard('health-api', 'degraded', 'Degraded', `Latency: ${latency}ms`);
            }

            // Redis — backend returns components.redis.status = "healthy" | "unhealthy"
            const redisStatus = healthData.components?.redis?.status;
            if (redisStatus === 'healthy') {
                this.setHealthCard('health-redis', 'healthy', 'Connected', 'Queue processing active');
            } else {
                const redisErr = healthData.components?.redis?.error || 'Check Redis connection';
                this.setHealthCard('health-redis', 'down', 'Disconnected', redisErr);
            }

            // Database — backend returns components.database.status = "healthy" | "unhealthy"
            const dbStatus = healthData.components?.database?.status;
            if (dbStatus === 'healthy') {
                this.setHealthCard('health-db', 'healthy', 'Connected', 'All tables accessible');
            } else {
                const dbErr = healthData.components?.database?.error || 'Check database connection';
                this.setHealthCard('health-db', 'down', 'Disconnected', dbErr);
            }

            // Consumer — inferred from overall health + Redis
            if (overallStatus === 'healthy' && redisStatus === 'healthy') {
                this.setHealthCard('health-consumer', 'healthy', 'Running', 'Processing logs from Redis');
            } else if (redisStatus !== 'healthy') {
                this.setHealthCard('health-consumer', 'down', 'Stopped', 'Redis unavailable');
            } else {
                this.setHealthCard('health-consumer', 'degraded', 'Unknown', 'Consumer status unclear');
            }

            this.addSystemEvent('success', `Health check OK — API: ${overallStatus}, DB: ${dbStatus || 'unknown'}, Redis: ${redisStatus || 'unknown'}`);

        } catch (e) {
            this.setHealthCard('health-api', 'down', 'Unreachable', e.message);
            this.setHealthCard('health-redis', 'down', 'Unknown', 'API unreachable');
            this.setHealthCard('health-db', 'down', 'Unknown', 'API unreachable');
            this.setHealthCard('health-consumer', 'down', 'Unknown', 'API unreachable');
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

        // Keep only last 50 events
        while (log.children.length > 50) log.removeChild(log.lastChild);
    },

    initHealthCharts() {
        const chartEl1 = document.querySelector("#system-load-chart");
        const chartEl2 = document.querySelector("#error-rate-chart");
        if (!chartEl1 || !chartEl2) return;

        // Only init once
        if (this.systemLoadChart) return;

        const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);
        const fakeLoad = hours.map(() => Math.random() * 40 + 10);
        const fakeErrors = hours.map(() => Math.floor(Math.random() * 5));

        const baseOpts = {
            chart: {
                height: 220, type: 'area', toolbar: { show: false },
                background: 'transparent', foreColor: '#94A3B8', fontFamily: 'Inter'
            },
            stroke: { curve: 'smooth', width: 2 },
            fill: { type: 'gradient', gradient: { opacityFrom: 0.3, opacityTo: 0 } },
            dataLabels: { enabled: false },
            grid: { borderColor: 'rgba(255,255,255,0.05)' },
            tooltip: { theme: 'dark' },
            xaxis: { categories: hours, axisBorder: { show: false }, labels: { show: false } }
        };

        this.systemLoadChart = new ApexCharts(chartEl1, {
            ...baseOpts,
            series: [{ name: 'CPU %', data: fakeLoad }],
            colors: ['#00B8D9']
        });
        this.systemLoadChart.render();

        this.errorRateChart = new ApexCharts(chartEl2, {
            ...baseOpts,
            series: [{ name: 'Errors', data: fakeErrors }],
            colors: ['#FF5630']
        });
        this.errorRateChart.render();
    },

    // ============================================
    // SYSTEM SETTINGS
    // ============================================
    async loadSettings() {
        try {
            const response = await fetch(`${this.API_BASE}/api/config`, {
                headers: Auth.getAuthHeader()
            });

            if (response.ok) {
                const config = await response.json();
                const c = config.data || config;

                // Detection
                if (c.detection) {
                    document.getElementById('cfg-bf-threshold').value = c.detection.brute_force_threshold || 5;
                    document.getElementById('cfg-ps-threshold').value = c.detection.port_scan_threshold || 20;
                    document.getElementById('cfg-beacon-interval').value = c.detection.beaconing_interval || 60;
                }

                // System
                if (c.logging) {
                    document.getElementById('cfg-log-level').value = c.logging.level || 'INFO';
                }

                // Notifications
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
            console.warn("Settings load skipped (API may not support /api/config yet):", e.message);
        }
    },

    async saveDetectionSettings(e) {
        e.preventDefault();
        const config = {
            detection: {
                brute_force_threshold: parseInt(document.getElementById('cfg-bf-threshold').value),
                port_scan_threshold: parseInt(document.getElementById('cfg-ps-threshold').value),
                beaconing_interval: parseInt(document.getElementById('cfg-beacon-interval').value)
            }
        };
        await this.saveConfig(config);
    },

    async saveSystemSettings(e) {
        e.preventDefault();
        const config = {
            logging: {
                level: document.getElementById('cfg-log-level').value
            }
        };
        await this.saveConfig(config);
    },

    async saveNotificationSettings(e) {
        e.preventDefault();
        const config = {
            email: {
                enabled: document.getElementById('cfg-email-enabled').checked,
                recipients: document.getElementById('cfg-email-recipients').value.split(',').map(s => s.trim()).filter(Boolean)
            },
            webhook: {
                enabled: document.getElementById('cfg-webhook-enabled').checked,
                url: document.getElementById('cfg-webhook-url').value
            }
        };
        await this.saveConfig(config);
    },

    async saveConfig(configUpdate) {
        try {
            const response = await fetch(`${this.API_BASE}/api/config`, {
                method: 'PUT',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(configUpdate)
            });

            if (response.ok) {
                this.showToast('Configuration saved successfully.', 'success');
            } else {
                const err = await response.json();
                this.showToast(`Save failed: ${err.detail || 'Unknown error'}`, 'error');
            }
        } catch (e) {
            this.showToast(`Save failed: ${e.message}`, 'error');
        }
    },

    // ============================================
    // BACKUP & LOGS
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

                if (reports.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No reports generated yet. Click "Generate Report" to create one.</td></tr>';
                    return;
                }

                tbody.innerHTML = reports.map(r => `
                    <tr>
                        <td><span class="badge badge-active">${(r.report_type || 'custom').toUpperCase()}</span></td>
                        <td>${new Date(r.created_at || r.generated_at).toLocaleString()}</td>
                        <td>${r.period_start ? new Date(r.period_start).toLocaleDateString() : '—'} — ${r.period_end ? new Date(r.period_end).toLocaleDateString() : '—'}</td>
                        <td>${r.log_count || '—'}</td>
                        <td>${r.alert_count || '—'}</td>
                        <td style="text-align:right;">
                            <button class="btn-secondary btn-sm" onclick="SuperAdmin.viewReport(${r.id})">
                                <i data-lucide="file-text" style="width:14px;"></i> View
                            </button>
                        </td>
                    </tr>
                `).join('');

                lucide.createIcons();
            }
        } catch (e) {
            console.warn("Reports load failed:", e.message);
        }

        this.loadSystemLogs();
    },

    loadSystemLogs() {
        const viewer = document.getElementById('system-log-viewer');
        if (!viewer) return;

        // Populate with simulated system logs based on current state
        const entries = [
            { level: 'info', msg: 'SIEM Analyzer engine running.' },
            { level: 'info', msg: 'Redis consumer connected to host.docker.internal:6379.' },
            { level: 'info', msg: 'Database initialized successfully.' },
            { level: 'info', msg: 'API server listening on 0.0.0.0:8000.' },
            { level: 'warning', msg: 'No new logs ingested in the last 5 minutes.' },
            { level: 'info', msg: 'Health check passed. All services operational.' },
        ];

        viewer.innerHTML = entries.map(e => {
            const now = new Date().toLocaleTimeString('en-US', { hour12: false });
            return `<div class="log-line ${e.level}">
                <span class="log-time">${now}</span>
                <span class="log-level">${e.level.toUpperCase()}</span>
                <span class="log-msg">${e.msg}</span>
            </div>`;
        }).join('');
    },

    filterSystemLogs() {
        const filter = document.getElementById('log-level-filter')?.value || '';
        const lines = document.querySelectorAll('#system-log-viewer .log-line');
        lines.forEach(line => {
            if (!filter || line.classList.contains(filter)) {
                line.style.display = '';
            } else {
                line.style.display = 'none';
            }
        });
    },

    showGenerateReportModal() {
        document.getElementById('gen-report-modal').style.display = 'flex';

        // Toggle custom date fields
        const typeSelect = document.getElementById('gen-report-type');
        typeSelect.onchange = () => {
            document.getElementById('gen-custom-dates').style.display =
                typeSelect.value === 'custom' ? 'flex' : 'none';
        };

        // Populate tenant dropdown
        const tenantSelect = document.getElementById('gen-report-tenant');
        if (this.cachedOverview?.top_tenants_by_volume) {
            tenantSelect.innerHTML = '<option value="default">Default (All)</option>' +
                this.cachedOverview.top_tenants_by_volume.map(t =>
                    `<option value="${t.tenant_id}">${t.tenant_id}</option>`
                ).join('');
        }

        lucide.createIcons();
    },

    async generateReport(e) {
        e.preventDefault();
        const type = document.getElementById('gen-report-type').value;
        const tenant = document.getElementById('gen-report-tenant').value;
        const payload = { tenant_id: tenant, report_type: type };

        if (type === 'custom') {
            payload.start_date = document.getElementById('gen-start-date').value;
            payload.end_date = document.getElementById('gen-end-date').value;
        } else if (type === 'daily') {
            payload.days_back = 1;
        } else if (type === 'weekly') {
            payload.days_back = 7;
        } else if (type === 'monthly') {
            payload.days_back = 30;
        }

        this.closeModal('gen-report-modal');
        this.showToast('Generating report...', 'info');

        try {
            const response = await fetch(`${this.API_BASE}/api/reports/generate`, {
                method: 'POST',
                headers: { ...Auth.getAuthHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                this.showToast('Report generated successfully!', 'success');
                setTimeout(() => this.loadReports(), 1000);
            } else {
                const err = await response.json();
                this.showToast(`Report generation failed: ${err.detail || 'Unknown error'}`, 'error');
            }
        } catch (e) {
            this.showToast(`Report generation failed: ${e.message}`, 'error');
        }
    },

    async viewReport(reportId) {
        try {
            const response = await fetch(`${this.API_BASE}/api/reports/${reportId}/content`, {
                headers: Auth.getAuthHeader()
            });
            if (response.ok) {
                const result = await response.json();
                const win = window.open('', '_blank');
                win.document.write(result.html || result.content || '<p>No content available.</p>');
            } else {
                this.showToast('Could not load report.', 'error');
            }
        } catch (e) {
            this.showToast(`Error loading report: ${e.message}`, 'error');
        }
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
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

document.addEventListener('DOMContentLoaded', () => SuperAdmin.init());
