/**
 * superadmin.js - Superadmin Dashboard Logic
 */

const SuperAdmin = {
    API_BASE: window.location.origin,
    tenantsChart: null,
    alertsChart: null,

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

        this.initCharts();
        await this.loadData();

        // Refresh every minute
        setInterval(() => this.loadData(), 60000);

        lucide.createIcons();
    },

    initCharts() {
        const chartOptions = {
            chart: {
                height: 250,
                type: 'area',
                toolbar: { show: false },
                background: 'transparent',
                foreColor: '#94A3B8',
                fontFamily: 'Inter, sans-serif'
            },
            stroke: { curve: 'smooth', width: 3 },
            fill: {
                type: 'gradient',
                gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0, stops: [0, 90, 100] }
            },
            dataLabels: { enabled: false },
            grid: { borderColor: 'rgba(255,255,255,0.05)', strokeDashArray: 3 },
            xaxis: { axisBorder: { show: false }, axisTicks: { show: false } }
        };

        this.tenantsChart = new ApexCharts(document.querySelector("#tenants-chart"), {
            ...chartOptions,
            series: [{ name: 'Logs', data: [12, 41, 35, 51, 49, 62, 69, 91, 148] }],
            colors: ['#3366FF'],
            xaxis: { categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'] }
        });
        this.tenantsChart.render();

        this.alertsChart = new ApexCharts(document.querySelector("#alerts-chart"), {
            ...chartOptions,
            series: [{ name: 'Alerts', data: [23, 11, 22, 27, 13, 19, 37, 21, 44] }],
            colors: ['#FF5630'],
            xaxis: { categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'] }
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
                if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--error);">Access Denied: Backend rejected your token. Please check .env SECRET_KEY.</td></tr>';
                return;
            }

            if (response.ok) {
                const result = await response.json();
                this.updateUI(result.data);
            }
        } catch (e) {
            console.error("Failed to load admin overview", e);
        }
    },

    updateUI(data) {
        if (!data) return;

        // Update Stat Cards (Mapping from backend nested structure)
        document.getElementById('total-logs').innerText = this.formatNumber(data.logs?.total || 0);
        document.getElementById('total-alerts').innerText = this.formatNumber(data.alerts?.total || 0);
        document.getElementById('total-tenants').innerText = data.tenants?.total || 0;

        // Convert bytes to MB/GB for display
        const storageBytes = data.estimated_storage_bytes || 0;
        const storageMB = (storageBytes / (1024 * 1024)).toFixed(2);
        document.getElementById('db-size').innerText = `${storageMB} MB`;

        // Update Tenant Table (Using top_tenants_by_volume)
        const tbody = document.getElementById('tenant-list');
        if (tbody && data.top_tenants_by_volume) {
            tbody.innerHTML = data.top_tenants_by_volume.map(t => `
                <tr>
                    <td><div style="display:flex;align-items:center;gap:12px;">
                        <div style="width:32px;height:32px;background:rgba(51,102,255,0.1);border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--primary);font-weight:700;">${(t.tenant_id || 'T').charAt(0).toUpperCase()}</div>
                        <span>${t.tenant_id}</span>
                    </div></td>
                    <td>${this.formatNumber(t.log_count || 0)}</td>
                    <td>—</td>
                    <td><span class="tenant-badge badge-active">Active</span></td>
                    <td style="text-align:right;"><button class="nav-item" style="padding:4px 8px;margin:0;" onclick="window.location.href='index.html?tenant=${t.tenant_id}'">View Dash</button></td>
                </tr>
            `).join('');
        }
    },

    formatNumber(n) {
        return n.toLocaleString();
    }
};

document.addEventListener('DOMContentLoaded', () => SuperAdmin.init());
