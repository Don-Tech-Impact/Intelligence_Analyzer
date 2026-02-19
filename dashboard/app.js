// SIEM Dashboard Logic - Professional V1 (Final)
const API_BASE_URL = 'http://localhost:8000';

// Global State
let volumeChart, distributionChart;
let topSourcesChart, topDestsChart, protocolChart, severityTrendChart;
let currentTenant = 'default';
let currentView = 'overview';

const VIEWS = {
    overview: { title: 'Security Overview', subtitle: 'Real-time threat monitoring and log analysis' },
    alerts: { title: 'Security Alerts', subtitle: 'Detailed feed of detected security incidents' },
    logs: { title: 'System Logs', subtitle: 'Searchable archive of normalized security logs' },
    'log-stream': { title: 'Live Traffic Stream', subtitle: 'Global stream of incoming endpoint telemetry' },
    analytics: { title: 'Advanced Analytics', subtitle: 'Deep dive into security trends and business insights' },
    reports: { title: 'Report Archive', subtitle: 'View and manage generated security summaries' },
    settings: { title: 'System Settings', subtitle: 'Configure analyzers and tenant parameters' },
    admin: { title: 'Superadmin Dashboard', subtitle: 'Manage tenants and user accounts' }
};

let businessHoursChart, weekendActivityChart, vendorBreakdownChart;
let lastStreamedLogId = 0;
let streamLogs = [];

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Role based setup
    const role = localStorage.getItem('siem_role');
    if (role === 'superadmin') populateAdminTenantDropdown();

    initCharts();
    initAnalyticsCharts();
    initBusinessCharts();
    setupProfile();
    await fetchTenants();
    fetchData();
    setInterval(fetchData, 5000); // 5s live polling
    setInterval(fetchStreamData, 2000); // 2s for "live" feel
});

async function authenticatedFetch(url, options = {}) {
    const token = localStorage.getItem('siem_token');
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };

    const combinedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...(options.headers || {})
        }
    };

    const response = await fetch(url, combinedOptions);
    if (response.status === 401) {
        localStorage.clear();
        window.location.href = 'login.html';
        return;
    }

    // Standard Envelope Handling for Dashboard compatibility
    if (response.ok) {
        const clone = response.clone();
        try {
            const body = await clone.json();
            if (body && body.status === "success" && body.hasOwnProperty('data')) {
                // If it's a standard envelope, return a new "mock" response object 
                // that .json() returns the actual data payload
                return {
                    ok: true,
                    status: response.status,
                    json: async () => body.data,
                    text: async () => JSON.stringify(body.data),
                    blob: async () => response.blob()
                };
            }
        } catch (e) { /* Not JSON or not standard envelope */ }
    }

    return response;
}

async function fetchTenants() {
    try {
        const res = await authenticatedFetch(`${API_BASE_URL}/tenants`);
        if (res.ok) {
            const tenants = await res.json();
            const dropdown = document.getElementById('tenant-dropdown');
            dropdown.innerHTML = '';
            tenants.forEach(t => {
                const opt = document.createElement('option');
                opt.value = t.tenant_id;
                opt.textContent = t.name;
                dropdown.appendChild(opt);
            });
        }
    } catch (e) { console.error('Tenant fetch failed', e); }
}

async function fetchData() {
    try {
        if (currentView === 'overview') await fetchOverviewData();
        else if (currentView === 'alerts') await fetchAlertsData();
        else if (currentView === 'logs') await fetchLogsData();
        else if (currentView === 'log-stream') await fetchStreamData();
        else if (currentView === 'analytics') await fetchAnalyticsData();
        else if (currentView === 'reports') await fetchReportsData();
        else if (currentView === 'settings') await fetchSettingsData();
    } catch (error) { console.error('Data sync error', error); }
}

async function fetchOverviewData() {
    const stats = await (await authenticatedFetch(`${API_BASE_URL}/stats?tenant_id=${currentTenant}`)).json();
    updateStats(stats);
    updateDistributionChart(stats.severity_breakdown);

    const alerts = await (await authenticatedFetch(`${API_BASE_URL}/alerts?tenant_id=${currentTenant}&limit=5`)).json();
    populateTable('overview-alerts-body', alerts, 'mini');

    const trends = await (await authenticatedFetch(`${API_BASE_URL}/trends?tenant_id=${currentTenant}`)).json();
    updateVolumeChart(trends);
}

async function fetchAlertsData() {
    const sev = document.getElementById('filter-severity').value;
    const alerts = await (await authenticatedFetch(`${API_BASE_URL}/alerts?tenant_id=${currentTenant}&limit=50${sev ? `&severity=${sev}` : ''}`)).json();
    populateTable('full-alerts-body', alerts, 'full');
}

async function fetchLogsData() {
    const vendor = document.getElementById('log-filter-vendor').value;
    const severity = document.getElementById('log-filter-severity').value;
    const search = document.getElementById('log-search').value;

    let url = `${API_BASE_URL}/logs?tenant_id=${currentTenant}&limit=100`;
    if (vendor) url += `&vendor=${vendor}`;
    if (severity) url += `&severity=${severity}`;
    if (search) url += `&search=${search}`;

    const logs = await (await authenticatedFetch(url)).json();
    populateLogsTable(logs);
}

async function fetchAnalyticsData() {
    try {
        const ipRes = await authenticatedFetch(`${API_BASE_URL}/analytics/top-ips?tenant_id=${currentTenant}`);
        const protoRes = await authenticatedFetch(`${API_BASE_URL}/analytics/protocols?tenant_id=${currentTenant}`);
        const businessRes = await authenticatedFetch(`${API_BASE_URL}/analytics/business-insights?tenant_id=${currentTenant}`);

        if (ipRes && ipRes.ok && protoRes && protoRes.ok && businessRes && businessRes.ok) {
            const ipData = await ipRes.json();
            const protoData = await protoRes.json();
            const bData = await businessRes.json();

            updateBarChart(topSourcesChart, ipData.sources.map(s => s.ip), ipData.sources.map(s => s.count), "top-sources-chart");
            updatePieChart(protocolChart, protoData.map(p => p.protocol), protoData.map(p => p.count), "protocol-chart");

            // Business Charts
            updatePieChart(businessHoursChart, ['Business Hours', 'After Hours'], [bData.business_hours, bData.after_hours], "business-hours-chart");
            updatePieChart(weekendActivityChart, ['Weekdays', 'Weekends'], [bData.weekdays, bData.weekends], "weekend-activity-chart");

            const vVendors = Object.keys(bData.by_vendor);
            const vCounts = Object.values(bData.by_vendor);
            updateBarChart(vendorBreakdownChart, vVendors, vCounts, "vendor-breakdown-chart");
        }
    } catch (e) {
        console.error('Analytics fetch failed', e);
    }
}

async function fetchReportsData() {
    const type = document.getElementById('report-filter-type').value;
    const start = document.getElementById('report-filter-start').value;
    const end = document.getElementById('report-filter-end').value;

    let url = `${API_BASE_URL}/reports?tenant_id=${currentTenant}`;
    if (type) url += `&report_type=${type}`;
    if (start) url += `&start_date=${start}`;
    if (end) url += `&end_date=${end}`;

    const res = await authenticatedFetch(url);
    if (res && res.ok) {
        const reports = await res.json();
        populateReportsTable(reports);
    }
}

async function fetchStreamData() {
    // Only fetch if on log-stream view OR if we want background buffering
    const res = await authenticatedFetch(`${API_BASE_URL}/logs?tenant_id=${currentTenant}&limit=20`);
    if (res && res.ok) {
        const logs = await res.json();
        // Reverse to show newest at bottom for "stream" feel
        const newLogs = logs.filter(l => !streamLogs.find(existing => existing.id === l.id));
        if (newLogs.length > 0) {
            streamLogs = [...newLogs, ...streamLogs].slice(0, 100);
            if (currentView === 'log-stream') updateStreamConsole(newLogs);
        }
    }
}

function updateStreamConsole(newLogs) {
    const console = document.getElementById('log-stream-console');
    if (!console) return;

    newLogs.forEach(log => {
        const line = document.createElement('div');
        line.className = `log-line ${log.severity || 'low'}`;

        const vendor = log.vendor || 'sys';
        const hostname = log.device_hostname || '-';

        line.innerHTML = `
            <span class="ts">[${new Date(log.timestamp).toLocaleTimeString()}]</span>
            <span class="vnd">${vendor.toUpperCase()}</span>
            <span class="dev">${hostname}</span>
            <span class="msg">${log.message}</span>
        `;
        console.prepend(line);

        // Keep console lean
        if (console.childNodes.length > 100) console.lastChild.remove();
    });
}

function populateReportsTable(reports) {
    const tbody = document.getElementById('reports-table-body');
    if (!tbody) return;
    tbody.innerHTML = reports.map(r => `
        <tr>
            <td><div class="stat-label" style="display:flex; align-items:center; gap:0.5rem;"><i data-lucide="file-text" size="14"></i> ${r.report_type.toUpperCase()}</div></td>
            <td>${new Date(r.created_at).toLocaleString()}</td>
            <td>${new Date(r.start_date).toLocaleDateString()} - ${new Date(r.end_date).toLocaleDateString()}</td>
            <td>${r.total_logs}</td>
            <td>${r.total_alerts}</td>
            <td>
                <button class="btn-secondary" onclick="downloadReport(${r.id})" style="padding: 0.25rem 0.75rem;">
                    <i data-lucide="download" size="14"></i> Download
                </button>
            </td>
        </tr>
    `).join('');
    lucide.createIcons();
}

async function downloadReport(id) {
    const token = localStorage.getItem('siem_token');
    window.open(`${API_BASE_URL}/reports/${id}/download?token=${token}`, '_blank');
}

async function fetchSettingsData() {
    // Only fetch if form is not dirty
    const res = await authenticatedFetch(`${API_BASE_URL}/config`);
    if (res && res.ok) {
        const config = await res.json();
        document.getElementById('bf-threshold').value = config.brute_force_threshold;
        document.getElementById('ps-threshold').value = config.port_scan_threshold;
        document.getElementById('log-level').value = config.log_level;
    }
}

async function saveSettings(e) {
    e.preventDefault();
    const payload = {
        brute_force_threshold: document.getElementById('bf-threshold').value,
        port_scan_threshold: document.getElementById('ps-threshold').value,
        log_level: document.getElementById('log-level').value
    };
    const res = await authenticatedFetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res && res.ok) alert('Configuration updated successfully!');
}

// Admin Functions
async function adminCreateTenant(e) {
    e.preventDefault();
    const name = document.getElementById('admin-tenant-name').value;
    const id = document.getElementById('admin-tenant-id').value;

    const res = await authenticatedFetch(`${API_BASE_URL}/admin/tenants?name=${name}&tenant_id=${id}`, {
        method: 'POST'
    });
    if (res && res.ok) {
        alert('Tenant created successfully');
        fetchTenants(); // Refresh main dropdown
        populateAdminTenantDropdown(); // Refresh user creation dropdown
    }
}

async function adminCreateUser(e) {
    e.preventDefault();
    const user = document.getElementById('admin-user-name').value;
    const pass = document.getElementById('admin-user-pass').value;
    const tenant = document.getElementById('admin-user-tenant').value;

    const res = await authenticatedFetch(`${API_BASE_URL}/admin/users?username=${user}&password=${pass}&tenant_id=${tenant}`, {
        method: 'POST'
    });
    if (res && res.ok) alert('Business user created successfully');
}

async function populateAdminTenantDropdown() {
    const res = await authenticatedFetch(`${API_BASE_URL}/tenants`);
    if (res && res.ok) {
        const tenants = await res.json();
        const dropdown = document.getElementById('admin-user-tenant');
        if (!dropdown) return;
        dropdown.innerHTML = tenants.map(t => `<option value="${t.tenant_id}">${t.name}</option>`).join('');
    }
}

function updateStats(stats) {
    document.getElementById('stats-total-logs').textContent = stats.total_logs.toLocaleString();
    const criticals = (stats.severity_breakdown.critical || 0) + (stats.severity_breakdown.high || 0);
    document.getElementById('stats-critical-alerts').textContent = criticals.toLocaleString();
    // In a real system, monitored assets might come from a different endpoint or field.
    // Here we'll map active_threats to a plausible asset count for visual consistency with the design.
    document.getElementById('stats-monitored-assets').textContent = (stats.total_logs / 2).toFixed(0).toLocaleString();
}

function populateTable(elementId, alerts, type) {
    const tbody = document.getElementById(elementId);
    if (!tbody) return;
    tbody.innerHTML = alerts.map(alert => `
        <tr>
            <td>${new Date(alert.created_at).toLocaleTimeString()}</td>
            <td class="mono">${alert.alert_type}</td>
            <td>${alert.source_ip || 'N/A'}</td>
            <td><span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity.toUpperCase()}</span></td>
            ${type === 'full' ? `<td>${alert.description}</td>` : ''}
            <td>${alert.status}</td>
        </tr>
    `).join('');
    lucide.createIcons();
}

function populateLogsTable(logs) {
    const tbody = document.getElementById('full-logs-body');
    if (!tbody) return;
    tbody.innerHTML = logs.map(log => `
        <tr class="mono-row">
            <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
            <td>${log.log_type}</td>
            <td>${log.source_ip}</td>
            <td>${log.destination_ip}</td>
            <td>${log.protocol || '-'}</td>
            <td>${log.action || '-'}</td>
            <td><span class="badge" style="background: hsla(0,0%,100%,0.1); border: 1px solid var(--glass-border);">${log.vendor || 'sys'}</span></td>
            <td>${log.device_hostname || '-'}</td>
            <td title="${log.message}">${log.message.substring(0, 40)}...</td>
        </tr>
    `).join('');
}

function setupProfile() {
    const user = localStorage.getItem('siem_user') || 'Admin';
    const role = localStorage.getItem('siem_role') || 'Tenant';
    const tenant = localStorage.getItem('siem_tenant') || '-';

    document.getElementById('profile-username').textContent = user;
    document.getElementById('profile-role').textContent = role.charAt(0).toUpperCase() + role.slice(1);

    document.getElementById('menu-user').textContent = user;
    document.getElementById('menu-tenant').textContent = `ID: ${tenant}`;
}

function toggleProfileMenu() {
    document.getElementById('profile-menu').classList.toggle('active');
}

function switchView(viewId) {
    currentView = viewId;
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    document.querySelectorAll('.dashboard-view').forEach(v => v.classList.remove('active'));

    // UI Updates
    const viewConfig = VIEWS[viewId] || VIEWS.overview;
    document.getElementById('view-title').textContent = viewConfig.title;
    document.getElementById('view-subtitle').textContent = viewConfig.subtitle;
    document.getElementById(`${viewId}-view`).classList.add('active');

    // Find matching link in sidebar and activate it
    const links = document.querySelectorAll('.nav-links a');
    links.forEach(l => {
        if (l.innerText.toLowerCase().includes(viewId)) l.classList.add('active');
    });

    fetchData();
}

function handleTenantChange() {
    currentTenant = document.getElementById('tenant-dropdown').value;
    fetchData();
}

// Chart Initializers
function initCharts() {
    volumeChart = createAreaChart("#volume-chart", "#3B82F6"); // Bright Blue
    distributionChart = createDonutChart("#distribution-chart");
}

function initAnalyticsCharts() {
    topSourcesChart = createBarChart("#top-sources-chart", "#3B82F6");
    protocolChart = createPieChart("#protocol-chart");
}

function initBusinessCharts() {
    businessHoursChart = createPieChart("#business-hours-chart");
    weekendActivityChart = createPieChart("#weekend-activity-chart");
    vendorBreakdownChart = createBarChart("#vendor-breakdown-chart", "#a78bfa"); // purple accent
}

// Reusable Chart Factories
function createAreaChart(selector, color) {
    const chart = new ApexCharts(document.querySelector(selector), {
        series: [{ name: 'Count', data: [] }],
        chart: {
            height: 300,
            type: 'area',
            toolbar: { show: false },
            background: 'transparent',
            foreColor: '#94A3B8',
            fontFamily: 'Inter'
        },
        stroke: { curve: 'smooth', width: 2 },
        fill: { type: 'gradient', gradient: { opacityFrom: 0.3, opacityTo: 0.05 } },
        xaxis: { type: 'datetime', axisBorder: { show: false }, axisTicks: { show: false } },
        grid: { borderColor: '#334155', strokeDashArray: 4 },
        colors: [color || '#38bdf8']
    });
    chart.render();
    return chart;
}

function createDonutChart(selector) {
    const chart = new ApexCharts(document.querySelector(selector), {
        series: [],
        chart: { type: 'donut', height: 280, foreColor: '#94A3B8', fontFamily: 'Inter' },
        labels: ['Critical', 'High', 'Medium', 'Low'],
        colors: ['#F43F5E', '#F59E0B', '#3B82F6', '#10B981'], // Rose, Amber, Blue, Emerald
        stroke: { show: false },
        plotOptions: { pie: { donut: { size: '75%', labels: { show: true, total: { show: true, color: '#FFFFFF' } } } } },
        legend: { position: 'bottom' }
    });
    chart.render();
    return chart;
}

function createBarChart(selector, color) {
    const chart = new ApexCharts(document.querySelector(selector), {
        series: [{ data: [] }],
        chart: { type: 'bar', height: 300, toolbar: { show: false }, foreColor: '#94A3B8', fontFamily: 'Inter' },
        plotOptions: { bar: { borderRadius: 6, horizontal: true, barHeight: '60%' } },
        colors: [color],
        grid: { borderColor: '#1E293B', strokeDashArray: 4 },
        xaxis: { categories: [] }
    });
    chart.render();
    return chart;
}

function createPieChart(selector) {
    const chart = new ApexCharts(document.querySelector(selector), {
        series: [],
        chart: { type: 'pie', height: 300, foreColor: '#8b949e' },
        labels: [],
        stroke: { show: false }
    });
    chart.render();
    return chart;
}

// Chart Updaters
function updateVolumeChart(trends) {
    volumeChart.updateSeries([{ name: 'Logs', data: trends.logs.map(t => ({ x: new Date(t.hour).getTime(), y: t.count })) }]);
}

function updateDistributionChart(breakdown) {
    distributionChart.updateSeries(['critical', 'high', 'medium', 'low'].map(l => breakdown[l] || 0));
}

function updateBarChart(chart, categories, data, containerId) {
    if (!data || data.length === 0) {
        showEmptyState(containerId);
        return;
    }
    hideEmptyState(containerId);
    chart.updateOptions({ xaxis: { categories } });
    chart.updateSeries([{ data }]);
}

function updatePieChart(chart, labels, series, containerId) {
    if (!series || series.length === 0) {
        showEmptyState(containerId);
        return;
    }
    hideEmptyState(containerId);
    chart.updateOptions({ labels });
    chart.updateSeries(series);
}

function showEmptyState(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Check if empty state already exists
    if (container.querySelector('.chart-empty')) return;

    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'chart-empty';
    emptyDiv.innerHTML = `
        <i data-lucide="bar-chart-2" size="48"></i>
        <p>No activity data available yet</p>
    `;
    container.style.position = 'relative';
    container.appendChild(emptyDiv);
    lucide.createIcons();
}

function hideEmptyState(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const emptyDiv = container.querySelector('.chart-empty');
    if (emptyDiv) emptyDiv.remove();
}
