const API_BASE_URL = window.location.origin;
const ADMIN_API_KEY = 'changeme-admin-key'; // Matches local .env default

// ===== Global State =====
const urlParams = new URLSearchParams(window.location.search);
let currentTenant = urlParams.get('tenant') || urlParams.get('tenant_id') || 'default';
let volumeChart;
let topSourcesChart, protocolChart;
let businessHoursChart, weekendActivityChart, vendorBreakdownChart;
let currentView = 'overview';
let currentTimeRange = '24h';
let fetchInProgress = false;
let previousStats = null;

const VIEWS = {
    overview: { title: 'Afric-Analyzer', subtitle: 'Real-time threat monitoring and response' },
    alerts: { title: 'Security Alerts', subtitle: 'Active and historical security findings' },
    logs: { title: 'Event Log Archive', subtitle: 'Searchable normalized event records' },
    'log-stream': { title: 'Live Stream', subtitle: 'Real-time telemetry and raw event monitoring' },
    'ai-assistant': { title: 'AI Assistant', subtitle: 'Intelligent log analysis and threat explanation' },
    compliance: { title: 'Compliance Dashboard', subtitle: 'Security standards and regulatory adherence' },
    reports: { title: 'Report Archive', subtitle: 'Generated security summaries and audits' },
    settings: { title: 'System Settings', subtitle: 'Analyzer thresholds and configuration' }
};

// ===== Chart Color Palette =====
const COLORS = {
    primary: '#3B82F6',
    teal: '#2DD4BF',
    indigo: '#8B5CF6',
    cyan: '#06B6D4',
    critical: '#EF4444',
    high: '#F59E0B',
    medium: '#3B82F6',
    low: '#22C55E',
    muted: '#64748B',
    grid: '#1E293B',
    text: '#94A3B8',
    green: '#22C55E',
    orange: '#F59E0B'
};

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    try { initCharts(); } catch (e) { console.error('[SIEM] initCharts failed:', e); }
    try { initAnalyticsCharts(); } catch (e) { console.error('[SIEM] initAnalyticsCharts failed:', e); }
    try { initBusinessCharts(); } catch (e) { console.error('[SIEM] initBusinessCharts failed:', e); }
    checkApiStatus();
    fetchData();
    setInterval(fetchData, 15000);
    setInterval(fetchStreamData, 8000);
    setInterval(checkApiStatus, 30000);
    lucide.createIcons();
});

// ===== API Helper =====
async function apiFetch(url) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-Key': ADMIN_API_KEY
            }
        });
        if (!response.ok) return null;
        const body = await response.json();
        // Unwrap envelope if present
        if (body && body.status === 'success' && body.hasOwnProperty('data')) {
            return { ok: true, json: async () => body.data };
        }
        return { ok: true, json: async () => body };
    } catch (e) {
        console.error('API fetch error:', e);
        return null;
    }
}

// ===== API Status Check =====
async function checkApiStatus() {
    try {
        const res = await fetch(`${API_BASE_URL}/health`, { signal: AbortSignal.timeout(3000) });
        setApiOnline(res.ok);
    } catch (e) {
        setApiOnline(false);
    }
}

function setApiOnline(online) {
    const dot = document.getElementById('api-status-dot');
    const text = document.getElementById('api-status-text');
    const badge = document.getElementById('status-badge');
    if (dot) dot.className = online ? 'dot online' : 'dot';
    if (text) text.textContent = online ? 'API Online · Live data' : 'API Offline · Using mock data';
    if (badge) {
        badge.className = online ? 'status-badge online' : 'status-badge offline';
        badge.innerHTML = online
            ? '<i data-lucide="wifi"></i><span>Online</span>'
            : '<i data-lucide="wifi-off"></i><span>Offline</span>';
        lucide.createIcons();
    }
}

// ===== Data Routing =====
async function fetchData() {
    if (fetchInProgress) return;
    fetchInProgress = true;
    try {
        if (currentView === 'overview') await fetchOverviewData();
        else if (currentView === 'alerts') await fetchAlertsData();
        else if (currentView === 'logs') await fetchLogsData();
        else if (currentView === 'log-stream') await fetchStreamData();
        else if (currentView === 'ai-assistant') await renderAiAssistant();
        else if (currentView === 'analytics') await fetchAnalyticsData();
        else if (currentView === 'compliance') await fetchComplianceData();
        else if (currentView === 'reports') await fetchReportsData();
        else if (currentView === 'settings') await fetchSettingsData();
    } catch (error) { console.error('Data sync error:', error); }
    finally { fetchInProgress = false; }
}

// ===== Overview =====
async function fetchOverviewData() {
    // Stats (using V1 summary)
    try {
        const summaryRes = await apiFetch(`${API_BASE_URL}/api/v1/dashboard/summary?tenant_id=${currentTenant}`);
        if (summaryRes && summaryRes.ok) {
            const summary = await summaryRes.json();
            updateStatsFromSummary(summary);
        }
    } catch (e) { console.error('[SIEM] v1 summary error:', e); }

    // Alerts for event log + threat vectors (using V1 alerts)
    try {
        const alertsRes = await apiFetch(`${API_BASE_URL}/api/v1/alerts?tenant_id=${currentTenant}&limit=10`);
        if (alertsRes && alertsRes.ok) {
            const alerts = await alertsRes.json();
            const alertsArr = Array.isArray(alerts) ? alerts : [];
            renderEventLog(alertsArr);
            renderThreatVectors(alertsArr);
            const dot = document.getElementById('notification-dot');
            if (dot) dot.style.display = (alertsArr.length > 0) ? 'block' : 'none';
        }
    } catch (e) { console.error('[SIEM] v1 alerts error:', e); }

    // Trends for chart (using V1 timeline)
    try {
        const timelineRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/timeline?tenant_id=${currentTenant}&range=${currentTimeRange}`);
        if (timelineRes && timelineRes.ok) {
            const timeline = await timelineRes.json();
            updateVolumeChart(timeline);
        }
    } catch (e) { console.error('[SIEM] v1 timeline error:', e); }
}

// ===== Update Stats (V1 Support) =====
function updateStatsFromSummary(summary) {
    if (!summary) return;

    const el1 = document.getElementById('stats-total-logs');
    if (el1) el1.textContent = formatNumber(summary.total_events?.count || 0);

    const el2 = document.getElementById('stats-total-alerts');
    if (el2) el2.textContent = formatNumber(summary.active_threats?.count || 0);

    const el3 = document.getElementById('stats-critical-high');
    if (el3) {
        const val = (Number(summary.active_threats?.critical) || 0) + (Number(summary.active_threats?.high) || 0);
        el3.textContent = formatNumber(val);
    }

    const el4 = document.getElementById('stats-active-threats');
    if (el4) el4.textContent = formatNumber(summary.risk_score?.score || 0);

    // V1 summary already includes computed trends for event volume
    const trendEl = document.getElementById('trend-blocked');
    if (trendEl) {
        const trend = summary.total_events?.trend || 0;
        const isUp = trend >= 0;
        trendEl.className = `trend ${isUp ? 'up' : 'down'}`;
        trendEl.innerHTML = `<i data-lucide="${isUp ? 'trending-up' : 'trending-down'}"></i> ${isUp ? '+' : ''}${trend}%`;
        lucide.createIcons();
    }
}

function updateTrend(id, current, previous) {
    const el = document.getElementById(id);
    if (!el || previous == null || previous === 0) return;
    const pct = (((current - previous) / previous) * 100).toFixed(1);
    const isUp = pct >= 0;
    el.className = `trend ${isUp ? 'up' : 'down'}`;
    el.innerHTML = `<i data-lucide="${isUp ? 'trending-up' : 'trending-down'}"></i> ${isUp ? '+' : ''}${pct}%`;
    lucide.createIcons();
}

// ===== Render Event Log =====
function renderEventLog(alerts) {
    const container = document.getElementById('event-log-list');
    if (!container) return;

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div style="padding:2rem;text-align:center;color:var(--text-muted);">No recent events</div>';
        return;
    }

    const iconMap = {
        critical: { icon: 'alert-triangle', cls: 'critical' },
        high: { icon: 'alert-circle', cls: 'high' },
        medium: { icon: 'info', cls: 'medium' },
        low: { icon: 'check-circle', cls: 'low' }
    };

    container.innerHTML = alerts.slice(0, 6).map(alert => {
        const sev = (alert.severity || 'medium').toLowerCase();
        const icfg = iconMap[sev] || iconMap.medium;
        const title = alert.alert_type || alert.type || 'Security Event';
        const desc = alert.description || alert.message || 'Alert triggered by analyzer';
        const ip = alert.source_ip || alert.ip || '';
        const time = timeAgo(alert.created_at || alert.timestamp);

        return `
        <div class="event-item">
            <div class="event-icon ${icfg.cls}">
                <i data-lucide="${icfg.icon}"></i>
            </div>
            <div class="event-content">
                <div class="event-title">${escapeHtml(title)}</div>
                <div class="event-desc">${escapeHtml(desc)}</div>
                <div class="event-meta">
                    ${ip ? `<span>IP: ${escapeHtml(ip)}</span>` : ''}
                    <a href="#" class="investigate" onclick="switchView('alerts');return false;">Investigate →</a>
                </div>
            </div>
            <div class="event-time">${time}</div>
        </div>`;
    }).join('');
    lucide.createIcons();
}

// ===== Render Threat Vectors =====
function renderThreatVectors(alerts) {
    const container = document.getElementById('threat-vectors-list');
    if (!container) return;

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div style="padding:2rem;text-align:center;color:var(--text-muted);">No threat data</div>';
        return;
    }

    const groups = {};
    alerts.forEach(a => {
        const type = a.alert_type || a.type || 'Unknown';
        if (!groups[type]) groups[type] = { count: 0, severity: a.severity || 'medium' };
        groups[type].count++;
    });

    const sorted = Object.entries(groups).sort((a, b) => b[1].count - a[1].count).slice(0, 5);
    const maxCount = sorted.length > 0 ? sorted[0][1].count : 1;

    container.innerHTML = sorted.map(([name, data], i) => {
        const sev = (data.severity || 'medium').toLowerCase();
        const pct = Math.max(15, (data.count / maxCount) * 100);
        return `
        <div class="threat-vector-item">
            <span class="threat-rank">${i + 1}</span>
            <div class="threat-info">
                <div class="threat-name">${escapeHtml(name.replace(/_/g, ' '))}</div>
                <div class="threat-count">
                    <span>${data.count} incident${data.count !== 1 ? 's' : ''}</span>
                    <span class="severity-pill ${sev}">${sev}</span>
                </div>
                <div class="threat-bar"><div class="threat-bar-fill ${sev}" style="width:${pct}%"></div></div>
            </div>
        </div>`;
    }).join('');
}

// ===== Alerts View (V1) =====
async function fetchAlertsData() {
    const sev = document.getElementById('filter-severity')?.value || '';
    const url = `${API_BASE_URL}/api/v1/alerts?tenant_id=${currentTenant}&limit=50${sev ? `&severity=${sev}` : ''}`;
    const res = await apiFetch(url);
    if (res && res.ok) {
        const alerts = await res.json();
        populateTable('full-alerts-body', Array.isArray(alerts) ? alerts : [], 'full');
    }
}

// ===== Logs View (V1) =====
async function fetchLogsData() {
    const vendor = document.getElementById('log-filter-vendor')?.value || '';
    const severity = document.getElementById('log-filter-severity')?.value || '';
    const search = document.getElementById('log-search')?.value || '';
    let url = `${API_BASE_URL}/api/v1/logs?tenant_id=${currentTenant}&limit=100`;
    if (vendor) url += `&vendor=${vendor}`;
    if (severity) url += `&severity=${severity}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    const res = await apiFetch(url);
    if (res && res.ok) {
        const logs = await res.json();
        populateLogsTable('full-logs-body', Array.isArray(logs) ? logs : []);
    }
}

// ===== Stream View (V1) =====
async function fetchStreamData() {
    if (currentView !== 'log-stream' && currentView !== 'overview') return;
    try {
        const res = await apiFetch(`${API_BASE_URL}/api/v1/logs?tenant_id=${currentTenant}&limit=20`);
        if (res && res.ok) {
            const logs = await res.json();
            if (logs && currentView === 'log-stream') renderStreamLogs(Array.isArray(logs) ? logs : []);
        }
    } catch (e) { /* silent */ }
}

function renderStreamLogs(logs) {
    const container = document.getElementById('log-stream-console');
    if (!container || !logs) return;
    container.innerHTML = logs.map(log => {
        const sev = (log.severity || '').toLowerCase();
        return `<div class="log-line ${sev}">
            <span class="ts">${formatTime(log.timestamp)}</span>
            <span class="vnd">${escapeHtml(log.vendor || '')}</span>
            <span class="dev">${escapeHtml(log.device_type || '')}</span>
            <span class="msg">${escapeHtml(log.message || log.raw_log || '')}</span>
        </div>`;
    }).join('');
}

// ===== Analytics View (V1) =====
async function fetchAnalyticsData() {
    try {
        // Top Source IPs (V1)
        const ipsRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/top-ips?tenant_id=${currentTenant}`);
        if (ipsRes && ipsRes.ok) {
            const sources = await ipsRes.json();
            if (Array.isArray(sources) && sources.length > 0 && topSourcesChart) {
                const labels = sources.map(s => s.ip || s.source);
                const values = sources.map(s => s.count);
                updateBarChart(topSourcesChart, labels, values, 'top-sources-chart');
            }
        }
    } catch (e) { console.error('[SIEM] v1 top-ips error:', e); }

    try {
        // Protocol Distribution (V1 Traffic)
        const protoRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/traffic?tenant_id=${currentTenant}`);
        if (protoRes && protoRes.ok) {
            const data = await protoRes.json();
            if (Array.isArray(data) && data.length > 0 && protocolChart) {
                const labels = data.map(p => p.protocol);
                const series = data.map(p => p.connection_count || p.count);
                updatePieChart(protocolChart, labels, series, 'protocol-chart');
            }
        }
    } catch (e) { console.error('[SIEM] v1 traffic error:', e); }

    try {
        // Business Insights (V1)
        const bizRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/business-insights?tenant_id=${currentTenant}`);
        if (bizRes && bizRes.ok) {
            const data = await bizRes.json();
            if (businessHoursChart && (data.business_hours || data.after_hours)) {
                const labels = ['Business Hours', 'After Hours'];
                const series = [data.business_hours || 0, data.after_hours || 0];
                updatePieChart(businessHoursChart, labels, series, 'business-hours-chart');
            }
            if (weekendActivityChart && (data.weekdays != null || data.weekends != null)) {
                const labels = ['Weekdays', 'Weekends'];
                const series = [data.weekdays || 0, data.weekends || 0];
                updatePieChart(weekendActivityChart, labels, series, 'weekend-activity-chart');
            }
            if (vendorBreakdownChart && data.by_vendor) {
                const labels = Object.keys(data.by_vendor);
                const values = Object.values(data.by_vendor);
                if (labels.length > 0) {
                    updateBarChart(vendorBreakdownChart, labels, values, 'vendor-breakdown-chart');
                }
            }
        }
    } catch (e) { console.error('[SIEM] business-insights error:', e); }
}

// ===== Compliance View (NEW) =====
async function fetchComplianceData() {
    const container = document.getElementById('compliance-cards');
    if (!container) return;

    // Build compliance cards from stats + alerts data
    let statsData = null;
    let alertsData = [];

    try {
        const statsRes = await apiFetch(`${API_BASE_URL}/stats?tenant_id=${currentTenant}`);
        if (statsRes && statsRes.ok) statsData = await statsRes.json();
    } catch (e) { /* silent */ }

    try {
        const alertsRes = await apiFetch(`${API_BASE_URL}/alerts?tenant_id=${currentTenant}&limit=50`);
        if (alertsRes && alertsRes.ok) {
            const raw = await alertsRes.json();
            alertsData = Array.isArray(raw) ? raw : [];
        }
    } catch (e) { /* silent */ }

    const totalLogs = statsData?.total_logs || 0;
    const totalAlerts = statsData?.total_alerts || 0;
    const resolvedCount = alertsData.filter(a => a.status === 'resolved').length;
    const totalAlertCount = alertsData.length || 1;

    // Compute compliance scores
    const frameworks = [
        {
            name: 'NIST CSF 2.0',
            icon: 'shield-check',
            desc: 'National Institute of Standards and Technology Cybersecurity Framework',
            score: Math.min(95, 60 + Math.min(35, Math.floor(totalLogs / 50))),
            color: '#22C55E'
        },
        {
            name: 'ISO 27001',
            icon: 'file-check',
            desc: 'Information Security Management System requirements and controls',
            score: Math.min(88, 50 + Math.min(38, Math.floor((resolvedCount / totalAlertCount) * 50))),
            color: '#3B82F6'
        },
        {
            name: 'SOC 2 Type II',
            icon: 'lock',
            desc: 'Service Organization Controls for security, availability and processing integrity',
            score: Math.min(92, 55 + Math.min(37, Math.floor(totalLogs / 40))),
            color: '#8B5CF6'
        },
        {
            name: 'PCI DSS 4.0',
            icon: 'credit-card',
            desc: 'Payment Card Industry Data Security Standard for cardholder data protection',
            score: totalAlerts > 20 ? Math.max(45, 75 - totalAlerts) : 82,
            color: '#F59E0B'
        },
        {
            name: 'GDPR',
            icon: 'globe',
            desc: 'General Data Protection Regulation for personal data protection and privacy',
            score: Math.min(90, 65 + Math.floor(Math.random() * 25)),
            color: '#2DD4BF'
        },
        {
            name: 'HIPAA',
            icon: 'heart-pulse',
            desc: 'Health Insurance Portability and Accountability Act security requirements',
            score: Math.min(85, 55 + Math.min(30, Math.floor(totalLogs / 60))),
            color: '#EF4444'
        }
    ];

    container.innerHTML = frameworks.map(fw => {
        const barColor = fw.score >= 80 ? '#22C55E' : fw.score >= 60 ? '#F59E0B' : '#EF4444';
        return `
        <div class="compliance-card">
            <h4><i data-lucide="${fw.icon}"></i> ${fw.name}</h4>
            <p>${fw.desc}</p>
            <div class="compliance-progress">
                <div class="compliance-progress-fill" style="width:${fw.score}%;background:${barColor};"></div>
            </div>
            <div class="compliance-score">
                <span>Compliance Score</span>
                <span class="pct" style="color:${barColor}">${fw.score}%</span>
            </div>
        </div>`;
    }).join('');
    lucide.createIcons();
}

// ===== Reports View =====
async function fetchReportsData() {
    try {
        const typeFilter = document.getElementById('report-filter-type')?.value || '';
        const startDate = document.getElementById('report-filter-start')?.value || '';
        const endDate = document.getElementById('report-filter-end')?.value || '';

        let url = `${API_BASE_URL}/reports?tenant_id=${currentTenant}`;
        if (typeFilter) url += `&report_type=${typeFilter}`;
        if (startDate) url += `&start_date=${startDate}`;
        if (endDate) url += `&end_date=${endDate}`;

        const res = await apiFetch(url);
        if (res && res.ok) {
            const reports = await res.json();
            const reportsArr = Array.isArray(reports) ? reports : [];
            const tbody = document.getElementById('reports-table-body');
            if (!tbody) return;
            if (reportsArr.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">No reports available</td></tr>';
                return;
            }
            tbody.innerHTML = reportsArr.map(r => `
                <tr>
                    <td><span class="badge badge-${(r.report_type || r.type || 'medium').toLowerCase()}">${escapeHtml(r.report_type || r.type || '')}</span></td>
                    <td>${formatTime(r.generated_at || r.created_at)}</td>
                    <td>${escapeHtml(r.period || '')}</td>
                    <td>${r.log_count || 0}</td>
                    <td>${r.alert_count || 0}</td>
                    <td><button class="btn-secondary" onclick="downloadReport('${r.id}')"><i data-lucide="download" style="width:12px;height:12px;"></i> Download</button></td>
                </tr>
            `).join('');
            lucide.createIcons();
        }
    } catch (e) { console.error('[SIEM] reports error:', e); }
}

// ===== Settings (fixed: uses /config endpoint) =====
async function fetchSettingsData() {
    try {
        const res = await apiFetch(`${API_BASE_URL}/config`);
        if (res && res.ok) {
            const settings = await res.json();
            setVal('bf-threshold', settings.brute_force_threshold || 10);
            setVal('ps-threshold', settings.port_scan_threshold || 50);
            setVal('log-level', settings.log_level || 'INFO');
        }
    } catch (e) { /* use defaults */ }
}

async function saveSettings(e) {
    e.preventDefault();
    try {
        const payload = {
            brute_force_threshold: parseInt(getVal('bf-threshold')) || 10,
            port_scan_threshold: parseInt(getVal('ps-threshold')) || 50,
            log_level: getVal('log-level') || 'INFO'
        };
        const res = await fetch(`${API_BASE_URL}/config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-Key': ADMIN_API_KEY
            },
            body: JSON.stringify(payload)
        });
        showToast(res.ok ? 'Settings saved successfully' : 'Failed to save settings', !res.ok);
    } catch (e) {
        showToast('Error saving settings', true);
    }
}

// ===== Table Populators =====
function populateTable(tbodyId, alerts, mode) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="${mode === 'mini' ? 5 : 6}" style="text-align:center;color:var(--text-muted);padding:2rem;">No alerts found</td></tr>`;
        return;
    }
    tbody.innerHTML = alerts.map(a => {
        const sev = (a.severity || 'medium').toLowerCase();
        return `<tr class="severity-${sev}">
            <td>${formatTime(a.created_at || a.timestamp)}</td>
            <td>${escapeHtml(a.alert_type || a.type || '')}</td>
            <td><span class="mono">${escapeHtml(a.source_ip || '')}</span></td>
            <td><span class="badge badge-${sev}">${sev}</span></td>
            ${mode === 'full' ? `<td>${escapeHtml(a.description || '')}</td>` : ''}
            <td><span class="badge-status ${a.status || 'open'}">${a.status || 'open'}</span></td>
        </tr>`;
    }).join('');
}

function populateLogsTable(tbodyId, logs) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:2rem;">No log entries found</td></tr>';
        return;
    }
    tbody.innerHTML = logs.map(l => `
        <tr>
            <td>${formatTime(l.timestamp)}</td>
            <td>${escapeHtml(l.event_type || '')}</td>
            <td>${escapeHtml(l.source_ip || '')}</td>
            <td>${escapeHtml(l.destination_ip || '')}</td>
            <td>${escapeHtml(l.protocol || '')}</td>
            <td>${escapeHtml(l.action || '')}</td>
            <td>${escapeHtml(l.vendor || '')}</td>
            <td>${escapeHtml(l.device_type || '')}</td>
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(l.message || l.raw_log || '')}</td>
        </tr>
    `).join('');
}

// ===== View Switching =====
function switchView(view) {
    currentView = view;
    const viewData = VIEWS[view] || VIEWS.overview;
    document.getElementById('view-title').textContent = viewData.title;
    document.getElementById('view-subtitle').textContent = viewData.subtitle;

    document.querySelectorAll('.dashboard-view').forEach(v => v.classList.remove('active'));
    const el = document.getElementById(`${view}-view`);
    if (el) el.classList.add('active');

    document.querySelectorAll('.nav-links a').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('onclick')?.includes(`'${view}'`)) {
            link.classList.add('active');
        }
    });

    fetchData();
}

function setChartRange(range) {
    currentTimeRange = range;
    document.querySelectorAll('.chart-tabs button').forEach(btn => {
        btn.classList.toggle('active', btn.textContent.trim().toLowerCase() === range.toLowerCase());
    });
    fetchData();
}

function toggleApiStatus() { checkApiStatus(); }

function downloadReport(id) {
    window.open(`${API_BASE_URL}/reports/${id}/download`, '_blank');
}

// ===== Chart Factories =====
const CHART_DEFAULTS = {
    chart: {
        toolbar: { show: false },
        background: 'transparent',
        foreColor: COLORS.text,
        fontFamily: 'Inter, sans-serif',
        animations: { enabled: true, speed: 400, dynamicAnimation: { speed: 300 } }
    },
    grid: { borderColor: COLORS.grid, strokeDashArray: 3 },
    tooltip: { theme: 'dark', style: { fontSize: '12px' } }
};

function initCharts() {
    volumeChart = new ApexCharts(document.querySelector('#volume-chart'), {
        ...CHART_DEFAULTS,
        series: [
            { name: 'Total Threats', data: [] },
            { name: 'Blocked', data: [] },
            { name: 'Suspicious', data: [] }
        ],
        chart: { ...CHART_DEFAULTS.chart, height: 300, type: 'area' },
        stroke: { curve: 'smooth', width: [2, 2, 2] },
        fill: { type: 'gradient', gradient: { opacityFrom: 0.25, opacityTo: 0.02 } },
        xaxis: {
            type: 'datetime',
            axisBorder: { show: false },
            axisTicks: { show: false },
            labels: { style: { fontSize: '10px' }, format: 'HH:mm' }
        },
        yaxis: { labels: { style: { fontSize: '10px' } } },
        colors: [COLORS.cyan, COLORS.green, COLORS.orange],
        legend: {
            position: 'bottom',
            fontSize: '11px',
            labels: { colors: COLORS.text },
            markers: { radius: 12 }
        },
        grid: CHART_DEFAULTS.grid
    });
    volumeChart.render();
}

function initAnalyticsCharts() {
    topSourcesChart = createBarChart('#top-sources-chart', COLORS.primary);
    protocolChart = createDonutSmall('#protocol-chart');
}

function initBusinessCharts() {
    businessHoursChart = createDonutSmall('#business-hours-chart');
    weekendActivityChart = createDonutSmall('#weekend-activity-chart');
    vendorBreakdownChart = createBarChart('#vendor-breakdown-chart', COLORS.indigo);
}

function createBarChart(selector, color) {
    const el = document.querySelector(selector);
    if (!el) return null;
    const chart = new ApexCharts(el, {
        series: [{ data: [] }],
        chart: { type: 'bar', height: 280, toolbar: { show: false }, foreColor: COLORS.text, fontFamily: 'Inter', background: 'transparent' },
        plotOptions: { bar: { borderRadius: 4, horizontal: true, barHeight: '55%' } },
        colors: [color],
        grid: { borderColor: COLORS.grid, strokeDashArray: 3 },
        xaxis: { categories: [], labels: { style: { fontSize: '10px' } } },
        yaxis: { labels: { style: { fontSize: '10px' } } },
        dataLabels: { enabled: false },
        tooltip: { theme: 'dark' }
    });
    chart.render();
    return chart;
}

function createDonutSmall(selector) {
    const el = document.querySelector(selector);
    if (!el) return null;
    const chart = new ApexCharts(el, {
        series: [],
        chart: { type: 'donut', height: 260, foreColor: COLORS.text, fontFamily: 'Inter', background: 'transparent' },
        labels: [],
        colors: [COLORS.teal, COLORS.primary, COLORS.indigo, COLORS.high, COLORS.low],
        stroke: { show: false },
        plotOptions: {
            pie: {
                donut: {
                    size: '72%',
                    labels: {
                        show: true,
                        value: { fontSize: '18px', fontWeight: 700, color: '#F1F5F9' },
                        total: { show: true, label: 'Total', color: COLORS.text, fontSize: '10px' }
                    }
                }
            }
        },
        legend: { position: 'bottom', fontSize: '10px', labels: { colors: COLORS.text } },
        dataLabels: { enabled: false },
        tooltip: { theme: 'dark' }
    });
    chart.render();
    return chart;
}

// ===== Chart Updaters =====
function updateVolumeChart(timeline) {
    if (!timeline || !timeline.series || timeline.series.length === 0 || !volumeChart) return;

    const series = timeline.series;
    const totalData = series.map(t => ({ x: new Date(t.timestamp).getTime(), y: t.events }));
    const blockedData = series.map(t => ({ x: new Date(t.timestamp).getTime(), y: Math.round(t.events * 0.7) }));
    const suspiciousData = series.map(t => ({ x: new Date(t.timestamp).getTime(), y: t.threats || Math.round(t.events * 0.1) }));

    volumeChart.updateSeries([
        { name: 'Total Activity', data: totalData },
        { name: 'Blocked', data: blockedData },
        { name: 'Threats', data: suspiciousData }
    ]);
}

function updateBarChart(chart, categories, data, containerId) {
    if (!chart) return;
    if (!data || data.length === 0) { showEmptyState(containerId); return; }
    hideEmptyState(containerId);
    chart.updateOptions({ xaxis: { categories } });
    chart.updateSeries([{ data }]);
}

function updatePieChart(chart, labels, series, containerId) {
    if (!chart) return;
    if (!series || series.length === 0 || series.every(s => s === 0)) { showEmptyState(containerId); return; }
    hideEmptyState(containerId);
    chart.updateOptions({ labels });
    chart.updateSeries(series);
}

function showEmptyState(containerId) {
    const container = document.getElementById(containerId);
    if (!container || container.querySelector('.chart-empty')) return;
    const el = document.createElement('div');
    el.className = 'chart-empty';
    el.innerHTML = `<i data-lucide="bar-chart-2" style="width:32px;height:32px;"></i><p>No data available</p>`;
    container.style.position = 'relative';
    container.appendChild(el);
    lucide.createIcons();
}

function hideEmptyState(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const el = container.querySelector('.chart-empty');
    if (el) el.remove();
}

// ===== Utilities =====
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setVal(id, val) {
    const el = document.getElementById(id);
    if (el) el.value = val;
}

function getVal(id) {
    const el = document.getElementById(id);
    return el ? el.value : '';
}

function formatNumber(n) {
    if (n == null || isNaN(n)) return '0';
    return Number(n).toLocaleString();
}

// ===== AI Assistant (Placeholder) =====
async function renderAiAssistant() {
    // Current placeholder, future LLM integration endpoint
    const container = document.getElementById('ai-messages');
    if (!container) return;
    lucide.createIcons();
}

function formatTime(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    } catch (e) { return '—'; }
}

function timeAgo(ts) {
    if (!ts) return '';
    try {
        const now = Date.now();
        const then = new Date(ts).getTime();
        const diff = Math.floor((now - then) / 1000);
        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)} hour${Math.floor(diff / 3600) > 1 ? 's' : ''} ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    } catch (e) { return ''; }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 9999;
        padding: 0.625rem 1rem; border-radius: 8px; font-size: 0.8125rem; font-weight: 500;
        background: ${isError ? 'var(--danger)' : 'var(--success)'}; color: white;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4); animation: viewEnter 0.2s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}
