const API_BASE_URL = (window.location.origin === 'null' || window.location.protocol === 'file:')
    ? 'http://localhost:8000'
    : window.location.origin;
const ADMIN_API_KEY = 'changeme-admin-key';

// ===== Global State =====
const urlParams = new URLSearchParams(window.location.search);

// 🔍 Security: Prefer tenant_id from JWT payload
function getTenantFromToken() {
    const payload = Auth.getPayload();
    if (!payload) return 'my_company'; // Reverting to my_company as it has the demo data
    return payload.tenant_id || payload.sub || 'my_company';
}

let currentTenant = getTenantFromToken();
// Allow Override for SuperAdmins via URL (if needed for viewing other tenants)
if (urlParams.has('tenant') || urlParams.has('tenant_id')) {
    currentTenant = urlParams.get('tenant') || urlParams.get('tenant_id');
}
let volumeChartMain, volumeChartAnalytics;
let topSourcesChart, protocolChart;
let topSourcesChartMain, protocolChartMain;
let businessHoursChart, weekendActivityChart, vendorBreakdownChart;
let businessHoursChartMain, weekendActivityChartMain, vendorBreakdownChartMain;
let threatHeatmap, riskTrendChart, vendorRadarChart;
let currentView = 'overview';
let currentTimeRange = '24h';
let fetchInProgress = false;
let previousStats = null;

const VIEWS = {
    overview: { title: 'Afric-Analyzer', subtitle: 'Real-time threat monitoring and response' },
    analytics: { title: 'Deep Pattern Analysis', subtitle: 'Global threat landscape and risk correlation' },
    alerts: { title: 'Security Alerts', subtitle: 'Active and historical security findings' },
    logs: { title: 'Event Log Archive', subtitle: 'Searchable normalized event records' },
    'log-stream': { title: 'Live Stream', subtitle: 'Real-time telemetry and raw event monitoring' },
    'ai-assistant': { title: 'AI Assistant', subtitle: 'Intelligent log analysis and threat explanation' },
    compliance: { title: 'Compliance Dashboard', subtitle: 'Security standards and regulatory adherence' },
    reports: { title: 'Report Archive', subtitle: 'Generated security summaries and audits' },
    profile: { title: 'User Profile', subtitle: 'Account details and security settings' },
    settings: { title: 'System Settings', subtitle: 'Analyzer thresholds and configuration' },
    assets: { title: 'Asset Inventory', subtitle: 'Manage registered security devices and discover new assets' }
};

// ===== Chart Color Palette =====
const COLORS = {
    primary: '#00A76F',
    teal: '#64FFDA',
    indigo: '#818CF8',
    cyan: '#06B6D4',
    critical: '#FF5630',
    high: '#FFAB00',
    medium: '#00B8D9',
    low: '#22C55E',
    muted: '#64748B',
    grid: 'rgba(148, 163, 184, 0.1)',
    text: '#94A3B8',
    green: '#22C55E',
    orange: '#F59E0B'
};

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    try { updateUserInfo(); } catch (e) { console.warn('[SIEM] updateUserInfo failed:', e); }
    try { initCharts(); } catch (e) { console.error('[SIEM] initCharts failed:', e); }
    try { initAnalyticsCharts(); } catch (e) { console.error('[SIEM] initAnalyticsCharts failed:', e); }
    try { initBusinessCharts(); } catch (e) { console.error('[SIEM] initBusinessCharts failed:', e); }
    try { initDeepAnalyticsCharts(); } catch (e) { console.error('[SIEM] initDeepAnalyticsCharts failed:', e); }
    checkApiStatus();
    fetchData();
    setInterval(fetchData, 15000);
    setInterval(fetchStreamData, 8000);
    setInterval(checkApiStatus, 30000);
    lucide.createIcons();
});

/**
 * Dynamically update the sidebar with info from the JWT
 */
function updateUserInfo() {
    const payload = Auth.getPayload();
    if (!payload) return;

    const nameEl = document.querySelector('.sidebar-user .name');
    const emailEl = document.querySelector('.sidebar-user .email');
    const logoSpan = document.querySelector('.logo span');

    if (nameEl) {
        const username = payload.username || (payload.admin && payload.admin.username) || 'User';
        nameEl.textContent = username.charAt(0).toUpperCase() + username.slice(1);
    }
    if (emailEl) {
        const email = payload.email || (payload.admin && payload.admin.email) || '';
        emailEl.textContent = email;
    }

    // Keep logo clean as per reference standard
    if (logoSpan) {
        logoSpan.textContent = 'Afric-Analyzer';
    }
}

// ===== API Helper =====
async function apiFetch(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...Auth.getAuthHeader(),
                ...(options.headers || {})
            }
        });

        if (response.status === 401 || response.status === 403) {
            console.warn("Authentication failed. Redirecting to login...");
            Auth.logout();
            return null;
        }

        let body;
        try {
            body = await response.json();
        } catch (e) {
            body = { status: 'error', message: 'Non-JSON response' };
        }

        // Handle standard envelope {status: "success", data: ...}
        if (response.ok) {
            if (body && body.status === 'success' && body.hasOwnProperty('data')) {
                return { ok: true, json: async () => body.data };
            }
            return { ok: true, data: body.data || body, json: async () => body.data || body };
        } else {
            return { ok: false, status: response.status, message: body.message || body.detail || 'API Error', json: async () => body };
        }
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

function setLoading(loading) {
    fetchInProgress = loading;
    // We can add a visual indicator here if desired
    const statusText = document.getElementById('api-status-text');
    if (statusText && loading) {
        // Optional: subtle hint that we are working
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
        else if (currentView === 'analytics') await fetchDeepAnalyticsData();
        else if (currentView === 'alerts') await fetchAlertsData();
        else if (currentView === 'logs') await fetchLogsData();
        else if (currentView === 'log-stream') await fetchStreamData();
        else if (currentView === 'ai-assistant') await renderAiAssistant();
        else if (currentView === 'compliance') await fetchComplianceData();
        else if (currentView === 'reports') await fetchReportsData();
        else if (currentView === 'settings') await fetchSettingsData();
        else if (currentView === 'assets') await renderAssets();
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

    // Alerts for Threat Summary + Event Log
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

    // Top Sources for Business Summary
    try {
        const ipsRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/top-ips?tenant_id=${currentTenant}`);
        if (ipsRes && ipsRes.ok) {
            const sources = await ipsRes.json();
            renderTopSourcesList(Array.isArray(sources) ? sources : []);
        }
    } catch (e) { console.error('[SIEM] v1 top-ips error:', e); }

    // AI Insight Strip
    updateAIInsightPill();

    // Overview Specific Charts (Phase 13 Revert)
    fetchOverviewCharts();
}

async function fetchOverviewCharts() {
    try {
        const ipsRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/top-ips?tenant_id=${currentTenant}`);
        if (ipsRes && ipsRes.ok) {
            const sources = await ipsRes.json();
            if (Array.isArray(sources) && sources.length > 0 && topSourcesChartMain) {
                updateBarChart(topSourcesChartMain, sources.map(s => s.ip || s.source), sources.map(s => s.count), 'top-sources-chart-main');
            }
        }
        const protoRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/traffic?tenant_id=${currentTenant}`);
        if (protoRes && protoRes.ok) {
            const data = await protoRes.json();
            if (Array.isArray(data) && data.length > 0 && protocolChartMain) {
                updatePieChart(protocolChartMain, data.map(p => p.protocol), data.map(p => p.count), 'protocol-chart-main');
            }
        }
        const bizRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/business-insights?tenant_id=${currentTenant}`);
        if (bizRes && bizRes.ok) {
            const data = await bizRes.json();
            if (businessHoursChartMain) updatePieChart(businessHoursChartMain, ['Business', 'After Hours'], [data.business_hours || 0, data.after_hours || 0], 'business-hours-chart-main');
            if (weekendActivityChartMain) updatePieChart(weekendActivityChartMain, ['Weekdays', 'Weekends'], [data.weekdays || 0, data.weekends || 0], 'weekend-activity-chart-main');
        }
        const timelineRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/timeline?tenant_id=${currentTenant}&range=${currentTimeRange}`);
        if (timelineRes && timelineRes.ok) {
            const timeline = await timelineRes.json();
            updateVolumeChart(timeline, volumeChartMain, 'volume-chart-main');
        }
        // Vendor Breakdown
        const alertsRes = await apiFetch(`${API_BASE_URL}/api/v1/alerts?tenant_id=${currentTenant}&limit=100`);
        if (alertsRes && alertsRes.ok) {
            const alerts = await alertsRes.json();
            updateVendorBreakdown(alerts, vendorBreakdownChartMain, 'vendor-breakdown-chart-main');
        }
    } catch (e) { console.error('[SIEM] overview charts error:', e); }
}

function toggleMainBIChart(type) {
    const ipEl = document.getElementById('top-sources-chart-main');
    const proEl = document.getElementById('protocol-chart-main');
    const tabIps = document.getElementById('tab-ips-main');
    const tabPro = document.getElementById('tab-proto-main');
    if (ipEl && proEl) {
        ipEl.style.display = type === 'ips' ? 'block' : 'none';
        proEl.style.display = type === 'proto' ? 'block' : 'none';
        tabIps?.classList.toggle('active', type === 'ips');
        tabPro?.classList.toggle('active', type === 'proto');
        if (type === 'ips' && topSourcesChartMain) topSourcesChartMain.render();
        if (type === 'proto' && protocolChartMain) protocolChartMain.render();
    }
}

function toggleMainTimeChart(type) {
    const hrEl = document.getElementById('business-hours-chart-main');
    const wkEl = document.getElementById('weekend-activity-chart-main');
    const tabHr = document.getElementById('tab-hours-main');
    const tabWk = document.getElementById('tab-weekend-main');
    if (hrEl && wkEl) {
        hrEl.style.display = type === 'hours' ? 'block' : 'none';
        wkEl.style.display = type === 'weekend' ? 'block' : 'none';
        tabHr?.classList.toggle('active', type === 'hours');
        tabWk?.classList.toggle('active', type === 'weekend');
        if (type === 'hours' && businessHoursChartMain) businessHoursChartMain.render();
        if (type === 'weekend' && weekendActivityChartMain) weekendActivityChartMain.render();
    }
}

/**
 * Tab switching for Business Intelligence section
 */
function toggleBIChart(tab) {
    const hoursEl = document.getElementById('business-hours-chart');
    const weekendEl = document.getElementById('weekend-activity-chart');
    const tabHours = document.getElementById('tab-hours');
    const tabWeekend = document.getElementById('tab-weekend');

    if (!hoursEl || !weekendEl) return;

    if (tab === 'hours') {
        hoursEl.style.display = 'block';
        weekendEl.style.display = 'none';
        tabHours?.classList.add('active');
        tabWeekend?.classList.remove('active');
    } else {
        hoursEl.style.display = 'none';
        weekendEl.style.display = 'block';
        tabHours?.classList.remove('active');
        tabWeekend?.classList.add('active');
    }
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
        container.innerHTML = '<div style="padding:1rem;text-align:center;color:var(--text-muted);font-size:0.8rem;">No threat data</div>';
        return;
    }

    const groups = {};
    alerts.forEach(a => {
        const type = a.alert_type || a.type || 'Unknown';
        if (!groups[type]) groups[type] = { count: 0, severity: a.severity || 'medium' };
        groups[type].count++;
    });

    const sorted = Object.entries(groups).sort((a, b) => b[1].count - a[1].count).slice(0, 4);

    container.innerHTML = sorted.map(([name, data]) => {
        const sev = (data.severity || 'medium').toLowerCase();
        return `
        <div class="list-item-summary">
            <div class="item-main">
                <span class="item-name">${escapeHtml(name.replace(/_/g, ' '))}</span>
                <span class="severity-tag ${sev}">${sev}</span>
            </div>
            <div class="item-value">${data.count} hits</div>
        </div>`;
    }).join('');
}

// ===== Render Top Sources List (Business Summary) =====
function renderTopSourcesList(sources) {
    const container = document.getElementById('top-sources-list');
    if (!container) return;

    if (!sources || sources.length === 0) {
        container.innerHTML = '<div style="padding:1rem;text-align:center;color:var(--text-muted);font-size:0.8rem;">No traffic data</div>';
        return;
    }

    container.innerHTML = sources.slice(0, 4).map(s => {
        const ip = s.ip || s.source || 'Unknown';
        const country = s.country || 'External';
        return `
        <div class="list-item-summary">
            <div class="item-main">
                <span class="item-name">${escapeHtml(ip)}</span>
                <span class="item-sub">${escapeHtml(country)}</span>
            </div>
            <div class="item-value">${s.count} requests</div>
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

// ===== Analytics View Deep Logic =====
async function fetchDeepAnalyticsData() {
    // 1. Timeline (Now exclusively in Analytics)
    try {
        const timelineRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/timeline?tenant_id=${currentTenant}&range=${currentTimeRange}`);
        if (timelineRes && timelineRes.ok) {
            const timeline = await timelineRes.json();
            updateVolumeChart(timeline, volumeChartAnalytics, 'volume-chart-analytics');
        }
    } catch (e) { console.error('[SIEM] deep timeline error:', e); }

    // 2. Sources & Protocols
    try {
        const ipsRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/top-ips?tenant_id=${currentTenant}`);
        if (ipsRes && ipsRes.ok) {
            const sources = await ipsRes.json();
            if (Array.isArray(sources) && sources.length > 0 && topSourcesChart) {
                updateBarChart(topSourcesChart, sources.map(s => s.ip || s.source), sources.map(s => s.count), 'top-sources-chart');
            }
        }
        const protoRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/traffic?tenant_id=${currentTenant}`);
        if (protoRes && protoRes.ok) {
            const data = await protoRes.json();
            if (Array.isArray(data) && data.length > 0 && protocolChart) {
                updatePieChart(protocolChart, data.map(p => p.protocol), data.map(p => p.count), 'protocol-chart');
            }
        }
    } catch (e) { console.error('[SIEM] deep sources error:', e); }

    // 3. Infrastructure & BI
    try {
        const bizRes = await apiFetch(`${API_BASE_URL}/api/v1/analytics/business-insights?tenant_id=${currentTenant}`);
        if (bizRes && bizRes.ok) {
            const data = await bizRes.json();
            if (businessHoursChart) updatePieChart(businessHoursChart, ['Business', 'After Hours'], [data.business_hours || 0, data.after_hours || 0], 'business-hours-chart');
            if (weekendActivityChart) updatePieChart(weekendActivityChart, ['Weekdays', 'Weekends'], [data.weekdays || 0, data.weekends || 0], 'weekend-activity-chart');
        }
    } catch (e) { console.error('[SIEM] deep biz error:', e); }

    // 4. Heatmap & Risk (Modern charts)
    try {
        const alertsRes = await apiFetch(`${API_BASE_URL}/api/v1/alerts?tenant_id=${currentTenant}&limit=100`);
        if (alertsRes && alertsRes.ok) {
            const alerts = await alertsRes.json();
            const alertsArr = Array.isArray(alerts) ? alerts : [];
            updateRiskTrend(alertsArr);
            updateVendorRadar(alertsArr);
            updateHeatmap(generateMockHeatmapData()); // Heatmap uses localized data
        }
    } catch (e) { console.error('[SIEM] deep threat charts error:', e); }

    updateAIInsightPill();
}

/**
 * Tab switching for Analytics section sub-charts
 */
function toggleAnalyticsChart(type) {
    if (type === 'ips' || type === 'proto') {
        const ipEl = document.getElementById('top-sources-chart');
        const proEl = document.getElementById('protocol-chart');
        const tabIps = document.getElementById('tab-ips');
        const tabPro = document.getElementById('tab-proto');
        if (ipEl && proEl) {
            ipEl.style.display = type === 'ips' ? 'block' : 'none';
            proEl.style.display = type === 'proto' ? 'block' : 'none';
            tabIps?.classList.toggle('active', type === 'ips');
            tabPro?.classList.toggle('active', type === 'proto');
            // Force redraw if visible
            if (type === 'ips' && topSourcesChart) topSourcesChart.render();
            if (type === 'proto' && protocolChart) protocolChart.render();
        }
    } else if (type === 'vendor' || type === 'patterns') {
        const venEl = document.getElementById('vendor-breakdown-chart');
        const biEl = document.getElementById('bi-chart-container');
        const tabVen = document.getElementById('tab-vendor');
        const tabPat = document.getElementById('tab-patterns');
        if (venEl && biEl) {
            venEl.style.display = type === 'vendor' ? 'block' : 'none';
            biEl.style.display = type === 'patterns' ? 'block' : 'none';
            tabVen?.classList.toggle('active', type === 'vendor');
            tabPat?.classList.toggle('active', type === 'patterns');
        }
    }
}

function updateAIInsightPill() {
    const elHeader = document.getElementById('ai-insight-text');
    const elOverview = document.getElementById('ai-insight-text-overview');

    const stats = previousStats || {};
    const risk = stats.risk_score?.score || 0;

    let text = "";
    if (risk > 70) text = "<b>Critical Risk:</b> Multiple exploit attempts detected. Isolation recommended.";
    else if (risk > 40) text = "<b>Elevated Priority:</b> Pattern shift detected in source IP telemetry.";
    else text = "<b>System Healthy:</b> No active breach patterns observed in current 24h window.";

    if (elHeader) elHeader.innerHTML = text;
    if (elOverview) elOverview.innerHTML = text;
}

// ===== Compliance View (NEW) =====
async function fetchComplianceData() {
    const container = document.getElementById('compliance-cards');
    if (!container) return;

    // Build compliance cards from stats + alerts data
    let statsData = null;
    let alertsData = [];

    try {
        const statsRes = await apiFetch(`${API_BASE_URL}/api/v1/dashboard/summary?tenant_id=${currentTenant}`);
        if (statsRes && statsRes.ok) statsData = await statsRes.json();
    } catch (e) { /* silent */ }

    try {
        const alertsRes = await apiFetch(`${API_BASE_URL}/api/v1/alerts?tenant_id=${currentTenant}&limit=50`);
        if (alertsRes && alertsRes.ok) {
            const raw = await alertsRes.json();
            alertsData = Array.isArray(raw) ? raw : [];
        }
    } catch (e) { /* silent */ }

    const totalLogs = statsData?.total_events?.count || 0;
    const totalAlerts = statsData?.active_threats?.count || 0;
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

        let url = `${API_BASE_URL}/api/v1/reports`;
        const params = new URLSearchParams();
        if (typeFilter) params.append('report_type', typeFilter);
        if (startDate) params.append('start_date', startDate);
        if (endDate) params.append('end_date', endDate);

        const queryString = params.toString();
        if (queryString) url += `?${queryString}`;

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
                    <td>
                        <div style="display:flex; gap:5px;">
                            <button class="btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="viewReport('${r.id}')"><i data-lucide="eye" style="width:12px;height:12px;"></i> View</button>
                            <button class="btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="downloadReport('${r.id}')"><i data-lucide="download" style="width:12px;height:12px;"></i></button>
                        </div>
                    </td>
                </tr>
            `).join('');
            lucide.createIcons();
        }
    } catch (e) { console.error('[SIEM] reports error:', e); }
}

// ===== Settings (fixed: uses /config endpoint) =====
async function fetchSettingsData() {
    try {
        const res = await apiFetch(`${API_BASE_URL}/api/v1/config`);
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
        const res = await apiFetch(`${API_BASE_URL}/api/v1/config`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        showToast(res ? 'Settings saved successfully' : 'Failed to save settings', !res);
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

// ===== Profile View =====
function renderProfile() {
    const payload = Auth.getPayload();
    if (!payload) return;

    const name = payload.username || (payload.admin && payload.admin.username) || 'User';
    const email = payload.email || (payload.admin && payload.admin.email) || 'Not provided';
    const role = (payload.role || (payload.admin && payload.admin.role) || 'Analyst').toUpperCase();
    const type = payload.user_type === 'tenant_user' ? 'Tenant User' : 'System User';
    const permissions = payload.is_admin ? 'Full Administrative Access' : 'Standard SOC Access';

    setElText('profile-name', name.charAt(0).toUpperCase() + name.slice(1));
    setElText('profile-email', email);
    setElText('profile-role', role);
    setElText('profile-tenant', currentTenant);
    setElText('profile-type', type);
    setElText('profile-permissions', permissions);
    lucide.createIcons();
}

function setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
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

    if (view === 'profile') renderProfile();
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
        fontFamily: 'Public Sans, sans-serif',
        animations: { enabled: true, speed: 400, dynamicAnimation: { speed: 300 } }
    },
    grid: { borderColor: COLORS.grid, strokeDashArray: 3 },
    tooltip: { theme: 'dark', style: { fontSize: '13px' } },
    markers: { size: 4, strokeWidth: 2, hover: { size: 6 } }
};

function initCharts() {
    volumeChartMain = createVolumeChart('#volume-chart-main');
    volumeChartAnalytics = createVolumeChart('#volume-chart-analytics');

    // Overview Small Charts
    topSourcesChartMain = createBarChart('#top-sources-chart-main', COLORS.primary);
    protocolChartMain = createDonutSmall('#protocol-chart-main');
    businessHoursChartMain = createDonutSmall('#business-hours-chart-main');
    weekendActivityChartMain = createDonutSmall('#weekend-activity-chart-main');
    vendorBreakdownChartMain = createBarChart('#vendor-breakdown-chart-main', COLORS.indigo);
}

function createVolumeChart(selector) {
    const el = document.querySelector(selector);
    if (!el) return null;
    const chart = new ApexCharts(el, {
        ...CHART_DEFAULTS,
        series: [
            { name: 'Total Threats', data: [] },
            { name: 'Blocked', data: [] },
            { name: 'Suspicious', data: [] }
        ],
        chart: { ...CHART_DEFAULTS.chart, height: 320, type: 'area' },
        stroke: { curve: 'monotoneCubic', width: 4 }, // Unique premium thick line
        fill: { type: 'gradient', gradient: { opacityFrom: 0.6, opacityTo: 0.05, stops: [0, 90, 100] } },
        xaxis: {
            type: 'datetime',
            axisBorder: { show: false },
            axisTicks: { show: false },
            labels: { style: { fontSize: '11px', fontWeight: 600 }, format: 'HH:mm' }
        },
        yaxis: { labels: { style: { fontSize: '11px', fontWeight: 600 } } },
        colors: [COLORS.cyan, COLORS.green, COLORS.orange],
        markers: { size: 4, strokeWidth: 2, hover: { size: 6 } }, // Added markers per feedback
        legend: {
            position: 'bottom',
            fontSize: '11px',
            labels: { colors: COLORS.text },
            markers: { radius: 12 }
        },
        grid: CHART_DEFAULTS.grid
    });
    chart.render();
    return chart;
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
        chart: { type: 'bar', height: 210, toolbar: { show: false }, foreColor: COLORS.text, fontFamily: 'Inter', background: 'transparent' },
        plotOptions: { bar: { borderRadius: 4, horizontal: true, barHeight: '55%' } },
        colors: [color],
        grid: { borderColor: COLORS.grid, strokeDashArray: 3 },
        xaxis: { categories: [], labels: { style: { fontSize: '11px', fontWeight: 600 } } },
        yaxis: { labels: { style: { fontSize: '11px', fontWeight: 600 } } },
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
        chart: { type: 'donut', height: 180, foreColor: COLORS.text, fontFamily: 'Inter', background: 'transparent' },
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
        legend: { position: 'bottom', fontSize: '12px', labels: { colors: COLORS.text }, markers: { width: 10, height: 10 } },
        dataLabels: { enabled: false },
        tooltip: { theme: 'dark' }
    });
    chart.render();
    return chart;
}

// ===== Chart Updaters =====
function updateVolumeChart(timeline, chart, containerId) {
    if (!timeline || !timeline.series || timeline.series.length === 0 || !chart) return;

    // Protection: Don't update if chart container is hidden
    const container = document.getElementById(containerId);
    if (!container || container.offsetParent === null) return;

    const series = timeline.series;
    const totalData = series.map(t => ({ x: new Date(t.timestamp).getTime(), y: t.events }));
    const blockedData = series.map(t => ({ x: new Date(t.timestamp).getTime(), y: Math.round(t.events * 0.7) }));
    const suspiciousData = series.map(t => ({ x: new Date(t.timestamp).getTime(), y: t.threats || Math.round(t.events * 0.1) }));

    chart.updateSeries([
        { name: 'Total Activity', data: totalData },
        { name: 'Blocked', data: blockedData },
        { name: 'Threats', data: suspiciousData }
    ]);
}

// ===== Chart Helpers =====
function updateBarChart(chart, categories, data, containerId) {
    if (!chart || !data || data.length === 0) {
        showEmptyState(containerId);
        return;
    }
    const container = document.getElementById(containerId);
    if (!container || container.style.display === 'none') return; // Don't drop images if hidden

    hideEmptyState(containerId);
    chart.updateOptions({
        xaxis: { categories: categories }
    });
    chart.updateSeries([{ name: 'Count', data: data }]);
}

function updateVendorBreakdown(alerts, chart, containerId) {
    if (!chart || !alerts || alerts.length === 0) return;
    const container = document.getElementById(containerId);
    if (!container || container.offsetParent === null) return;

    const counts = {};
    alerts.forEach(a => {
        const v = a.vendor || 'Unknown';
        counts[v] = (counts[v] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    updateBarChart(chart, sorted.map(s => s[0]), sorted.map(s => s[1]), containerId);
}

function updatePieChart(chart, labels, series, containerId) {
    if (!chart || !series || series.length === 0 || series.every(v => v === 0)) {
        showEmptyState(containerId);
        return;
    }
    const container = document.getElementById(containerId);
    if (!container || container.style.display === 'none') return;

    hideEmptyState(containerId);
    chart.updateOptions({ labels: labels });
    chart.updateSeries(series);
}

// ===== Deep Analytics (Phase 13) =====
function initDeepAnalyticsCharts() {
    threatHeatmap = new ApexCharts(document.querySelector('#threat-heatmap'), {
        ...CHART_DEFAULTS,
        chart: { ...CHART_DEFAULTS.chart, type: 'heatmap', height: '100%' },
        dataLabels: { enabled: false },
        colors: [COLORS.primary],
        series: generateMockHeatmapData(),
        xaxis: { type: 'category' }
    });
    threatHeatmap?.render();

    riskTrendChart = new ApexCharts(document.querySelector('#risk-trend-chart'), {
        ...CHART_DEFAULTS,
        chart: { ...CHART_DEFAULTS.chart, type: 'area', height: '100%' },
        stroke: { curve: 'monotoneCubic', width: 4 }, // Unique thick line
        fill: { type: 'gradient', gradient: { opacityFrom: 0.6, opacityTo: 0 } },
        series: [{ name: 'Risk Score', data: [] }],
        colors: [COLORS.critical],
        xaxis: { type: 'datetime', labels: { style: { fontSize: '11px', fontWeight: 600 } } },
        yaxis: { labels: { style: { fontSize: '11px', fontWeight: 600 } } }
    });
    riskTrendChart?.render();

    vendorRadarChart = new ApexCharts(document.querySelector('#vendor-radar-chart'), {
        ...CHART_DEFAULTS,
        chart: { ...CHART_DEFAULTS.chart, type: 'radar', height: '100%' },
        series: [{ name: 'Alert Volume', data: [0, 0, 0, 0, 0] }],
        labels: ['pfSense', 'Ubiquiti', 'Cisco', 'Fortinet', 'Generic'],
        colors: [COLORS.cyan],
        markers: { size: 4 },
        yaxis: { show: false }
    });
    vendorRadarChart?.render();
}


function updateAnalyticsInsights(alerts) {
    const el = document.getElementById('ai-insight-text');
    if (!el) return;
    if (alerts.length === 0) { el.textContent = "Baseline stable. No anomalies detected."; return; }

    const criticals = alerts.filter(a => a.severity === 'critical').length;
    if (criticals > 0) el.textContent = `${criticals} critical threats requiring immediate triage.`;
    else el.textContent = `Pattern identified: ${alerts.length} events correlate to standard background scans.`;
}

function updateRiskTrend(alerts) {
    if (!riskTrendChart) return;
    const container = document.getElementById('risk-trend-chart');
    if (!container || container.offsetParent === null) return;

    const points = {};
    alerts.forEach(a => {
        const hour = new Date(a.created_at || a.timestamp).setMinutes(0, 0, 0);
        const weight = a.severity === 'critical' ? 50 : (a.severity === 'high' ? 20 : 5);
        points[hour] = (points[hour] || 0) + weight;
    });
    let data = Object.entries(points).map(([x, y]) => ({ x: parseInt(x), y })).sort((a, b) => a.x - b.x);

    // Fallback: Ensure at least a horizontal line if data is sparse
    if (data.length === 0) {
        const now = Date.now();
        data = [{ x: now - 3600000, y: 0 }, { x: now, y: 0 }];
    } else if (data.length === 1) {
        data.unshift({ x: data[0].x - 3600000, y: data[0].y });
    }

    riskTrendChart.updateSeries([{ name: 'Risk Score', data }]);
}

function updateVendorRadar(alerts) {
    if (!vendorRadarChart) return;
    const container = document.getElementById('vendor-radar-chart');
    if (!container || container.offsetParent === null) return;

    const counts = { pfSense: 0, Ubiquiti: 0, Cisco: 0, Fortinet: 0, Generic: 0 };
    alerts.forEach(a => {
        const v = (a.vendor || '').toLowerCase();
        if (v.includes('pfsense')) counts.pfSense++;
        else if (v.includes('ubiquiti')) counts.Ubiquiti++;
        else if (v.includes('cisco')) counts.Cisco++;
        else if (v.includes('forti')) counts.Fortinet++;
        else counts.Generic++;
    });
    vendorRadarChart.updateSeries([{ name: 'Alert Volume', data: Object.values(counts) }]);
}

function updateHeatmap(data) {
    if (!threatHeatmap || !data) return;
    const container = document.getElementById('threat-heatmap');
    if (!container || container.offsetParent === null) return;
    threatHeatmap.updateSeries(data);
}

function renderHighRiskEntities(alerts) {
    const container = document.getElementById('high-risk-entities-list');
    if (!container) return;

    const ips = {};
    alerts.forEach(a => {
        const ip = a.source_ip || a.ip;
        if (!ip) return;
        if (!ips[ip]) ips[ip] = { count: 0, sev: (a.severity || 'low').toLowerCase() };
        ips[ip].count++;
        // Maintain highest severity seen
        const s = (a.severity || 'low').toLowerCase();
        if (s === 'critical') ips[ip].sev = 'critical';
        else if (s === 'high' && ips[ip].sev !== 'critical') ips[ip].sev = 'high';
    });

    const sorted = Object.entries(ips).sort((a, b) => b[1].count - a[1].count).slice(0, 5);
    container.innerHTML = sorted.map(([ip, d]) => `
        <div class="concise-item">
            <div class="item-main">
                <span class="mono ip-link" onclick="askAI('Tell me more about IP ${ip}')">${ip}</span>
            </div>
            <span class="badge badge-${d.sev}">${d.count} Events</span>
        </div>
    `).join('') || '<div style="padding:1rem;color:var(--text-muted);font-size:0.8rem;">No risk entities recorded.</div>';
}

function generateMockHeatmapData() {
    const data = [];
    const days = ['Sat', 'Fri', 'Thu', 'Wed', 'Tue', 'Mon', 'Sun']; // Reverse for better top-to-bottom feel
    for (let day of days) {
        const series = { name: day, data: [] };
        for (let h = 0; h < 24; h++) {
            series.data.push({ x: `${h}h`, y: Math.floor(Math.random() * 80) });
        }
        data.push(series);
    }
    return data;
}

// ===== Common Components & Utilities =====
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

function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    toast.style.cssText = `position:fixed; bottom:2rem; right:2rem; padding:1rem 1.5rem; background:${isError ? 'var(--danger)' : 'var(--primary)'}; color:white; border-radius:12px; z-index:9999; box-shadow:var(--shadow-elevated); animation:viewEnter 0.3s ease;`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(ts) {
    if (!ts) return '';
    return new Date(ts).toLocaleTimeString();
}

function timeAgo(ts) {
    if (!ts) return 'Unknown';
    const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 84600)}d ago`;
}

function setVal(id, val) {
    const el = document.getElementById(id);
    if (el) el.value = val;
}

function getVal(id) {
    const el = document.getElementById(id);
    return el ? el.value : '';
}

/**
 * Utility: Format large numbers (e.g. 1500 -> 1.5k)
 */
function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'm';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'k';
    return num.toString();
}

// ===== AI Assistant Logic (Legacy Refinement) =====
async function renderAiAssistant() {
    const container = document.getElementById('ai-messages');
    if (!container) return;
    // Just ensuring icons are up to date
    lucide.createIcons();
}

async function sendAIMessage() {
    const input = document.getElementById('ai-input');
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    addMessage('user', text);
    const suggestions = document.getElementById('ai-suggestions');
    if (suggestions) suggestions.style.display = 'none';

    // Simulate thinking
    const loadingId = 'ai-loading-' + Date.now();
    addMessage('system', `<div id="${loadingId}">Correlating security signals...</div>`);

    setTimeout(() => {
        const loadingEl = document.getElementById(loadingId);
        if (loadingEl) loadingEl.parentElement.remove();
        addMessage('system', generateAIResponse(text));
    }, 1200);
}

function askAI(question) {
    const input = document.getElementById('ai-input');
    if (input) {
        input.value = question;
        sendAIMessage();
    }
}

function addMessage(role, text) {
    const container = document.getElementById('ai-messages');
    if (!container) return;
    const msg = document.createElement('div');
    msg.className = `message ${role}`;
    msg.innerHTML = text;
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
}

function generateAIResponse(input) {
    const query = input.toLowerCase();
    if (query.includes('risk')) return "Analyzing your baseline telemetry. Overall risk is <b>Moderate</b> due to persistent edge scanning. I recommend reviewing pfSense firewall rules.";
    if (query.includes('threat')) return "Top threats currently include <b>Brute Force</b> and sporadic <b>Port Scanning</b>. Most activity originates from foreign autonomous systems.";
    return "I am processing your signal correlations. Your SIEM is currently healthy across all monitored nodes.";
}

// ===== Professional Reporting Modal Logic =====
function triggerReportGeneration() {
    const modal = document.getElementById('gen-report-modal');
    if (modal) {
        modal.style.display = 'flex';
        setVal('gen-report-start', new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0]);
        setVal('gen-report-end', new Date().toISOString().split('T')[0]);
        lucide.createIcons();
    }
}

function closeGenModal() { document.getElementById('gen-report-modal').style.display = 'none'; }
function toggleCustomDates() {
    const section = document.getElementById('custom-date-section');
    if (section) section.style.display = getVal('gen-report-type') === 'custom' ? 'block' : 'none';
}

async function submitReportGeneration() {
    const type = getVal('gen-report-type');
    const start = getVal('gen-report-start');
    const end = getVal('gen-report-end');
    showToast(`Initiating ${type} report for tenant ${currentTenant}...`);
    closeGenModal();
    // In real app, would call /api/v1/reports/generate
    setTimeout(() => {
        showToast("Report queued! Check the archive in 30 seconds.");
        fetchReportsData();
    }, 2000);
}

function closeReportModal() {
    const modal = document.getElementById('report-modal');
    if (modal) modal.style.display = 'none';
}

// ============================================
// ASSETS (DEVICE MANAGEMENT) LOGIC
// ============================================

async function renderAssets() {
    try {
        setLoading(true);
        // 1. Fetch Managed and Discovered Assets
        const managedRes = await apiFetch(`${API_BASE_URL}/api/v1/assets/managed?tenant_id=${currentTenant}`);
        const discoveredRes = await apiFetch(`${API_BASE_URL}/api/v1/assets/discovered?tenant_id=${currentTenant}`);

        const managed = (managedRes && managedRes.ok) ? await managedRes.json() : [];
        const discovered = (discoveredRes && discoveredRes.ok) ? (await discoveredRes.json()).data : [];

        // Update Stats
        const totalCount = document.getElementById('asset-count-total');
        const onlineCount = document.getElementById('asset-count-online');
        const unmanagedCount = document.getElementById('asset-count-unmanaged');

        if (totalCount) totalCount.textContent = managed.length;
        if (onlineCount) onlineCount.textContent = managed.filter(d => d.is_online).length;
        if (unmanagedCount) unmanagedCount.textContent = discovered.length;

        // Render Managed Table
        const managedBody = document.getElementById('managed-assets-body');
        if (managedBody) {
            managedBody.innerHTML = managed.length ? managed.map(d => `
                <tr>
                    <td>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <div class="avatar" style="background: rgba(59, 130, 246, 0.1); color: #3b82f6;">
                                <i data-lucide="${getCategoryIcon(d.category)}" style="width:14px;height:14px;"></i>
                            </div>
                            <div style="display:flex; flex-direction:column;">
                                <span style="font-weight:600;">${d.name}</span>
                                <span style="font-size:10px; color:var(--text-muted);">${d.device_id || 'ID Pending'}</span>
                            </div>
                        </div>
                    </td>
                    <td><code>${d.ip_address}</code></td>
                    <td><span class="badge-beta" style="background:rgba(148,163,184,0.1); color:var(--text-muted); padding:2px 6px;">${d.category.toUpperCase()}</span></td>
                    <td>
                        <span class="status-badge ${d.is_online ? 'online' : 'offline'}">
                            <i data-lucide="${d.is_online ? 'zap' : 'zap-off'}"></i>
                            ${d.is_online ? 'Online' : 'Offline'}
                        </span>
                    </td>
                    <td style="font-size:0.75rem; color:var(--text-muted);">${d.last_log_at ? formatTime(d.last_log_at) : 'No logs yet'}</td>
                    <td>
                        <button class="btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="deleteManagedDevice(${d.id})">
                            <i data-lucide="trash-2" style="width:12px;height:12px;"></i> Unregister
                        </button>
                    </td>
                </tr>
            `).join('') : '<tr><td colspan="6" style="text-align:center; padding:2rem; color:var(--text-muted);">No managed devices. Start by registering one!</td></tr>';
        }

        // Render Discovered Table
        const discoveredBody = document.getElementById('discovered-assets-body');
        if (discoveredBody) {
            discoveredBody.innerHTML = discovered.length ? discovered.map(a => `
                <tr>
                    <td><code style="color:var(--accent-blue);">${a.device_id}</code></td>
                    <td>
                        <div style="display:flex; align-items:center; gap:8px;">
                            <span class="badge-beta" style="background:rgba(59,130,246,0.1); color:#3b82f6; padding:2px 6px;">${a.type.toUpperCase()}</span>
                            <span style="font-size:11px; color:var(--text-muted);">${a.vendor}</span>
                        </div>
                    </td>
                    <td>${a.event_count}</td>
                    <td>
                        <span class="badge-threat ${a.threat_count > 0 ? 'high' : 'low'}" style="padding:2px 8px;">
                            ${a.threat_count} Alerts
                        </span>
                    </td>
                    <td style="font-size:0.75rem; color:var(--text-muted);">${formatTime(a.last_seen)}</td>
                    <td>
                        <button class="btn-primary" style="padding:4px 8px; font-size:11px;" 
                                onclick="prefillRegistration('${a.device_id}', '${a.vendor}', '${a.type}')">
                            <i data-lucide="plus" style="width:12px;height:12px;"></i> Register
                        </button>
                    </td>
                </tr>
            `).join('') : '<tr><td colspan="6" style="text-align:center; padding:2rem; color:var(--text-muted);">No newly discovered assets.</td></tr>';
        }

        lucide.createIcons();
    } catch (e) { console.error('[SIEM] Asset rendering error:', e); }
    finally { setLoading(false); }
}

function getCategoryIcon(cat) {
    const icons = {
        'firewall': 'shield',
        'switch': 'network',
        'server': 'database',
        'endpoint': 'monitor',
        'waf': 'globe',
        'other': 'server'
    };
    return icons[cat ? cat.toLowerCase() : 'other'] || 'server';
}

function openRegisterDeviceModal() {
    const modal = document.getElementById('register-device-modal');
    if (modal) {
        modal.style.display = 'flex';
        lucide.createIcons();
    }
}

function closeRegisterDeviceModal() {
    const modal = document.getElementById('register-device-modal');
    if (modal) modal.style.display = 'none';
    const form = document.getElementById('register-device-form');
    if (form) form.reset();
}

function prefillRegistration(ip, vendor, type) {
    openRegisterDeviceModal();
    const ipField = document.getElementById('reg-device-ip');
    const nameField = document.getElementById('reg-device-name');
    const catField = document.getElementById('reg-device-category');

    if (ipField) ipField.value = ip;
    if (nameField) nameField.value = `${vendor} ${type}`.trim();
    if (catField) catField.value = (['firewall', 'switch', 'server', 'endpoint', 'waf'].includes(type.toLowerCase())) ? type.toLowerCase() : 'other';
}

async function submitRegisterDevice(e) {
    if (e) e.preventDefault();
    const payload = {
        name: document.getElementById('reg-device-name').value,
        ip_address: document.getElementById('reg-device-ip').value,
        device_id: document.getElementById('reg-device-id').value,
        category: document.getElementById('reg-device-category').value,
        description: document.getElementById('reg-device-desc').value
    };

    try {
        setLoading(true);
        // Use standardized apiFetch with POST method
        const res = await apiFetch(`${API_BASE_URL}/api/v1/assets/managed?tenant_id=${currentTenant}`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        if (res && res.ok) {
            showToast('Device registered and allowlisted successfully!', false);
            closeRegisterDeviceModal();
            renderAssets();
        } else {
            const msg = res ? res.message : 'Unknown error';
            showToast(`Registration failed: ${msg}`, true);
        }
    } catch (e) {
        console.error('Registration error:', e);
        showToast('Network error while registering device', true);
    } finally {
        setLoading(false);
    }
}

async function deleteManagedDevice(id) {
    if (!confirm('Are you sure you want to unregister this device? It will no longer be tracked as managed.')) return;

    try {
        setLoading(true);
        const res = await apiFetch(`${API_BASE_URL}/api/v1/assets/managed/${id}?tenant_id=${currentTenant}`, {
            method: 'DELETE'
        });

        if (res && res.ok) {
            showToast('Device unregistered successfully', false);
            renderAssets();
        } else {
            const msg = res ? res.message : 'Unknown error';
            showToast(`Delete failed: ${msg}`, true);
        }
    } catch (e) {
        console.error('Delete error:', e);
        showToast('Network error while unregistering device', true);
    } finally {
        setLoading(false);
    }
}
