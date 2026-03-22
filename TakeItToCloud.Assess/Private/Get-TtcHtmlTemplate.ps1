function Get-TtcHtmlTemplate {
    <#
    .SYNOPSIS
        Returns the self-contained HTML report template.
    .DESCRIPTION
        Generates the HTML/CSS/JS template used by Export-TtcHtmlReport.
        The template uses placeholder tokens that get replaced with actual data.
        Fully self-contained with no external CDN dependencies.
    #>
    [CmdletBinding()]
    param()

    return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ReportTitle}}  -  TakeItToCloud Assessment</title>
<style>
:root {
    --navy-900: #0f172a; --navy-800: #1e293b; --navy-700: #334155; --navy-600: #475569;
    --navy-500: #64748b; --navy-400: #94a3b8; --navy-300: #cbd5e1; --navy-200: #e2e8f0; --navy-100: #f1f5f9;
    --green-500: #10b981; --green-400: #34d399; --green-600: #059669;
    --red-500: #ef4444; --red-400: #f87171; --orange-500: #f97316; --yellow-500: #eab308; --blue-500: #3b82f6;
    --font-main: 'Segoe UI', system-ui, -apple-system, sans-serif;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: var(--font-main); background: var(--navy-100); color: var(--navy-800); line-height: 1.6; }

/* --- Header --- */
.header { background: linear-gradient(135deg, var(--navy-900) 0%, var(--navy-800) 100%); color: white; padding: 2.5rem 2rem; }
.header h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.25rem; }
.header .subtitle { color: var(--green-400); font-size: 1rem; font-weight: 500; }
.header .meta { display: flex; gap: 2rem; margin-top: 1rem; font-size: 0.85rem; color: var(--navy-300); flex-wrap: wrap; }
.header .meta span { display: flex; align-items: center; gap: 0.35rem; }

/* --- Container --- */
.container { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }

/* --- Score Cards --- */
.scores { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.score-card { background: white; border-radius: 10px; padding: 1.5rem; text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08); border-top: 4px solid var(--navy-300); transition: transform 0.15s; }
.score-card:hover { transform: translateY(-2px); }
.score-card.overall { border-top-color: var(--green-500); }
.score-card.security { border-top-color: var(--red-500); }
.score-card.health { border-top-color: var(--blue-500); }
.score-card.governance { border-top-color: var(--orange-500); }
.score-value { font-size: 2.5rem; font-weight: 800; line-height: 1.2; }
.score-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--navy-500); margin-top: 0.25rem; }
.score-good { color: var(--green-600); }
.score-warn { color: var(--orange-500); }
.score-bad { color: var(--red-500); }

/* --- Summary Strip --- */
.summary-strip { display: flex; gap: 0.75rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.summary-badge { padding: 0.6rem 1.2rem; border-radius: 8px; font-weight: 600; font-size: 0.9rem; color: white; text-align: center; min-width: 110px; }
.sev-critical { background: var(--red-500); } .sev-high { background: var(--orange-500); }
.sev-medium { background: var(--yellow-500); color: var(--navy-900); } .sev-low { background: var(--blue-500); }
.sev-info { background: var(--navy-400); } .sev-pass { background: var(--green-500); }

/* --- Section --- */
.section { background: white; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.section h2 { font-size: 1.15rem; font-weight: 700; color: var(--navy-900); margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 2px solid var(--navy-200); }

/* --- Filters --- */
.filters { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem; align-items: center; }
.filters select, .filters input { padding: 0.5rem 0.75rem; border: 1px solid var(--navy-300); border-radius: 6px;
    font-size: 0.85rem; font-family: var(--font-main); background: white; color: var(--navy-800); }
.filters input { min-width: 250px; }
.filters select:focus, .filters input:focus { outline: none; border-color: var(--green-500); box-shadow: 0 0 0 2px rgba(16,185,129,0.15); }
.btn-reset { padding: 0.5rem 1rem; background: var(--navy-200); border: none; border-radius: 6px; cursor: pointer;
    font-size: 0.85rem; font-family: var(--font-main); color: var(--navy-700); transition: background 0.15s; }
.btn-reset:hover { background: var(--navy-300); }
.result-count { font-size: 0.85rem; color: var(--navy-500); margin-left: auto; }

/* --- Table --- */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
thead th { background: var(--navy-900); color: white; padding: 0.7rem 0.6rem; text-align: left;
    font-weight: 600; position: sticky; top: 0; cursor: pointer; white-space: nowrap; user-select: none; }
thead th:hover { background: var(--navy-700); }
thead th .sort-arrow { margin-left: 4px; opacity: 0.5; }
thead th.sorted .sort-arrow { opacity: 1; }
tbody tr { border-bottom: 1px solid var(--navy-200); transition: background 0.1s; }
tbody tr:hover { background: var(--navy-100); }
tbody td { padding: 0.6rem; vertical-align: top; }
.sev-badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; color: white; }
.sev-badge.Critical { background: var(--red-500); } .sev-badge.High { background: var(--orange-500); }
.sev-badge.Medium { background: var(--yellow-500); color: var(--navy-900); } .sev-badge.Low { background: var(--blue-500); }
.sev-badge.Informational { background: var(--navy-400); }
.status-badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
.status-badge.Fail { background: #fee2e2; color: var(--red-500); } .status-badge.Pass { background: #d1fae5; color: var(--green-600); }
.status-badge.Warning { background: #fef3c7; color: #b45309; } .status-badge.Error { background: #fde8e8; color: #991b1b; }
.status-badge.NotAssessed { background: var(--navy-200); color: var(--navy-600); }

/* --- Expandable Detail --- */
.detail-toggle { cursor: pointer; color: var(--green-600); text-decoration: underline; font-size: 0.8rem; }
.detail-row { display: none; }
.detail-row.open { display: table-row; }
.detail-cell { padding: 1rem; background: var(--navy-100); }
.detail-cell dl { display: grid; grid-template-columns: 140px 1fr; gap: 0.3rem 1rem; font-size: 0.82rem; }
.detail-cell dt { font-weight: 600; color: var(--navy-600); }
.detail-cell dd { color: var(--navy-800); }

/* --- Workload Grid --- */
.wl-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
.wl-card { border: 1px solid var(--navy-200); border-radius: 8px; padding: 1rem; }
.wl-card h3 { font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem; }
.wl-bar { height: 6px; border-radius: 3px; background: var(--navy-200); margin-top: 0.5rem; overflow: hidden; }
.wl-bar-fill { height: 100%; border-radius: 3px; transition: width 0.5s; }

/* --- Footer --- */
.footer { text-align: center; padding: 2rem; color: var(--navy-500); font-size: 0.8rem; }
.footer a { color: var(--green-600); text-decoration: none; }

/* --- Print --- */
@media print { .filters, .btn-reset { display: none; } .header { background: var(--navy-900) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
@media (max-width: 768px) { .scores { grid-template-columns: repeat(2, 1fr); } .filters { flex-direction: column; } .filters input { min-width: 100%; } }
</style>
</head>
<body>

<div class="header">
    <h1>{{ReportTitle}}</h1>
    <div class="subtitle">TakeItToCloud Infrastructure & Security Assessment</div>
    <div class="meta">
        <span>Generated: {{GeneratedAt}}</span>
        <span>Customer: {{CustomerName}}</span>
        <span>Assessed By: {{AssessedBy}}</span>
        <span>Findings: {{TotalFindings}}</span>
    </div>
</div>

<div class="container">

    <!-- Score Cards -->
    <div class="scores">
        <div class="score-card overall">
            <div class="score-value {{OverallScoreClass}}">{{OverallScore}}</div>
            <div class="score-label">Overall Score</div>
        </div>
        <div class="score-card security">
            <div class="score-value {{SecurityScoreClass}}">{{SecurityScore}}</div>
            <div class="score-label">Security</div>
        </div>
        <div class="score-card health">
            <div class="score-value {{HealthScoreClass}}">{{HealthScore}}</div>
            <div class="score-label">Health</div>
        </div>
        <div class="score-card governance">
            <div class="score-value {{GovernanceScoreClass}}">{{GovernanceScore}}</div>
            <div class="score-label">Governance</div>
        </div>
    </div>

    <!-- Severity Summary -->
    <div class="summary-strip">
        <div class="summary-badge sev-critical">Critical: {{CriticalCount}}</div>
        <div class="summary-badge sev-high">High: {{HighCount}}</div>
        <div class="summary-badge sev-medium">Medium: {{MediumCount}}</div>
        <div class="summary-badge sev-low">Low: {{LowCount}}</div>
        <div class="summary-badge sev-pass">Pass: {{PassCount}}</div>
    </div>

    <!-- Workload Breakdown -->
    <div class="section">
        <h2>Workload Breakdown</h2>
        <div class="wl-grid">
            {{WorkloadCards}}
        </div>
    </div>

    <!-- Findings Table -->
    <div class="section">
        <h2>Assessment Findings</h2>
        <div class="filters">
            <select id="fSeverity"><option value="">All Severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select>
            <select id="fWorkload"><option value="">All Workloads</option>{{WorkloadOptions}}</select>
            <select id="fCategory"><option value="">All Categories</option>{{CategoryOptions}}</select>
            <select id="fStatus"><option value="">All Statuses</option><option>Fail</option><option>Pass</option><option>Warning</option><option>Error</option><option>NotAssessed</option></select>
            <select id="fFramework"><option value="">All Frameworks</option>{{FrameworkOptions}}</select>
            <input type="text" id="fSearch" placeholder="Search findings...">
            <button class="btn-reset" onclick="resetFilters()">Reset</button>
            <span class="result-count" id="resultCount"></span>
        </div>
        <div class="table-wrap">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">ID <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(1)">Severity <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(2)">Status <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(3)">Workload <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(4)">Category <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(5)">Check Name <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(6)">Issue Detected <span class="sort-arrow">&#9650;</span></th>
                        <th onclick="sortTable(7)">Framework <span class="sort-arrow">&#9650;</span></th>
                        <th>Detail</th>
                    </tr>
                </thead>
                <tbody>
                    {{FindingsRows}}
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="footer">
    <p>Generated by <a href="https://takeittocloud.com" target="_blank">TakeItToCloud.Assess</a> &mdash; Microsoft 365 &amp; Hybrid Infrastructure Assessment Framework</p>
</div>

<script>
// --- Filter logic ---
function applyFilters() {
    const sev = document.getElementById('fSeverity').value;
    const wl  = document.getElementById('fWorkload').value;
    const cat = document.getElementById('fCategory').value;
    const st  = document.getElementById('fStatus').value;
    const fw  = document.getElementById('fFramework').value;
    const q   = document.getElementById('fSearch').value.toLowerCase();
    const rows = document.querySelectorAll('#findingsTable tbody tr.finding-row');
    let visible = 0;
    rows.forEach(r => {
        const d = r.dataset;
        const text = r.textContent.toLowerCase();
        const match = (!sev || d.severity === sev) && (!wl || d.workload === wl) && (!cat || d.category === cat)
            && (!st || d.status === st) && (!fw || d.framework === fw) && (!q || text.includes(q));
        r.style.display = match ? '' : 'none';
        // Also hide associated detail row
        const detailRow = r.nextElementSibling;
        if (detailRow && detailRow.classList.contains('detail-row')) {
            detailRow.style.display = 'none';
            detailRow.classList.remove('open');
        }
        if (match) visible++;
    });
    document.getElementById('resultCount').textContent = visible + ' of ' + rows.length + ' findings';
}
function resetFilters() {
    document.getElementById('fSeverity').value = '';
    document.getElementById('fWorkload').value = '';
    document.getElementById('fCategory').value = '';
    document.getElementById('fStatus').value = '';
    document.getElementById('fFramework').value = '';
    document.getElementById('fSearch').value = '';
    applyFilters();
}
document.querySelectorAll('.filters select, .filters input').forEach(el => {
    el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', applyFilters);
});

// --- Sort logic ---
let sortDir = {};
function sortTable(col) {
    const table = document.getElementById('findingsTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr.finding-row'));
    sortDir[col] = !sortDir[col];
    const dir = sortDir[col] ? 1 : -1;
    const sevOrder = {Critical:0, High:1, Medium:2, Low:3, Informational:4};
    rows.sort((a, b) => {
        let aVal = a.children[col]?.textContent.trim() || '';
        let bVal = b.children[col]?.textContent.trim() || '';
        if (col === 1) { aVal = sevOrder[aVal] ?? 9; bVal = sevOrder[bVal] ?? 9; return (aVal - bVal) * dir; }
        return aVal.localeCompare(bVal) * dir;
    });
    rows.forEach(r => {
        const detail = r.nextElementSibling;
        tbody.appendChild(r);
        if (detail && detail.classList.contains('detail-row')) tbody.appendChild(detail);
    });
}

// --- Detail toggle ---
function toggleDetail(id) {
    const row = document.getElementById('detail-' + id);
    if (row) row.classList.toggle('open');
}

// --- Init ---
applyFilters();
</script>
</body>
</html>
'@
}
