/**
 * Global Constants & Endpoints
 */
const API_BASE = "https://endoflife.date/api/v1";
const OSV_API = "https://api.osv.dev/v1/query";
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const BATCH_SIZE = 5;

/**
 * Severity Parser for OSV
 */
function getSeverityLabel(vuln) {
    const dbSpec = vuln.database_specific || {};
    const priority = dbSpec.ubuntu_priority || dbSpec.priority || dbSpec.severity || dbSpec.level;
    if (priority && typeof priority === 'string') {
        const label = priority.trim().toLowerCase();
        if (label.includes('crit')) return "Critical";
        if (label.includes('high')) return "High";
        if (label.includes('med')) return "Medium";
        if (label.includes('low')) return "Low";
    }
    const cvssObj = vuln.severity?.find(s => s.type === 'CVSS_V3' || s.type === 'CVSS_V2');
    const score = cvssObj ? parseFloat(cvssObj.score) : parseFloat(dbSpec.cvss_score);
    if (!isNaN(score)) {
        if (score >= 9.0) return "Critical";
        if (score >= 7.0) return "High";
        if (score >= 4.0) return "Medium";
        return "Low";
    }
    return "Unknown";
}

/**
 * Comprehensive Severity Parser for NVD
 */
function getNVDSeverity(cve) {
    let metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];

    const label = metrics?.cvssData?.baseSeverity || metrics?.baseSeverity;
    if (label) {
        const l = label.toLowerCase();
        return l.charAt(0).toUpperCase() + l.slice(1);
    }

    const score = metrics?.cvssData?.baseScore;
    if (score !== undefined && score !== null) {
        if (score >= 9.0) return "Critical";
        if (score >= 7.0) return "High";
        if (score >= 4.0) return "Medium";
        return "Low";
    }
    return "Unknown";
}

/**
 * Extract Fixed Version from NVD
 */
function getNVDFixedVersion(cve) {
    if (!cve.configurations) return "Not Fixed";
    for (const config of cve.configurations) {
        for (const node of config.nodes) {
            if (!node.cpeMatch) continue;
            for (const match of node.cpeMatch) {
                if (match.versionEndExcluding) return match.versionEndExcluding;
            }
        }
    }
    return "Check NVD";
}

function getFixedVersion(vuln) {
    if (!vuln.affected) return "None";
    for (const affected of vuln.affected) {
        if (!affected.ranges) continue;
        for (const range of affected.ranges) {
            const fixedEvent = range.events?.find(e => e.fixed);
            if (fixedEvent) return fixedEvent.fixed;
        }
    }
    return "Not Fixed";
}

async function fetchOSVVulnerabilities(packageName, version) {
    if (!version) return [];
    try {
        const response = await fetch(OSV_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ version: version.toString(), package: { name: packageName } })
        });
        const data = await response.json();
        return data.vulns || [];
    } catch (err) { return 'Err'; }
}

async function fetchNVDVulnerabilities(productName, version) {
    if (!version) return [];
    try {
        const url = `${NVD_API}?keywordSearch=${productName} ${version}`;
        const response = await fetch(url);
        if (!response.ok) return 'Err';
        const data = await response.json();
        return data.vulnerabilities || [];
    } catch (err) { return 'Err'; }
}

function calculateDaysRemaining(dateStr) {
    if (!dateStr) return null;
    const diffTime = new Date(dateStr) - new Date();
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}

function toggleRow(id, btn) {
    const row = document.getElementById(id);
    const isOpen = row.style.display === 'table-row';

    document.querySelectorAll('.details-row').forEach(r => {
        r.style.display = 'none';
    });
    document.querySelectorAll('.expand-btn').forEach(b => {
        if (b.id !== "resetFilters") b.textContent = '+';
    });

    if (!isOpen) {
        row.style.display = 'table-row';
        btn.textContent = '−';
    }
}

function applyFilters() {
    const s = document.getElementById("toolSearch").value.toUpperCase();
    const c = document.getElementById("categoryFilter").value;
    const m = document.getElementById("maintenanceFilter").value;
    const sec = document.getElementById("securityFilter").value;

    document.querySelectorAll('.details-row').forEach(r => r.style.display = 'none');
    document.querySelectorAll('.expand-btn').forEach(b => {
        if (b.id !== "resetFilters") b.textContent = '+';
    });

    document.querySelectorAll(".row-tool").forEach(row => {
        const isEol = row.getAttribute('data-eol') === 'true';
        const days = parseInt(row.getAttribute('data-days'));
        const rowCat = row.getAttribute('data-category');
        const hasVulns = row.getAttribute('data-has-vulns') === 'true';

        const matchesSearch = row.innerText.toUpperCase().includes(s);
        const matchesCat = (c === 'all' || rowCat === c);

        let matchesMtn = true;
        if (m === 'eol') matchesMtn = isEol;
        else if (m === '30') matchesMtn = !isEol && days <= 30;
        else if (m === '60') matchesMtn = !isEol && days <= 60;
        else if (m === '90') matchesMtn = !isEol && days <= 90;

        let matchesSec = true;
        if (sec === 'vulnerable') matchesSec = hasVulns;
        else if (sec === 'secure') matchesSec = !hasVulns;

        row.style.display = (matchesSearch && matchesCat && matchesMtn && matchesSec) ? "" : "none";
    });
}

function resetFilters() {
    document.getElementById("toolSearch").value = "";
    document.getElementById("categoryFilter").value = "all";
    document.getElementById("maintenanceFilter").value = "all";
    document.getElementById("securityFilter").value = "all";

    document.querySelectorAll('.details-row').forEach(row => {
        row.style.display = 'none';
    });
    document.querySelectorAll('.expand-btn').forEach(btn => {
        if (btn.id !== "resetFilters") btn.textContent = '+';
    });

    applyFilters();
}

async function initDashboard() {
    const tableBody = document.getElementById('tableBody');
    const progress = document.getElementById('progress');
    const catFilterSelect = document.getElementById('categoryFilter');

    try {
        const productsResponse = await fetch(`${API_BASE}/products`);
        const productsList = await productsResponse.json();
        const categories = [...new Set(productsList.result.map(p => p.category))].sort();
        categories.forEach(cat => {
            const opt = document.createElement('option');
            opt.value = cat; opt.textContent = cat;
            catFilterSelect.appendChild(opt);
        });

        const listResponse = await fetch('tools.json');
        const myToolsConfig = await listResponse.json();

        for (let i = 0; i < myToolsConfig.length; i += BATCH_SIZE) {
            const batch = myToolsConfig.slice(i, i + BATCH_SIZE);
            const results = await Promise.all(batch.map(async (item) => {
                const lifecycle = await fetch(`${API_BASE}/products/${item.name}`).then(r => r.ok ? r.json() : { error: true });
                const osvVulns = await fetchOSVVulnerabilities(item.name, item.current);
                const nvdVulns = await fetchNVDVulnerabilities(item.name, item.current);
                return { lifecycle, osvVulns, nvdVulns, configItem: item };
            }));

            results.forEach((res, index) => {
                const { lifecycle, osvVulns, nvdVulns, configItem } = res;
                const globalIndex = i + index;
                if (lifecycle.error) return;

                const product = lifecycle.result;
                const releases = product.releases;
                const currentCycle = releases.find(r => r.name === configItem.current.toString());
                const daysUntilEol = calculateDaysRemaining(currentCycle?.eolFrom);
                const isEol = currentCycle ? currentCycle.isEol : null;

                let statusText = currentCycle ? (isEol ? 'End of Life' : 'Maintained') : 'Version Unknown';

                // FIXED: Use status-neutral for Unknown versions
                let statusClass = 'status-neutral';
                if (currentCycle) {
                    statusClass = isEol ? 'status-eol' : (daysUntilEol !== null && daysUntilEol <= 90 ? 'status-warning' : 'status-active');
                    if (!isEol && daysUntilEol !== null && daysUntilEol <= 90) statusText = `EOL in ${daysUntilEol} Days`;
                }

                const osvFound = Array.isArray(osvVulns) && osvVulns.length > 0;
                const nvdFound = Array.isArray(nvdVulns) && nvdVulns.length > 0;
                const hasAnyVulns = osvFound || nvdFound;

                const rowHtml = `
                    <tr class="row-tool" data-eol="${isEol}" data-category="${product.category}" data-days="${daysUntilEol ?? 9999}" data-has-vulns="${hasAnyVulns}">
                        <td><button class="expand-btn" onclick="toggleRow('details-${globalIndex}', this)">+</button></td>
                        <td style="min-width: 200px;">
                            <div style="font-weight: 700; font-size: 1rem;">${product.label}</div>
                            <div style="font-size:0.75rem; color:var(--text-muted); text-transform: uppercase; letter-spacing: 0.02em;">${product.category}</div>
                        </td>
                        <td><span class="v-tag">${configItem.current}</span></td>
                        <td>${currentCycle?.releaseDate || '—'}</td>
                        <td><span class="v-tag">${releases[0].name}</span></td>
                        <td>${releases[0].releaseDate}</td>
                        <td><span class="badge ${statusClass}">${statusText}</span></td>
                        <td>${osvFound ? `<span class="badge status-eol">${osvVulns.length} Issues</span>` : `<span class="badge status-active">Secure</span>`}</td>
                        <td>${nvdFound ? `<span class="badge status-warning">${nvdVulns.length} CVEs</span>` : `<span class="badge status-active">0 CVEs</span>`}</td>
                    </tr>
                    <tr id="details-${globalIndex}" class="details-row" style="display: none;">
                        <td colspan="9">
                            <div class="details-wrapper">
                                <details style="margin-bottom: 1rem;">
                                    <summary style="cursor: pointer; font-weight: 600; font-size: 1rem; color: var(--brand);">Full Release History</summary>
                                    <table class="history-table">
                                        <thead><tr><th>Cycle</th><th>Release Date</th><th>EOL Date</th></tr></thead>
                                        <tbody>
                                            ${releases.slice(0, 10).map(r => `<tr><td><strong>${r.name}</strong></td><td>${r.releaseDate}</td><td>${r.eolFrom || 'Maintained'}</td></tr>`).join('')}
                                        </tbody>
                                    </table>
                                </details>

                                <details style="margin-bottom: 1rem;">
                                    <summary style="cursor: pointer; font-weight: 600; font-size: 1rem; color: var(--danger);">OSV Advisories (${osvFound ? osvVulns.length : 0})</summary>
                                    <table class="history-table">
                                        <thead><tr><th>ID</th><th>Severity</th><th>Fixed In</th><th>Description</th></tr></thead>
                                        <tbody>
                                            ${osvFound ? osvVulns.map(v => `
                                                <tr>
                                                    <td><a href="https://osv.dev/vulnerability/${v.id}" target="_blank" class="vuln-link">${v.id}</a></td>
                                                    <td><span class="badge ${getSeverityLabel(v) === 'Critical' || getSeverityLabel(v) === 'High' ? 'status-eol' : 'status-warning'}">${getSeverityLabel(v)}</span></td>
                                                    <td><span class="fixed-tag">${getFixedVersion(v)}</span></td>
                                                    <td>${v.summary || (v.details ? v.details.substring(0, 100) + '...' : 'N/A')}</td>
                                                </tr>`).join('') : '<tr><td colspan="4">No OSV issues found.</td></tr>'}
                                        </tbody>
                                    </table>
                                </details>

                                <details>
                                    <summary style="cursor: pointer; font-weight: 600; font-size: 1rem; color: #92400e;">NVD Advisories (${nvdFound ? nvdVulns.length : 0})</summary>
                                    <table class="history-table">
                                        <thead><tr><th>CVE ID</th><th>Severity</th><th>Fixed In</th><th>Description</th></tr></thead>
                                        <tbody>
                                            ${nvdFound ? nvdVulns.map(v => `
                                                <tr>
                                                    <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve.id}" target="_blank" class="vuln-link">${v.cve.id}</a></td>
                                                    <td><span class="badge ${getNVDSeverity(v.cve) === 'Critical' || getNVDSeverity(v.cve) === 'High' ? 'status-eol' : 'status-warning'}">${getNVDSeverity(v.cve)}</span></td>
                                                    <td><span class="fixed-tag">${getNVDFixedVersion(v.cve)}</span></td>
                                                    <td>${v.cve.descriptions?.[0]?.value ? v.cve.descriptions[0].value.substring(0, 100) + '...' : 'N/A'}</td>
                                                </tr>`).join('') : '<tr><td colspan="4">No NVD issues found.</td></tr>'}
                                        </tbody>
                                    </table>
                                </details>
                            </div>
                        </td>
                    </tr>`;
                tableBody.insertAdjacentHTML('beforeend', rowHtml);
            });
            progress.style.width = Math.round(((i + batch.length) / myToolsConfig.length) * 100) + '%';
            document.getElementById('itemCount').textContent = `${Math.min(i + batch.length, myToolsConfig.length)} / ${myToolsConfig.length} Tools Tracked`;
        }
    } catch (err) { console.error(err); }
}

initDashboard();
