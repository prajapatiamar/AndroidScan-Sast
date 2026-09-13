/* ============================================================
   Branding — edit these to personalize the dashboard.
   ============================================================ */
const BRAND = {
  name: "Amar Kumar",
  role: "Technical Lead",
  company: "Appinventiv",
  quote: "Secure Code Builds a Stronger Tomorrow.",
  headerQuote: "Clean Code. Safer Apps. Better Users.",
};

const SEVERITY_COLORS = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)',
  low: 'var(--low)', info: 'var(--info)',
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORY_ORDER = ['vulnerability', 'bug', 'code_smell'];
const CATEGORY_LABELS = { vulnerability: 'Vulnerabilities', bug: 'Bugs', code_smell: 'Code Smells' };
const CATEGORY_ICON_BG = { vulnerability: 'rgba(242,84,91,.15)', bug: 'rgba(86,168,232,.15)', code_smell: 'rgba(242,201,76,.15)' };
const CATEGORY_ICON_FG = { vulnerability: 'var(--critical)', bug: 'var(--low)', code_smell: 'var(--medium)' };
const DISPLAY_CATEGORY_ORDER = ['code_smell', 'vulnerability', 'maintainability', 'bug'];
const DISPLAY_CATEGORY_LABELS = { code_smell: 'Code Smell', vulnerability: 'Security Vulnerability', maintainability: 'Maintainability', bug: 'Bug' };
const DISPLAY_CATEGORY_COLORS = { code_smell: 'var(--medium)', vulnerability: 'var(--high)', maintainability: 'var(--low)', bug: '#9B7CF2' };
const PAGE_SIZE = 150;

let pendingFiles = null;
let pendingZip = null;
let currentResult = null;   // the scan currently shown on Dashboard / Findings
let historyCache = [];
let rulesCache = null;
let activeSeverity = 'all';
let activeCategory = 'all';
let renderedCount = 0;
let pollTimer = null;

/* ============================================================
   Branding injection
   ============================================================ */
function initials(name) {
  return name.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
}
function applyBranding() {
  const firstName = BRAND.name.split(/\s+/)[0];
  document.getElementById('sidebarQuote').textContent = BRAND.quote;
  document.getElementById('sidebarUserName').textContent = BRAND.name;
  document.getElementById('sidebarUserRole').textContent = `${BRAND.role}, ${BRAND.company}`;
  document.getElementById('userAvatarInitials').textContent = initials(BRAND.name);
  document.getElementById('topbarAvatarInitials').textContent = initials(BRAND.name);
  document.getElementById('poweredByName').textContent = firstName;
  document.getElementById('footerSignature').textContent = firstName;
  document.getElementById('footerCompany').textContent = BRAND.company;
  document.getElementById('headerQuote').textContent = `\u201C${BRAND.headerQuote}\u201D`;
  document.getElementById('headerQuoteName').textContent = BRAND.name;
  document.getElementById('headerQuoteRole').textContent = `${BRAND.role}, ${BRAND.company}`;
}
applyBranding();

/* ============================================================
   Page navigation
   ============================================================ */
function goToPage(pageId) {
  document.querySelectorAll('.page').forEach(el => el.classList.toggle('hidden', el.dataset.page !== pageId));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.page === pageId));
  if (pageId === 'scan-history') renderHistoryPage();
  if (pageId === 'reports') renderReportsPage();
  if (pageId === 'security-rules') renderRulesPage();
  if (pageId === 'settings') renderSettingsPage();
  if (pageId === 'findings') renderFindingsPage();
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
}
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => goToPage(item.dataset.page));
});
document.getElementById('newScanBtn').addEventListener('click', () => goToPage('scan-projects'));

/* ============================================================
   Upload handling (Scan Projects page)
   ============================================================ */
const dropzone = document.getElementById('dropzone');
const folderInput = document.getElementById('folderInput');
const zipInput = document.getElementById('zipInput');
const pickFolderBtn = document.getElementById('pickFolderBtn');
const pickZipBtn = document.getElementById('pickZipBtn');
const scanBtn = document.getElementById('scanBtn');
const fileList = document.getElementById('fileList');

pickFolderBtn.addEventListener('click', () => folderInput.click());
pickZipBtn.addEventListener('click', () => zipInput.click());

folderInput.addEventListener('change', () => {
  if (folderInput.files.length) {
    pendingFiles = Array.from(folderInput.files);
    pendingZip = null;
    describeSelection(pendingFiles.map(f => f.webkitRelativePath || f.name));
  }
});
zipInput.addEventListener('change', () => {
  if (zipInput.files.length) {
    pendingZip = zipInput.files[0];
    pendingFiles = null;
    describeSelection([pendingZip.name]);
  }
});
['dragenter', 'dragover'].forEach(evt =>
  dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.add('drag'); })
);
['dragleave', 'drop'].forEach(evt =>
  dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.remove('drag'); })
);
dropzone.addEventListener('drop', e => {
  const dt = e.dataTransfer;
  if (!dt) return;
  const files = Array.from(dt.files || []);
  if (files.length === 1 && /\.(zip|apk)$/i.test(files[0].name)) {
    pendingZip = files[0]; pendingFiles = null;
    describeSelection([pendingZip.name]);
  } else if (files.length) {
    pendingFiles = files; pendingZip = null;
    describeSelection(pendingFiles.map(f => f.webkitRelativePath || f.name));
  }
});
function describeSelection(names) {
  document.getElementById('fileListWrap').classList.remove('hidden');
  fileList.innerHTML = names.slice(0, 200).map(n => `<div>${escapeHtml(n)}</div>`).join('');
  scanBtn.disabled = false;
}

scanBtn.addEventListener('click', runScan);

async function runScan() {
  const projectName = document.getElementById('project_name').value.trim() || 'project';
  const form = new FormData();
  form.append('project_name', projectName);
  if (pendingZip) form.append('zipfile', pendingZip);
  else if (pendingFiles) { for (const f of pendingFiles) form.append('files', f, f.webkitRelativePath || f.name); }
  else return;

  goToPage('dashboard');
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('dashboardResults').classList.add('hidden');
  document.getElementById('progressState').classList.remove('hidden');
  setProgress('preparing', 0, 'Uploading...');
  scanBtn.disabled = true;

  try {
    const res = await fetch('/api/scan', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) { alert(data.error || 'Scan failed.'); resetToEmpty(); return; }
    pollJob(data.job_id);
  } catch (err) {
    alert('Could not reach the local server: ' + err);
    resetToEmpty();
  }
}

function resetToEmpty() {
  document.getElementById('progressState').classList.add('hidden');
  document.getElementById('emptyState').classList.remove('hidden');
  scanBtn.disabled = false;
}
function setProgress(phase, percent, message) {
  document.getElementById('progressPhase').textContent = phase;
  document.getElementById('progressFill').style.width = `${Math.max(2, percent)}%`;
  document.getElementById('progressMessage').textContent = message || '';
}

function pollJob(jobId) {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/scan/progress/${jobId}`);
      const job = await res.json();
      if (!res.ok) { clearInterval(pollTimer); alert(job.error || 'Scan failed.'); resetToEmpty(); return; }
      setProgress(job.phase || '', job.percent || 0, job.message || '');
      if (job.status === 'error') { clearInterval(pollTimer); alert(job.error || 'Scan failed.'); resetToEmpty(); return; }
      if (job.status === 'done') {
        clearInterval(pollTimer);
        const resultRes = await fetch(`/api/scan/result/${jobId}`);
        const result = await resultRes.json();
        currentResult = result;
        activeSeverity = 'all'; activeCategory = 'all'; renderedCount = 0;
        renderDashboard(result);
        loadHistory();
        scanBtn.disabled = false;
      }
    } catch (err) {
      clearInterval(pollTimer);
      alert('Lost connection to the local server: ' + err);
      resetToEmpty();
    }
  }, 700);
}

/* ============================================================
   Dashboard rendering
   ============================================================ */
function renderDashboard(r) {
  document.getElementById('progressState').classList.add('hidden');
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('dashboardResults').classList.remove('hidden');

  const warningsBox = document.getElementById('warningsBox');
  if (r.warnings && r.warnings.length) {
    warningsBox.classList.remove('hidden');
    warningsBox.innerHTML = r.warnings.map(w => `⚠ ${escapeHtml(w)}`).join('<br>');
  } else warningsBox.classList.add('hidden');

  const infoBox = document.getElementById('infoNotesBox');
  if (r.info_notes && r.info_notes.length) {
    infoBox.classList.remove('hidden');
    infoBox.innerHTML = r.info_notes.map(w => escapeHtml(w)).join('<br>');
  } else infoBox.classList.add('hidden');

  renderHero(r);
  renderCategoryTiles(r);
  renderSeverityDonut(r);
  renderCategoryBars(r);
  renderTopFiles(r);
  renderLatestFindings(r);
  updateProjectSelectorLabel(r);
}

function renderHero(r) {
  const score = r.security_score ?? 0;
  const gateMin = r.quality_gate_min_score ?? 80;
  document.getElementById('scoreValue').textContent = score;
  document.getElementById('scoreValue2').textContent = score;
  document.getElementById('gradeLetter').textContent = r.grade;
  const color = gradeColor(r.grade);
  document.getElementById('gradeLetter').style.color = color;
  document.getElementById('gradeLetter').style.borderColor = color;

  // circular gauge: circumference = 2*pi*64 ≈ 402.1
  const circumference = 402.1;
  const offset = circumference - (score / 100) * circumference;
  const arc = document.getElementById('gaugeArc');
  arc.style.stroke = color;
  arc.setAttribute('stroke-dashoffset', String(offset));

  document.getElementById('heroProjectName').textContent = r.project_name;
  document.getElementById('heroFilesCount').textContent = `${r.files_scanned} file${r.files_scanned === 1 ? '' : 's'}`;
  document.getElementById('heroSlocCount').textContent = `${r.totals.sloc.toLocaleString()} SLOC`;
  document.getElementById('heroDuration').textContent = r.duration_seconds != null ? `${r.duration_seconds}s` : '—';
  document.getElementById('heroLastScanned').textContent = `Last scanned: ${r.generated_at}`;

  const fill = document.getElementById('scoreBarFill');
  fill.style.width = `${score}%`;
  fill.style.background = color;
  document.getElementById('scoreBarMarker').style.left = `${gateMin}%`;
  document.getElementById('gateMarkerLabel').textContent = `${gateMin} — typical release bar`;

  const pill = document.getElementById('gatePill');
  pill.className = 'gate-pill ' + (r.quality_gate_passed ? 'pass' : 'fail');
  pill.textContent = r.quality_gate_passed ? '✓ Release ready' : '⚠ Not release ready';

  const banner = document.getElementById('gateBanner');
  banner.className = 'gate-banner ' + (r.quality_gate_passed ? 'pass' : '');
  document.getElementById('gateHeadline').textContent = r.quality_gate_passed
    ? `Passes the typical release-readiness bar (no critical/high findings, score ≥ ${gateMin}/100).`
    : `Fails the typical release-readiness bar (no critical/high findings, score ≥ ${gateMin}/100).`;
  document.getElementById('gateSub').textContent = r.quality_gate_reason || '';
}

function trendArrow(curr, prev, higherIsBad) {
  if (prev == null || prev === curr) return '';
  const pct = prev === 0 ? 100 : Math.round(((curr - prev) / prev) * 100);
  const up = curr > prev;
  const bad = higherIsBad ? up : !up;
  const cls = bad ? (up ? 'up-bad' : 'down-bad') : (up ? 'up-good' : 'down-good');
  const arrow = up ? '↑' : '↓';
  return `<span class="tile-trend ${cls}">${arrow} ${Math.abs(pct)}%</span>`;
}

function renderCategoryTiles(r) {
  const counts = r.category_counts || {};
  const prevCounts = (r.previous_scan && r.previous_scan.category_counts) || null;
  const sevCounts = r.severity_counts || {};

  const tiles = CATEGORY_ORDER.map(c => {
    const n = counts[c] || 0;
    const prev = prevCounts ? prevCounts[c] : null;
    const trendHtml = trendArrow(n, prev, true);
    let sub = '';
    if (c === 'vulnerability') {
      sub = `${sevCounts.critical || 0} critical, ${sevCounts.high || 0} high, ${sevCounts.medium || 0} medium`;
    }
    return `
      <button class="tile ${activeCategory === c ? 'active' : ''}" data-cat="${c}">
        <div class="tile-icon" style="background:${CATEGORY_ICON_BG[c]};color:${CATEGORY_ICON_FG[c]}">${TILE_ICONS[c]}</div>
        <div class="tile-body">
          <div class="tile-num-row"><span class="tile-num" style="color:${CATEGORY_ICON_FG[c]}">${n}</span>${trendHtml}</div>
          <div class="tile-label">${CATEGORY_LABELS[c]}</div>
          ${sub ? `<div class="tile-sub">${sub}</div>` : ''}
        </div>
      </button>`;
  }).join('');

  const total = r.findings.length;
  const prevTotal = r.previous_scan ? Object.values(r.previous_scan.severity_counts || {}).reduce((a, b) => a + b, 0) : null;
  const totalTile = `
    <button class="tile" data-cat="all">
      <div class="tile-icon" style="background:rgba(155,124,242,.15);color:#9B7CF2">${TILE_ICONS.total}</div>
      <div class="tile-body">
        <div class="tile-num-row"><span class="tile-num" style="color:#9B7CF2">${total}</span>${trendArrow(total, prevTotal, true)}</div>
        <div class="tile-label">Total Findings</div>
      </div>
    </button>`;

  const html = tiles + totalTile;
  document.getElementById('categoryTiles').innerHTML = html;
  document.querySelectorAll('#categoryTiles .tile').forEach(tile => {
    tile.addEventListener('click', () => {
      activeCategory = tile.dataset.cat === 'all' ? 'all' : tile.dataset.cat;
      goToPage('findings');
    });
  });
}

function renderSeverityDonut(r) {
  const counts = r.severity_counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  document.getElementById('donutTotal').textContent = total;
  let acc = 0;
  const stops = SEVERITY_ORDER.map(s => {
    const n = counts[s] || 0;
    const start = total ? (acc / total) * 100 : 0;
    acc += n;
    const end = total ? (acc / total) * 100 : 0;
    return `${SEVERITY_COLORS[s]} ${start}% ${end}%`;
  }).join(', ');
  document.getElementById('sevDonut').style.background = total > 0 ? `conic-gradient(${stops})` : 'var(--surface-raised)';
  document.getElementById('sevLegend').innerHTML = SEVERITY_ORDER.map(s => {
    const n = counts[s] || 0;
    const pct = total ? ((n / total) * 100).toFixed(1) : '0.0';
    return `<div class="legend-row"><span class="lg-left"><span class="dot" style="background:${SEVERITY_COLORS[s]}"></span>${cap(s)}</span><span class="lg-right">${n} (${pct}%)</span></div>`;
  }).join('');
}

function renderCategoryBars(r) {
  const dc = r.display_category_counts || {};
  const max = Math.max(1, ...DISPLAY_CATEGORY_ORDER.map(c => dc[c] || 0));
  document.getElementById('catBarList').innerHTML = DISPLAY_CATEGORY_ORDER.map(c => {
    const n = dc[c] || 0;
    return `
      <div class="catbar-row">
        <div class="catbar-head"><span>${DISPLAY_CATEGORY_LABELS[c]}</span><span style="color:var(--text-muted);font-family:var(--mono);">${n}</span></div>
        <div class="catbar-track"><div class="catbar-fill" style="width:${(n / max) * 100}%;background:${DISPLAY_CATEGORY_COLORS[c]}"></div></div>
      </div>`;
  }).join('');
}

function renderTopFiles(r) {
  const tbody = document.getElementById('topFilesBody');
  if (!r.top_files.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);">No issues found</td></tr>';
    return;
  }
  tbody.innerHTML = r.top_files.slice(0, 6).map(f => {
    const findingsForFile = r.findings.filter(x => x.file === f.file);
    const worst = SEVERITY_ORDER.find(s => findingsForFile.some(x => x.severity === s)) || 'info';
    return `<tr>
      <td><span class="fname" title="${escapeHtml(f.file)}">${escapeHtml(f.file)}</span></td>
      <td>${f.count}</td>
      <td><span class="sev-chip"><span class="dot" style="background:${SEVERITY_COLORS[worst]}"></span>${cap(worst)}</span></td>
    </tr>`;
  }).join('');
}

function renderLatestFindings(r) {
  const list = r.findings.slice(0, 5);
  const el = document.getElementById('latestFindingsList');
  if (!list.length) { el.innerHTML = '<div style="color:var(--text-muted);font-size:12.5px;">No findings — nice and clean.</div>'; return; }
  el.innerHTML = list.map(f => `
    <div class="lf-row ${f.severity}" onclick="goToPage('findings')">
      <span class="lf-sev-tag ${f.severity}">${f.severity.toUpperCase()}</span>
      <span class="lf-cat-tag">${CATEGORY_LABELS[f.category] || f.category}</span>
      <div class="lf-body">
        <div class="lf-title">${escapeHtml(f.title)}</div>
        <div class="lf-loc">${escapeHtml(f.file)}:${f.line}</div>
      </div>
      ${f.cwe ? `<span class="lf-cwe">${f.cwe}</span>` : ''}
    </div>
  `).join('');
}

/* ============================================================
   Findings page (full filterable list)
   ============================================================ */
function renderFindingsPage() {
  const empty = document.getElementById('findingsEmpty');
  if (!currentResult) {
    empty.classList.remove('hidden');
    document.getElementById('categoryTilesFindings').innerHTML = '';
    document.getElementById('filters').innerHTML = '';
    document.getElementById('findings').innerHTML = '';
    return;
  }
  empty.classList.add('hidden');
  document.getElementById('findingsSubtitle').textContent = `${currentResult.findings.length} findings for "${currentResult.project_name}"`;
  renderFindingsCategoryTiles(currentResult);
  renderFilters(currentResult);
  renderFindings(currentResult, true);
}

function renderFindingsCategoryTiles(r) {
  const counts = r.category_counts || {};
  const wrap = document.getElementById('categoryTilesFindings');
  const all = CATEGORY_ORDER.map(c => `
    <button class="tile ${activeCategory === c ? 'active' : ''}" data-cat="${c}">
      <div class="tile-icon" style="background:${CATEGORY_ICON_BG[c]};color:${CATEGORY_ICON_FG[c]}">${TILE_ICONS[c]}</div>
      <div class="tile-body">
        <div class="tile-num" style="color:${CATEGORY_ICON_FG[c]}">${counts[c] || 0}</div>
        <div class="tile-label">${CATEGORY_LABELS[c]}</div>
      </div>
    </button>`).join('');
  wrap.innerHTML = all;
  wrap.querySelectorAll('.tile').forEach(tile => {
    tile.addEventListener('click', () => {
      const c = tile.dataset.cat;
      activeCategory = activeCategory === c ? 'all' : c;
      renderedCount = 0;
      renderFindingsCategoryTiles(r);
      renderFilters(r);
      renderFindings(r, true);
    });
  });
}

function filteredFindings(r) {
  return r.findings.filter(f =>
    (activeSeverity === 'all' || f.severity === activeSeverity) &&
    (activeCategory === 'all' || f.category === activeCategory)
  );
}

function renderFilters(r) {
  const sevCounts = { all: r.findings.length };
  SEVERITY_ORDER.forEach(s => sevCounts[s] = r.severity_counts[s]);
  const wrap = document.getElementById('filters');
  wrap.innerHTML = Object.keys(sevCounts).map(key =>
    `<button data-filter="${key}" class="${activeSeverity === key ? 'active' : ''}">${cap(key)} (${sevCounts[key]})</button>`
  ).join('');
  wrap.querySelectorAll('button').forEach(btn => {
    btn.addEventListener('click', () => {
      activeSeverity = btn.dataset.filter;
      renderedCount = 0;
      renderFilters(r);
      renderFindings(r, true);
    });
  });
}

function renderFindings(r, reset) {
  const list = filteredFindings(r);
  const container = document.getElementById('findings');
  const loadMoreWrap = document.getElementById('loadMoreWrap');
  if (!list.length) {
    container.innerHTML = '<div class="loading" style="margin-top:0;padding:30px 0;">No findings in this category.</div>';
    loadMoreWrap.classList.add('hidden');
    return;
  }
  if (reset) { renderedCount = 0; container.innerHTML = ''; }
  const nextSlice = list.slice(renderedCount, renderedCount + PAGE_SIZE);
  const html = nextSlice.map(f => `
    <div class="finding ${f.severity}">
      <div class="finding-head">
        <span class="sev-tag ${f.severity}">${f.severity.toUpperCase()}</span>
        <span class="category-tag">${CATEGORY_LABELS[f.category] || f.category}</span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
        ${f.cwe ? `<span class="cwe-badge">${f.cwe}</span>` : ''}
        <span class="finding-loc">${escapeHtml(f.file)}:${f.line}</span>
        <span class="chevron">›</span>
      </div>
      <div class="finding-body">
        <p><span class="label">What this means:</span> ${escapeHtml(f.description)}</p>
        ${f.snippet ? `<pre>${escapeHtml(f.snippet)}</pre>` : ''}
        <p><span class="label">Recommendation:</span> ${escapeHtml(f.recommendation)}</p>
      </div>
    </div>
  `).join('');
  container.insertAdjacentHTML('beforeend', html);
  renderedCount += nextSlice.length;
  container.querySelectorAll('.finding-head').forEach(head => {
    if (head.dataset.bound) return;
    head.dataset.bound = '1';
    head.addEventListener('click', () => head.parentElement.classList.toggle('open'));
  });
  if (renderedCount < list.length) {
    loadMoreWrap.classList.remove('hidden');
    document.getElementById('loadMoreBtn').textContent = `Show more findings (${list.length - renderedCount} remaining)`;
  } else loadMoreWrap.classList.add('hidden');
}
document.getElementById('loadMoreBtn').addEventListener('click', () => { if (currentResult) renderFindings(currentResult, false); });

/* ============================================================
   Scan History page
   ============================================================ */
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    historyCache = await res.json();
    renderTrend(historyCache);
    updateProjectDropdown();
  } catch (e) { /* non-fatal */ }
}

function renderHistoryPage() {
  const tbody = document.getElementById('historyTableBody');
  const empty = document.getElementById('historyEmpty');
  if (!historyCache.length) { tbody.innerHTML = ''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  tbody.innerHTML = historyCache.map(h => `
    <tr onclick="loadScanIntoView('${h.scan_id}')">
      <td>${escapeHtml(h.project_name)}</td>
      <td style="font-family:var(--mono);color:var(--text-muted);">${h.generated_at}</td>
      <td style="font-family:var(--mono);">${h.security_score}/100</td>
      <td><span style="color:${gradeColor(h.grade)};font-weight:600;">${h.grade}</span></td>
      <td>${h.files_scanned}</td>
      <td style="font-family:var(--mono);color:var(--text-muted);">${h.duration_seconds ?? '—'}s</td>
    </tr>
  `).join('');
}

async function loadScanIntoView(scanId) {
  try {
    const res = await fetch(`/api/report/${scanId}?format=json`);
    if (!res.ok) { alert('That scan is no longer available.'); return; }
    const result = await res.json();
    currentResult = result;
    activeSeverity = 'all'; activeCategory = 'all'; renderedCount = 0;
    renderDashboard(result);
    goToPage('dashboard');
  } catch (e) { alert('Could not load that scan: ' + e); }
}

/* ============================================================
   Reports page
   ============================================================ */
function renderReportsPage() {
  const tbody = document.getElementById('reportsTableBody');
  const empty = document.getElementById('reportsEmpty');
  if (!historyCache.length) { tbody.innerHTML = ''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  tbody.innerHTML = historyCache.map(h => `
    <tr>
      <td>${escapeHtml(h.project_name)}</td>
      <td style="font-family:var(--mono);color:var(--text-muted);">${h.generated_at}</td>
      <td style="font-family:var(--mono);">${h.security_score}/100</td>
      <td><span style="color:${gradeColor(h.grade)};font-weight:600;">${h.grade}</span></td>
      <td>
        <button class="secondary" style="margin-right:6px;" onclick="window.open('/api/report/${h.scan_id}?format=html','_blank')">HTML</button>
        <button class="secondary" onclick="window.open('/api/report/${h.scan_id}?format=json','_blank')">JSON</button>
      </td>
    </tr>
  `).join('');
}

/* ============================================================
   Security Rules page
   ============================================================ */
let activeRuleCategory = 'all';
async function renderRulesPage() {
  if (!rulesCache) {
    try {
      const res = await fetch('/api/rules');
      rulesCache = await res.json();
      document.getElementById('settingsRuleCount').textContent = rulesCache.length;
    } catch (e) { rulesCache = []; }
  }
  document.getElementById('rulesSubtitle').textContent = `${rulesCache.length} rules across vulnerability, bug, and code-smell checks`;

  const catCounts = { all: rulesCache.length };
  CATEGORY_ORDER.forEach(c => catCounts[c] = rulesCache.filter(r => r.category === c).length);
  document.getElementById('ruleCategoryFilters').innerHTML = Object.keys(catCounts).map(key =>
    `<button data-cat="${key}" class="${activeRuleCategory === key ? 'active' : ''}">${key === 'all' ? 'All' : CATEGORY_LABELS[key]} (${catCounts[key]})</button>`
  ).join('');
  document.querySelectorAll('#ruleCategoryFilters button').forEach(btn => {
    btn.addEventListener('click', () => { activeRuleCategory = btn.dataset.cat; renderRulesList(); renderRulesPage(); });
  });
  renderRulesList();
  document.getElementById('ruleSearch').oninput = renderRulesList;
}
function renderRulesList() {
  const q = (document.getElementById('ruleSearch').value || '').toLowerCase();
  const list = rulesCache.filter(r =>
    (activeRuleCategory === 'all' || r.category === activeRuleCategory) &&
    (!q || r.title.toLowerCase().includes(q) || r.id.includes(q) || (r.cwe || '').toLowerCase().includes(q))
  );
  document.getElementById('rulesList').innerHTML = list.map(r => `
    <div class="rule-row">
      <div class="rule-row-head">
        <span class="sev-tag ${r.severity}">${r.severity.toUpperCase()}</span>
        <span class="category-tag">${CATEGORY_LABELS[r.category] || r.category}</span>
        <strong>${escapeHtml(r.title)}</strong>
        ${r.cwe ? `<span class="cwe-badge">${r.cwe}</span>` : ''}
        <span class="rule-id">${r.id}</span>
      </div>
      <div class="rule-row-desc">${escapeHtml(r.description)}</div>
    </div>
  `).join('') || '<div class="loading" style="padding:30px 0;">No rules match.</div>';
}

/* ============================================================
   Settings page
   ============================================================ */
async function renderSettingsPage() {
  if (!rulesCache) {
    try { const res = await fetch('/api/rules'); rulesCache = await res.json(); } catch (e) { rulesCache = []; }
  }
  document.getElementById('settingsRuleCount').textContent = rulesCache.length;
}

/* ============================================================
   Project selector (topbar)
   ============================================================ */
function updateProjectSelectorLabel(r) {
  document.getElementById('projectSelectLabel').textContent = r.project_name;
}
function updateProjectDropdown() {
  const dd = document.getElementById('projectDropdown');
  const seen = new Set();
  const items = [];
  for (const h of historyCache) {
    if (seen.has(h.project_name)) continue;
    seen.add(h.project_name);
    items.push(h);
  }
  dd.innerHTML = items.length
    ? items.map(h => `<div class="dd-item" onclick="loadScanIntoView('${h.scan_id}')">${escapeHtml(h.project_name)}</div>`).join('')
    : '<div class="dd-empty">No scans yet</div>';
}
document.getElementById('projectSelect').addEventListener('click', (e) => {
  document.getElementById('projectDropdown').classList.toggle('hidden');
  e.stopPropagation();
});
document.addEventListener('click', () => document.getElementById('projectDropdown').classList.add('hidden'));

/* ============================================================
   Trend chart (Security Score Trend)
   ============================================================ */
function renderTrend(history) {
  const svg = document.getElementById('trendSvg');
  if (!history || history.length < 2) {
    svg.innerHTML = `<text x="200" y="85" fill="var(--text-muted)" font-size="12" text-anchor="middle" font-family="var(--sans)">Run at least 2 scans to see a trend</text>`;
    return;
  }
  const ordered = [...history].reverse();
  const w = 400, h = 170, padL = 30, padR = 15, padT = 15, padB = 25;
  const scores = ordered.map(x => x.security_score ?? 0);
  const stepX = (w - padL - padR) / Math.max(1, ordered.length - 1);
  const yFor = s => h - padB - (s / 100) * (h - padT - padB);
  const points = scores.map((s, i) => `${padL + i * stepX},${yFor(s)}`);
  const areaPoints = `${padL},${yFor(0)} ` + points.join(' ') + ` ${padL + (scores.length - 1) * stepX},${yFor(0)}`;
  const gridLines = [0, 25, 50, 75, 100].map(v => `
    <line x1="${padL}" y1="${yFor(v)}" x2="${w - padR}" y2="${yFor(v)}" stroke="var(--border)" stroke-width="1"/>
    <text x="${padL - 6}" y="${yFor(v) + 3}" fill="var(--text-muted)" font-size="9" text-anchor="end" font-family="var(--mono)">${v}</text>
  `).join('');
  const xLabels = ordered.map((x, i) => {
    const parts = (x.generated_at || '').split(' ');
    const sameDay = ordered.every(o => (o.generated_at || '').split(' ')[0] === parts[0]);
    const label = sameDay ? (parts[1] || '').slice(0, 5) : parts[0].slice(5);
    return `<text x="${padL + i * stepX}" y="${h - 6}" fill="var(--text-muted)" font-size="9" text-anchor="middle" font-family="var(--mono)">${label}</text>`;
  }).join('');
  svg.innerHTML = `
    ${gridLines}
    <polygon points="${areaPoints}" fill="var(--accent)" opacity="0.12"/>
    <polyline points="${points.join(' ')}" fill="none" stroke="var(--accent)" stroke-width="2"/>
    ${points.map((p, i) => {
      const [x, y] = p.split(',');
      return `<circle cx="${x}" cy="${y}" r="3.5" fill="var(--accent)"><title>${escapeHtml(ordered[i].project_name)}: ${scores[i]}/100</title></circle>`;
    }).join('')}
    ${xLabels}
  `;
}

/* ============================================================
   Icons + helpers
   ============================================================ */
const TILE_ICONS = {
  vulnerability: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.3 3.9L2.6 17a1.8 1.8 0 001.5 2.7h15.8a1.8 1.8 0 001.5-2.7L13.7 3.9a1.8 1.8 0 00-3.4 0z"/></svg>',
  bug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="8" y="7" width="8" height="10" rx="4"/><path d="M12 3v4M8 10H4M8 14H4M16 10h4M16 14h4M9 5l-1.5-1.5M15 5l1.5-1.5"/></svg>',
  code_smell: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 8l-4 4 4 4M15 8l4 4-4 4"/></svg>',
  total: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
};

function gradeColor(g) {
  return { A: 'var(--accent)', B: 'var(--low)', C: 'var(--medium)', D: 'var(--high)', F: 'var(--critical)' }[g] || 'var(--text)';
}
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

loadHistory();
