/* ================= DATA ================= */
const SEV = { Critical: '◆', High: '▲', Medium: '●', Low: '▼', Info: 'ℹ' };
const T = [
    ['SQL injection', 'CWE-89', 9.8, 'db/queries.py', 'cur.execute("SELECT * FROM users WHERE id=" + uid)'],
    ['Cross-site scripting (XSS)', 'CWE-79', 7.4, 'web/render.js', 'el.innerHTML = params.name'],
    ['Server-side request forgery', 'CWE-918', 8.1, 'api/fetch.go', 'http.Get(r.URL.Query().Get("u"))'],
    ['Hardcoded secret', 'CWE-798', 9.1, 'config/aws.py', 'AWS_KEY = "AKIAEXAMPLE1234567"'],
    ['Outdated dependency (lodash 4.17.15)', 'CWE-1104', 5.6, 'package.json', '"lodash": "4.17.15"']
];
const REPOS = ['payments-api', 'web-app', 'auth-svc', 'infra', 'mobile-bff'];
const sevOf = c => c >= 9 ? 'Critical' : c >= 7 ? 'High' : c >= 4 ? 'Medium' : c >= 2 ? 'Low' : 'Info';

const V = Array.from({ length: 26 }, (_, i) => {
    const t = T[i % 5];
    let c = +(t[2] - (i * 7 % 13) / 5).toFixed(1);
    if (i % 9 == 8) c = 1.4;
    if (c < 1) c = 3.1;
    return {
        id: 'VULN-' + (1001 + i),
        cve: 'CVE-2026-' + (21400 + i * 37),
        title: t[0],
        cwe: t[1],
        cvss: c,
        sev: sevOf(c),
        file: t[3],
        code: t[4],
        repo: REPOS[(i * 3) % 5],
        status: ['open', 'in progress', 'fixed', 'open'][i % 4],
        date: '2026-09-' + String(28 - i % 27).padStart(2, '0'),
        line: 20 + i * 3,
        pt: [0, 1, 0, 2, 1][i % 5]
    }
});

const P = [
    { t: 'Parameterize SQL query', old: ['- cur.execute("SELECT * FROM users WHERE id=" + uid)'], nw: ['+ cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'], conf: 94,
        ex: 'User input was concatenated into SQL. Bound parameters make the driver treat uid strictly as data, closing CWE-89.', tests: ['rejects "1 OR 1=1" payload', 'returns user for valid id', 'regression: VULN-1001 payload blocked'] },
    { t: 'Escape output via textContent', old: ['- el.innerHTML = params.name'], nw: ['+ el.textContent = params.name'], conf: 89,
        ex: 'innerHTML parses markup, allowing script injection. textContent renders the value as plain text.', tests: ['<script> payload rendered inert', 'preserves unicode names', 'regression: VULN-1002 payload blocked'] },
    { t: 'Move secret to environment', old: ['- AWS_KEY = "AKIAEXAMPLE1234567"'], nw: ['+ AWS_KEY = os.environ["AWS_KEY"]', '+ # rotate the leaked key immediately'], conf: 97,
        ex: 'A committed credential is exposed to anyone with repo access. Load it at runtime and rotate the old key.', tests: ['raises when AWS_KEY missing', 'loads key from env', 'no secrets in repo scan'] }
];

const M = [['Raw SQL string concat in reports', 'CWE-89', 'Python', 'SQL injection', 'Switched to parameterized queries', true, 'Lint rule added after 2nd recurrence', 82],
    ['innerHTML with user comments', 'CWE-79', 'JavaScript', 'XSS', 'Sanitized with textContent', false, 'Prefer textContent by default', 74],
    ['AWS key committed to infra repo', 'CWE-798', 'Terraform', 'Secrets', 'Rotated key, added pre-commit scan', true, 'Secrets recur when CI scan is optional', 68],
    ['Webhook URL fetch without allowlist', 'CWE-918', 'Go', 'SSRF', 'Added host allowlist + IP block', false, 'Validate schemes and resolved IPs', 71],
    ['Vulnerable lodash prototype pollution', 'CWE-1104', 'JavaScript', 'Dependency', 'Bumped to 4.17.21', true, 'Enable automated dependency PRs', 55],
    ['ORM raw() with f-string', 'CWE-89', 'Python', 'SQL injection', 'Bound params in raw()', true, 'Third SQLi in Python data layer', 88],
    ['Stored XSS in markdown preview', 'CWE-79', 'TypeScript', 'XSS', 'Added DOMPurify config', false, 'Sanitize at render, not at save', 63],
    ['Slack token in test fixtures', 'CWE-798', 'JavaScript', 'Secrets', 'Fixtures use fake tokens', false, 'Scan test folders too', 59]].map((m, i) => ({ i, t: m[0], cwe: m[1], lang: m[2], pat: m[3], fix: m[4], rec: m[5], les: m[6], s: m[7], when: (2 + i * 3) + ' weeks ago' }));

const JOBS = Array.from({ length: 16 }, (_, i) => ({ t: '10:' + String(59 - i * 3).padStart(2, '0'), m: ['Scan finished: ' + REPOS[i % 5], 'Patch generated for VULN-' + (1001 + i), 'Tests passed for VULN-' + (1001 + i), 'Deploy to staging: ' + REPOS[i % 5], 'Test run failed for VULN-' + (1001 + i)][i % 5], ok: i % 5 != 4 }));
const CHATS = { sql: ['Use parameterized queries. Example:', 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'], xss: ['Prefer textContent over innerHTML:', 'el.textContent = params.name'], secret: ['Rotate the key, then load it from env:', 'AWS_KEY = os.environ["AWS_KEY"]'] };

/* ================= STATE ================= */
const S = {
    view: 'dash', theme: 'dark', sev: 'all', status: 'all', q: '', sort: 'cvss', dir: -1, sel: new Set(), drawer: null, pi: 0, tests: null, testProg: 0,
    ctx: V[0], chat: [{ u: 0, t: 'Hi! I can explain vulnerabilities, suggest fixes, and reference your memory. Ask me anything.' }], typing: false, mq: '', tag: '',
    stages: [{ n: 'Scan queue', s: 'running', p: 40 }, { n: 'Patch generation', s: 'queued', p: 0 }, { n: 'Test runs', s: 'queued', p: 0 }, { n: 'Deployments', s: 'passed', p: 100 }],
    keys: [{ n: 'CI key', v: 'sk_live_9f8a7c6b5d4e3f2a1b0c', show: false }, { n: 'Read-only', v: 'sk_ro_1a2b3c4d5e6f7a8b9c0d', show: false }],
    notif: { Critical: true, Digest: false, 'PR updates': true }, bulkMsg: ''
};

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const $ = s => document.querySelector(s);
const sevB = s => `<span class="sev ${s}"><span aria-hidden="true">${SEV[s]}</span>${s}</span>`;
function toast(m) { const t = $('#toast'); t.textContent = m; t.style.display = 'block'; clearTimeout(t.h); t.h = setTimeout(() => t.style.display = 'none', 2200) }

/* ================= VIEWS ================= */
const NAV = [['chat', '💬', 'AI Chat'], ['status', '📡', 'Status'], ['vulns', '🐞', 'Vulnerabilities'], ['dash', '📊', 'Dashboard'], ['memory', '🧠', 'Hindsight'], ['patch', '🩹', 'AI Patch'], ['profile', '👤', 'Profile']];

function renderNav() { $('#nav').innerHTML = '<h1>🛡️ Sentinel</h1>' + NAV.map(n => `<button data-a="go" data-v="${n[0]}" ${S.view == n[0] ? 'aria-current="page"' : ''}><span aria-hidden="true">${n[1]}</span>${n[2]}</button>`).join('') }

function donut() {
    const c = {}; V.forEach(v => c[v.sev] = (c[v.sev] || 0) + 1);
    const col = { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)', Low: 'var(--low)', Info: 'var(--info)' };
    let o = 0; const tot = V.length;
    const arcs = Object.keys(SEV).map(k => {
        const n = c[k] || 0, l = n / tot * 100;
        const r = `<circle r="15.9" cx="21" cy="21" fill="none" stroke="${col[k]}" stroke-width="6" stroke-dasharray="${l} ${100 - l}" stroke-dashoffset="${-o}" transform="rotate(-90 21 21)"/>`;
        o += l; return r
    }).join('');
    return `<div class="row"><svg width="140" height="140" viewBox="0 0 42 42" role="img" aria-label="Severity distribution">${arcs}</svg><ul style="list-style:none;padding:0">${Object.keys(SEV).map(k => `<li">${sevB(k)} ${c[k] || 0}</li>`).join('')}</ul></div\>`
}

function trend() {
    const d = [12, 15, 14, 19, 22, 18, 24, 21, 26, 23, 25, 26];
    const pts = d.map((y, i) => `${i * 28 + 10},${100 - y * 3}`).join(' ');
    return `<svg viewBox="0 0 320 110" width="100%" role="img" aria-label="Vulnerability trend"><polyline points="${pts}" fill="none" stroke="var(--ac)" stroke-width="2"/>${d.map((y, i) => `<circle cx="${i * 28 + 10}" cy="${100 - y * 3}" r="3" fill="var(--ac)"/>`).join('')}</svg><div class="sub">Last 12 weeks</div>`
}

function rDash() {
    const open = V.filter(v => v.status != 'fixed');
    const ch = open.filter(v => v.sev == 'Critical' || v.sev == 'High').length;
    const risk = REPOS.map(r => [r, V.filter(v => v.repo == r && v.status != 'fixed').reduce((a, v) => a + v.cvss, 0)]).sort((a, b) => b[1] - a[1]);
    return `<h2>Dashboard</h2><div class="grid">${[['Total vulnerabilities', V.length], ['Critical/High open', ch], ['Mean time to fix', '3.2 days'], ['Patches merged this week', 9]].map(k => `<div class="card kpi"><span class="sub">${k[0]}</span><b>${k[1]}</b></div>`).join('')}</div>
<div class="grid"><div class="card"><h3>Severity distribution</h3>${donut()}</div><div class="card"><h3>Trend</h3>${trend()}</div></div >
<div class="grid"><div class="card"><h3>Top risky repositories</h3>${risk.map(r => `<div>${r[0]} <span class="sub">risk ${r[1].toFixed(1)}</span><div class="bar"><i style="width:${Math.min(100, r[1] * 3)}%"></i></div ></div>`).join('')}</div>
<div class="card"><h3>Recent activity</h3>${JOBS.slice(0, 6).map(j => `<div><span class="mono sub">${j.t}</span> ${esc(j.m)}</div>`).join('')}</div></div >`
}

function filtered() {
    let r = V.filter(v => (S.sev == 'all' || v.sev == S.sev) && (S.status == 'all' || v.status == S.status) && (v.id + v.cve + v.title + v.repo + v.cwe).toLowerCase().includes(S.q.toLowerCase()));
    return r.sort((a, b) => (a[S.sort] > b[S.sort] ? 1 : -1) * S.dir)
}

function rVulns() {
    const r = filtered();
    const th = (k, l) => `<th scope="col"><button data-a="sort" data-v="${k}" aria-label="Sort by ${l}">${l}${S.sort == k ? (S.dir > 0 ? ' ▲' : ' ▼') : ''}</button></th>`;
    return `<h2>Vulnerabilities <span class="sub">(${r.length})</span></h2>
<div class="row" style="margin-bottom:12px"><label>Severity <select data-a="fsev">${['all', ...Object.keys(SEV)].map(s => `<option ${S.sev == s ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
<label>Status <select data-a="fstat">${['all', 'open', 'in progress', 'fixed'].map(s => `<option ${S.status == s ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
<input id="vq" value="${esc(S.q)}" placeholder="Filter…" aria-label="Filter table">
<button data-a="bulk" data-v="fixed">Mark fixed</button><button data-a="bulk" data-v="assign">Assign</button><button data-a="bulk" data-v="export">Export</button><span class="sub">${S.sel.size} selected</span></div >
<div class="card scroll">${r.length ? `<table><thead><tr><th><input type="checkbox" data-a="selall" aria-label="Select all"></th>${th('id', 'ID')}${th('sev', 'Severity')}${th('title', 'Title')}${th('repo', 'Repo')}${th('cve', 'CVE')}${th('cvss', 'CVSS')}${th('status', 'Status')}${th('date', 'Detected')}</tr></thead><tbody>
${r.map(v => `<tr data-a="open" data-v="${v.id}" tabindex="0"><td><input type="checkbox" data-a="sel" data-v="${v.id}" ${S.sel.has(v.id) ? 'checked' : ''} aria-label="Select ${v.id}"></td><td class="mono">${v.id}</td><td>${sevB(v.sev)}</td><td>${esc(v.title)}</td><td>${v.repo}</td><td class="mono">${v.cve}</td><td class="mono">${v.cvss}</td><td>${v.status}</td><td class="mono">${v.date}</td></tr>`).join('')}</tbody></table>` : `<div class="empty">No vulnerabilities match. <button data-a="reset">Clear filters</button></div>`}</div>`
}

function rDrawer() {
    const v = V.find(x => x.id == S.drawer); if (!v) return '';
    const b = [['Attack vector', 'Network', 90], ['Complexity', 'Low', 80], ['Privileges', 'None', 85], ['User interaction', 'None', 80], ['Confidentiality', 'High', 95], ['Integrity', 'High', 90]];
    const lines = [v.line - 2, v.line - 1, v.line, v.line + 1];
    return `<aside class="drawer" role="dialog" aria-label="${v.id} details"><div class="row"><h2 style="flex:1">${v.id}</h2><button data-a="close" aria-label="Close">✕</button></div>
<div class="row">${sevB(v.sev)}<span class="mono">${v.cve}</span><span class="mono">${v.cwe}</span></div>
<p style="margin:12px 0">${esc(v.title)} in <b>${v.repo}</b>. Untrusted input reaches a sensitive sink without validation, allowing an attacker to compromise data integrity or confidentiality.</p>
<h3 style="margin-top:12px">Affected: <span class="mono">${v.file}:${v.line}</span></h3>
<pre>${lines.map((l, i) => `<span class="ln ${i == 2 ? 'hl' : ''}">${String(l).padStart(3)}  ${i == 2 ? esc(v.code) : ['# handler', 'def run(request):', '', 'return ok'][i]}</span>`).join('')}</pre>
<h3 style="margin-top:12px">CVSS ${v.cvss}</h3>${b.map(x => `<div class="row"><span style="width:130px">${x[0]}</span><div class="bar" style="flex:1"><i style="width:${x[2]}%"></i></div ><span class="mono">${x[1]}</span></div>`).join('')}
<h3 style="margin-top:12px">References</h3><ul><li style="margin-bottom:4px"><a style="color:var(--ac)" href="#" data-a="ref">NVD ${v.cve}</a></li><li style="margin-bottom:4px"><a style="color:var(--ac)" href="#" data-a="ref">${v.cwe} – MITRE</a></li></ul>
<button class="pri" style="margin-top:16px; width:100%" data-a="genpatch" data-v="${v.id}">Generate AI Patch</button></aside>`
}

function rMemory() {
    const cur = S.ctx; const q = S.mq.toLowerCase().split(/\s+/).filter(Boolean);
    let list = M.map(m => {
        const hit = q.filter(w => (m.t + m.cwe + m.lang + m.pat + m.fix).toLowerCase().includes(w)).length;
        return { ...m, sc: q.length ? Math.min(99, hit * 30 + m.s / 4) : (m.cwe == cur.cwe ? m.s : Math.round(m.s * .6)) }
    }).filter(m => (!q.length || m.sc > 25) && (!S.tag || [m.cwe, m.lang, m.pat].includes(S.tag))).sort((a, b) => b.sc - a.sc);
    const tags = [...new Set(M.flatMap(m => [m.cwe, m.lang, m.pat]))];
    const rec = M.filter(m => m.rec);
    return `<h2>Hindsight Memory</h2><div class="row" style="margin-bottom:12px"><input id="mq" style="flex:1" value="${esc(S.mq)}" placeholder="find issues similar to… (e.g. string concat in queries)" aria-label="Semantic search"><button data-a="msearch">Search</button></div>
<div class="row" style="margin-bottom:12px">${tags.map(t => `<button class="chip" data-a="tag" data-v="${t}" aria-pressed="${S.tag == t}" ${S.tag == t ? 'style="background:var(--ac);color:var(--on)"' : ''}>${t}</button>`).join('')}${S.tag ? '<button class="chip" data-a="tag" data-v="">Clear</button>' : ''}</div >
<div class="grid"><div class="card" style="grid-column:1/-1"><h3 style="margin-bottom:8px">Recurring patterns</h3>${rec.length} of ${M.length} past issues recurred. Most repeated: <b style="color:var(--ac)">SQL injection (Python)</b> – 3 times. Insight: automate lint rules for these patterns.</div></div >
${list.length ? list.map(m => `<div class="card" style="margin-bottom:12px;border-left:4px solid var(--ac)"><div class="row"><b style="flex:1">${esc(m.t)}</b><span class="sub">${m.when}</span><span class="sev Info">Match ${Math.round(m.sc)}%</span></div>
<div style="margin:4px 0"><b class="sub">Issue:</b> ${m.cwe} · ${m.lang} · ${m.pat}</div><div><b class="sub">Fix:</b> ${esc(m.fix)}</div><div><b class="sub">Recurred:</b> <span class="${m.rec ? 'failed' : 'passed'}">${m.rec ? '✗ Yes' : '✓ No'}</span></div><div class="sub" style="margin-top:4px">Lesson: ${esc(m.les)}</div></div>`).join('') : '<div class="empty">No similar memories found.</div>'}`
}

function rPatch() {
    const p = P[S.pi], ts = S.tests;
    return `<h2>AI Patch + Test</h2><div class="row" style="margin-bottom:12px">${P.map((x, i) => `<button data-a="pi" data-v="${i}" aria-pressed="${S.pi == i}" ${S.pi == i ? 'class="pri"' : ''}>Patch ${i + 1}: ${x.t}</button>`).join('')}</div >
<div class="split"><div class="card"><h3>Original</h3><pre>${p.old.map(l => `<span class="ln d">${esc(l)}</span>`).join('')}</pre></div>
<div class="card"><h3>Proposed patch</h3><pre>${p.nw.map(l => `<span class="ln a">${esc(l)}</span>`).join('')}</pre></div></div >
<div class="grid" style="margin-top:16px"><div class="card"><h3>AI explanation</h3><p>${p.ex}</p><p>Confidence: <b class="mono">${p.conf}%</b></p><div class="bar"><i style="width:${p.conf}%"></i></div ></div>
<div class="card"><h3>Generated tests</h3>${p.tests.map((t, i) => `<div class="row" style="margin-bottom:4px"><span class="st ${ts && ts[i] || 'queued'}">${ts && ts[i] == 'passed' ? '✓ PASS' : ts && ts[i] == 'running' ? '… RUN' : '○ NOT RUN'}</span>${t}</div>`).join('')}
<div class="bar" style="margin:8px 0"><i style="width:${S.testProg}%"></i></div ><button data-a="runtests">Run tests</button></div></div >
<div class="row"><button class="pri" data-a="act" data-v="Patch approved">Approve</button><button data-a="regen">Regenerate</button><button data-a="act" data-v="Editor opened (simulated)">Edit</button><button data-a="act" data-v="Pull request #482 created">Create PR</button></div>`
}

function rStatus() {
    return `<h2>Status</h2><div class="grid" id="stages">${stagesHtml()}</div>
<div class="grid"><div class="card"><h3>Service health</h3>${['Scanner', 'Patch engine', 'Test runner', 'Deploy hook'].map((s, i) => `<div style="margin-bottom:4px">${i == 2 ? '<span class="running">▲ Degraded</span>' : '<span class="passed">✓ Healthy</span>'} ${s}</div>`).join('')}</div>
<div class="card" style="max-height:260px;overflow:auto"><h3 style="margin-bottom:8px">Recent jobs</h3>${JOBS.map(j => `<div style="margin-bottom:4px"><span class="mono sub">${j.t}</span> <span class="${j.ok ? 'passed' : 'failed'}">${j.ok ? '✓' : '✗'}</span> ${esc(j.m)}</div>`).join('')}</div></div >`
}

function stagesHtml() { return S.stages.map(s => `<div class="card"><b style="display:block;margin-bottom:4px">${s.n}</b> <span class="st ${s.s}">${s.s.toUpperCase()}</span><div class="bar" style="margin-top:8px" role="progressbar" aria-valuenow="${s.p}" aria-valuemin="0" aria-valuemax="100"><i style="width:${s.p}%"></i></div ></div>`).join('') }

function rChat() {
    return `<h2>AI Chat</h2><div class="row" style="margin-bottom:8px"><span class="sev Info">Context: ${S.ctx.id} · ${S.ctx.title}</span></div >
<div class="chat" id="chatlog" role="log" aria-live="polite">${S.chat.map(m => `<div class="msg ${m.u ? 'u' : ''}">${esc(m.t)}${m.code ? `<pre>${esc(m.code)}</pre><button data-a="copy" data-v="${esc(m.code).replace(/"/g, '&quot;')}">Copy</button>` : ''}</div>`).join('')}${S.typing ? '<div class="msg dots" aria-label="Typing"><span></span><span></span><span></span></div>' : ''}</div >
<div class="row" style="margin-bottom:8px">${['Explain this vulnerability', 'How do I fix it?', 'Any similar past issues?', 'How many critical are open?'].map(c => `<button class="chip" data-a="ask" data-v="${c}">${c}</button>`).join('')}</div >
<form class="row" id="cform"><input id="cin" style="flex:1" aria-label="Message" placeholder="Ask about a vulnerability…"><button type="button" data-a="mic" data-v="chat" aria-label="Voice input">🎤</button><button class="pri">Send</button></form>`
}

function rProfile() {
    return `<h2>Profile</h2><div class="grid"><div class="card"><div class="row"><svg width="56" height="56" viewBox="0 0 56 56" role="img" aria-label="Avatar"><circle cx="28" cy="28" r="28" fill="var(--ac)" /><text x="28" y="35" text-anchor="middle" font-size="20" font-weight="700" fill="var(--on)">AR</text></svg><div style="margin-left:12px"><b style="display:block">Asha Rao</b><div class="sub">Security Engineer · Admin</div><div class="sub">asha@example.com</div></div></div>
<h3 style="margin-top:16px">Theme</h3><button data-a="theme">Switch to ${S.theme == 'dark' ? 'light' : 'dark'}</button></div>
<div class="card"><h3 style="margin-bottom:8px">API keys</h3>${S.keys.map((k, i) => `<div class="row" style="margin-bottom:8px"><span style="flex:1">${k.n}</span><code style="margin-right:8px">${k.show ? k.v : '••••••••' + k.v.slice(-4)}</code><button data-a="reveal" data-v="${i}">${k.show ? 'Hide' : 'Reveal'}</button><button data-a="copy" data-v="${k.v}">Copy</button></div>`).join('')}</div>
<div class="card"><h3 style="margin-bottom:8px">Notifications</h3>${Object.keys(S.notif).map(n => `<div class="row" style="margin-bottom:8px"><button class="tog" role="switch" aria-checked="${S.notif[n]}" aria-label="${n}" data-a="notif" data-v="${n}"><i></i></button>${n}</div>`).join('')}</div>
<div class="card"><h3 style="margin-bottom:8px">Connected repositories</h3>${REPOS.map(r => `<div style="margin-bottom:4px">✓ ${r}</div>`).join('')}</div></div >`
}

const R = { dash: rDash, vulns: rVulns, memory: rMemory, patch: rPatch, status: rStatus, chat: rChat, profile: rProfile };

function render() {
    renderNav();
    $('#main').innerHTML = R[S.view]() + rDrawer();
    const l = $('#chatlog');
    if (l) l.scrollTop = l.scrollHeight
}

function go(v) {
    S.view = v; S.drawer = null; renderNav();
    $('#main').innerHTML = '<div class="sk"></div><div class="sk"></div><div class="sk"></div>';
    setTimeout(render, 220)
}

/* ================= ACTIONS ================= */
function ask(t) {
    S.chat.push({ u: 1, t }); S.typing = true; render();
    setTimeout(() => {
        S.typing = false; const c = S.ctx, l = t.toLowerCase(); let m;
        if (/critical|how many/.test(l)) m = { t: `${V.filter(v => v.sev == 'Critical' && v.status != 'fixed').length} critical vulnerabilities are open across ${REPOS.length} repos.` };
        else if (/similar|past/.test(l)) m = { t: `Hindsight found ${M.filter(x => x.cwe == c.cwe).length} past ${c.cwe} issues; the closest recurred, so consider a lint rule.` };
        else if (/fix/.test(l)) { const k = c.pt == 0 ? 'sql' : c.pt == 1 ? 'xss' : 'secret'; m = { t: CHATS[k][0], code: CHATS[k][1] } }
        else m = { t: `${c.id} is ${c.title} (${c.cwe}, CVSS ${c.cvss}) in ${c.file}:${c.line}. Open the Vulnerabilities view to generate a patch.` };
        S.chat.push({ u: 0, ...m }); if (S.view == 'chat') render()
    }, 900)
}

function vcmd(t) {
    t = t.toLowerCase();
    const map = { dashboard: 'dash', vulnerabilities: 'vulns', hindsight: 'memory', memory: 'memory', patch: 'patch', status: 'status', chat: 'chat', profile: 'profile' };
    const sv = Object.keys(SEV).find(s => t.includes(s.toLowerCase()));
    if (/show/.test(t) && sv) { S.sev = sv; go('vulns'); toast('Filter: ' + sv); return true }
    const k = Object.keys(map).find(k => /open|go to/.test(t) && t.includes(k));
    if (k) { go(map[k]); toast('Opened ' + k); return true }
    return false
}

function tprint(s) { const o = $('#tout'); o.textContent += s + '\n'; o.scrollTop = o.scrollHeight }

function tcmd(c) {
    tprint('$ ' + c); const a = c.trim().split(/\s+/), x = a[0];
    if (x == 'help') tprint('help | ls | open <section> | filter <severity> | scan | status | theme | clear');
    else if (x == 'ls') V.slice(0, 8).forEach(v => tprint(`${v.id} ${v.sev.padEnd(8)} ${v.cvss} ${v.file}`));
    else if (x == 'open' && R[a[1] === 'vulns' || a[1]]) { go(a[1]); }
    else if (x == 'filter') {
        const s = Object.keys(SEV).find(s => s.toLowerCase() == (a[1] || '').toLowerCase());
        if (s) { S.sev = s; go('vulns'); tprint('filtered ' + s) } else tprint('unknown severity')
    }
    else if (x == 'scan') { tprint('queued scan of ' + REPOS.join(', ')); S.stages[0] = { n: 'Scan queue', s: 'running', p: 0 } }
    else if (x == 'status') S.stages.forEach(s => tprint(`${s.n}: ${s.s} ${s.p}%`));
    else if (x == 'theme') act('theme'); else if (x == 'clear') $('#tout').textContent = '';
    else if (x) tprint('command not found: ' + x)
}

function act(a, v, el) {
    if (a == 'go') go(v); else if (a == 'open') { S.drawer = v; render() } else if (a == 'close') { S.drawer = null; render() }
    else if (a == 'sort') { S.dir = S.sort == v ? -S.dir : 1; S.sort = v; render() }
    else if (a == 'sel') { S.sel.has(v) ? S.sel.delete(v) : S.sel.add(v); render() }
    else if (a == 'selall') { filtered().forEach(x => el.checked ? S.sel.add(x.id) : S.sel.delete(x.id)); render() }
    else if (a == 'bulk') {
        if (!S.sel.size) return toast('Select rows first');
        if (v == 'fixed') V.forEach(x => { if (S.sel.has(x.id)) x.status = 'fixed' });
        toast(`${v}: ${S.sel.size} items`); S.sel.clear(); render()
    }
    else if (a == 'reset') { S.sev = 'all'; S.status = 'all'; S.q = ''; render() }
    else if (a == 'genpatch') { const x = V.find(y => y.id == v); S.ctx = x; S.pi = x.pt; S.tests = null; S.testProg = 0; S.drawer = null; go('patch'); toast('Patch generated') }
    else if (a == 'ref') toast('Opening reference (simulated)');
    else if (a == 'pi') { S.pi = +v; S.tests = null; S.testProg = 0; render() }
    else if (a == 'runtests') {
        S.tests = ['running', 'running', 'running']; S.testProg = 0;
        const h = setInterval(() => {
            S.testProg += 10;
            if (S.testProg >= 100) { clearInterval(h); S.tests = ['passed', 'passed', 'passed']; toast('All tests passed') }
            if (S.view == 'patch') render()
        }, 200)
    }
    else if (a == 'regen') { S.tests = null; S.testProg = 0; P[S.pi].conf = 80 + Math.floor(Math.random() * 19); render(); toast('Patch regenerated') }
    else if (a == 'act') toast(v);
    else if (a == 'ask') ask(v);
    else if (a == 'copy') { (navigator.clipboard ? navigator.clipboard.writeText(v) : Promise.reject()).then(() => toast('Copied'), () => toast('Copy unavailable')) }
    else if (a == 'tag') { S.tag = v; render() } else if (a == 'msearch') { S.mq = $('#mq').value; render() }
    else if (a == 'reveal') { S.keys[v].show = !S.keys[v].show; render() } else if (a == 'notif') { S.notif[v] = !S.notif[v]; render() }
    else if (a == 'theme') { S.theme = S.theme == 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = S.theme; render() }
    else if (a == 'term') { $('#term').classList.toggle('off') }
    else if (a == 'mic') voice(v)
}

/* ================= VOICE ================= */
let rec;
function vset(h, on = true) { const b = $('#vbar'); b.classList.toggle('on', on); b.innerHTML = h }
function voice(target) {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { vset('⚠ Voice input is not supported in this browser. Type instead. <button data-a="vhide">Dismiss</button>'); return }
    if (rec) { rec.stop(); return }
    rec = new SR(); rec.interimResults = true; rec.lang = 'en-US'; let fin = '';
    rec.onstart = () => vset('<span class="wave" aria-hidden="true"><i></i><i></i><i></i><i></i></span> Listening… <span class="sub">say "open vulnerabilities" or "show critical issues"</span>');
    rec.onresult = e => { let t = ''; for (const r of e.results) { t += r[0].transcript; if (r.isFinal) fin = t } vset('<span class="wave"><i></i><i></i><i></i><i></i></span> ' + esc(t)) };
    rec.onend = () => { rec = null; if (!fin) { vset('Voice idle', false); return } vset('Processing…'); setTimeout(() => { vset('', false); if (!vcmd(fin)) { if (target == 'chat' && S.view == 'chat') ask(fin); else { S.q = fin; $('#gs').value = fin; go('vulns') } } }, 400) };
    rec.onerror = e => { rec = null; vset('⚠ Voice error: ' + esc(e.error) + ' <button data-a="vhide">Dismiss</button>') };
    try { rec.start() } catch (x) { rec = null; vset('⚠ Could not start microphone') }
}

/* ================= EVENTS ================= */
document.addEventListener('click', e => {
    const el = e.target.closest('[data-a]'); if (!el) return;
    if (el.dataset.a == 'vhide') { vset('', false); return }
    if (el.tagName == 'A') e.preventDefault();
    if (el.dataset.a == 'sel' || el.dataset.a == 'selall') { e.stopPropagation(); act(el.dataset.a, el.dataset.v, el); return }
    act(el.dataset.a, el.dataset.v, el)
});

document.addEventListener('change', e => {
    const a = e.target.dataset.a;
    if (a == 'fsev') { S.sev = e.target.value; render() }
    if (a == 'fstat') { S.status = e.target.value; render() }
});

document.addEventListener('input', e => {
    if (e.target.id == 'vq') {
        S.q = e.target.value; const p = e.target.selectionStart; render(); const n = $('#vq'); n.focus(); n.setSelectionRange(p, p)
    }
});

document.addEventListener('submit', e => {
    e.preventDefault();
    if (e.target.id == 'cform') { const i = $('#cin'); if (i.value.trim()) { ask(i.value.trim()) } }
    if (e.target.id == 'tform') { const i = $('#tin'); tcmd(i.value); i.value = '' }
});

document.addEventListener('keydown', e => {
    if (e.key == 'Escape' && S.drawer) { S.drawer = null; render() }
    if (e.ctrlKey && e.key == '`') act('term');
    if (e.key == 'Enter' && e.target.matches('tr[data-a=open]')) act('open', e.target.dataset.v);
    if (e.key == 'Enter' && e.target.id == 'gs') { if (!vcmd(e.target.value)) { S.q = e.target.value; go('vulns') } }
});

/* ================= LIVE STATUS SIMULATION ================= */
setInterval(() => {
    const s = S.stages; let ch = false;
    for (let i = 0; i < 3; i++) {
        if (s[i].s == 'running') {
            s[i].p = Math.min(100, s[i].p + 7); ch = true;
            if (s[i].p >= 100) {
                s[i].s = i == 2 && Math.random() < .3 ? 'failed' : 'passed';
                JOBS.unshift({ t: 'now', m: s[i].n + ' ' + s[i].s, ok: s[i].s == 'passed' });
                if (i < 2) { s[i + 1] = { n: s[i + 1].n, s: 'running', p: 0 } }
            }
        }
    }
    if (!s.some(x => x.s == 'running') && Math.random() < .2) s[0] = { n: 'Scan queue', s: 'running', p: 0 };
    const d = $('#stages'); if (ch && d && S.view == 'status') d.innerHTML = stagesHtml()
}, 900);

/* ================= INIT ================= */
if (innerWidth <= 800) $('#term').classList.add('off');
tprint('Sentinel shell v1.0 — type "help"');
render();
