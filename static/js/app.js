// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initLogAnalyzer();
});

// ── Navigation ────────────────────────────────────────────────────────────────

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('tool-' + item.dataset.tool).classList.add('active');
    if (item.dataset.tool === 'settings') loadSettings();
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function loading(el) {
  el.innerHTML = `<div class="result-card"><span class="spinner"></span><span class="loading-text">Running…</span></div>`;
}

function err(el, msg) {
  el.innerHTML = `<div class="alert alert-error">⚠ ${esc(msg)}</div>`;
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function row(label, value, extra='') {
  return `<div class="result-row"><span class="result-label">${esc(label)}</span><span class="result-value">${value}${extra}</span></div>`;
}

function badge(text, type='neutral') {
  return `<span class="badge badge-${type}">${esc(String(text))}</span>`;
}

function scoreColor(pct) {
  if (pct === 0) return 'var(--safe)';
  if (pct < 30) return 'var(--warn)';
  return 'var(--danger)';
}

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return r.json();
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

function switchTab(tool, tab, btn) {
  document.querySelectorAll(`#tool-${tool} .tab`).forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll(`[id^="${tool}-tab-"]`).forEach(el => el.style.display = 'none');
  document.getElementById(`${tool}-tab-${tab}`).style.display = '';
  document.getElementById(`${tool}-results`).innerHTML = '';
}

// ── Reputation ────────────────────────────────────────────────────────────────

async function checkReputation() {
  const el = document.getElementById('rep-results');
  const ioc = document.getElementById('rep-ioc').value.trim();
  const type = document.getElementById('rep-type').value;
  if (!ioc) { err(el, 'Enter a value first.'); return; }
  loading(el);
  const data = await post('/api/reputation', {ioc, type});
  renderReputation(el, ioc, data);
}

function renderReputation(el, ioc, data) {
  let html = '';

  if (data.vt) {
    const vt = data.vt;
    if (vt.error) {
      html += `<div class="alert alert-warn">⚠ VirusTotal: ${esc(vt.error)}</div>`;
    } else {
      const pct = vt.total > 0 ? Math.round((vt.malicious / vt.total) * 100) : 0;
      const btype = vt.malicious > 0 ? 'danger' : 'safe';
      html += `<div class="result-card">
        <div class="result-title">VirusTotal</div>
        ${row('IOC', `<code>${esc(ioc)}</code>`)}
        ${row('Verdict', badge(vt.malicious > 0 ? 'MALICIOUS' : 'CLEAN', btype))}
        ${row('Malicious', `${vt.malicious} / ${vt.total}`)}
        ${row('Suspicious', `${vt.suspicious} / ${vt.total}`)}
        ${row('Harmless', `${vt.harmless} / ${vt.total}`)}
        <div class="score-bar-wrap">
          <div class="score-bar-label">Detection rate: ${pct}%</div>
          <div class="score-bar-bg"><div class="score-bar-fill" style="width:${pct}%;background:${scoreColor(pct)}"></div></div>
        </div>
        ${vt.tags && vt.tags.length ? row('Tags', `<div class="tag-list">${vt.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div>`) : ''}
      </div>`;
    }
  }

  if (data.abuseipdb) {
    const ab = data.abuseipdb;
    if (ab.error) {
      html += `<div class="alert alert-warn">⚠ AbuseIPDB: ${esc(ab.error)}</div>`;
    } else {
      const score = ab.abuseConfidenceScore ?? 0;
      const btype = score >= 50 ? 'danger' : score > 0 ? 'warn' : 'safe';
      html += `<div class="result-card">
        <div class="result-title">AbuseIPDB</div>
        ${row('Abuse Score', badge(`${score}%`, btype))}
        ${row('Country', esc(ab.countryCode || 'N/A'))}
        ${row('ISP', esc(ab.isp || 'N/A'))}
        ${row('Domain', esc(ab.domain || 'N/A'))}
        ${row('Total Reports', String(ab.totalReports ?? 0))}
        ${row('Last Reported', esc(ab.lastReportedAt || 'Never'))}
        ${row('Usage Type', esc(ab.usageType || 'N/A'))}
        ${row('Is Tor', ab.isTor ? badge('YES','danger') : badge('NO','safe'))}
      </div>`;
    }
  }

  el.innerHTML = html || `<div class="alert alert-info">No results.</div>`;
}

// ── URL Tools ─────────────────────────────────────────────────────────────────

function toggleUrlTextarea() {
  const action = document.getElementById('url-action').value;
  const single = document.getElementById('url-single-input');
  const textarea = document.getElementById('url-text-input');
  if (action === 'extract') { single.style.display = 'none'; textarea.style.display = ''; }
  else { single.style.display = ''; textarea.style.display = 'none'; }
}

async function runUrlTool() {
  const el = document.getElementById('url-results');
  const action = document.getElementById('url-action').value;
  const url = document.getElementById('url-value').value.trim();
  const text = document.getElementById('url-text').value;
  loading(el);

  const body = action === 'extract' ? {action, text} : {action, url};
  const data = await post('/api/url', body);

  if (data.error) { err(el, data.error); return; }

  if (action === 'extract') {
    if (!data.urls || data.urls.length === 0) {
      el.innerHTML = `<div class="alert alert-info">No URLs found in text.</div>`; return;
    }
    let html = `<div class="result-card"><div class="result-title">Extracted URLs (${data.count})</div>`;
    data.urls.forEach(u => { html += `<div class="result-row"><code>${esc(u)}</code></div>`; });
    html += '</div>';
    el.innerHTML = html;
  } else {
    el.innerHTML = `<div class="result-card">
      <div class="result-title">Result</div>
      <div class="result-row"><code>${esc(data.result)}</code></div>
    </div>`;
  }
}

// ── DNS & WHOIS ───────────────────────────────────────────────────────────────

async function runDns() {
  const el = document.getElementById('dns-results');
  const target = document.getElementById('dns-target').value.trim();
  const type = document.getElementById('dns-type').value;
  if (!target) { err(el, 'Enter a domain or IP first.'); return; }
  loading(el);

  const data = await post('/api/dns', {target, type});

  if (data.error) { err(el, data.error); return; }

  let html = `<div class="result-card"><div class="result-title">${type.toUpperCase()} — ${esc(target)}</div>`;

  if (type === 'dns') {
    const types = ['A','AAAA','MX','NS','TXT','CNAME','SOA'];
    let any = false;
    types.forEach(t => {
      if (data[t] && data[t].length) {
        any = true;
        html += row(t, data[t].map(r => `<code>${esc(r)}</code>`).join('<br>'));
      }
    });
    if (!any) html += `<div class="alert alert-info" style="margin-top:8px">No records found.</div>`;
  } else if (type === 'whois') {
    Object.entries(data).forEach(([k, v]) => {
      if (v) {
        const val = Array.isArray(v) ? v.join(', ') : v;
        html += row(k.replace(/_/g,' '), esc(val));
      }
    });
  } else {
    html += row('Hostname', data.hostname ? `<code>${esc(data.hostname)}</code>` : badge('No record','neutral'));
  }

  html += '</div>';
  el.innerHTML = html;
}

// ── Hash Tools ────────────────────────────────────────────────────────────────

async function hashString() {
  const el = document.getElementById('hash-results');
  const text = document.getElementById('hash-string').value;
  if (!text) { err(el, 'Enter a string.'); return; }
  loading(el);
  const data = await post('/api/hash/text', {text});
  el.innerHTML = `<div class="result-card">
    <div class="result-title">Hashes</div>
    ${row('MD5', `<code>${esc(data.md5)}</code>`)}
    ${row('SHA1', `<code>${esc(data.sha1)}</code>`)}
    ${row('SHA256', `<code>${esc(data.sha256)}</code>`)}
  </div>`;
}

async function hashFile() {
  const el = document.getElementById('hash-results');
  const file = document.getElementById('hash-file').files[0];
  const checkVt = document.getElementById('hash-vt-check').checked;
  if (!file) { err(el, 'Select a file first.'); return; }
  loading(el);

  const fd = new FormData();
  fd.append('file', file);
  fd.append('check_vt', checkVt ? 'true' : 'false');

  const r = await fetch('/api/hash/file', {method: 'POST', body: fd});
  const data = await r.json();
  if (data.error) { err(el, data.error); return; }

  let html = `<div class="result-card">
    <div class="result-title">File: ${esc(data.filename)}</div>
    ${row('MD5', `<code>${esc(data.hashes.MD5)}</code>`)}
    ${row('SHA1', `<code>${esc(data.hashes.SHA1)}</code>`)}
    ${row('SHA256', `<code>${esc(data.hashes.SHA256)}</code>`)}
  </div>`;

  if (data.vt) {
    const vt = data.vt;
    if (vt.error) {
      html += `<div class="alert alert-warn">⚠ VT: ${esc(vt.error)}</div>`;
    } else if (!vt.found) {
      html += `<div class="alert alert-info">Hash not found in VirusTotal.</div>`;
    } else {
      const btype = vt.malicious > 0 ? 'danger' : 'safe';
      html += `<div class="result-card">
        <div class="result-title">VirusTotal</div>
        ${row('Name', esc(vt.name))}
        ${row('Type', esc(vt.type))}
        ${row('Size', vt.size ? `${vt.size.toLocaleString()} bytes` : 'N/A')}
        ${row('Verdict', badge(vt.malicious > 0 ? 'MALICIOUS' : 'CLEAN', btype))}
        ${row('Malicious', `${vt.malicious} / ${vt.total}`)}
        ${row('First Seen', esc(vt.first_seen))}
      </div>`;
    }
  }
  el.innerHTML = html;
}

async function checkHash() {
  const el = document.getElementById('hash-results');
  const h = document.getElementById('hash-vt').value.trim();
  if (!h) { err(el, 'Enter a hash.'); return; }
  loading(el);
  const data = await post('/api/hash/check', {hash: h});
  if (data.error) { err(el, data.error); return; }
  if (!data.found) {
    el.innerHTML = `<div class="alert alert-info">Hash not found in VirusTotal database.</div>`; return;
  }
  const btype = data.malicious > 0 ? 'danger' : 'safe';
  el.innerHTML = `<div class="result-card">
    <div class="result-title">VirusTotal Hash Report</div>
    ${row('Name', esc(data.name))}
    ${row('Type', esc(data.type))}
    ${row('Size', data.size ? `${data.size.toLocaleString()} bytes` : 'N/A')}
    ${row('Verdict', badge(data.malicious > 0 ? 'MALICIOUS' : 'CLEAN', btype))}
    ${row('Malicious', `${data.malicious} / ${data.total}`)}
    ${row('Suspicious', `${data.suspicious} / ${data.total}`)}
    ${row('First Seen', esc(data.first_seen))}
  </div>`;
}

// ── Email Analyzer ────────────────────────────────────────────────────────────

async function analyzeEmail() {
  const el = document.getElementById('email-results');
  const file = document.getElementById('email-file').files[0];
  if (!file) { err(el, 'Upload a .eml file first.'); return; }
  loading(el);

  const fd = new FormData();
  fd.append('file', file);
  const r = await fetch('/api/email', {method: 'POST', body: fd});
  const data = await r.json();
  if (data.error) { err(el, data.error); return; }

  const authColors = {pass: 'safe', fail: 'danger', unknown: 'warn'};

  let html = `<div class="result-card">
    <div class="result-title">Headers</div>
    ${Object.entries(data.headers).map(([k,v]) => row(k, esc(v))).join('')}
  </div>`;

  if (Object.keys(data.auth).length) {
    html += `<div class="result-card">
      <div class="result-title">Authentication</div>
      ${Object.entries(data.auth).map(([k,v]) => row(k, badge(v.toUpperCase(), authColors[v] || 'neutral'))).join('')}
    </div>`;
  }

  html += `<div class="result-card">
    <div class="result-title">Phishing Indicators</div>
    ${data.reply_mismatch ? `<div class="alert alert-error" style="margin-bottom:8px">⚠ Reply-To differs from From address — common phishing tactic</div>` : ''}
    ${data.phishing_keywords.length
      ? row('Suspicious keywords', `<div class="tag-list">${data.phishing_keywords.map(k=>`<span class="tag">${esc(k)}</span>`).join('')}</div>`)
      : `<div class="alert alert-info">No common phishing keywords detected.</div>`}
  </div>`;

  if (data.urls.length) {
    html += `<div class="result-card">
      <div class="result-title">Extracted URLs (${data.urls.length})</div>
      ${data.urls.map(u => `<div class="result-row"><code>${esc(u)}</code></div>`).join('')}
    </div>`;
  }

  if (data.ips.length) {
    html += `<div class="result-card">
      <div class="result-title">Extracted IPs</div>
      ${data.ips.map(ip => `<div class="result-row"><code>${esc(ip)}</code></div>`).join('')}
    </div>`;
  }

  if (data.attachments.length) {
    html += `<div class="result-card">
      <div class="result-title">Attachments (${data.attachments.length})</div>
      ${data.attachments.map(a => row(esc(a.name), `${esc(a.type)} — ${a.size.toLocaleString()} bytes`)).join('')}
    </div>`;
  }

  el.innerHTML = html;
}

// ── Breach Check ──────────────────────────────────────────────────────────────

async function checkBreachEmail() {
  const el = document.getElementById('breach-results');
  const email = document.getElementById('breach-email').value.trim();
  if (!email) { err(el, 'Enter an email address.'); return; }
  loading(el);
  const data = await post('/api/breach/email', {email});
  if (data.error) { err(el, data.error); return; }
  if (!data.found) {
    el.innerHTML = `<div class="alert alert-info">✓ ${esc(email)} not found in any known breaches.</div>`; return;
  }
  let html = `<div class="alert alert-error">⚠ Found in ${data.breaches.length} breach(es)</div>`;
  data.breaches.forEach(b => {
    html += `<div class="result-card">
      <div class="result-title">${esc(b.Name)}</div>
      ${row('Domain', esc(b.Domain || 'N/A'))}
      ${row('Date', esc(b.BreachDate || 'N/A'))}
      ${row('Records', (b.PwnCount||0).toLocaleString())}
      ${row('Data Exposed', `<div class="tag-list">${(b.DataClasses||[]).map(d=>`<span class="tag">${esc(d)}</span>`).join('')}</div>`)}
      ${row('Verified', b.IsVerified ? badge('YES','safe') : badge('NO','neutral'))}
      ${row('Sensitive', b.IsSensitive ? badge('YES','danger') : badge('NO','neutral'))}
    </div>`;
  });
  el.innerHTML = html;
}

async function checkBreachDomain() {
  const el = document.getElementById('breach-results');
  const domain = document.getElementById('breach-domain').value.trim();
  if (!domain) { err(el, 'Enter a domain.'); return; }
  loading(el);
  const data = await post('/api/breach/domain', {domain});
  if (data.error) { err(el, data.error); return; }
  if (!data.breaches || data.breaches.length === 0) {
    el.innerHTML = `<div class="alert alert-info">✓ No breaches found for domain ${esc(domain)}.</div>`; return;
  }
  let html = `<div class="alert alert-error">⚠ ${data.breaches.length} breach(es) for ${esc(domain)}</div>
  <div class="result-card"><div class="result-title">Breaches</div>`;
  data.breaches.forEach(b => {
    html += row(esc(b.Name), `${esc(b.BreachDate)} — ${(b.PwnCount||0).toLocaleString()} accounts`);
  });
  html += '</div>';
  el.innerHTML = html;
}

async function checkBreachPassword() {
  const el = document.getElementById('breach-results');
  const pw = document.getElementById('breach-password').value;
  if (!pw) { err(el, 'Enter a password.'); return; }
  loading(el);
  const data = await post('/api/breach/password', {password: pw});
  if (data.error) { err(el, data.error); return; }
  if (data.found) {
    el.innerHTML = `<div class="result-card">
      <div class="alert alert-error">⚠ This password has been exposed ${data.count.toLocaleString()} time(s) in data breaches. Do NOT use it.</div>
    </div>`;
  } else {
    el.innerHTML = `<div class="alert alert-info">✓ Password not found in known breach databases.</div>`;
  }
}

// ── IP Tools ──────────────────────────────────────────────────────────────────

async function checkIp() {
  const el = document.getElementById('ip-results');
  const ip = document.getElementById('ip-value').value.trim();
  const checks = [];
  if (document.getElementById('ip-geo').checked) checks.push('geo');
  if (document.getElementById('ip-tor').checked) checks.push('tor');
  if (document.getElementById('ip-dnsbl').checked) checks.push('dnsbl');
  if (!ip) { err(el, 'Enter an IP address.'); return; }
  if (!checks.length) { err(el, 'Select at least one check.'); return; }
  loading(el);
  const data = await post('/api/ip', {ip, checks});
  let html = '';

  if (data.geo) {
    const g = data.geo;
    if (g.error) {
      html += `<div class="alert alert-warn">⚠ GeoIP: ${esc(g.error)}</div>`;
    } else {
      html += `<div class="result-card">
        <div class="result-title">GeoIP</div>
        ${row('Country', `${esc(g.country||'')} (${esc(g.countryCode||'')})`)}
        ${row('Region', esc(g.regionName||'N/A'))}
        ${row('City', esc(g.city||'N/A'))}
        ${row('ISP', esc(g.isp||'N/A'))}
        ${row('Org / ASN', esc(g.as||'N/A'))}
        ${row('Timezone', esc(g.timezone||'N/A'))}
        ${row('Hosting', g.hosting ? badge('YES','warn') : badge('NO','safe'))}
        ${row('Proxy', g.proxy ? badge('YES','danger') : badge('NO','safe'))}
        ${row('VPN', g.vpn ? badge('YES','danger') : badge('NO','safe'))}
        ${row('Tor', g.tor ? badge('YES','danger') : badge('NO','safe'))}
      </div>`;
    }
  }

  if (data.tor) {
    if (data.tor.error) {
      html += `<div class="alert alert-warn">⚠ Tor: ${esc(data.tor.error)}</div>`;
    } else {
      html += `<div class="result-card">
        <div class="result-title">Tor Exit Node</div>
        ${row('Is Tor Exit Node', data.tor.is_tor ? badge('YES — Known Tor exit','danger') : badge('NO','safe'))}
      </div>`;
    }
  }

  if (data.dnsbl) {
    const listed = Object.entries(data.dnsbl).filter(([,v]) => v);
    const clean  = Object.entries(data.dnsbl).filter(([,v]) => !v);
    html += `<div class="result-card">
      <div class="result-title">DNSBL Blacklists</div>
      ${row('Listed on', listed.length ? badge(`${listed.length} list(s)`,'danger') : badge('None','safe'))}
      ${listed.map(([bl]) => `<div class="result-row"><span class="result-label" style="color:var(--danger)">⛔ ${esc(bl)}</span></div>`).join('')}
      ${clean.map(([bl]) => `<div class="result-row"><span class="result-label" style="color:var(--safe)">✓ ${esc(bl)}</span></div>`).join('')}
    </div>`;
  }

  el.innerHTML = html || `<div class="alert alert-info">No results.</div>`;
}

// ── Log Analyzer ─────────────────────────────────────────────────────────────

const LA_MODELS = { claude: [], openai: [] };

async function initLogAnalyzer() {
  const data = await fetch('/api/log/models').then(r => r.json());
  LA_MODELS.claude = data.claude || [];
  LA_MODELS.openai = data.openai || [];
  populateModels('claude');
}

function populateModels(provider) {
  const sel = document.getElementById('la-model');
  sel.innerHTML = '';
  (LA_MODELS[provider] || []).forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = m.label;
    sel.appendChild(opt);
  });
}

function onProviderChange() {
  const provider = document.getElementById('la-provider').value;
  populateModels(provider);
}

function clearLog() {
  document.getElementById('la-log').value = '';
  document.getElementById('la-results').innerHTML = '';
  document.getElementById('la-status').textContent = '';
}

async function analyzeLog() {
  const el = document.getElementById('la-results');
  const log_text = document.getElementById('la-log').value.trim();
  const provider = document.getElementById('la-provider').value;
  const model = document.getElementById('la-model').value;
  const api_key = document.getElementById('la-apikey').value.trim();
  const btn = document.getElementById('la-btn');
  const status = document.getElementById('la-status');

  if (!log_text) { err(el, 'Paste some log data first.'); return; }

  btn.disabled = true;
  btn.textContent = 'Analyzing…';
  status.textContent = 'Sending to AI — this may take 15-30 seconds…';
  loading(el);

  try {
    const data = await post('/api/log/analyze', {log_text, provider, model, api_key});
    renderLogResults(el, data);
  } catch(e) {
    err(el, 'Request failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze with AI';
    status.textContent = '';
  }
}

function renderLogResults(el, data) {
  if (data.error) { err(el, data.error); return; }

  const sev = data.severity || 'INFO';
  const sevIcons = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🟢', INFO:'⚪' };

  let html = '';

  // Header bar
  html += `<div class="result-card" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
    <span class="severity-badge sev-${esc(sev)}">${sevIcons[sev] || '⚪'} ${esc(sev)}</span>
    <span style="font-size:12px;color:var(--muted)">Model: <code>${esc(data.model || '')}</code></span>
  </div>`;

  // Handle non-JSON raw response
  if (data.parse_error) {
    html += `<div class="result-card">
      <div class="result-title">AI Response (raw)</div>
      <pre class="analysis-text">${esc(data.raw_response || '')}</pre>
    </div>`;
    el.innerHTML = html;
    return;
  }

  // Summary
  if (data.summary) {
    html += `<div class="result-card">
      <div class="result-title">Summary</div>
      <p class="analysis-text">${esc(data.summary)}</p>
    </div>`;
  }

  // Analysis
  if (data.analysis) {
    html += `<div class="result-card">
      <div class="result-title">Technical Analysis</div>
      <p class="analysis-text">${esc(data.analysis)}</p>
    </div>`;
  }

  // Recommendations
  if (data.recommendations && data.recommendations.length) {
    html += `<div class="result-card">
      <div class="result-title">Recommendations (${data.recommendations.length})</div>
      <ol class="rec-list">
        ${data.recommendations.map(r => `<li>${esc(r)}</li>`).join('')}
      </ol>
    </div>`;
  }

  // MITRE ATT&CK
  if (data.mitre_techniques && data.mitre_techniques.length) {
    html += `<div class="result-card">
      <div class="result-title">MITRE ATT&CK Techniques</div>
      <div style="padding-top:4px">${data.mitre_techniques.map(t => `<span class="mitre-tag">${esc(t)}</span>`).join('')}</div>
    </div>`;
  }

  // IOCs found
  const iocs = data.iocs_found || {};
  const totalIocs = ['ips','urls','domains','hashes','emails'].reduce((s,k) => s + (iocs[k]||[]).length, 0);
  if (totalIocs > 0) {
    html += `<div class="result-card">
      <div class="result-title">IOCs Extracted (${totalIocs})</div>`;

    const iocTypes = [
      ['ips',     '📡 IP Addresses'],
      ['urls',    '🔗 URLs'],
      ['domains', '🌐 Domains'],
      ['hashes',  '🔐 File Hashes'],
      ['emails',  '📧 Email Addresses'],
    ];
    iocTypes.forEach(([key, label]) => {
      const list = iocs[key] || [];
      if (list.length) {
        html += `<div style="margin-bottom:10px">
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">${label}</div>
          ${list.map(v => `<div style="padding:3px 0"><code>${esc(v)}</code></div>`).join('')}
        </div>`;
      }
    });
    html += `</div>`;
  }

  // IOC Enrichment results
  const enrich = data.enrichment || {};
  const enrichKeys = Object.keys(enrich);
  if (enrichKeys.length) {
    html += `<div class="result-card">
      <div class="result-title">IOC Enrichment (Reputation Lookup)</div>`;

    enrichKeys.forEach(type => {
      Object.entries(enrich[type]).forEach(([ioc, sources]) => {
        html += `<div class="ioc-enrichment-card">
          <div class="ioc-enrichment-label">${esc(ioc)}</div>`;

        if (sources.virustotal && !sources.virustotal.error) {
          const vt = sources.virustotal;
          const btype = vt.malicious > 0 ? 'danger' : 'safe';
          html += `${row('VirusTotal', `${badge(vt.malicious > 0 ? 'MALICIOUS' : 'CLEAN', btype)} &nbsp; ${vt.malicious}/${vt.total} detections`)}`;
        }
        if (sources.abuseipdb && !sources.abuseipdb.error) {
          const ab = sources.abuseipdb;
          const score = ab.abuseConfidenceScore ?? 0;
          const btype = score >= 50 ? 'danger' : score > 0 ? 'warn' : 'safe';
          html += `${row('AbuseIPDB', `${badge(score + '%', btype)} &nbsp; ${esc(ab.countryCode||'')} — ${esc(ab.isp||'')}`)}`;
        }
        html += `</div>`;
      });
    });

    html += `</div>`;
  }

  el.innerHTML = html;
}

// ── Settings ──────────────────────────────────────────────────────────────────

async function loadSettings() {
  const el = document.getElementById('settings-form');
  el.innerHTML = '<p class="loading-text"><span class="spinner"></span>Loading…</p>';
  const data = await fetch('/api/settings').then(r => r.json());

  const labels = {
    virustotal_api_key: 'VirusTotal',
    abuseipdb_api_key:  'AbuseIPDB',
    hibp_api_key:       'HaveIBeenPwned',
    urlscan_api_key:    'URLScan.io',
    shodan_api_key:     'Shodan',
    claude_api_key:     '🤖 Anthropic Claude (Log Analyzer)',
    openai_api_key:     '🤖 OpenAI / ChatGPT (Log Analyzer)',
  };

  let html = '';
  Object.entries(data).forEach(([key, masked]) => {
    html += `<div class="settings-row">
      <span class="settings-label">${esc(labels[key] || key)}</span>
      <div class="settings-value">
        <input type="password" class="input-text" id="s-${key}"
               placeholder="${masked ? '(already set — paste to update)' : 'Paste API key…'}"
               style="font-family:monospace" />
      </div>
    </div>`;
  });

  html += `<div style="margin-top:16px">
    <button class="btn-primary" onclick="saveSettings()">Save Keys</button>
    <span id="save-status" style="margin-left:12px;font-size:13px;color:var(--safe)"></span>
  </div>`;

  el.innerHTML = html;
}

async function saveSettings() {
  const keys = ['virustotal_api_key','abuseipdb_api_key','hibp_api_key','urlscan_api_key','shodan_api_key','claude_api_key','openai_api_key'];
  const body = {};
  keys.forEach(k => {
    const v = document.getElementById('s-' + k)?.value.trim();
    if (v) body[k] = v;
  });
  if (!Object.keys(body).length) {
    document.getElementById('save-status').textContent = 'Nothing to save.'; return;
  }
  await post('/api/settings', body);
  document.getElementById('save-status').textContent = '✓ Saved';
  setTimeout(() => { document.getElementById('save-status').textContent = ''; }, 3000);
}
