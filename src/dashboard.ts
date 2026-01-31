import type { Database } from 'bun:sqlite';
import {
  DEFAULT_COMMON_NAME_INTERMEDIATE,
  DEFAULT_COMMON_NAME_ROOT,
} from './constants.js';
import { htmlEscape, attrEscape, escapeForScript } from './escape.js';
import type { PathHelpers } from './paths.js';
import { getSummaryData } from './summary.js';

/**
 * Rendert das Dashboard-HTML mit aktuellen Summary-Daten.
 * Escape-Funktionen verhindern XSS und Parser-Brüche durch Benutzerdaten.
 */
export function renderDashboard(database: Database, paths: PathHelpers): Response {
  const { summary, challenges, certificates, cas, intermediates } = getSummaryData(database, paths);
  const initialData = { cas, intermediates, caConfigured: summary.caConfigured };
  const initialDataJson = escapeForScript(JSON.stringify(initialData));

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dashboard</title>
  <style>
    body { font-family: sans-serif; max-width: 1200px; margin: 40px auto; padding: 20px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .summary-item { background: #f5f5f5; padding: 16px; border-radius: 8px; }
    .summary-item dt { font-size: 0.85em; color: #666; margin-bottom: 4px; }
    .summary-item dd { margin: 0; font-weight: 500; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
    .setup { margin-top: 32px; }
    .setup h2 { font-size: 1.25rem; margin-bottom: 16px; }
    .setup-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }
    .setup-card { background: #f5f5f5; padding: 20px; border-radius: 8px; }
    .setup-card h3 { margin: 0 0 12px; font-size: 1rem; }
    .setup-card p { margin: 0 0 16px; font-size: 0.9em; color: #555; }
    .setup-card .btn { display: inline-block; padding: 8px 16px; background: #007bff; color: #fff; border: none; border-radius: 6px; font-size: 0.9rem; cursor: pointer; text-decoration: none; }
    .setup-card .btn:hover { background: #0056b3; }
    .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 100; align-items: center; justify-content: center; }
    .modal-overlay.open { display: flex; }
    .modal { background: #fff; padding: 24px; border-radius: 8px; max-width: 420px; width: 90%; }
    .modal h3 { margin: 0 0 16px; }
    .modal label { display: block; margin-bottom: 4px; font-size: 0.9em; }
    .modal input, .modal select { width: 100%; padding: 8px; margin-bottom: 12px; box-sizing: border-box; }
    .modal-actions { margin-top: 20px; display: flex; gap: 8px; justify-content: flex-end; }
    .modal-actions .btn-secondary { background: #6c757d; }
    .modal-actions .btn-secondary:hover { background: #545b62; }
  </style>
</head>
<body>
  <section class="summary">
    <div class="summary-item">
      <dt>Zertifikate gespeichert</dt>
      <dd id="certsTotal">${summary.certsTotal}</dd>
    </div>
    <div class="summary-item">
      <dt>Zertifikate gültig</dt>
      <dd id="certsValid">${summary.certsValid}</dd>
    </div>
    <div class="summary-item">
      <dt>Zeit (UTC)</dt>
      <dd id="timeUtc">${summary.timeUtc}</dd>
    </div>
    <div class="summary-item">
      <dt>Zeit (lokal)</dt>
      <dd id="timeLocal">${summary.timeLocal}</dd>
    </div>
    <div class="summary-item">
      <dt>Let's Encrypt Account</dt>
      <dd id="letsEncryptEmail">${summary.letsEncrypt ? htmlEscape(summary.letsEncrypt.email) : '—'}</dd>
      <dt id="accountUrlLabel" style="margin-top:8px; display:${summary.letsEncrypt?.accountUrl ? 'block' : 'none'}">Account URL</dt>
      <dd id="letsEncryptUrl" style="word-break:break-all;font-size:0.9em">${summary.letsEncrypt?.accountUrl ? htmlEscape(summary.letsEncrypt.accountUrl) : ''}</dd>
    </div>
  </section>

  <section class="setup">
    <h2>Setup</h2>
    <div class="setup-grid">
      <div class="setup-card">
        <h3>Let's Encrypt Zertifikate</h3>
        <p>Account anlegen oder verbinden, um Zertifikate von Let's Encrypt per HTTP- oder DNS-Challenge anzufordern.</p>
        <button type="button" class="btn" onclick="alert('Let\\'s Encrypt Setup – kommt noch')">Einrichten</button>
      </div>
      <div class="setup-card">
        <h3>Eigene CA</h3>
        <div id="caNotConfigured">
          <p>Root-CA per Knopfdruck einrichten. Danach können ACME-Clients (z. B. Reverse-Proxys) Zertifikate von dieser CA anfordern.</p>
          <button type="button" class="btn" onclick="document.getElementById('caModal').classList.add('open')">Einrichten</button>
        </div>
        <div id="caConfigured" style="display:none">
          <p>In deinem Reverse-Proxy oder ACME-Client die <strong>Directory-URL</strong> eintragen und das <strong>CA-Zertifikat</strong> als vertrauenswürdige CA hinterlegen – dann können Zertifikate von dieser CA angefordert werden.</p>
          <p style="margin-bottom:8px"><strong>Directory-URL:</strong><br><code id="caDirectoryUrl" style="word-break:break-all"></code></p>
          <p style="margin-bottom:8px"><strong>Aktive CAs:</strong></p>
          <ul id="caListSetup" style="margin:0 0 12px; padding-left:20px"></ul>
          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button type="button" class="btn" onclick="document.getElementById('caModal').classList.add('open')">CA hinzufügen</button>
            <button type="button" class="btn" onclick="openIntermediateModal()">Intermediat Certifikat erstellen</button>
          </div>
        </div>
      </div>
      <div class="setup-card">
        <h3>Zertifikate erstellen</h3>
        <p style="margin-bottom:12px">Domain-Zertifikat über die eingerichtete CA ausstellen.</p>
        <button type="button" class="btn" onclick="openCertCreateModal()">Certificat erstellen</button>
      </div>
    </div>
  </section>

  <div id="caModal" class="modal-overlay" onclick="if(event.target===this) this.classList.remove('open')">
    <div class="modal" onclick="event.stopPropagation()">
      <h3>Root-CA einrichten</h3>
      <form id="caSetupForm" onsubmit="submitCaSetup(event); return false;">
        <label>Name (für die Liste)</label>
        <input type="text" name="name" placeholder="z. B. Meine CA" required>
        <label>Common Name (CN)</label>
        <input type="text" name="commonName" value="${htmlEscape(DEFAULT_COMMON_NAME_ROOT)}" placeholder="z. B. Meine CA" required>
        <label>Organisation (O)</label>
        <input type="text" name="organization" placeholder="optional">
        <label>Organisationseinheit (OU)</label>
        <input type="text" name="organizationalUnit" placeholder="optional">
        <label>Land (C)</label>
        <input type="text" name="country" placeholder="z. B. DE" maxlength="2">
        <label>Ort (L)</label>
        <input type="text" name="locality" placeholder="optional">
        <label>Bundesland (ST)</label>
        <input type="text" name="stateOrProvince" placeholder="optional">
        <label>E-Mail</label>
        <input type="email" name="email" placeholder="optional">
        <label>Gültigkeit (Jahre)</label>
        <input type="number" name="validityYears" value="10" min="1" max="30">
        <label>Schlüssellänge</label>
        <select name="keySize">
          <option value="2048">2048 Bit</option>
          <option value="4096">4096 Bit</option>
        </select>
        <label>Hash-Algorithmus</label>
        <select name="hashAlgo">
          <option value="sha256">SHA-256</option>
          <option value="sha384">SHA-384</option>
          <option value="sha512">SHA-512</option>
        </select>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="document.getElementById('caModal').classList.remove('open')">Abbrechen</button>
          <button type="button" class="btn" id="caSubmitBtn" onclick="submitCaSetup(event)">CA erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="intermediateModal" class="modal-overlay" onclick="if(event.target===this) this.classList.remove('open')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:420px">
      <h3>Intermediate-CA erstellen</h3>
      <p style="margin-bottom:12px;font-size:0.9em;color:#555">Die Intermediate-CA wird von der gewählten Root-CA signiert.</p>
      <form id="intermediateSetupForm" onsubmit="submitIntermediateSetup(event); return false;">
        <label>Parent-CA (ausstellende Root-CA)</label>
        <select name="parentCaId" id="intermediateParentSelect" required style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="">– Bitte wählen –</option>
        </select>
        <label>Name (für die Liste)</label>
        <input type="text" name="name" placeholder="z. B. Meine Intermediate CA" required>
        <label>Common Name (CN)</label>
        <input type="text" name="commonName" value="${htmlEscape(DEFAULT_COMMON_NAME_INTERMEDIATE)}" placeholder="z. B. Intermediate CA" required>
        <label>Organisation (O)</label>
        <input type="text" name="organization" placeholder="optional">
        <label>Organisationseinheit (OU)</label>
        <input type="text" name="organizationalUnit" placeholder="optional">
        <label>Land (C)</label>
        <input type="text" name="country" placeholder="z. B. DE" maxlength="2">
        <label>Ort (L)</label>
        <input type="text" name="locality" placeholder="optional">
        <label>Bundesland (ST)</label>
        <input type="text" name="stateOrProvince" placeholder="optional">
        <label>E-Mail</label>
        <input type="email" name="email" placeholder="optional">
        <label>Gültigkeit (Jahre)</label>
        <input type="number" name="validityYears" value="10" min="1" max="30">
        <label>Schlüssellänge</label>
        <select name="keySize">
          <option value="2048">2048 Bit</option>
          <option value="4096">4096 Bit</option>
        </select>
        <label>Hash-Algorithmus</label>
        <select name="hashAlgo">
          <option value="sha256">SHA-256</option>
          <option value="sha384">SHA-384</option>
          <option value="sha512">SHA-512</option>
        </select>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="document.getElementById('intermediateModal').classList.remove('open')">Abbrechen</button>
          <button type="submit" class="btn" id="intermediateSubmitBtn">Intermediate-CA erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="certCreateModal" class="modal-overlay" onclick="if(event.target===this) this.classList.remove('open')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:420px">
      <h3>Zertifikat erstellen</h3>
      <form id="certCreateForm" onsubmit="submitCertCreate(event); return false;">
        <label>Ausstellende CA</label>
        <select name="issuerId" id="certCreateCaSelect" required style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="">– Bitte wählen –</option>
        </select>
        <label>Domain (CN / erste SAN)</label>
        <input type="text" name="domain" id="certCreateDomain" placeholder="z. B. example.com" required style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
        <label>Weitere Domains (SAN, kommagetrennt, optional)</label>
        <input type="text" name="sanDomains" id="certCreateSan" placeholder="www.example.com, api.example.com" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
        <label>Gültigkeit (Tage)</label>
        <input type="number" name="validityDays" value="365" min="1" max="825" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
        <label>Schlüssellänge</label>
        <select name="keySize" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="2048">2048 Bit</option>
          <option value="4096">4096 Bit</option>
        </select>
        <label>Hash-Algorithmus</label>
        <select name="hashAlgo" style="width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box">
          <option value="sha256">SHA-256</option>
          <option value="sha384">SHA-384</option>
          <option value="sha512">SHA-512</option>
        </select>
        <div id="certCreateSuccess" style="display:none;margin-bottom:12px;padding:12px;background:#e8f5e9;border-radius:6px;font-size:0.9em">
          <strong>Zertifikat erstellt.</strong>
          <p style="margin:8px 0 0 0"><a href="#" id="certCreateDownloadCert" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat herunterladen</a>
          <a href="#" id="certCreateDownloadKey" class="btn" style="padding:4px 8px;font-size:0.85rem;margin-left:4px" download>Schlüssel herunterladen</a></p>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="document.getElementById('certCreateModal').classList.remove('open')">Abbrechen</button>
          <button type="submit" class="btn" id="certCreateSubmitBtn">Zertifikat erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <h2 style="margin-top:24px;font-size:1.1rem">Challenges</h2>
  <table>
    <thead><tr><th>Token</th><th>Domain</th><th>Läuft ab</th></tr></thead>
    <tbody id="challenges">${challenges
      .map(
        (challenge) => `
      <tr>
        <td><code>${htmlEscape(challenge.token)}</code></td>
        <td>${htmlEscape(challenge.domain)}</td>
        <td>${challenge.expires_at ? new Date(challenge.expires_at).toLocaleString() : '-'}</td>
      </tr>
    `
      )
      .join('')}</tbody>
  </table>

  <h2 style="margin-top:24px;font-size:1.1rem">Zertifikate</h2>
  <h3 style="font-size:1rem; margin:16px 0 8px">Root-CAs</h3>
  <table>
    <thead><tr><th>Name</th><th>Common Name</th><th>Aktiv</th><th>Gültig bis</th><th>Erstellt</th><th>Aktionen</th></tr></thead>
    <tbody id="cas">${cas
      .map(
        (ca) => `
      <tr>
        <td>${htmlEscape(ca.name)}</td>
        <td>${htmlEscape(ca.commonName)}</td>
        <td>${ca.isActive ? '✓' : ''}</td>
        <td>${ca.notAfter ? new Date(ca.notAfter).toLocaleString() : '—'}</td>
        <td>${ca.createdAt ? new Date(ca.createdAt).toLocaleString() : '—'}</td>
        <td>
          ${!ca.isActive ? '<button type="button" class="btn" style="padding:4px 8px;font-size:0.85rem" data-ca-id="' + attrEscape(ca.id) + '">Aktivieren</button> ' : ''}
          <a href="/api/ca-cert?id=' + encodeURIComponent(ca.id) + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat</a>
        </td>
      </tr>
    `
      )
      .join('')}</tbody>
  </table>
  <h3 style="font-size:1rem; margin:16px 0 8px">Intermediate-CAs</h3>
  <table>
    <thead><tr><th>Name</th><th>Common Name</th><th>Parent-CA</th><th>Gültig bis</th><th>Erstellt</th><th>Aktionen</th></tr></thead>
    <tbody id="intermediates">${intermediates
      .map(
        (intermediate) => `
      <tr>
        <td>${htmlEscape(intermediate.name)}</td>
        <td>${htmlEscape(intermediate.commonName)}</td>
        <td>${htmlEscape(intermediate.parentCaId)}</td>
        <td>${intermediate.notAfter ? new Date(intermediate.notAfter).toLocaleString() : '—'}</td>
        <td>${intermediate.createdAt ? new Date(intermediate.createdAt).toLocaleString() : '—'}</td>
        <td><a href="/api/ca-cert?id=' + encodeURIComponent(intermediate.id) + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat</a></td>
      </tr>
    `
      )
      .join('')}</tbody>
  </table>
  <h3 style="font-size:1rem; margin:16px 0 8px">Ausgestellte Zertifikate (Domains)</h3>
  <table>
    <thead><tr><th>Domain</th><th>Gültig bis</th><th>Erstellt</th><th>Aktionen</th></tr></thead>
    <tbody id="certificates">${certificates
      .map(
        (certificate) => `
      <tr>
        <td>${htmlEscape(certificate.domain)}</td>
        <td>${certificate.not_after ? new Date(certificate.not_after).toLocaleString() : '—'}</td>
        <td>${certificate.created_at ? new Date(certificate.created_at).toLocaleString() : '—'}</td>
        <td>${certificate.has_pem ? '<a href="/api/cert/download?id=' + certificate.id + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat</a> <a href="/api/cert/key?id=' + certificate.id + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Schlüssel</a>' : '—'}</td>
      </tr>
    `
      )
      .join('')}</tbody>
  </table>

  <script type="application/json" id="initialData">${initialDataJson}</script>
  <script>
    var initialData = { cas: [], intermediates: [], caConfigured: false };
    try { initialData = JSON.parse(document.getElementById('initialData').textContent); } catch (e) {}
    function updateCaCard(configured) {
      document.getElementById('caNotConfigured').style.display = configured ? 'none' : 'block';
      document.getElementById('caConfigured').style.display = configured ? 'block' : 'none';
      if (configured) document.getElementById('caDirectoryUrl').textContent = window.location.origin + '/acme/directory';
    }
    function updateCaList(casList) {
      const ul = document.getElementById('caListSetup');
      if (!ul) return;
      function attrEscape(s) { return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }
      ul.innerHTML = (casList || []).map(function(c) {
        var validUntil = c.notAfter ? new Date(c.notAfter).toLocaleString() : '\\u2014';
        return '<li>' + (c.isActive ? '<strong>' + c.name + '</strong> (aktiv)' : c.name) +
          ' \\u2013 Gültig bis ' + validUntil +
          ' \\u2013 <a href="/api/ca-cert?id=' + encodeURIComponent(c.id) + '" download>Zertifikat</a>' +
          (!c.isActive ? ' <button type="button" class="btn" style="padding:2px 6px;font-size:0.8rem" data-ca-id="' + attrEscape(c.id) + '">Aktivieren</button>' : '') + '</li>';
      }).join('');
    }
    function updateCasTable(casList) {
      const tbody = document.getElementById('cas');
      if (!tbody) return;
      function attrEscape(s) { return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }
      tbody.innerHTML = (casList || []).map(function(c) {
        var validUntil = c.notAfter ? new Date(c.notAfter).toLocaleString() : '\\u2014';
        return '<tr><td>' + c.name + '</td><td>' + c.commonName + '</td><td>' + (c.isActive ? '\\u2713' : '') + '</td><td>' + validUntil + '</td><td>' + (c.createdAt ? new Date(c.createdAt).toLocaleString() : '\\u2014') + '</td><td>' +
          (!c.isActive ? '<button type="button" class="btn" style="padding:4px 8px;font-size:0.85rem" data-ca-id="' + attrEscape(c.id) + '">Aktivieren</button> ' : '') +
          '<a href="/api/ca-cert?id=' + encodeURIComponent(c.id) + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat</a></td></tr>';
      }).join('');
    }
    document.body.addEventListener('click', function(e) {
      var btn = e.target.closest && e.target.closest('[data-ca-id]');
      if (btn) { e.preventDefault(); activateCa(btn.getAttribute('data-ca-id')); }
    });
    async function activateCa(id) {
      const res = await fetch('/api/ca/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id }) });
      if (!res.ok) { alert('Fehler: ' + ((await res.json().catch(function() { return {}; })).error || res.status)); return; }
      location.reload();
    }
    updateCaCard(initialData.caConfigured);
    updateCaList(initialData.cas || []);
    updateCasTable(initialData.cas || []);
    function updateIntermediatesTable(list) {
      var tbody = document.getElementById('intermediates');
      if (!tbody) return;
      list = list || [];
      tbody.innerHTML = list.map(function(c) {
        var validUntil = c.notAfter ? new Date(c.notAfter).toLocaleString() : '\\u2014';
        var created = c.createdAt ? new Date(c.createdAt).toLocaleString() : '\\u2014';
        return '<tr><td>' + (c.name || '') + '</td><td>' + (c.commonName || '') + '</td><td>' + (c.parentCaId || '') + '</td><td>' + validUntil + '</td><td>' + created + '</td><td><a href="/api/ca-cert?id=' + encodeURIComponent(c.id) + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat</a></td></tr>';
      }).join('');
    }
    updateIntermediatesTable(initialData.intermediates || []);
    function openIntermediateModal() {
      var sel = document.getElementById('intermediateParentSelect');
      if (!sel) return;
      sel.innerHTML = '<option value="">– Bitte wählen –</option>';
      (initialData.cas || []).forEach(function(c) {
        var opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = c.name + (c.commonName && c.commonName !== c.name ? ' (' + c.commonName + ')' : '');
        sel.appendChild(opt);
      });
      document.getElementById('intermediateModal').classList.add('open');
    }
    async function submitIntermediateSetup(ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      var btn = document.getElementById('intermediateSubmitBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Wird erstellt…'; }
      var form = document.getElementById('intermediateSetupForm');
      var body = {
        parentCaId: getFormVal(form, 'parentCaId') || undefined,
        name: getFormVal(form, 'name') || getFormVal(form, 'commonName') || '${escapeForScript(DEFAULT_COMMON_NAME_INTERMEDIATE)}',
        commonName: getFormVal(form, 'commonName') || '${escapeForScript(DEFAULT_COMMON_NAME_INTERMEDIATE)}',
        organization: getFormVal(form, 'organization') || undefined,
        organizationalUnit: getFormVal(form, 'organizationalUnit') || undefined,
        country: getFormVal(form, 'country') || undefined,
        locality: getFormVal(form, 'locality') || undefined,
        stateOrProvince: getFormVal(form, 'stateOrProvince') || undefined,
        email: getFormVal(form, 'email') || undefined,
        validityYears: parseInt(getFormVal(form, 'validityYears') || '10', 10) || 10,
        keySize: parseInt(getFormVal(form, 'keySize') || '2048', 10) || 2048,
        hashAlgo: getFormVal(form, 'hashAlgo') || 'sha256',
      };
      try {
        var res = await fetch('/api/ca/intermediate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await res.json().catch(function() { return {}; });
        if (!res.ok) {
          if (btn) { btn.disabled = false; btn.textContent = 'Intermediate-CA erstellen'; }
          alert('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        document.getElementById('intermediateModal').classList.remove('open');
        location.reload();
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Intermediate-CA erstellen'; }
        alert('Fehler: ' + (e && e.message ? e.message : String(e)));
      }
      return false;
    }
    function openCertCreateModal() {
      var sel = document.getElementById('certCreateCaSelect');
      if (!sel) return;
      sel.innerHTML = '<option value="">– Bitte wählen –</option>';
      var casList = initialData.cas || [];
      casList.forEach(function(c) {
        var opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = c.name + (c.commonName && c.commonName !== c.name ? ' (' + c.commonName + ')' : '');
        sel.appendChild(opt);
      });
      var intList = initialData.intermediates || [];
      intList.forEach(function(c) {
        var opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = (c.name || c.id) + ' (Intermediate)';
        sel.appendChild(opt);
      });
      if (casList.length === 0 && intList.length === 0) {
        var opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'Keine CA eingerichtet';
        opt.disabled = true;
        sel.appendChild(opt);
      }
      document.getElementById('certCreateSuccess').style.display = 'none';
      document.getElementById('certCreateModal').classList.add('open');
    }
    async function submitCertCreate(ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      var form = document.getElementById('certCreateForm');
      var issuerId = (form && form.elements.issuerId && form.elements.issuerId.value) ? form.elements.issuerId.value.trim() : '';
      var domain = (form && form.elements.domain && form.elements.domain.value) ? form.elements.domain.value.trim().toLowerCase() : '';
      if (!issuerId || !domain) { alert('Bitte CA und Domain angeben.'); return false; }
      var sanRaw = (form && form.elements.sanDomains && form.elements.sanDomains.value) ? form.elements.sanDomains.value : '';
      var sanDomains = sanRaw.split(/[,\\s]+/).map(function(s) { return s.trim().toLowerCase(); }).filter(Boolean);
      var validityDays = parseInt((form && form.elements.validityDays && form.elements.validityDays.value) || '365', 10) || 365;
      var keySize = parseInt((form && form.elements.keySize && form.elements.keySize.value) || '2048', 10) || 2048;
      var hashAlgo = (form && form.elements.hashAlgo && form.elements.hashAlgo.value) || 'sha256';
      var btn = document.getElementById('certCreateSubmitBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Wird erstellt…'; }
      try {
        var res = await fetch('/api/cert/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ issuerId: issuerId, domain: domain, sanDomains: sanDomains, validityDays: validityDays, keySize: keySize, hashAlgo: hashAlgo })
        });
        var data = await res.json().catch(function() { return {}; });
        if (!res.ok) {
          if (btn) { btn.disabled = false; btn.textContent = 'Zertifikat erstellen'; }
          alert('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        var certId = data.id;
        document.getElementById('certCreateSuccess').style.display = 'block';
        document.getElementById('certCreateDownloadCert').href = '/api/cert/download?id=' + certId;
        document.getElementById('certCreateDownloadKey').href = '/api/cert/key?id=' + certId;
        if (btn) { btn.disabled = false; btn.textContent = 'Zertifikat erstellen'; }
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Zertifikat erstellen'; }
        alert('Fehler: ' + (e && e.message ? e.message : String(e)));
      }
      return false;
    }
    function getFormVal(form, name) {
      const el = form.elements[name] || form.querySelector('[name="' + name + '"]');
      return el ? (el.value || '').trim() : '';
    }
    async function submitCaSetup(ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      var btn = document.getElementById('caSubmitBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Wird erstellt…'; }
      var form = document.getElementById('caSetupForm');
      var body = {
        name: getFormVal(form, 'name') || getFormVal(form, 'commonName') || '${escapeForScript(DEFAULT_COMMON_NAME_ROOT)}',
        commonName: getFormVal(form, 'commonName') || '${escapeForScript(DEFAULT_COMMON_NAME_ROOT)}',
        organization: getFormVal(form, 'organization') || undefined,
        organizationalUnit: getFormVal(form, 'organizationalUnit') || undefined,
        country: getFormVal(form, 'country') || undefined,
        locality: getFormVal(form, 'locality') || undefined,
        stateOrProvince: getFormVal(form, 'stateOrProvince') || undefined,
        email: getFormVal(form, 'email') || undefined,
        validityYears: parseInt(getFormVal(form, 'validityYears') || '10', 10) || 10,
        keySize: parseInt(getFormVal(form, 'keySize') || '2048', 10) || 2048,
        hashAlgo: getFormVal(form, 'hashAlgo') || 'sha256',
      };
      try {
        var res = await fetch('/api/ca/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await res.json().catch(function() { return {}; });
        if (!res.ok) {
          if (btn) { btn.disabled = false; btn.textContent = 'CA erstellen'; }
          alert('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        document.getElementById('caModal').classList.remove('open');
        updateCaCard(true);
        location.reload();
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'CA erstellen'; }
        alert('Fehler: ' + (e && e.message ? e.message : String(e)));
      }
      return false;
    }
    const es = new EventSource('/api/events');
    es.onmessage = (e) => {
      const d = JSON.parse(e.data);
      const s = d.summary;
      document.getElementById('certsTotal').textContent = s.certsTotal;
      document.getElementById('certsValid').textContent = s.certsValid;
      document.getElementById('timeUtc').textContent = s.timeUtc;
      document.getElementById('timeLocal').textContent = s.timeLocal;
      document.getElementById('letsEncryptEmail').textContent = s.letsEncrypt ? s.letsEncrypt.email : '—';
      const urlEl = document.getElementById('letsEncryptUrl');
      const labelEl = document.getElementById('accountUrlLabel');
      if (s.letsEncrypt && s.letsEncrypt.accountUrl) {
        urlEl.textContent = s.letsEncrypt.accountUrl;
        labelEl.style.display = 'block';
      } else {
        urlEl.textContent = '';
        labelEl.style.display = 'none';
      }
      if (s.caConfigured !== undefined) updateCaCard(s.caConfigured);
      if (d.cas) { initialData.cas = d.cas; updateCaList(d.cas); updateCasTable(d.cas); }
      if (d.intermediates) { initialData.intermediates = d.intermediates; updateIntermediatesTable(d.intermediates); }
      document.getElementById('challenges').innerHTML = d.challenges.map(function(c) { return '<tr><td><code>' + c.token + '</code></td><td>' + c.domain + '</td><td>' + (c.expires_at ? new Date(c.expires_at).toLocaleString() : '-') + '</td></tr>'; }).join('');
      document.getElementById('certificates').innerHTML = d.certificates.map(function(c) {
        var actions = c.has_pem ? '<a href="/api/cert/download?id=' + c.id + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat</a> <a href="/api/cert/key?id=' + c.id + '" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Schlüssel</a>' : '—';
        return '<tr><td>' + (c.domain || '') + '</td><td>' + (c.not_after ? new Date(c.not_after).toLocaleString() : '—') + '</td><td>' + (c.created_at ? new Date(c.created_at).toLocaleString() : '—') + '</td><td>' + actions + '</td></tr>';
      }).join('');
    };
  </script>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}
