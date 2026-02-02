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
function getIssuerDisplayName(
  issuerId: string | null,
  cas: Array<{ id: string; name: string }>,
  intermediates: Array<{ id: string; name: string }>
): string {
  if (!issuerId) return '—';
  const rootCa = cas.find((c) => c.id === issuerId);
  if (rootCa) return rootCa.name;
  const intermediate = intermediates.find((i) => i.id === issuerId);
  if (intermediate) return intermediate.name + ' (Intermediate CA)';
  return issuerId;
}

type CertForTree = {
  id: number;
  domain: string;
  not_after: string | null;
  created_at: string | null;
  has_pem: number;
  issuer_id: string | null;
  revoked?: number;
};

function renderCertTree(
  certificates: CertForTree[],
  cas: Array<{ id: string; name: string; commonName: string; notAfter: string | null; createdAt: string | null; isActive: boolean }>,
  intermediates: Array<{ id: string; parentCaId: string; name: string; commonName: string; notAfter: string | null; createdAt: string | null }>,
  htmlEscapeFn: (s: string) => string,
  attrEscapeFn: (s: string) => string
): string {
  const certRow = (cert: CertForTree, depth: number) => {
    const validUntil = cert.not_after ? new Date(cert.not_after).toLocaleString() : '—';
    const createdAt = cert.created_at ? new Date(cert.created_at).toLocaleString() : '—';
    const issuerName = getIssuerDisplayName(cert.issuer_id, cas, intermediates);
    const isRevoked = cert.revoked !== undefined && cert.revoked !== 0;
    const metaText = isRevoked ? 'Widerrufen · Gültig bis ' + validUntil : 'Gültig bis ' + validUntil;
    const revokeBtn = isRevoked ? '' : '<button type="button" class="btn btn-revoke" data-cert-id="' + cert.id + '" title="Zertifikat widerrufen">Widerrufen</button> ';
    const actions =
      '<button type="button" class="btn btn-view-cert" data-cert-id="' + cert.id + '" data-cert-domain="' + attrEscapeFn(cert.domain) + '" data-cert-not-after="' + attrEscapeFn(validUntil) + '" data-cert-created-at="' + attrEscapeFn(createdAt) + '" data-cert-issuer="' + attrEscapeFn(issuerName) + '" title="Details anzeigen">View</button> ' +
      (cert.has_pem
        ? '<a href="/api/cert/download?id=' + cert.id + '" class="btn" download>Zertifikat</a> <a href="/api/cert/key?id=' + cert.id + '" class="btn" download>Schlüssel</a> '
        : '') +
      revokeBtn +
      '<button type="button" class="btn btn-delete" data-cert-id="' + cert.id + '" title="Zertifikat löschen">Löschen</button>';
    return (
      '<li class="cert-tree__item cert-tree__item--depth-' +
      depth +
      (isRevoked ? ' cert-tree__item--revoked' : '') +
      '"><span class="cert-tree__label">' +
      htmlEscapeFn(cert.domain) +
      '</span><span class="cert-tree__meta">' +
      metaText +
      '</span><span class="cert-tree__actions">' +
      actions +
      '</span></li>'
    );
  };

  const togglerRow = (
    depth: number,
    label: string,
    meta: string,
    actions: string
  ) =>
    '<div class="cert-tree__item cert-tree__item--depth-' +
    depth +
    ' cert-tree__toggler" role="button" tabindex="0" aria-expanded="true">' +
    '<span class="cert-tree__toggle" aria-hidden="true">▼</span>' +
    '<span class="cert-tree__label">' +
    label +
    '</span><span class="cert-tree__meta">' +
    meta +
    '</span>' +
    '<span class="cert-tree__actions">' +
    actions +
    '</span></div>';

  const parts: string[] = [];

  for (const root of cas) {
    const rootValidUntil = root.notAfter ? new Date(root.notAfter).toLocaleString() : '—';
    const rootActions =
      '<button type="button" class="btn btn-view-cert btn-view-ca" data-ca-id="' + attrEscapeFn(root.id) + '" data-ca-type="root" title="Details anzeigen">View</button> ' +
      (!root.isActive
        ? '<button type="button" class="btn" data-ca-id="' + attrEscapeFn(root.id) + '">Aktivieren</button> '
        : '') +
      ' <a href="/api/ca-cert?id=' +
      encodeURIComponent(root.id) +
      '" class="btn" download>Zertifikat</a> <button type="button" class="btn btn-delete btn-delete-ca" data-ca-id="' +
      attrEscapeFn(root.id) +
      '" data-ca-type="root" title="Root-CA löschen">Löschen</button>';
    const underRoot = intermediates.filter((i) => i.parentCaId === root.id);
    const certsUnderRoot = certificates.filter((c) => c.issuer_id === root.id);
    const hasChildren = underRoot.length > 0 || certsUnderRoot.length > 0;

    const childrenParts: string[] = [];
    for (const int of underRoot) {
      const intValidUntil = int.notAfter ? new Date(int.notAfter).toLocaleString() : '—';
      const intActions =
        '<button type="button" class="btn btn-view-cert btn-view-ca" data-ca-id="' + attrEscapeFn(int.id) + '" data-ca-type="intermediate" title="Details anzeigen">View</button> ' +
        '<a href="/api/ca-cert?id=' +
        encodeURIComponent(int.id) +
        '" class="btn" download>Zertifikat</a> <button type="button" class="btn btn-delete btn-delete-ca" data-ca-id="' +
        attrEscapeFn(int.id) +
        '" data-ca-type="intermediate" title="Intermediate-CA löschen">Löschen</button>';
      const certsUnderInt = certificates.filter((c) => c.issuer_id === int.id);
      const intChildren = certsUnderInt.map((c) => certRow(c, 2)).join('');
      childrenParts.push(
        '<li class="cert-tree__branch" data-branch-id="int-' +
          attrEscapeFn(int.id) +
          '">' +
          togglerRow(
            1,
            htmlEscapeFn(int.name) + ' <span class="cert-tree__meta">(Intermediate CA)</span>',
            'Gültig bis ' + intValidUntil,
            intActions
          ) +
          '<ul class="cert-tree__children">' +
          intChildren +
          '</ul></li>'
      );
    }
    for (const cert of certsUnderRoot) {
      childrenParts.push(certRow(cert, 1));
    }

    parts.push(
      '<li class="cert-tree__branch" data-branch-id="' +
        attrEscapeFn(root.id) +
        '">' +
        togglerRow(
          0,
          htmlEscapeFn(root.name) + ' <span class="cert-tree__meta">(Root-CA)</span>',
          (root.isActive ? 'Aktiv · ' : '') + 'Gültig bis ' + rootValidUntil,
          rootActions
        ) +
        '<ul class="cert-tree__children">' +
        childrenParts.join('') +
        '</ul></li>'
    );
  }

  const certsWithoutIssuer = certificates.filter((c) => !c.issuer_id);
  if (certsWithoutIssuer.length > 0) {
    const noCaChildren = certsWithoutIssuer.map((c) => certRow(c, 1)).join('');
    parts.push(
      '<li class="cert-tree__branch" data-branch-id="no-ca">' +
        togglerRow(0, 'Ohne CA', '(ältere Einträge)', '') +
        '<ul class="cert-tree__children">' +
        noCaChildren +
        '</ul></li>'
    );
  }

  if (parts.length === 0) {
    return '<li class="cert-tree__item cert-tree__item--depth-0"><span class="cert-tree__label empty-table">Keine CAs oder Zertifikate</span></li>';
  }
  return parts.join('');
}

export function renderDashboard(database: Database, paths: PathHelpers): Response {
  const { summary, challenges, acmeChallenges, acmeValidationStatus, certificates, cas, intermediates } = getSummaryData(database, paths);
  const initialData = { cas, intermediates, caConfigured: summary.caConfigured };
  const initialDataJson = escapeForScript(JSON.stringify(initialData));

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dashboard</title>
  <style>
    :root {
      --gh-canvas: #ffffff;
      --gh-canvas-subtle: #f6f8fa;
      --gh-border: #d0d7de;
      --gh-accent: #0969da;
      --gh-accent-hover: #0550ae;
      --gh-danger: #cf222e;
      --gh-danger-hover: #a40e26;
      --gh-fg: #1f2328;
      --gh-fg-muted: #656d76;
      --gh-btn-hover: #eaeef2;
      --gh-modal-overlay: rgba(31,35,40,0.5);
      --gh-modal-shadow: 0 8px 24px rgba(31,35,40,0.12);
    }
    html[data-theme="dark"] {
      --gh-canvas: #0d1117;
      --gh-canvas-subtle: #161b22;
      --gh-border: #30363d;
      --gh-accent: #58a6ff;
      --gh-accent-hover: #79b8ff;
      --gh-danger: #f85149;
      --gh-danger-hover: #ff7b72;
      --gh-fg: #c9d1d9;
      --gh-fg-muted: #8b949e;
      --gh-btn-hover: #30363d;
      --gh-modal-overlay: rgba(0,0,0,0.6);
      --gh-modal-shadow: 0 8px 24px rgba(0,0,0,0.4);
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      color: var(--gh-fg);
      background: var(--gh-canvas);
      margin: 0;
      padding: 0;
    }
    .gh-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      background: var(--gh-canvas-subtle);
      border-bottom: 1px solid var(--gh-border);
      padding: 16px 24px;
      margin-bottom: 0;
    }
    .gh-header h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 600;
    }
    .theme-toggle {
      padding: 6px 12px;
      font-size: 18px;
      line-height: 1;
    }
    main {
      max-width: 1340px;
      margin: 0 auto;
      padding: 24px;
    }
    .gh-card {
      background: var(--gh-canvas);
      border: 1px solid var(--gh-border);
      border-radius: 6px;
      overflow: hidden;
      margin-bottom: 24px;
    }
    .gh-card-header {
      padding: 16px;
      background: var(--gh-canvas-subtle);
      border-bottom: 1px solid var(--gh-border);
      font-size: 14px;
      font-weight: 600;
    }
    .gh-card-body { padding: 16px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .summary-item {
      background: var(--gh-canvas);
      border: 1px solid var(--gh-border);
      border-radius: 6px;
      padding: 16px;
    }
    .summary-item dt { font-size: 12px; color: var(--gh-fg-muted); margin-bottom: 4px; font-weight: 400; }
    .summary-item dd { margin: 0; font-weight: 600; font-size: 18px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 16px; text-align: left; border-bottom: 1px solid var(--gh-border); }
    th { background: var(--gh-canvas-subtle); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.02em; color: var(--gh-fg-muted); }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr:hover td { background: var(--gh-canvas-subtle); }
    .setup { margin-top: 0; }
    .setup h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; }
    .setup-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
    .setup-card {
      background: var(--gh-canvas);
      border: 1px solid var(--gh-border);
      border-radius: 6px;
      padding: 20px;
    }
    .setup-card h3 { margin: 0 0 12px; font-size: 14px; font-weight: 600; }
    .setup-card p { margin: 0 0 16px; font-size: 13px; color: var(--gh-fg-muted); }
    .btn, a.btn {
      display: inline-block;
      padding: 5px 16px;
      font-size: 14px;
      font-weight: 500;
      line-height: 20px;
      border-radius: 6px;
      border: 1px solid var(--gh-border);
      background: var(--gh-canvas-subtle);
      color: var(--gh-fg);
      cursor: pointer;
      text-decoration: none;
      font-family: inherit;
    }
    .btn:hover, a.btn:hover { background: var(--gh-btn-hover); border-color: var(--gh-border); }
    .btn-primary, a.btn-primary { background: var(--gh-accent); color: #fff; border-color: var(--gh-accent); }
    .btn-primary:hover, a.btn-primary:hover { background: var(--gh-accent-hover); border-color: var(--gh-accent-hover); }
    .setup-card .btn, .modal-actions .btn:not(.btn-secondary):not(.btn-delete) { background: var(--gh-accent); color: #fff; border-color: var(--gh-accent); }
    .setup-card .btn:hover, .modal-actions .btn:not(.btn-secondary):not(.btn-delete):hover { background: var(--gh-accent-hover); border-color: var(--gh-accent-hover); }
    .modal-overlay { display: none; position: fixed; inset: 0; background: var(--gh-modal-overlay); z-index: 100; align-items: center; justify-content: center; }
    .modal-overlay.open { display: flex; }
    .modal { background: var(--gh-canvas); padding: 24px; border-radius: 6px; max-width: 420px; width: 90%; border: 1px solid var(--gh-border); box-shadow: var(--gh-modal-shadow); }
    .modal h3 { margin: 0 0 16px; font-size: 16px; font-weight: 600; }
    .modal label { display: block; margin-bottom: 4px; font-size: 14px; font-weight: 500; }
    .modal input, .modal select { width: 100%; padding: 5px 12px; margin-bottom: 12px; font-size: 14px; border: 1px solid var(--gh-border); border-radius: 6px; font-family: inherit; background: var(--gh-canvas); color: var(--gh-fg); }
    .modal-actions { margin-top: 20px; display: flex; gap: 8px; justify-content: flex-end; }
    .modal-actions .btn-secondary { background: var(--gh-canvas-subtle); }
    .modal-actions .btn-secondary:hover { background: var(--gh-btn-hover); }
    .btn:focus-visible, a.btn:focus-visible { outline: 2px solid var(--gh-accent); outline-offset: 2px; }
    .empty-table { color: var(--gh-fg-muted); font-style: italic; padding: 16px; text-align: center; }
    .directory-url-wrap { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px; }
    .directory-url-wrap code { flex: 1; word-break: break-all; font-size: 12px; background: var(--gh-canvas-subtle); padding: 4px 8px; border-radius: 4px; border: 1px solid var(--gh-border); }
    .btn-copy { flex-shrink: 0; padding: 5px 12px; font-size: 12px; }
    #toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: var(--gh-danger); color: #fff; padding: 12px 20px; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); z-index: 200; display: none; max-width: 90%; cursor: pointer; font-size: 14px; }
    #toast.show { display: block; }
    .cert-tree { list-style: none; padding-left: 0; margin: 0; border: 1px solid var(--gh-border); border-radius: 6px; overflow: hidden; }
    .cert-tree__item { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; padding: 8px 16px; border-bottom: 1px solid var(--gh-border); background: var(--gh-canvas); }
    .cert-tree__item:last-child { border-bottom: none; }
    .cert-tree__item--depth-0 { padding-left: 16px; font-weight: 600; background: var(--gh-canvas-subtle); }
    .cert-tree__item--depth-1 { padding-left: 28px; border-left: 3px solid var(--gh-accent); }
    .cert-tree__item--depth-2 { padding-left: 44px; border-left: 3px solid var(--gh-fg-muted); font-size: 13px; }
    .cert-tree__item--depth-3 { padding-left: 60px; border-left: 3px solid var(--gh-border); font-size: 13px; }
    .cert-tree__label { flex: 1 1 auto; min-width: 0; }
    .cert-tree__meta { color: var(--gh-fg-muted); font-size: 12px; font-weight: normal; }
    .cert-tree__actions { flex-shrink: 0; }
    .cert-tree__actions .btn { padding: 2px 8px; font-size: 12px; }
    .cert-tree__branch { list-style: none; padding-left: 0; margin: 0; }
    .cert-tree__branch > .cert-tree__children { list-style: none; padding-left: 0; margin: 0; }
    .cert-tree__branch--collapsed > .cert-tree__children { display: none; }
    .cert-tree__toggler { cursor: pointer; }
    .cert-tree__toggler:hover { background: var(--gh-canvas-subtle) !important; }
    .cert-tree__toggle { display: inline-block; width: 1em; text-align: center; }
    .btn-delete { background: var(--gh-danger); color: #fff; border-color: var(--gh-danger); }
    .btn-delete:hover { background: var(--gh-danger-hover); border-color: var(--gh-danger-hover); }
    .btn-revoke { background: var(--gh-fg-muted); color: #fff; border-color: var(--gh-fg-muted); }
    .btn-revoke:hover { background: var(--gh-fg); border-color: var(--gh-fg); }
    .cert-tree__item--revoked .cert-tree__meta { text-decoration: line-through; color: var(--gh-danger); }
    .btn-view-cert, .btn-view-ca { background: var(--gh-accent); color: #fff; border-color: var(--gh-accent); }
    .btn-view-cert:hover, .btn-view-ca:hover { background: var(--gh-accent-hover); border-color: var(--gh-accent-hover); }
    code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; background: var(--gh-canvas-subtle); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--gh-border); }
    h2 { font-size: 16px; font-weight: 600; margin: 24px 0 12px; }
    h2:first-of-type { margin-top: 0; }
    .acme-validation-cell { vertical-align: middle; min-width: 220px; }
    .acme-validation-progress { display: inline-flex; align-items: center; gap: 10px; }
    .acme-validation-circle-wrap { position: relative; width: 40px; height: 40px; flex-shrink: 0; }
    .acme-validation-circle { width: 40px; height: 40px; transform: rotate(-90deg); }
    .acme-validation-ring-bg { fill: none; stroke: var(--gh-border); stroke-width: 3; stroke-dasharray: 100 100; }
    .acme-validation-ring-fill { fill: none; stroke: var(--gh-accent); stroke-width: 3; stroke-dasharray: 100 100; transition: stroke-dashoffset 0.3s ease; }
    .acme-validation-text { font-weight: 600; font-size: 12px; min-width: 24px; }
    .acme-validation-countdown { font-variant-numeric: tabular-nums; }
    .acme-validation-hint { font-size: 12px; color: var(--gh-fg-muted); margin-left: 4px; }
    .acme-validation-waiting { flex-wrap: wrap; }
  </style>
</head>
<body>
  <div id="toast" role="alert" aria-live="assertive"></div>
  <header class="gh-header">
    <button type="button" id="themeToggle" class="btn theme-toggle" title="Dark/Light umschalten" aria-label="Theme umschalten">
      <span class="theme-toggle-icon theme-icon-light" aria-hidden="true">☀</span>
      <span class="theme-toggle-icon theme-icon-dark" aria-hidden="true" style="display:none">☽</span>
    </button>
  </header>
  <main>
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

  <div class="gh-card">
    <div class="gh-card-header">Setup</div>
    <div class="gh-card-body">
  <div class="setup-grid">
      <div class="setup-card">
        <h3>Eigene CA</h3>
        <div id="caNotConfigured">
          <p>Root-CA per Knopfdruck einrichten. Danach können ACME-Clients (z. B. Reverse-Proxys) Zertifikate von dieser CA anfordern.</p>
          <button type="button" class="btn" onclick="document.getElementById('caModal').classList.add('open')">CA erstellen</button>
        </div>
        <div id="caConfigured" style="display:none">
          <p>In deinem Reverse-Proxy oder ACME-Client die <strong>Directory-URL</strong> eintragen und das <strong>CA-Zertifikat</strong> als vertrauenswürdige CA hinterlegen – dann können Zertifikate von dieser CA angefordert werden.</p>
          <p style="margin-bottom:8px"><strong>Directory-URL:</strong></p>
          <div class="directory-url-wrap">
            <code id="caDirectoryUrl"></code>
            <button type="button" class="btn btn-copy" id="copyDirectoryUrlBtn" aria-label="URL kopieren">Kopieren</button>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">
            <button type="button" class="btn" onclick="document.getElementById('caModal').classList.add('open')">CA hinzufügen</button>
            <button type="button" class="btn" onclick="openIntermediateModal()">Intermediate-CA erstellen</button>
          </div>
        </div>
      </div>
      <div class="setup-card">
        <h3>Zertifikate erstellen</h3>
        <p style="margin-bottom:12px">Domain-Zertifikat über die eingerichtete CA ausstellen.</p>
        <button type="button" class="btn" onclick="openCertCreateModal()">Zertifikat erstellen</button>
      </div>
    </div>
    </div>
  </div>

  <div id="caModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="caModalTitle" onclick="if(event.target===this) closeModal('caModal')">
    <div class="modal" onclick="event.stopPropagation()">
      <h3 id="caModalTitle">Root-CA erstellen</h3>
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
          <button type="button" class="btn btn-secondary" onclick="closeModal('caModal')">Abbrechen</button>
          <button type="submit" class="btn" id="caSubmitBtn">CA erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="intermediateModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="intermediateModalTitle" onclick="if(event.target===this) closeModal('intermediateModal')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:420px">
      <h3 id="intermediateModalTitle">Intermediate-CA erstellen</h3>
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
          <button type="button" class="btn btn-secondary" onclick="closeModal('intermediateModal')">Abbrechen</button>
          <button type="submit" class="btn" id="intermediateSubmitBtn">Intermediate-CA erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="certViewModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="certViewModalTitle" onclick="if(event.target===this) closeModal('certViewModal')">
    <div class="modal cert-view-modal" onclick="event.stopPropagation()" style="max-width:560px">
      <h3 id="certViewModalTitle">Zertifikat-Details</h3>
      <dl id="certViewDl" style="display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0 0 16px;font-size:14px">
        <dt class="cert-view-cert-only" style="color:var(--gh-fg-muted);margin:0">Domain</dt>
        <dd class="cert-view-cert-only" style="margin:0" id="certViewDomain">—</dd>
        <dt class="cert-view-ca-only" style="color:var(--gh-fg-muted);margin:0;display:none">Typ</dt>
        <dd class="cert-view-ca-only" style="margin:0;display:none" id="certViewType">—</dd>
        <dt class="cert-view-ca-only" style="color:var(--gh-fg-muted);margin:0;display:none">Name</dt>
        <dd class="cert-view-ca-only" style="margin:0;display:none" id="certViewName">—</dd>
        <dt class="cert-view-ca-only" style="color:var(--gh-fg-muted);margin:0;display:none">Common Name</dt>
        <dd class="cert-view-ca-only" style="margin:0;display:none" id="certViewCommonName">—</dd>
        <dt class="cert-view-ca-only cert-view-int-only" style="color:var(--gh-fg-muted);margin:0;display:none">Übergeordnete CA</dt>
        <dd class="cert-view-ca-only cert-view-int-only" style="margin:0;display:none" id="certViewParentCa">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Subject</dt>
        <dd style="margin:0" id="certViewSubject">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Issuer</dt>
        <dd style="margin:0" id="certViewIssuer">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Seriennummer</dt>
        <dd style="margin:0" id="certViewSerial">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Gültig von</dt>
        <dd style="margin:0" id="certViewNotBefore">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Gültig bis</dt>
        <dd style="margin:0" id="certViewNotAfter">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Fingerprint (SHA-256)</dt>
        <dd style="margin:0" id="certViewFingerprint">—</dd>
        <dt class="cert-view-cert-only" style="color:var(--gh-fg-muted);margin:0">Subject Alt Names</dt>
        <dd class="cert-view-cert-only" style="margin:0" id="certViewSan">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Erstellt am</dt>
        <dd style="margin:0" id="certViewCreatedAt">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">ID</dt>
        <dd style="margin:0" id="certViewId">—</dd>
      </dl>
      <p style="margin:0 0 6px;font-size:13px;color:var(--gh-fg-muted)">Zertifikat (PEM)</p>
      <pre id="certViewPem" style="margin:0;padding:12px;background:var(--gh-canvas-subtle);border:1px solid var(--gh-border);border-radius:6px;font-size:11px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all">—</pre>
      <div id="certViewDownloads" style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap"></div>
      <div class="modal-actions" style="margin-top:16px">
        <button type="button" class="btn btn-secondary" onclick="closeModal('certViewModal')">Schließen</button>
      </div>
    </div>
  </div>

  <div id="certCreateModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="certCreateModalTitle" onclick="if(event.target===this) closeModal('certCreateModal')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:420px">
      <h3 id="certCreateModalTitle">Zertifikat erstellen</h3>
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
          <button type="button" class="btn btn-secondary" onclick="closeModal('certCreateModal')">Abbrechen</button>
          <button type="submit" class="btn" id="certCreateSubmitBtn">Zertifikat erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <div class="gh-card">
    <div class="gh-card-header">Challenges</div>
    <div class="gh-card-body">
  <table>
    <thead><tr><th>Token</th><th>Domain</th><th>Läuft ab</th><th></th></tr></thead>
    <tbody id="challenges">${challenges.length === 0
      ? '<tr><td colspan="4" class="empty-table">Keine Einträge</td></tr>'
      : challenges
          .map(
            (challenge) => `
      <tr>
        <td><code>${htmlEscape(challenge.token)}</code></td>
        <td>${htmlEscape(challenge.domain)}</td>
        <td>${challenge.expires_at ? new Date(challenge.expires_at).toLocaleString() : '-'}</td>
        <td><button type="button" class="btn btn-delete btn-delete-challenge" data-challenge-id="${challenge.id}" title="Challenge löschen">Löschen</button></td>
      </tr>
    `
          )
          .join('')}</tbody>
  </table>
    </div>
  </div>

  <div class="gh-card">
    <div class="gh-card-header">ACME-Challenges (Certbot / Bestellungen)</div>
    <div class="gh-card-body">
  <p style="margin:0 0 12px;font-size:13px;color:var(--gh-fg-muted)">Offene Challenges aus ACME-Bestellungen. Der Server liefert die Validierung unter <code>/.well-known/acme-challenge/&lt;Token&gt;</code>.</p>
  <table>
    <thead><tr><th>Domain</th><th>Token</th><th>Status</th><th>Validierung</th><th></th></tr></thead>
    <tbody id="acmeChallenges">${acmeChallenges.length === 0
      ? '<tr><td colspan="5" class="empty-table">Keine offenen ACME-Challenges</td></tr>'
      : acmeChallenges
          .map((ac) => {
            const val = acmeValidationStatus.find((s) => s.challengeId === ac.challengeId);
            const validationCell = val
              ? (() => {
                  const secs = Math.max(0, Math.ceil((val.nextAttemptAt - Date.now()) / 1000));
                  const ringOffset = 100 * (1 - Math.min(5, secs) / 5);
                  return `<span class="acme-validation-progress" data-next-at="${val.nextAttemptAt}">
  <span class="acme-validation-circle-wrap"><svg class="acme-validation-circle" viewBox="0 0 36 36" aria-hidden="true"><circle class="acme-validation-ring-bg" cx="18" cy="18" r="16"/><circle class="acme-validation-ring-fill" cx="18" cy="18" r="16" style="stroke-dashoffset:${ringOffset}"/></svg></span>
  <span class="acme-validation-text">Versuch ${val.attemptCount}/${val.maxAttempts}</span>
  <span>nächster in <span class="acme-validation-countdown" data-next-at="${val.nextAttemptAt}">${secs}</span> s</span>
</span>`;
                })()
              : ac.status === 'pending'
                ? '<span class="acme-validation-progress acme-validation-waiting"><span class="acme-validation-text">Versuch —/5</span><span class="acme-validation-hint">Warte auf Auslösung (Certbot: Enter)</span></span>'
                : '—';
            return `
      <tr data-authz-id="${attrEscape(ac.authzId)}" data-challenge-id="${attrEscape(ac.challengeId)}">
        <td>${htmlEscape(ac.domain)}</td>
        <td><code>${htmlEscape(ac.token)}</code></td>
        <td>${htmlEscape(ac.status)}</td>
        <td class="acme-validation-cell">${validationCell}</td>
        <td><button type="button" class="btn btn-accept-acme btn-accept-acme-authz" data-authz-id="${attrEscape(ac.authzId)}" title="Challenge manuell als gültig markieren">Manuell annehmen</button> <button type="button" class="btn btn-delete btn-delete-acme-authz" data-authz-id="${attrEscape(ac.authzId)}" title="ACME-Challenge löschen">Löschen</button></td>
      </tr>
    `;
          })
          .join('')}</tbody>
  </table>
    </div>
  </div>

  <div class="gh-card">
    <div class="gh-card-header">Zertifikate</div>
    <div class="gh-card-body">
  <p style="margin:0 0 12px;font-size:13px;color:var(--gh-fg-muted)">Hierarchie wie in XCA: Root-CAs, darunter Intermediate-CAs und ausgestellte Zertifikate.</p>
  <ul id="certTree" class="cert-tree">${renderCertTree(certificates, cas, intermediates, htmlEscape, attrEscape)}</ul>
    </div>
  </div>

  </main>
  <script type="application/json" id="initialData">${initialDataJson}</script>
  <script>
    var initialData = { cas: [], intermediates: [], caConfigured: false };
    try { initialData = JSON.parse(document.getElementById('initialData').textContent); } catch (e) {}
    (function themeInit() {
      var stored = localStorage.getItem('theme');
      var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      var theme = stored === 'dark' || stored === 'light' ? stored : (prefersDark ? 'dark' : 'light');
      document.documentElement.setAttribute('data-theme', theme);
      function updateThemeIcons() {
        var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        var lightIcon = document.querySelector('.theme-icon-light');
        var darkIcon = document.querySelector('.theme-icon-dark');
        if (lightIcon) lightIcon.style.display = isDark ? '' : 'none';
        if (darkIcon) darkIcon.style.display = isDark ? 'none' : '';
      }
      updateThemeIcons();
      var toggle = document.getElementById('themeToggle');
      if (toggle) toggle.addEventListener('click', function() {
        var el = document.documentElement;
        var next = el.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        el.setAttribute('data-theme', next);
        try { localStorage.setItem('theme', next); } catch (e) {}
        updateThemeIcons();
      });
    })();
    function htmlEscapeClient(s) {
      if (s == null) return '';
      var str = String(s);
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function showError(msg) {
      var el = document.getElementById('toast');
      if (!el) return;
      el.textContent = msg;
      el.classList.add('show');
      clearTimeout(el._hideId);
      el._hideId = setTimeout(function() { el.classList.remove('show'); }, 5000);
    }
    document.getElementById('toast').addEventListener('click', function() { this.classList.remove('show'); });
    function closeModal(id) { var el = document.getElementById(id); if (el) el.classList.remove('open'); }
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        ['caModal', 'intermediateModal', 'certCreateModal', 'certViewModal'].forEach(closeModal);
      }
    });
    function copyDirectoryUrl() {
      var el = document.getElementById('caDirectoryUrl');
      if (!el || !el.textContent) return;
      navigator.clipboard.writeText(el.textContent).then(function() {
        var btn = document.getElementById('copyDirectoryUrlBtn');
        if (btn) { var t = btn.textContent; btn.textContent = 'Kopiert!'; setTimeout(function() { btn.textContent = t; }, 2000); }
      }).catch(function() { showError('Kopieren fehlgeschlagen'); });
    }
    var copyBtn = document.getElementById('copyDirectoryUrlBtn');
    if (copyBtn) copyBtn.addEventListener('click', copyDirectoryUrl);
    function updateCaCard(configured) {
      document.getElementById('caNotConfigured').style.display = configured ? 'none' : 'block';
      document.getElementById('caConfigured').style.display = configured ? 'block' : 'none';
      if (configured) document.getElementById('caDirectoryUrl').textContent = window.location.origin + '/acme/directory';
    }
    setInterval(function updateAcmeCountdowns() {
      document.querySelectorAll('.acme-validation-countdown').forEach(function(span) {
        var nextAt = parseInt(span.getAttribute('data-next-at'), 10);
        if (isNaN(nextAt)) return;
        var secs = Math.max(0, Math.ceil((nextAt - Date.now()) / 1000));
        span.textContent = String(secs);
      });
      document.querySelectorAll('.acme-validation-progress').forEach(function(wrapper) {
        var nextAt = parseInt(wrapper.getAttribute('data-next-at'), 10);
        if (isNaN(nextAt)) return;
        var secs = Math.max(0, Math.ceil((nextAt - Date.now()) / 1000));
        var fill = wrapper.querySelector('.acme-validation-ring-fill');
        if (fill) fill.style.strokeDashoffset = String(100 * (1 - Math.min(5, secs) / 5));
      });
    }, 1000);
    document.body.addEventListener('click', function(e) {
      var acceptAcmeBtn = e.target.closest && e.target.closest('.btn-accept-acme-authz');
      if (acceptAcmeBtn) {
        e.preventDefault();
        var authzId = acceptAcmeBtn.getAttribute('data-authz-id');
        if (authzId && confirm('Challenge manuell als gültig markieren? Certbot kann danach mit Enter fortfahren.')) {
          acceptAcmeBtn.disabled = true;
          fetch('/api/acme-challenge/accept?id=' + encodeURIComponent(authzId), { method: 'POST' }).then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Fehlgeschlagen'); }).finally(function() { acceptAcmeBtn.disabled = false; });
        }
        return;
      }
      var delAcmeBtn = e.target.closest && e.target.closest('.btn-delete-acme-authz');
      if (delAcmeBtn) {
        e.preventDefault();
        var authzId = delAcmeBtn.getAttribute('data-authz-id');
        if (authzId && confirm('ACME-Authorisierung und zugehörige Challenges wirklich löschen?')) {
          delAcmeBtn.disabled = true;
          fetch('/api/acme-authz?id=' + encodeURIComponent(authzId), { method: 'DELETE' }).then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Löschen fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Löschen fehlgeschlagen'); }).finally(function() { delAcmeBtn.disabled = false; });
        }
        return;
      }
      var delChBtn = e.target.closest && e.target.closest('.btn-delete-challenge');
      if (delChBtn) {
        e.preventDefault();
        var chId = delChBtn.getAttribute('data-challenge-id');
        if (chId && confirm('Challenge wirklich löschen?')) {
          delChBtn.disabled = true;
          fetch('/api/challenges?id=' + encodeURIComponent(chId), { method: 'DELETE' }).then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Löschen fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Löschen fehlgeschlagen'); }).finally(function() { delChBtn.disabled = false; });
        }
        return;
      }
      var btn = e.target.closest && e.target.closest('[data-ca-id]');
      if (btn) { e.preventDefault(); activateCa(btn.getAttribute('data-ca-id')); }
    });
    async function activateCa(id) {
      const res = await fetch('/api/ca/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id }) });
      if (!res.ok) { showError('Fehler: ' + ((await res.json().catch(function() { return {}; })).error || res.status)); return; }
      location.reload();
    }
    updateCaCard(initialData.caConfigured);
    function buildCertTreeHtml(certs, casList, intList) {
      function attrEscape(s) { return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }
      function getIssuerName(issuerId, cas, ints) {
        if (!issuerId) return '—';
        var c = (cas || []).find(function(x) { return x.id === issuerId; });
        if (c) return c.name;
        var i = (ints || []).find(function(x) { return x.id === issuerId; });
        if (i) return i.name + ' (Intermediate CA)';
        return issuerId;
      }
      function certRow(cert, depth) {
        var validUntil = cert.not_after ? new Date(cert.not_after).toLocaleString() : '—';
        var createdAt = cert.created_at ? new Date(cert.created_at).toLocaleString() : '—';
        var issuerName = getIssuerName(cert.issuer_id, casList, intList);
        var isRevoked = cert.revoked !== undefined && cert.revoked !== 0;
        var metaText = isRevoked ? 'Widerrufen · Gültig bis ' + validUntil : 'Gültig bis ' + validUntil;
        var revokeBtn = isRevoked ? '' : '<button type="button" class="btn btn-revoke" data-cert-id="' + cert.id + '" title="Zertifikat widerrufen">Widerrufen</button> ';
        var actions = '<button type="button" class="btn btn-view-cert" data-cert-id="' + cert.id + '" data-cert-domain="' + attrEscape(cert.domain) + '" data-cert-not-after="' + attrEscape(validUntil) + '" data-cert-created-at="' + attrEscape(createdAt) + '" data-cert-issuer="' + attrEscape(issuerName) + '" title="Details anzeigen">View</button> ' + (cert.has_pem ? '<a href="/api/cert/download?id=' + cert.id + '" class="btn" download>Zertifikat</a> <a href="/api/cert/key?id=' + cert.id + '" class="btn" download>Schlüssel</a> ' : '') + revokeBtn + '<button type="button" class="btn btn-delete" data-cert-id="' + cert.id + '" title="Zertifikat löschen">Löschen</button>';
        return '<li class="cert-tree__item cert-tree__item--depth-' + depth + (isRevoked ? ' cert-tree__item--revoked' : '') + '"><span class="cert-tree__label">' + htmlEscapeClient(cert.domain) + '</span><span class="cert-tree__meta">' + metaText + '</span><span class="cert-tree__actions">' + actions + '</span></li>';
      }
      function togglerRow(depth, label, meta, actions) {
        return '<div class="cert-tree__item cert-tree__item--depth-' + depth + ' cert-tree__toggler" role="button" tabindex="0" aria-expanded="true"><span class="cert-tree__toggle" aria-hidden="true">▼</span><span class="cert-tree__label">' + label + '</span><span class="cert-tree__meta">' + meta + '</span><span class="cert-tree__actions">' + actions + '</span></div>';
      }
      var parts = [];
      casList = casList || [];
      intList = intList || [];
      certs = certs || [];
      casList.forEach(function(root) {
        var rootValidUntil = root.notAfter ? new Date(root.notAfter).toLocaleString() : '—';
        var rootActions = '<button type="button" class="btn btn-view-cert btn-view-ca" data-ca-id="' + attrEscape(root.id) + '" data-ca-type="root" title="Details anzeigen">View</button> ' + (!root.isActive ? '<button type="button" class="btn" data-ca-id="' + attrEscape(root.id) + '">Aktivieren</button> ' : '') + '<a href="/api/ca-cert?id=' + encodeURIComponent(root.id) + '" class="btn" download>Zertifikat</a> <button type="button" class="btn btn-delete btn-delete-ca" data-ca-id="' + attrEscape(root.id) + '" data-ca-type="root" title="Root-CA löschen">Löschen</button>';
        var childParts = [];
        intList.filter(function(i) { return i.parentCaId === root.id; }).forEach(function(int) {
          var intValidUntil = int.notAfter ? new Date(int.notAfter).toLocaleString() : '—';
          var intActions = '<button type="button" class="btn btn-view-cert btn-view-ca" data-ca-id="' + attrEscape(int.id) + '" data-ca-type="intermediate" title="Details anzeigen">View</button> <a href="/api/ca-cert?id=' + encodeURIComponent(int.id) + '" class="btn" download>Zertifikat</a> <button type="button" class="btn btn-delete btn-delete-ca" data-ca-id="' + attrEscape(int.id) + '" data-ca-type="intermediate" title="Intermediate-CA löschen">Löschen</button>';
          var intChildRows = certs.filter(function(c) { return c.issuer_id === int.id; }).map(function(c) { return certRow(c, 2); }).join('');
          childParts.push('<li class="cert-tree__branch" data-branch-id="int-' + attrEscape(int.id) + '">' + togglerRow(1, htmlEscapeClient(int.name) + ' <span class="cert-tree__meta">(Intermediate CA)</span>', 'Gültig bis ' + intValidUntil, intActions) + '<ul class="cert-tree__children">' + intChildRows + '</ul></li>');
        });
        certs.filter(function(c) { return c.issuer_id === root.id; }).forEach(function(c) { childParts.push(certRow(c, 1)); });
        parts.push('<li class="cert-tree__branch" data-branch-id="' + attrEscape(root.id) + '">' + togglerRow(0, htmlEscapeClient(root.name) + ' <span class="cert-tree__meta">(Root-CA)</span>', (root.isActive ? 'Aktiv · ' : '') + 'Gültig bis ' + rootValidUntil, rootActions) + '<ul class="cert-tree__children">' + childParts.join('') + '</ul></li>');
      });
      var certsNoIssuer = certs.filter(function(c) { return !c.issuer_id; });
      if (certsNoIssuer.length > 0) {
        var noCaChildren = certsNoIssuer.map(function(c) { return certRow(c, 1); }).join('');
        parts.push('<li class="cert-tree__branch" data-branch-id="no-ca">' + togglerRow(0, 'Ohne CA', '(ältere Einträge)', '') + '<ul class="cert-tree__children">' + noCaChildren + '</ul></li>');
      }
      if (parts.length === 0) parts.push('<li class="cert-tree__item cert-tree__item--depth-0"><span class="cert-tree__label empty-table">Keine CAs oder Zertifikate</span></li>');
      return parts.join('');
    }
    var TREE_COLLAPSED_KEY = 'cert-manager-tree-collapsed';
    function getStoredCollapsedIds() {
      try { return JSON.parse(localStorage.getItem(TREE_COLLAPSED_KEY) || '[]'); } catch (e) { return []; }
    }
    function saveCollapsedIds(ids) {
      try { localStorage.setItem(TREE_COLLAPSED_KEY, JSON.stringify(ids)); } catch (e) {}
    }
    function applyStoredCollapsedState() {
      var el = document.getElementById('certTree');
      if (!el) return;
      var ids = getStoredCollapsedIds();
      ids.forEach(function(id) {
        var branch = el.querySelector('.cert-tree__branch[data-branch-id="' + id.replace(/"/g, '\\"') + '"]');
        if (branch) {
          branch.classList.add('cert-tree__branch--collapsed');
          var toggler = branch.querySelector('.cert-tree__toggler');
          if (toggler) {
            toggler.setAttribute('aria-expanded', 'false');
            var arrow = toggler.querySelector('.cert-tree__toggle');
            if (arrow) arrow.textContent = '▶';
          }
        }
      });
    }
    function saveCollapsedState() {
      var el = document.getElementById('certTree');
      if (!el) return;
      var ids = [];
      el.querySelectorAll('.cert-tree__branch--collapsed').forEach(function(branch) {
        var id = branch.getAttribute('data-branch-id');
        if (id) ids.push(id);
      });
      saveCollapsedIds(ids);
    }
    function updateCertTree(certs, casList, intList) {
      var el = document.getElementById('certTree');
      if (!el) return;
      el.innerHTML = buildCertTreeHtml(certs, casList, intList);
      applyStoredCollapsedState();
    }
    document.getElementById('certTree').addEventListener('click', function(e) {
      var delCaBtn = e.target.closest && e.target.closest('.btn-delete-ca');
      if (delCaBtn) {
        e.preventDefault();
        var caId = delCaBtn.getAttribute('data-ca-id');
        var caType = delCaBtn.getAttribute('data-ca-type');
        var msg = caType === 'intermediate'
          ? 'Intermediate-CA und alle von ihr ausgestellten Zertifikate wirklich löschen? Dies kann nicht rückgängig gemacht werden.'
          : 'Root-CA und alle zugehörigen Intermediate-CAs sowie ausgestellten Zertifikate wirklich löschen? Dies kann nicht rückgängig gemacht werden.';
        if (caId && confirm(msg)) {
          delCaBtn.disabled = true;
          var url = caType === 'intermediate' ? '/api/ca/intermediate?id=' + encodeURIComponent(caId) : '/api/ca?id=' + encodeURIComponent(caId);
          fetch(url, { method: 'DELETE' }).then(function(res) {
            return res.json().then(function(data) { return { ok: res.ok, data: data }; });
          }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Löschen fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Löschen fehlgeschlagen'); }).finally(function() { delCaBtn.disabled = false; });
        }
        return;
      }
      var viewCaBtn = e.target.closest && e.target.closest('.btn-view-ca');
      if (viewCaBtn) {
        e.preventDefault();
        e.stopPropagation();
        var caId = viewCaBtn.getAttribute('data-ca-id');
        var caType = viewCaBtn.getAttribute('data-ca-type') || '';
        if (!caId) return;
        document.getElementById('certViewModal').classList.add('open');
        document.getElementById('certViewModalTitle').textContent = 'CA-Details';
        document.querySelectorAll('.cert-view-cert-only').forEach(function(el) { el.style.display = 'none'; });
        document.querySelectorAll('.cert-view-ca-only').forEach(function(el) { el.style.display = ''; });
        document.querySelectorAll('.cert-view-int-only').forEach(function(el) { el.style.display = caType === 'intermediate' ? '' : 'none'; });
        document.getElementById('certViewPem').textContent = 'Lade…';
        document.getElementById('certViewDownloads').innerHTML = '';
        fetch('/api/ca/info?id=' + encodeURIComponent(caId)).then(function(res) {
          return res.json().then(function(d) {
            if (!res.ok) { throw new Error(d && d.error ? d.error : 'Laden fehlgeschlagen'); }
            return d;
          });
        }).then(function(d) {
          var fmt = function(v) { return v != null && v !== '' ? String(v) : '—'; };
          document.getElementById('certViewType').textContent = d.type === 'root' ? 'Root-CA' : 'Intermediate CA';
          document.getElementById('certViewName').textContent = fmt(d.name);
          document.getElementById('certViewCommonName').textContent = fmt(d.commonName);
          document.getElementById('certViewParentCa').textContent = fmt(d.parentCaId);
          document.getElementById('certViewSubject').textContent = fmt(d.subject);
          document.getElementById('certViewIssuer').textContent = fmt(d.issuer);
          document.getElementById('certViewSerial').textContent = fmt(d.serialNumber);
          document.getElementById('certViewNotBefore').textContent = fmt(d.notBefore);
          document.getElementById('certViewNotAfter').textContent = fmt(d.notAfter);
          document.getElementById('certViewFingerprint').textContent = fmt(d.fingerprint256);
          document.getElementById('certViewCreatedAt').textContent = d.createdAt ? new Date(d.createdAt).toLocaleString() : '—';
          document.getElementById('certViewId').textContent = fmt(d.id);
          document.getElementById('certViewPem').textContent = d.pem || '—';
          var dl = document.getElementById('certViewDownloads');
          dl.innerHTML = '<a href="/api/ca-cert?id=' + encodeURIComponent(d.id) + '" class="btn" download>Zertifikat herunterladen</a>';
        }).catch(function(err) { showError(err && err.message ? err.message : 'Laden fehlgeschlagen'); document.getElementById('certViewPem').textContent = '—'; });
        return;
      }
      var viewBtn = e.target.closest && e.target.closest('.btn-view-cert');
      if (viewBtn) {
        e.preventDefault();
        e.stopPropagation();
        var certId = viewBtn.getAttribute('data-cert-id');
        if (!certId) return;
        document.getElementById('certViewModal').classList.add('open');
        document.getElementById('certViewModalTitle').textContent = 'Zertifikat-Details';
        document.querySelectorAll('.cert-view-cert-only').forEach(function(el) { el.style.display = ''; });
        document.querySelectorAll('.cert-view-ca-only').forEach(function(el) { el.style.display = 'none'; });
        document.querySelectorAll('.cert-view-int-only').forEach(function(el) { el.style.display = 'none'; });
        document.getElementById('certViewPem').textContent = 'Lade…';
        document.getElementById('certViewDownloads').innerHTML = '';
        fetch('/api/cert/info?id=' + encodeURIComponent(certId)).then(function(res) {
          return res.json().then(function(d) {
            if (!res.ok) { throw new Error(d && d.error ? d.error : 'Laden fehlgeschlagen'); }
            return d;
          });
        }).then(function(d) {
          var fmt = function(v) { return v != null && v !== '' ? String(v) : '—'; };
          document.getElementById('certViewDomain').textContent = fmt(d.domain);
          document.getElementById('certViewSubject').textContent = fmt(d.subject);
          document.getElementById('certViewIssuer').textContent = fmt(d.issuer);
          document.getElementById('certViewSerial').textContent = fmt(d.serialNumber);
          document.getElementById('certViewNotBefore').textContent = fmt(d.notBefore);
          document.getElementById('certViewNotAfter').textContent = fmt(d.notAfter);
          document.getElementById('certViewFingerprint').textContent = fmt(d.fingerprint256);
          document.getElementById('certViewSan').textContent = fmt(d.subjectAltName);
          document.getElementById('certViewCreatedAt').textContent = d.createdAt ? new Date(d.createdAt).toLocaleString() : '—';
          document.getElementById('certViewId').textContent = fmt(d.id);
          document.getElementById('certViewPem').textContent = d.pem || '—';
          var dl = document.getElementById('certViewDownloads');
          dl.innerHTML = '<a href="/api/cert/download?id=' + encodeURIComponent(d.id) + '" class="btn" download>Zertifikat herunterladen</a> <a href="/api/cert/key?id=' + encodeURIComponent(d.id) + '" class="btn" download>Schlüssel herunterladen</a>';
        }).catch(function(err) { showError(err && err.message ? err.message : 'Laden fehlgeschlagen'); document.getElementById('certViewPem').textContent = '—'; });
        return;
      }
      var revokeBtn = e.target.closest && e.target.closest('.btn-revoke');
      if (revokeBtn) {
        e.preventDefault();
        e.stopPropagation();
        var id = revokeBtn.getAttribute('data-cert-id');
        if (id && confirm('Zertifikat wirklich widerrufen?')) {
          revokeBtn.disabled = true;
          fetch('/api/cert/revoke?id=' + encodeURIComponent(id), { method: 'POST' }).then(function(res) {
            return res.json().then(function(data) { return { ok: res.ok, data: data }; });
          }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Widerruf fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Widerruf fehlgeschlagen'); }).finally(function() { revokeBtn.disabled = false; });
        }
        return;
      }
      var delBtn = e.target.closest && e.target.closest('.btn-delete');
      if (delBtn) {
        e.preventDefault();
        var id = delBtn.getAttribute('data-cert-id');
        if (id && confirm('Zertifikat wirklich löschen? Dies kann nicht rückgängig gemacht werden.')) {
          delBtn.disabled = true;
          fetch('/api/cert?id=' + encodeURIComponent(id), { method: 'DELETE' }).then(function(res) {
            return res.json().then(function(data) { return { ok: res.ok, data: data }; });
          }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Löschen fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Löschen fehlgeschlagen'); }).finally(function() { delBtn.disabled = false; });
        }
        return;
      }
      var toggler = e.target.closest && e.target.closest('.cert-tree__toggler');
      if (!toggler || e.target.closest('.cert-tree__actions')) return;
      var branch = toggler.closest('.cert-tree__branch');
      if (!branch) return;
      var expanded = branch.classList.toggle('cert-tree__branch--collapsed');
      toggler.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      var arrow = toggler.querySelector('.cert-tree__toggle');
      if (arrow) arrow.textContent = expanded ? '▶' : '▼';
      saveCollapsedState();
    });
    document.getElementById('certTree').addEventListener('keydown', function(e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var toggler = e.target.closest && e.target.closest('.cert-tree__toggler');
      if (!toggler) return;
      e.preventDefault();
      var branch = toggler.closest('.cert-tree__branch');
      if (!branch) return;
      var expanded = branch.classList.toggle('cert-tree__branch--collapsed');
      toggler.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      var arrow = toggler.querySelector('.cert-tree__toggle');
      if (arrow) arrow.textContent = expanded ? '▶' : '▼';
      saveCollapsedState();
    });
    applyStoredCollapsedState();
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
          showError('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        closeModal('intermediateModal');
        location.reload();
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Intermediate-CA erstellen'; }
        showError(e && e.message ? e.message : String(e));
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
        opt.textContent = (c.name || c.id) + ' (Intermediate CA)';
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
      if (!issuerId || !domain) { showError('Bitte CA und Domain angeben.'); return false; }
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
          showError('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        var certId = data.id;
        document.getElementById('certCreateSuccess').style.display = 'block';
        document.getElementById('certCreateDownloadCert').href = '/api/cert/download?id=' + certId;
        document.getElementById('certCreateDownloadKey').href = '/api/cert/key?id=' + certId;
        if (btn) { btn.disabled = false; btn.textContent = 'Zertifikat erstellen'; }
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Zertifikat erstellen'; }
        showError(e && e.message ? e.message : String(e));
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
          showError('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        closeModal('caModal');
        updateCaCard(true);
        location.reload();
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'CA erstellen'; }
        showError(e && e.message ? e.message : String(e));
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
      if (d.cas) initialData.cas = d.cas;
      if (d.intermediates) initialData.intermediates = d.intermediates;
      updateCertTree(d.certificates || [], initialData.cas || [], initialData.intermediates || []);
      var challengesEl = document.getElementById('challenges');
      if (challengesEl) {
        var ch = d.challenges || [];
        challengesEl.innerHTML = ch.length === 0
          ? '<tr><td colspan="4" class="empty-table">Keine Einträge</td></tr>'
          : ch.map(function(c) { return '<tr><td><code>' + htmlEscapeClient(c.token) + '</code></td><td>' + htmlEscapeClient(c.domain) + '</td><td>' + (c.expires_at ? new Date(c.expires_at).toLocaleString() : '-') + '</td><td><button type="button" class="btn btn-delete btn-delete-challenge" data-challenge-id="' + c.id + '" title="Challenge löschen">Löschen</button></td></tr>'; }).join('');
      }
      var acmeChallengesEl = document.getElementById('acmeChallenges');
      if (acmeChallengesEl && d.acmeChallenges) {
        var ach = d.acmeChallenges;
        var valStatus = d.acmeValidationStatus || [];
        function attrEscapeClient(s) { return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }
        function acmeRow(ac) {
          var val = valStatus.find(function(s) { return s.challengeId === ac.challengeId; });
          var validationCell;
          if (val) {
            var secs = Math.max(0, Math.ceil((val.nextAttemptAt - Date.now()) / 1000));
            var ringOffset = 100 * (1 - Math.min(5, secs) / 5);
            validationCell = '<span class="acme-validation-progress" data-next-at="' + val.nextAttemptAt + '"><span class="acme-validation-circle-wrap"><svg class="acme-validation-circle" viewBox="0 0 36 36" aria-hidden="true"><circle class="acme-validation-ring-bg" cx="18" cy="18" r="16"/><circle class="acme-validation-ring-fill" cx="18" cy="18" r="16" style="stroke-dashoffset:' + ringOffset + '"/></svg></span><span class="acme-validation-text">Versuch ' + val.attemptCount + '/' + val.maxAttempts + '</span><span>nächster in <span class="acme-validation-countdown" data-next-at="' + val.nextAttemptAt + '">' + secs + '</span> s</span></span>';
          } else if (ac.status === 'pending') {
            validationCell = '<span class="acme-validation-progress acme-validation-waiting"><span class="acme-validation-text">Versuch —/5</span><span class="acme-validation-hint">Warte auf Auslösung (Certbot: Enter)</span></span>';
          } else {
            validationCell = '—';
          }
          return '<tr data-authz-id="' + attrEscapeClient(ac.authzId) + '" data-challenge-id="' + attrEscapeClient(ac.challengeId) + '"><td>' + htmlEscapeClient(ac.domain) + '</td><td><code>' + htmlEscapeClient(ac.token) + '</code></td><td>' + htmlEscapeClient(ac.status) + '</td><td class="acme-validation-cell">' + validationCell + '</td><td><button type="button" class="btn btn-accept-acme btn-accept-acme-authz" data-authz-id="' + attrEscapeClient(ac.authzId) + '" title="Challenge manuell als gültig markieren">Manuell annehmen</button> <button type="button" class="btn btn-delete btn-delete-acme-authz" data-authz-id="' + attrEscapeClient(ac.authzId) + '" title="ACME-Challenge löschen">Löschen</button></td></tr>';
        }
        acmeChallengesEl.innerHTML = ach.length === 0
          ? '<tr><td colspan="5" class="empty-table">Keine offenen ACME-Challenges</td></tr>'
          : ach.map(acmeRow).join('');
      }
    };
  </script>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}
