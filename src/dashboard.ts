import type { Database } from 'bun:sqlite';
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
  ca_certificate_id?: number | null;
  is_ev?: number;
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
    const isExpired = cert.not_after ? new Date(cert.not_after) < new Date() : false;
    const isAcme = cert.ca_certificate_id != null && cert.ca_certificate_id !== 0;
    const isEv = cert.is_ev != null && cert.is_ev !== 0;
    const metaText = (isRevoked ? 'Widerrufen · Gültig bis ' + validUntil : 'Gültig bis ' + validUntil) + (isAcme ? ' · ACME' : '') + (isEv ? ' · EV' : '');
    const revokeBtn =
      isRevoked || isExpired ? '' : '<button type="button" class="btn btn-revoke" data-cert-id="' + cert.id + '" title="Zertifikat widerrufen">Widerrufen</button> ';
    const renewBtn =
      isRevoked || isAcme ? '' : '<button type="button" class="btn btn-renew" data-cert-id="' + cert.id + '" data-cert-domain="' + attrEscapeFn(cert.domain) + '" title="Zertifikat erneuern">Erneuern</button> ';
    const actions =
      '<button type="button" class="btn btn-view-cert" data-cert-id="' + cert.id + '" data-cert-domain="' + attrEscapeFn(cert.domain) + '" data-cert-not-after="' + attrEscapeFn(validUntil) + '" data-cert-created-at="' + attrEscapeFn(createdAt) + '" data-cert-issuer="' + attrEscapeFn(issuerName) + '" title="Details anzeigen">View</button> ' +
      (cert.has_pem
        ? '<a href="/api/cert/download?id=' + cert.id + '" class="btn" download>Zertifikat</a> <a href="/api/cert/key?id=' + cert.id + '" class="btn" download>Schlüssel</a> '
        : '') +
      revokeBtn +
      renewBtn +
      '<button type="button" class="btn btn-delete" data-cert-id="' + cert.id + '" title="Zertifikat löschen">Löschen</button>';
    return (
      '<li class="cert-tree__item cert-tree__item--depth-' +
      depth +
      (isRevoked ? ' cert-tree__item--revoked' : '') +
      '"><span class="cert-tree__label">' +
      htmlEscapeFn(cert.domain) +
      (cert.is_ev != null && cert.is_ev !== 0 ? ' <span class="cert-tree__badge cert-tree__badge--ev" title="Extended Validation">EV</span>' : '') +
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
  const { summary, challenges, acmeChallenges, acmeValidationStatus, acmeWhitelistDomains, acmeCaDomainAssignments, activeAcmeIntermediateId, defaultCommonNameRoot, defaultCommonNameIntermediate, certificates, cas, intermediates } = getSummaryData(database, paths);
  const initialData = { cas, intermediates, certificates, caConfigured: summary.caConfigured, activeAcmeIntermediateId, defaultCommonNameRoot, defaultCommonNameIntermediate };
  const getCaDisplayName = (caId: string): string => {
    const root = cas.find((c) => c.id === caId);
    if (root) return root.name + (root.commonName !== root.name ? ' (' + root.commonName + ')' : '');
    const int = intermediates.find((c) => c.id === caId);
    if (int) return (int.name || int.id) + ' (Intermediate)';
    return caId;
  };
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
      --gh-success: #1a7f37;
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
      --gh-success: #3fb950;
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
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      gap: 16px;
      background: var(--gh-canvas-subtle);
      border-bottom: 1px solid var(--gh-border);
      padding: 16px 24px;
      margin-bottom: 0;
    }
    .gh-header-brand {
      display: flex;
      flex-direction: column;
      gap: 0;
      line-height: 1.2;
    }
    .gh-header-brand .gh-header-title {
      margin: 0;
      font-size: 18px;
      font-weight: 600;
      color: var(--gh-fg);
    }
    .gh-header-brand .gh-header-made {
      font-size: 11px;
      color: var(--gh-fg-muted);
      font-weight: 400;
    }
    .gh-header-brand .gh-header-made a {
      color: var(--gh-fg-muted);
      text-decoration: none;
    }
    .gh-header-brand .gh-header-made a:hover {
      text-decoration: underline;
      color: var(--gh-accent);
    }
    .gh-header-nav {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      flex-wrap: wrap;
    }
    .gh-header-nav .nav-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      font-size: 13px;
      color: var(--gh-fg);
      text-decoration: none;
      border: none;
      background: none;
      cursor: pointer;
      font-family: inherit;
      border-radius: 6px;
    }
    .gh-header-nav .nav-link svg {
      flex-shrink: 0;
      width: 16px;
      height: 16px;
    }
    .gh-header-nav .nav-link:hover {
      background: var(--gh-btn-hover);
    }
    .gh-header-nav .nav-link.active {
      background: var(--gh-accent);
      color: #fff;
    }
    .gh-header-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 8px;
    }
    .theme-toggle,
    .gh-header-btn {
      padding: 6px 12px;
      font-size: 18px;
      line-height: 1;
    }
    .gh-header-btn svg {
      display: block;
      width: 1.25em;
      height: 1.25em;
    }
    .app-layout {
      min-height: calc(100vh - 53px);
    }
    .app-content {
      flex: 1;
      overflow: auto;
      max-width: 1200px;
      padding: 24px;
    }
    .dashboard-section {
      display: none;
    }
    .dashboard-section.active {
      display: block;
    }
    main {
      max-width: 1340px;
      margin: 0 auto;
      padding: 0;
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
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
      max-width: 100%;
    }
    .summary-item {
      background: var(--gh-canvas);
      border: 1px solid var(--gh-border);
      border-radius: 6px;
      padding: 16px;
      min-width: 0;
    }
    .summary-item dt { font-size: 12px; color: var(--gh-fg-muted); margin-bottom: 4px; font-weight: 400; }
    .summary-item dd { margin: 0; font-weight: 600; font-size: 18px; overflow: hidden; text-overflow: ellipsis; }
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
    .cert-tree__badge { display: inline-block; padding: 2px 6px; font-size: 10px; font-weight: 600; border-radius: 4px; margin-left: 6px; vertical-align: middle; }
    .cert-tree__badge--ev { background: var(--gh-accent); color: #fff; }
    .cert-view-modal { max-width: 720px; width: 90%; }
    .cert-view-modal #certViewDl dd { min-width: 0; overflow-wrap: break-word; word-break: break-word; }
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
    .acme-challenges-table { width: 100%; }
    .acme-challenges-table th:last-child, .acme-challenges-table td:last-child { text-align: right; }
    .acme-challenges-table .btn { padding: 2px 8px; font-size: 12px; }
    .gh-card-body input[type="text"] { padding: 5px 12px; font-size: 14px; border: 1px solid var(--gh-border); border-radius: 6px; font-family: inherit; background: var(--gh-canvas); color: var(--gh-fg); box-sizing: border-box; }
    .gh-card-body .acme-whitelist-form input[type="text"] { flex: 1; min-width: 0; }
    .gh-card-body .acme-whitelist-form select { padding: 5px 12px; font-size: 14px; border: 1px solid var(--gh-border); border-radius: 6px; font-family: inherit; background: var(--gh-canvas); color: var(--gh-fg); min-width: 180px; box-sizing: border-box; }
    .acme-whitelist-table { width: 100%; }
    .acme-whitelist-table th:last-child, .acme-whitelist-table td:last-child { text-align: right; }
    .acme-whitelist-table .btn { padding: 2px 8px; font-size: 12px; }
    .btn-renew { background: var(--gh-accent); color: #fff; border-color: var(--gh-accent); }
    .btn-renew:hover { background: var(--gh-accent-hover); border-color: var(--gh-accent-hover); }
    .log-terminal-wrap {
      background: #0d1117;
      border: 1px solid var(--gh-border);
      border-radius: 6px;
      padding: 12px;
      max-height: 320px;
      overflow: auto;
    }
    #section-log.dashboard-section.active {
      display: flex;
      flex-direction: column;
      height: calc(100vh - 53px - 48px);
      max-height: calc(100vh - 53px - 48px);
      overflow: hidden;
    }
    #section-log.dashboard-section.active .gh-card {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-height: 0;
      overflow: hidden;
    }
    #section-log.dashboard-section.active .gh-card-body {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-height: 0;
      overflow: hidden;
    }
    #section-log.dashboard-section.active .gh-card-body > p {
      flex-shrink: 0;
    }
    #section-log.dashboard-section.active .log-terminal-wrap {
      flex: 1;
      min-height: 0;
      max-height: none;
      overflow: auto;
    }
    .log-terminal {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.45;
      color: #7ee787;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
    }
    html[data-theme="dark"] .log-terminal-wrap { background: #010409; border-color: #30363d; }
    html[data-theme="dark"] .log-terminal { color: #7ee787; }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
    .stats-charts { margin-top: 24px; max-width: 100%; }
    .stats-chart-card { margin-bottom: 24px; min-width: 0; }
    .stats-chart-card h3 { font-size: 14px; font-weight: 600; margin: 0 0 12px; color: var(--gh-fg-muted); }
    .stats-chart-wrap { background: var(--gh-canvas-subtle); border: 1px solid var(--gh-border); border-radius: 6px; padding: 12px; min-height: 200px; height: 200px; width: 100%; max-width: 100%; box-sizing: border-box; position: relative; }
    .stats-chart-wrap canvas { display: block; width: 100% !important; height: 100% !important; }
    .stats-chart-bar { fill: var(--gh-accent); }
    .stats-chart-bar.revoked { fill: var(--gh-danger); }
    .stats-chart-bar.requests { fill: var(--gh-fg-muted); }
    .stats-chart-line { fill: none; stroke: var(--gh-accent); stroke-width: 2; }
    .stats-chart-grid { stroke: var(--gh-border); stroke-width: 1; }
    .stats-chart-empty { font-size: 13px; color: var(--gh-fg-muted); text-align: center; padding: 24px; }
    .cert-honeycomb-wrap { margin-bottom: 24px; }
    .cert-honeycomb-canvas { display: block; width: 100%; max-width: 100%; height: auto; border: 1px solid var(--gh-border); border-radius: 6px; background: var(--gh-canvas-subtle); }
  </style>
</head>
<body>
  <div id="toast" role="alert" aria-live="assertive"></div>
  <header class="gh-header">
    <div class="gh-header-brand">
      <h1 class="gh-header-title">Cert-Manager</h1>
      <span class="gh-header-made">made by <a href="https://trackhe.de" target="_blank" rel="noopener noreferrer">trackhe.de</a></span>
    </div>
    <nav class="gh-header-nav" aria-label="Hauptnavigation">
      <button type="button" class="nav-link active" data-section="overview" aria-current="page">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
        Übersicht
      </button>
      <button type="button" class="nav-link" data-section="acme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        ACME & Challenges
      </button>
      <button type="button" class="nav-link" data-section="certificates">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h2"/><path d="M8 17h2"/><path d="M14 13h2"/><path d="M14 17h2"/></svg>
        Zertifikate
      </button>
      <button type="button" class="nav-link" data-section="log">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
        Log
      </button>
      <button type="button" class="nav-link" data-section="statistics">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
        Statistiken
      </button>
    </nav>
    <div class="gh-header-actions">
      <a href="https://github.com/Trackhe/Cert-Manager" target="_blank" rel="noopener noreferrer" class="btn gh-header-btn theme-toggle" title="Cert-Manager auf GitHub" aria-label="GitHub öffnen">
        <svg aria-hidden="true" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
      </a>
      <button type="button" id="themeToggle" class="btn theme-toggle" title="Dark/Light umschalten" aria-label="Theme umschalten">
        <span class="theme-toggle-icon theme-icon-light" aria-hidden="true">☀</span>
        <span class="theme-toggle-icon theme-icon-dark" aria-hidden="true" style="display:none">☽</span>
      </button>
    </div>
  </header>
  <div class="app-layout">
  <main class="app-content">
  <section id="section-overview" class="dashboard-section active" aria-labelledby="heading-overview">
  <h2 id="heading-overview" class="sr-only">Übersicht</h2>
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
      <dt>ACME Client</dt>
      <dd id="letsEncryptEmail">${summary.letsEncrypt ? htmlEscape(summary.letsEncrypt.email) : 'coming soon'}</dd>
      <dt id="accountUrlLabel" style="margin-top:8px; display:${summary.letsEncrypt?.accountUrl ? 'block' : 'none'}">Account URL</dt>
      <dd id="letsEncryptUrl" style="word-break:break-all;font-size:0.9em">${summary.letsEncrypt?.accountUrl ? htmlEscape(summary.letsEncrypt.accountUrl) : ''}</dd>
    </div>
  </section>

  <div class="gh-card">
    <div class="gh-card-header">Setup</div>
    <div class="gh-card-body">
  <div class="setup-grid">
      <div class="setup-card">
        <h3>ACME Client <span style="font-size:12px;font-weight:400;color:var(--gh-fg-muted)">(geplant)</span></h3>
        <p>Der Cert-Manager soll künftig selbst als <strong>ACME-Client</strong> agieren – vergleichbar mit Certbot. Er würde per <strong>DNS-Challenge</strong> bei Let's Encrypt oder einem anderen ACME-Server Zertifikate anfordern, die Challenge erfüllen, das Zertifikat hier speichern und optional an Nginx Proxy Manager (NPM) ausliefern.</p>
        <p>Ziel: NPM bezieht alle Zertifikate vom Cert-Manager; der Cert-Manager übernimmt Anforderung, Renewal und Auslieferung. Diese Funktion ist <strong>noch nicht implementiert</strong>.</p>
      </div>
      <div class="setup-card">
        <h3>Eigene CA</h3>
        <div id="caNotConfigured">
          <p>Root-CA per Knopfdruck einrichten oder eine bestehende CA (Zertifikat + Schlüssel im PEM-Format) hochladen. Danach können ACME-Clients (z. B. Reverse-Proxys) Zertifikate von dieser CA anfordern.</p>
          <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
            <button type="button" class="btn" onclick="document.getElementById('caModal').classList.add('open')">CA erstellen</button>
            <button type="button" class="btn" onclick="openCaUploadModal()">CA hochladen</button>
          </div>
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
            <button type="button" class="btn" onclick="openCaUploadModal()">CA hochladen</button>
            <button type="button" class="btn" onclick="openIntermediateModal()">Intermediate-CA erstellen</button>
          </div>
        </div>
      </div>
      <div class="setup-card">
        <h3>Zertifikate erstellen</h3>
        <p style="margin-bottom:12px">Domain-Zertifikat über die eingerichtete CA ausstellen oder bestehendes Zertifikat hochladen.</p>
        <div style="display:flex;flex-wrap:wrap;gap:8px">
          <button type="button" class="btn" onclick="openCertCreateModal()">Zertifikat erstellen</button>
          <button type="button" class="btn" onclick="openCertUploadModal()">Zertifikat hochladen</button>
        </div>
      </div>
    </div>
    </div>
  </div>
  </section>

  <section id="section-acme" class="dashboard-section" aria-labelledby="heading-acme">
  <h2 id="heading-acme" class="sr-only">ACME & Challenges</h2>
  <div class="gh-card">
    <div class="gh-card-header">ACME Client</div>
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
  <table class="acme-challenges-table">
    <thead><tr><th>Domain</th><th>Token</th><th>Status</th><th>Validierung</th><th></th></tr></thead>
    <tbody id="acmeChallenges">${acmeChallenges.length === 0
      ? '<tr><td colspan="5" class="empty-table">Keine offenen ACME-Challenges</td></tr>'
      : acmeChallenges
          .map((ac) => {
            const val = acmeValidationStatus.find((s) => s.challengeId === ac.challengeId);
            const acceptedExpireAt = ac.acceptedAt != null ? ac.acceptedAt * 1000 + 60000 : 0;
            let validationCell: string;
            if (ac.acceptedAt != null) {
              const secs = Math.max(0, Math.ceil((acceptedExpireAt - Date.now()) / 1000));
              const ringOffset = 100 * (1 - Math.min(60, secs) / 60);
              validationCell = `<span class="acme-validation-progress acme-validation-accept-timer" data-next-at="${acceptedExpireAt}" data-timer-max="60">
  <span class="acme-validation-circle-wrap"><svg class="acme-validation-circle" viewBox="0 0 36 36" aria-hidden="true"><circle class="acme-validation-ring-bg" cx="18" cy="18" r="16"/><circle class="acme-validation-ring-fill" cx="18" cy="18" r="16" style="stroke-dashoffset:${ringOffset}"/></svg></span>
  <span class="acme-validation-text">Manuell akzeptiert</span>
  <span>Löschung in <span class="acme-validation-countdown" data-next-at="${acceptedExpireAt}">${secs}</span> s (wenn nicht eingelöst)</span>
</span>`;
            } else if (val) {
              const secs = Math.max(0, Math.ceil((val.nextAttemptAt - Date.now()) / 1000));
              const ringOffset = 100 * (1 - Math.min(5, secs) / 5);
              validationCell = `<span class="acme-validation-progress" data-next-at="${val.nextAttemptAt}">
  <span class="acme-validation-circle-wrap"><svg class="acme-validation-circle" viewBox="0 0 36 36" aria-hidden="true"><circle class="acme-validation-ring-bg" cx="18" cy="18" r="16"/><circle class="acme-validation-ring-fill" cx="18" cy="18" r="16" style="stroke-dashoffset:${ringOffset}"/></svg></span>
  <span class="acme-validation-text">Versuch ${val.attemptCount}/${val.maxAttempts}</span>
  <span>nächster in <span class="acme-validation-countdown" data-next-at="${val.nextAttemptAt}">${secs}</span> s</span>
</span>`;
            } else if (ac.status === 'pending') {
              validationCell = '<span class="acme-validation-progress acme-validation-waiting"><span class="acme-validation-text">Versuch —/5</span><span class="acme-validation-hint">Warte auf Auslösung (Certbot: Enter)</span></span>';
            } else {
              validationCell = '—';
            }
            const displayStatus = ac.acceptedAt != null ? 'akzeptiert' : ac.status;
            return `
      <tr data-authz-id="${attrEscape(ac.authzId)}" data-challenge-id="${attrEscape(ac.challengeId)}">
        <td>${htmlEscape(ac.domain)}</td>
        <td><code>${htmlEscape(ac.token)}</code></td>
        <td>${htmlEscape(displayStatus)}</td>
        <td class="acme-validation-cell">${validationCell}</td>
        <td>${ac.status !== 'valid' ? `<button type="button" class="btn btn-accept-acme btn-accept-acme-authz" data-authz-id="${attrEscape(ac.authzId)}" title="Challenge manuell als gültig markieren">Manuell annehmen</button> ` : ''}<button type="button" class="btn btn-delete btn-delete-acme-authz" data-authz-id="${attrEscape(ac.authzId)}" title="ACME-Challenge löschen">Löschen</button></td>
      </tr>
    `;
          })
          .join('')}</tbody>
  </table>
    </div>
  </div>

  <div class="gh-card">
    <div class="gh-card-header">Domains ohne HTTP-Challenge (Whitelist)</div>
    <div class="gh-card-body">
  <p style="margin:0 0 12px;font-size:13px;color:var(--gh-fg-muted)">Domains oder Adressen, für die die ACME HTTP-01-Challenge automatisch als gültig akzeptiert wird. Nützlich im lokalen Netz. Mit <code>*.</code> (z. B. <code>*.example.com</code>) werden alle Subdomains akzeptiert.</p>
  <form id="acmeWhitelistForm" class="acme-whitelist-form" style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
    <input type="text" id="acmeWhitelistDomain" name="domain" placeholder="z. B. test2.example.com, *.example.com">
    <button type="submit" class="btn">Hinzufügen</button>
  </form>
  <table class="acme-whitelist-table">
    <thead><tr><th>Domain</th><th></th></tr></thead>
    <tbody id="acmeWhitelistDomains">${acmeWhitelistDomains.length === 0
      ? '<tr><td colspan="2" class="empty-table">Keine Einträge</td></tr>'
      : acmeWhitelistDomains
          .map(
            (w) => `
      <tr data-whitelist-id="${attrEscape(String(w.id))}">
        <td><code>${htmlEscape(w.domain)}</code></td>
        <td><button type="button" class="btn btn-delete btn-delete-acme-whitelist" data-id="${attrEscape(String(w.id))}" title="Aus Whitelist löschen">Löschen</button></td>
      </tr>
    `
          )
          .join('')}</tbody>
  </table>
    </div>
  </div>

  <div class="gh-card">
    <div class="gh-card-header">CA pro Domain (ACME)</div>
    <div class="gh-card-body">
  <p style="margin:0 0 8px;font-size:13px;color:var(--gh-fg-muted)">Standard-Intermediate für ACME: Wird verwendet, wenn keine Domain-Zuordnung passt.</p>
  <form id="acmeDefaultIntermediateForm" class="acme-whitelist-form" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px;">
    <select id="acmeDefaultIntermediateSelect" name="intermediate_id" class="acme-ca-assignment-select" style="min-width:220px">
      <option value="">– Keine (erste Intermediate der aktiven Root) –</option>
      ${intermediates.map((c) => '<option value="' + attrEscape(c.id) + '"' + (activeAcmeIntermediateId === c.id ? ' selected' : '') + '>' + htmlEscape(c.name || c.id) + '</option>').join('')}
    </select>
    <button type="submit" class="btn">Als Standard setzen</button>
  </form>
  <p style="margin:0 0 12px;font-size:13px;color:var(--gh-fg-muted)">Domain-Zuordnung: Bei ACME-Anfragen wird für die angegebene Domain (oder Wildcard) die gewählte CA statt der Standard-CA verwendet. Unterstützt exakte Domains und <code>*.</code> (z. B. <code>*.example.com</code>).</p>
  <form id="acmeCaAssignmentsForm" class="acme-whitelist-form" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px;">
    <input type="text" id="acmeCaAssignmentPattern" name="domain_pattern" placeholder="z. B. example.com oder *.example.com" style="min-width:200px">
    <select id="acmeCaAssignmentCa" name="ca_id" class="acme-ca-assignment-select">
      <option value="">– Intermediate-CA wählen –</option>
      ${intermediates.map((c) => '<option value="' + attrEscape(c.id) + '">' + htmlEscape(c.name || c.id) + '</option>').join('')}
    </select>
    <button type="submit" class="btn">Hinzufügen</button>
  </form>
  <table class="acme-whitelist-table">
    <thead><tr><th>Domain / Muster</th><th>CA</th><th></th></tr></thead>
    <tbody id="acmeCaAssignments">${acmeCaDomainAssignments.length === 0
      ? '<tr><td colspan="3" class="empty-table">Keine Zuordnungen. Standard-CA wird verwendet.</td></tr>'
      : acmeCaDomainAssignments
          .map(
            (a) => `
      <tr data-pattern="${attrEscape(a.domainPattern)}">
        <td><code>${htmlEscape(a.domainPattern)}</code></td>
        <td>${htmlEscape(getCaDisplayName(a.caId))}</td>
        <td><button type="button" class="btn btn-delete btn-delete-acme-ca-assignment" data-pattern="${attrEscape(a.domainPattern)}" title="Zuordnung löschen">Löschen</button></td>
      </tr>
    `
          )
          .join('')}</tbody>
  </table>
    </div>
  </div>
  </section>

  <section id="section-certificates" class="dashboard-section" aria-labelledby="heading-certificates">
  <h2 id="heading-certificates" class="sr-only">Zertifikate</h2>
  <div class="gh-card">
    <div class="gh-card-header">Zertifikate</div>
    <div class="gh-card-body">
  <p style="margin:0 0 12px;font-size:13px;color:var(--gh-fg-muted)">Hierarchie wie in XCA: Root-CAs, darunter Intermediate-CAs und ausgestellte Zertifikate.</p>
  <div class="cert-honeycomb-wrap" aria-hidden="false">
    <p style="margin:0 0 8px;font-size:12px;color:var(--gh-fg-muted)">Honeycomb: jede Kachel = ein Zertifikat bzw. eine CA (dunkel = CA, hell = Zertifikate um die CA).</p>
    <canvas id="certHoneycombCanvas" class="cert-honeycomb-canvas" width="800" height="360" role="img" aria-label="Zertifikate-Honeycomb"></canvas>
  </div>
  <ul id="certTree" class="cert-tree">${renderCertTree(certificates, cas, intermediates, htmlEscape, attrEscape)}</ul>
    </div>
  </div>
  </section>

  <section id="section-log" class="dashboard-section" aria-labelledby="heading-log">
  <h2 id="heading-log" class="sr-only">Log</h2>
  <div class="gh-card">
    <div class="gh-card-header">Log</div>
    <div class="gh-card-body">
  <p style="margin:0 0 12px;font-size:13px;color:var(--gh-fg-muted)">Server-Log (Terminal-Ausgabe). Aktualisiert sich live.</p>
  <div class="log-terminal-wrap">
    <pre id="logTerminal" class="log-terminal" aria-live="polite">Lade…</pre>
  </div>
    </div>
  </div>
  </section>

  <section id="section-statistics" class="dashboard-section" aria-labelledby="heading-statistics">
  <h2 id="heading-statistics" class="sr-only">Statistiken</h2>
  <div class="gh-card">
    <div class="gh-card-header">Statistiken</div>
    <div class="gh-card-body">
  <p style="margin:0 0 16px;font-size:13px;color:var(--gh-fg-muted)">Überblick über Zertifikate, CAs und ACME. Weitere Darstellungen können hier ergänzt werden.</p>
  <div class="summary" id="statsSummary">
    <div class="summary-item">
      <dt>Zertifikate gesamt</dt>
      <dd id="statsCertsTotal">—</dd>
    </div>
    <div class="summary-item">
      <dt>Zertifikate gültig</dt>
      <dd id="statsCertsValid">—</dd>
    </div>
    <div class="summary-item">
      <dt>Zertifikate abgelaufen</dt>
      <dd id="statsCertsExpired">—</dd>
    </div>
    <div class="summary-item">
      <dt>Zertifikate widerrufen</dt>
      <dd id="statsCertsRevoked">—</dd>
    </div>
    <div class="summary-item">
      <dt>Root-CAs</dt>
      <dd id="statsRootCas">—</dd>
    </div>
    <div class="summary-item">
      <dt>Intermediate-CAs</dt>
      <dd id="statsIntermediates">—</dd>
    </div>
    <div class="summary-item">
      <dt>ACME-Challenges / Whitelist</dt>
      <dd id="statsAcmeChallenges">—</dd>
    </div>
    <div class="summary-item">
      <dt>Whitelist-Einträge</dt>
      <dd id="statsWhitelist">—</dd>
    </div>
  </div>
  <div class="stats-charts" id="statsCharts">
    <div class="stats-chart-card">
      <h3>HTTP-Anfragen pro Tag</h3>
      <div class="stats-chart-wrap" id="chartRequests" aria-hidden="true"></div>
    </div>
    <div class="stats-chart-card">
      <h3>Zertifikate erstellt pro Tag</h3>
      <div class="stats-chart-wrap" id="chartCertsCreated" aria-hidden="true"></div>
    </div>
    <div class="stats-chart-card">
      <h3>Zertifikate widerrufen pro Tag</h3>
      <div class="stats-chart-wrap" id="chartCertsRevoked" aria-hidden="true"></div>
    </div>
    <div class="stats-chart-card">
      <h3>Zertifikate erneuert pro Tag</h3>
      <div class="stats-chart-wrap" id="chartCertsRenewed" aria-hidden="true"></div>
    </div>
    <div class="stats-chart-card">
      <h3>ACME-Bestellungen pro Tag</h3>
      <div class="stats-chart-wrap" id="chartAcmeOrders" aria-hidden="true"></div>
    </div>
    <div class="stats-chart-card">
      <h3>Zertifikate gesamt (Verlauf)</h3>
      <div class="stats-chart-wrap" id="chartCertsTotal" aria-hidden="true"></div>
    </div>
  </div>
    </div>
  </div>
  </section>

  </main>
  </div>

  <div id="caModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="caModalTitle" onclick="if(event.target===this) closeModal('caModal')">
    <div class="modal" onclick="event.stopPropagation()">
      <h3 id="caModalTitle">Root-CA erstellen</h3>
      <form id="caSetupForm" onsubmit="submitCaSetup(event); return false;">
        <label>Name (für die Liste)</label>
        <input type="text" name="name" placeholder="z. B. Meine CA" required>
        <label>Common Name (CN)</label>
        <input type="text" name="commonName" value="${htmlEscape(defaultCommonNameRoot)}" placeholder="z. B. Meine CA" required>
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
        <input type="text" name="commonName" value="${htmlEscape(defaultCommonNameIntermediate)}" placeholder="z. B. Intermediate CA" required>
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
    <div class="modal cert-view-modal" onclick="event.stopPropagation()" style="max-width:720px">
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
        <dt style="color:var(--gh-fg-muted);margin:0">Schlüsseltyp</dt>
        <dd style="margin:0" id="certViewKeyType">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Schlüssel</dt>
        <dd style="margin:0" id="certViewKeyInfo">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">Signaturalgorithmus</dt>
        <dd style="margin:0" id="certViewSignatureAlgorithm">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">X509v3 Basic Constraints</dt>
        <dd style="margin:0" id="certViewBasicConstraints">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">X509v3 Subject Key Identifier</dt>
        <dd style="margin:0" id="certViewSubjectKeyIdentifier">—</dd>
        <dt style="color:var(--gh-fg-muted);margin:0">X509v3 Key Usage</dt>
        <dd style="margin:0" id="certViewKeyUsage">—</dd>
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
        <p style="margin:12px 0 6px;font-size:13px;font-weight:600;color:var(--gh-fg-muted)">Subject-Details (optional)</p>
        <label style="font-size:13px">Organisation (O)</label>
        <input type="text" name="organization" id="certCreateOrganization" placeholder="z. B. Meine Firma GmbH" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
        <label style="font-size:13px">Organisationseinheit (OU)</label>
        <input type="text" name="organizationalUnit" id="certCreateOu" placeholder="z. B. IT" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
        <label style="font-size:13px">Land (C)</label>
        <input type="text" name="country" id="certCreateCountry" placeholder="z. B. DE" maxlength="2" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
        <label style="font-size:13px">Ort (L)</label>
        <input type="text" name="locality" id="certCreateLocality" placeholder="z. B. Berlin" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
        <label style="font-size:13px">Bundesland (ST)</label>
        <input type="text" name="stateOrProvince" id="certCreateState" placeholder="z. B. Berlin" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
        <label style="font-size:13px">E-Mail</label>
        <input type="email" name="email" id="certCreateEmail" placeholder="optional" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
        <label>Gültigkeit (Tage)</label>
        <input type="number" name="validityDays" value="365" min="1" max="825" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
        <label>Schlüsselart</label>
        <select name="keyAlgorithm" id="certCreateKeyAlgorithm" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="rsa-2048">RSA 2048 Bit</option>
          <option value="rsa-3072">RSA 3072 Bit</option>
          <option value="rsa-4096">RSA 4096 Bit</option>
          <option value="ec-p256">ECDSA P-256</option>
          <option value="ec-p384">ECDSA P-384</option>
        </select>
        <label>Hash-Algorithmus</label>
        <select name="hashAlgo" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="sha256">SHA-256</option>
          <option value="sha384">SHA-384</option>
          <option value="sha512">SHA-512</option>
        </select>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:12px;cursor:pointer">
          <input type="checkbox" name="ev" id="certCreateEv" value="1" style="width:auto">
          <span>EV-Zertifikat (Extended Validation)</span>
        </label>
        <div id="certCreateEvFields" style="display:none;margin-bottom:12px;padding:12px;background:var(--gh-canvas-subtle);border-radius:6px;border:1px solid var(--gh-border-default)">
          <p style="margin:0 0 10px;font-size:13px;font-weight:600">OID (PEN)</p>
          <label style="font-size:12px">Basis-ID (PEN)</label>
          <input type="text" name="policyOidBase" id="certCreatePolicyOidBase" placeholder="z. B. 1.3.6.1.4.1.52357" style="width:100%;padding:8px;margin-bottom:4px;box-sizing:border-box">
          <p style="margin:0 0 8px;font-size:11px;color:var(--gh-fg-muted)">Deine IANA Enterprise Number findest du im IANA-Register unter <a href="https://pen.iana.org" target="_blank" rel="noopener noreferrer" style="color:var(--gh-accent-fg)">pen.iana.org</a>.</p>
          <label style="font-size:12px">Sub-ID</label>
          <input type="text" name="policyOidSub" id="certCreatePolicyOidSub" placeholder="z. B. .1.1" style="width:100%;padding:8px;margin-bottom:10px;box-sizing:border-box">
          <p style="margin:0 0 10px;font-size:13px;font-weight:600">EV-Subject-Felder</p>
          <label style="font-size:12px">businessCategory</label>
          <input type="text" name="businessCategory" id="certCreateBusinessCategory" placeholder="z. B. Private Organization" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
          <label style="font-size:12px">jurisdictionCountryName</label>
          <input type="text" name="jurisdictionCountryName" id="certCreateJurisdictionCountryName" placeholder="z. B. DE" style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box">
          <label style="font-size:12px">serialNumber (Handelsregisternummer oder N/A)</label>
          <input type="text" name="serialNumber" id="certCreateSerialNumber" placeholder="z. B. HRB 12345 oder N/A" style="width:100%;padding:8px;margin-bottom:0;box-sizing:border-box">
        </div>
        <div id="certCreateSuccess" style="display:none;margin-bottom:12px;padding:12px;background:#e8f5e9;border-radius:6px;font-size:0.9em">
          <strong>Zertifikat erstellt.</strong>
          <p style="margin:8px 0 0 0"><a href="#" id="certCreateDownloadCert" class="btn" style="padding:4px 8px;font-size:0.85rem" download>Zertifikat herunterladen</a>
          <a href="#" id="certCreateDownloadKey" class="btn" style="padding:4px 8px;font-size:0.85rem;margin-left:4px" download>Schlüssel herunterladen</a>
          <a href="#" id="certCreateViewDetails" class="btn btn-view-cert" style="padding:4px 8px;font-size:0.85rem;margin-left:4px" data-cert-id="">Details anzeigen</a></p>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="closeModal('certCreateModal')">Abbrechen</button>
          <button type="submit" class="btn" id="certCreateSubmitBtn">Zertifikat erstellen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="caUploadModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="caUploadModalTitle" onclick="if(event.target===this) closeModal('caUploadModal')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:520px">
      <h3 id="caUploadModalTitle">CA hochladen</h3>
      <form id="caUploadForm" onsubmit="submitCaUpload(event); return false;">
        <label>Typ</label>
        <select name="caUploadType" id="caUploadType" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="root">Root-CA</option>
          <option value="intermediate">Intermediate-CA</option>
        </select>
        <div id="caUploadParentWrap" style="display:none;margin-bottom:12px">
          <label>Übergeordnete CA (Parent)</label>
          <select name="caUploadParentId" id="caUploadParentId" style="width:100%;padding:8px;box-sizing:border-box">
            <option value="">– Bitte wählen –</option>
          </select>
        </div>
        <label>Anzeigename (optional)</label>
        <input type="text" name="caUploadName" id="caUploadName" placeholder="z. B. Meine CA" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
        <label>Zertifikat (PEM)</label>
        <textarea name="caUploadCertPem" id="caUploadCertPem" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;..." style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:12px" required></textarea>
        <label>Privatschlüssel (PEM)</label>
        <textarea name="caUploadKeyPem" id="caUploadKeyPem" rows="5" placeholder="-----BEGIN PRIVATE KEY-----&#10;..." style="width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:12px" required></textarea>
        <div id="caUploadSuccess" style="display:none;margin-bottom:12px;padding:12px;background:#e8f5e9;border-radius:6px;font-size:0.9em">
          <strong>CA hochgeladen.</strong> <span id="caUploadSuccessId"></span>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="closeModal('caUploadModal')">Abbrechen</button>
          <button type="submit" class="btn" id="caUploadSubmitBtn">Hochladen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="certUploadModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="certUploadModalTitle" onclick="if(event.target===this) closeModal('certUploadModal')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:520px">
      <h3 id="certUploadModalTitle">Zertifikat hochladen</h3>
      <form id="certUploadForm" onsubmit="submitCertUpload(event); return false;">
        <label>Ausstellende CA (optional)</label>
        <select name="certUploadIssuerId" id="certUploadIssuerId" style="width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box">
          <option value="">– Keine / Unbekannt –</option>
        </select>
        <label>Zertifikat (PEM)</label>
        <textarea name="certUploadCertPem" id="certUploadCertPem" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;..." style="width:100%;padding:8px;margin-bottom:8px;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:12px" required></textarea>
        <label>Privatschlüssel (PEM)</label>
        <textarea name="certUploadKeyPem" id="certUploadKeyPem" rows="5" placeholder="-----BEGIN PRIVATE KEY-----&#10;..." style="width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:12px" required></textarea>
        <div id="certUploadSuccess" style="display:none;margin-bottom:12px;padding:12px;background:#e8f5e9;border-radius:6px;font-size:0.9em">
          <strong>Zertifikat hochgeladen.</strong> <a href="#" id="certUploadDownloadCert" class="btn" style="padding:4px 8px;font-size:0.85rem;margin-left:4px" download>Zertifikat</a> <a href="#" id="certUploadDownloadKey" class="btn" style="padding:4px 8px;font-size:0.85rem;margin-left:4px" download>Schlüssel</a>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="closeModal('certUploadModal')">Abbrechen</button>
          <button type="submit" class="btn" id="certUploadSubmitBtn">Hochladen</button>
        </div>
      </form>
    </div>
  </div>

  <div id="certRenewModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="certRenewModalTitle" onclick="if(event.target===this) closeModal('certRenewModal')">
    <div class="modal" onclick="event.stopPropagation()" style="max-width:420px">
      <h3 id="certRenewModalTitle">Zertifikat erneuern</h3>
      <p id="certRenewModalText" style="margin:0 0 16px;font-size:14px">Zertifikat für <strong id="certRenewDomain"></strong> erneuern? Das bestehende Zertifikat wird widerrufen und ein neues ausgestellt.</p>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" onclick="closeModal('certRenewModal')">Abbrechen</button>
        <button type="button" class="btn" id="certRenewConfirmBtn">Erneuern</button>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script type="application/json" id="initialData">${initialDataJson}</script>
  <script>
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
    var initialData = { cas: [], intermediates: [], caConfigured: false };
    try { var idEl = document.getElementById('initialData'); if (idEl && idEl.textContent) initialData = JSON.parse(idEl.textContent); } catch (e) {}
    function formatDnForDisplay(dnStr) {
      if (dnStr == null || dnStr === '') return '—';
      var parts = dnStr.split(', ');
      function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
      return parts.map(esc).join('<br>');
    }
    function formatIssuerForDisplay(subject, issuer) {
      if (issuer == null || issuer === '') return '—';
      if (subject != null && subject === issuer) return 'Wie Subject (selbstsigniert)';
      return formatDnForDisplay(issuer);
    }
    var resizeAndDrawHoneycomb = function() {};
    (function navInit() {
      var STORAGE_KEY = 'cert-manager-section';
      function showSection(sectionId) {
        document.querySelectorAll('.dashboard-section').forEach(function(el) { el.classList.remove('active'); });
        document.querySelectorAll('.gh-header-nav .nav-link').forEach(function(el) {
          el.classList.remove('active');
          el.removeAttribute('aria-current');
        });
        var section = document.getElementById('section-' + sectionId);
        var link = document.querySelector('.gh-header-nav .nav-link[data-section="' + sectionId + '"]');
        if (section) section.classList.add('active');
        if (link) { link.classList.add('active'); link.setAttribute('aria-current', 'page'); }
        try { localStorage.setItem(STORAGE_KEY, sectionId); } catch (e) {}
        if (sectionId === 'certificates' && typeof resizeAndDrawHoneycomb === 'function') {
          requestAnimationFrame(function() { resizeAndDrawHoneycomb(); });
        }
      }
      var saved = '';
      try { saved = localStorage.getItem(STORAGE_KEY) || ''; } catch (e) {}
      var valid = ['overview', 'acme', 'certificates', 'log', 'statistics'].indexOf(saved) >= 0;
      if (valid) showSection(saved); else showSection('overview');
      if (valid && saved === 'statistics' && typeof loadStatsCharts === 'function') try { loadStatsCharts(); } catch (e) {}
      document.querySelectorAll('.gh-header-nav .nav-link').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = this.getAttribute('data-section');
          if (id) {
            showSection(id);
            if (id === 'statistics') loadStatsCharts();
          }
        });
      });
    })();
    var statsChartsLoaded = false;
    function getLastDays(n) {
      var out = [];
      for (var i = n - 1; i >= 0; i--) {
        var d = new Date();
        d.setDate(d.getDate() - i);
        out.push(d.toISOString().slice(0, 10));
      }
      return out;
    }
    function mapToDays(daysArr, dataArr) {
      var map = {};
      (dataArr || []).forEach(function(o) { map[o.date] = o.count; });
      return daysArr.map(function(date) { return { date: date, count: map[date] || 0 }; });
    }
    var statsChartInstances = {};
    function getChartColor(cssVar, fallback) {
      try {
        var val = getComputedStyle(document.documentElement).getPropertyValue(cssVar).trim();
        if (val) return val;
      } catch (e) {}
      return fallback || '#0969da';
    }
    function createBarChart(containerId, data, colorKey) {
      var wrap = document.getElementById(containerId);
      if (!wrap || typeof Chart === 'undefined') return;
      try {
        wrap.innerHTML = '';
        var canvas = document.createElement('canvas');
        wrap.appendChild(canvas);
        var color = colorKey === 'requests' ? getChartColor('--gh-fg-muted', '#6e7781') : colorKey === 'revoked' ? getChartColor('--gh-danger', '#cf222e') : colorKey === 'renewed' ? getChartColor('--gh-success', '#1a7f37') : getChartColor('--gh-accent', '#0969da');
        var labels = data.map(function(d) { return d.date.slice(5); });
        var values = data.map(function(d) { return d.count; });
        var chart = new Chart(canvas, {
          type: 'bar',
          data: { labels: labels, datasets: [{ label: '', data: values, backgroundColor: color, borderColor: color, borderWidth: 1 }] },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { ticks: { maxRotation: 45, maxTicksLimit: 14, font: { size: 10 } }, grid: { display: false } },
              y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: 'var(--gh-border)' } }
            }
          }
        });
        statsChartInstances[containerId] = chart;
      } catch (err) {
        wrap.innerHTML = '<p class="stats-chart-empty">Diagramm konnte nicht geladen werden</p>';
      }
    }
    function createLineChart(containerId, data) {
      var wrap = document.getElementById(containerId);
      if (!wrap || typeof Chart === 'undefined') return;
      if (data.length < 2) {
        wrap.innerHTML = '<p class="stats-chart-empty">Nicht genug Daten für Verlauf</p>';
        return;
      }
      try {
        wrap.innerHTML = '';
        var canvas = document.createElement('canvas');
        wrap.appendChild(canvas);
        var color = getChartColor('--gh-accent', '#0969da');
        var labels = data.map(function(d) { return d.date.slice(5); });
        var values = data.map(function(d) { return d.count; });
        var chart = new Chart(canvas, {
          type: 'line',
          data: { labels: labels, datasets: [{ label: 'Gesamt', data: values, borderColor: color, backgroundColor: color + '20', fill: true, tension: 0.2, pointRadius: 2 }] },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { ticks: { maxRotation: 45, maxTicksLimit: 14, font: { size: 10 } }, grid: { display: false } },
              y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: 'var(--gh-border)' } }
            }
          }
        });
        statsChartInstances[containerId] = chart;
      } catch (err) {
        wrap.innerHTML = '<p class="stats-chart-empty">Diagramm konnte nicht geladen werden</p>';
      }
    }
    function loadStatsCharts() {
      if (statsChartsLoaded) return;
      statsChartsLoaded = true;
      try {
        Object.keys(statsChartInstances || {}).forEach(function(id) { var ch = statsChartInstances[id]; if (ch && typeof ch.destroy === 'function') ch.destroy(); statsChartInstances[id] = null; });
      } catch (e) {}
      statsChartInstances = {};
      fetch('/api/stats/history?days=30').then(function(res) { return res.json(); }).then(function(r) {
        var days = getLastDays(r.days || 30);
        var requests = mapToDays(days, r.requestsByDay || []);
        var created = mapToDays(days, r.certsCreatedByDay || []);
        var revoked = mapToDays(days, r.certsRevokedByDay || []);
        var renewed = mapToDays(days, r.certsRenewedByDay || []);
        var acme = mapToDays(days, r.acmeOrdersByDay || []);
        var cumulative = [];
        var total = 0;
        days.forEach(function(date) {
          var c = (r.certsCreatedByDay || []).find(function(o) { return o.date === date; });
          var rev = (r.certsRevokedByDay || []).find(function(o) { return o.date === date; });
          if (c) total += c.count;
          if (rev) total -= rev.count;
          cumulative.push({ date: date, count: total });
        });
        createBarChart('chartRequests', requests, 'requests');
        createBarChart('chartCertsCreated', created, '');
        createBarChart('chartCertsRevoked', revoked, 'revoked');
        createBarChart('chartCertsRenewed', renewed, 'renewed');
        createBarChart('chartAcmeOrders', acme, '');
        createLineChart('chartCertsTotal', cumulative);
      }).catch(function() {
        ['chartRequests', 'chartCertsCreated', 'chartCertsRevoked', 'chartCertsRenewed', 'chartAcmeOrders', 'chartCertsTotal'].forEach(function(id) {
          var el = document.getElementById(id);
          if (el) el.innerHTML = '<p class="stats-chart-empty">Daten konnten nicht geladen werden</p>';
        });
        statsChartsLoaded = false;
      });
    }
    function htmlEscape(s) {
      if (s == null) return '';
      var str = String(s);
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function attrEscape(s) { return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }
    function showError(msg) {
      var el = document.getElementById('toast');
      if (!el) return;
      el.textContent = msg;
      el.classList.add('show');
      clearTimeout(el._hideId);
      el._hideId = setTimeout(function() { el.classList.remove('show'); }, 5000);
    }
    var toastEl = document.getElementById('toast');
    if (toastEl) toastEl.addEventListener('click', function() { this.classList.remove('show'); });
    function closeModal(id) { var el = document.getElementById(id); if (el) el.classList.remove('open'); }
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        ['caModal', 'intermediateModal', 'certCreateModal', 'certViewModal', 'certRenewModal'].forEach(closeModal);
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
      var caNot = document.getElementById('caNotConfigured');
      var caYes = document.getElementById('caConfigured');
      if (caNot) caNot.style.display = configured ? 'none' : 'block';
      if (caYes) caYes.style.display = configured ? 'block' : 'none';
      var url = configured ? window.location.origin + '/acme/directory' : '';
      var urlEl = document.getElementById('caDirectoryUrl');
      if (urlEl) urlEl.textContent = url;
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
        var maxSecs = 5;
        var timerMax = wrapper.getAttribute('data-timer-max');
        if (timerMax) { var m = parseInt(timerMax, 10); if (!isNaN(m)) maxSecs = m; }
        var fill = wrapper.querySelector('.acme-validation-ring-fill');
        if (fill) fill.style.strokeDashoffset = String(100 * (1 - Math.min(maxSecs, secs) / maxSecs));
      });
    }, 1000);
    document.body.addEventListener('click', function(e) {
      var clickEl = e.target && e.target.nodeType === 3 ? e.target.parentElement : e.target;
      if (!clickEl) return;
      var viewCertBtn = clickEl.closest ? clickEl.closest('.btn-view-cert') : null;
      var viewCertId = viewCertBtn ? viewCertBtn.getAttribute('data-cert-id') : null;
      if (viewCertBtn && viewCertId) {
        e.preventDefault();
        e.stopPropagation();
        var modal = document.getElementById('certViewModal');
        if (modal) {
          modal.classList.add('open');
          document.getElementById('certViewModalTitle').textContent = 'Zertifikat-Details';
          document.querySelectorAll('.cert-view-cert-only').forEach(function(el) { el.style.display = ''; });
          document.querySelectorAll('.cert-view-ca-only').forEach(function(el) { el.style.display = 'none'; });
          document.querySelectorAll('.cert-view-int-only').forEach(function(el) { el.style.display = 'none'; });
          document.getElementById('certViewPem').textContent = 'Lade…';
          document.getElementById('certViewDownloads').innerHTML = '';
          fetch('/api/cert/info?id=' + encodeURIComponent(viewCertId)).then(function(res) {
            return res.json().then(function(d) {
              if (!res.ok) { throw new Error(d && d.error ? d.error : 'Laden fehlgeschlagen'); }
              return d;
            });
          }).then(function(d) {
            var fmt = function(v) { return v != null && v !== '' ? String(v) : '—'; };
            document.getElementById('certViewDomain').textContent = fmt(d.domain);
            document.getElementById('certViewSubject').innerHTML = formatDnForDisplay(d.subject);
            document.getElementById('certViewIssuer').innerHTML = formatIssuerForDisplay(d.subject, d.issuer);
            document.getElementById('certViewSerial').textContent = fmt(d.serialNumber);
            document.getElementById('certViewNotBefore').textContent = fmt(d.notBefore);
            document.getElementById('certViewNotAfter').textContent = fmt(d.notAfter);
            document.getElementById('certViewFingerprint').textContent = fmt(d.fingerprint256);
            document.getElementById('certViewKeyType').textContent = fmt(d.keyType);
            document.getElementById('certViewKeyInfo').textContent = fmt(d.keyInfo);
            document.getElementById('certViewSignatureAlgorithm').textContent = fmt(d.signatureAlgorithm);
            document.getElementById('certViewBasicConstraints').textContent = fmt(d.basicConstraints);
            document.getElementById('certViewSubjectKeyIdentifier').textContent = fmt(d.subjectKeyIdentifier);
            document.getElementById('certViewKeyUsage').textContent = fmt(d.keyUsage);
            document.getElementById('certViewSan').textContent = fmt(d.subjectAltName);
            document.getElementById('certViewCreatedAt').textContent = d.createdAt ? new Date(d.createdAt).toLocaleString() : '—';
            document.getElementById('certViewId').textContent = fmt(d.id);
            document.getElementById('certViewPem').textContent = d.pem || '—';
            var dl = document.getElementById('certViewDownloads');
            dl.innerHTML = '<a href="/api/cert/download?id=' + encodeURIComponent(d.id) + '" class="btn" download>Zertifikat herunterladen</a> <a href="/api/cert/key?id=' + encodeURIComponent(d.id) + '" class="btn" download>Schlüssel herunterladen</a>';
          }).catch(function(err) { showError(err && err.message ? err.message : 'Laden fehlgeschlagen'); document.getElementById('certViewPem').textContent = '—'; });
        }
        return;
      }
      var renewCertBtn = clickEl.closest ? clickEl.closest('.btn-renew') : null;
      if (renewCertBtn) {
        e.preventDefault();
        e.stopPropagation();
        var certId = renewCertBtn.getAttribute('data-cert-id');
        var domain = renewCertBtn.getAttribute('data-cert-domain');
        if (certId && domain != null) {
          document.getElementById('certRenewDomain').textContent = domain.replace(/&quot;/g, '"');
          var confirmBtn = document.getElementById('certRenewConfirmBtn');
          if (confirmBtn) confirmBtn.setAttribute('data-cert-id', certId);
          document.getElementById('certRenewModal').classList.add('open');
        }
        return;
      }
      var viewCaBtn = clickEl.closest ? clickEl.closest('.btn-view-ca') : null;
      if (viewCaBtn) {
        e.preventDefault();
        e.stopPropagation();
        var caId = viewCaBtn.getAttribute('data-ca-id');
        var caType = viewCaBtn.getAttribute('data-ca-type') || '';
        if (caId) {
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
            document.getElementById('certViewSubject').innerHTML = formatDnForDisplay(d.subject);
            document.getElementById('certViewIssuer').innerHTML = formatIssuerForDisplay(d.subject, d.issuer);
            document.getElementById('certViewSerial').textContent = fmt(d.serialNumber);
            document.getElementById('certViewNotBefore').textContent = fmt(d.notBefore);
            document.getElementById('certViewNotAfter').textContent = fmt(d.notAfter);
            document.getElementById('certViewFingerprint').textContent = fmt(d.fingerprint256);
            document.getElementById('certViewKeyType').textContent = fmt(d.keyType);
            document.getElementById('certViewKeyInfo').textContent = fmt(d.keyInfo);
            document.getElementById('certViewSignatureAlgorithm').textContent = fmt(d.signatureAlgorithm);
            document.getElementById('certViewBasicConstraints').textContent = fmt(d.basicConstraints);
            document.getElementById('certViewSubjectKeyIdentifier').textContent = fmt(d.subjectKeyIdentifier);
            document.getElementById('certViewKeyUsage').textContent = fmt(d.keyUsage);
            document.getElementById('certViewCreatedAt').textContent = d.createdAt ? new Date(d.createdAt).toLocaleString() : '—';
            document.getElementById('certViewId').textContent = fmt(d.id);
            document.getElementById('certViewPem').textContent = d.pem || '—';
            var dl = document.getElementById('certViewDownloads');
            dl.innerHTML = '<a href="/api/ca-cert?id=' + encodeURIComponent(d.id) + '" class="btn" download>Zertifikat herunterladen</a>';
          }).catch(function(err) { showError(err && err.message ? err.message : 'Laden fehlgeschlagen'); document.getElementById('certViewPem').textContent = '—'; });
        }
        return;
      }
      var acceptAcmeBtn = clickEl.closest ? clickEl.closest('.btn-accept-acme-authz') : null;
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
      var delAcmeBtn = clickEl.closest ? clickEl.closest('.btn-delete-acme-authz') : null;
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
      var delChBtn = clickEl.closest ? clickEl.closest('.btn-delete-challenge') : null;
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
      var delWhitelistBtn = clickEl.closest ? clickEl.closest('.btn-delete-acme-whitelist') : null;
      if (delWhitelistBtn) {
        e.preventDefault();
        var wid = delWhitelistBtn.getAttribute('data-id');
        if (wid) {
          delWhitelistBtn.disabled = true;
          fetch('/api/acme-whitelist?id=' + encodeURIComponent(wid), { method: 'DELETE' }).then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Löschen fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Löschen fehlgeschlagen'); }).finally(function() { delWhitelistBtn.disabled = false; });
        }
        return;
      }
      var delCaAssignmentBtn = clickEl.closest ? clickEl.closest('.btn-delete-acme-ca-assignment') : null;
      if (delCaAssignmentBtn) {
        e.preventDefault();
        var pattern = delCaAssignmentBtn.getAttribute('data-pattern');
        if (pattern) {
          delCaAssignmentBtn.disabled = true;
          fetch('/api/acme-ca-assignments?pattern=' + encodeURIComponent(pattern), { method: 'DELETE' }).then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); }).then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Zuordnung löschen fehlgeschlagen'));
          }).catch(function(err) { showError(err && err.message ? err.message : 'Zuordnung löschen fehlgeschlagen'); }).finally(function() { delCaAssignmentBtn.disabled = false; });
        }
        return;
      }
      var btn = clickEl.closest ? clickEl.closest('[data-ca-id]') : null;
      if (btn && !btn.classList.contains('btn-view-ca') && !btn.classList.contains('btn-view-cert')) {
        e.preventDefault();
        activateCa(btn.getAttribute('data-ca-id'));
      }
    });
    async function activateCa(id) {
      const res = await fetch('/api/ca/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id }) });
      if (!res.ok) { showError('Fehler: ' + ((await res.json().catch(function() { return {}; })).error || res.status)); return; }
      location.reload();
    }
    var acmeWhitelistForm = document.getElementById('acmeWhitelistForm');
    if (acmeWhitelistForm) {
      acmeWhitelistForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var input = document.getElementById('acmeWhitelistDomain');
        var domain = input && input.value ? input.value.trim().toLowerCase() : '';
        if (!domain) { showError('Bitte eine Domain eingeben.'); return; }
        acmeWhitelistForm.querySelector('button[type="submit"]').disabled = true;
        fetch('/api/acme-whitelist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: domain }) })
          .then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); })
          .then(function(r) {
            if (r.ok) { input.value = ''; location.reload(); } else { showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Hinzufügen fehlgeschlagen')); }
          })
          .catch(function(err) { showError(err && err.message ? err.message : 'Hinzufügen fehlgeschlagen'); })
          .finally(function() { acmeWhitelistForm.querySelector('button[type="submit"]').disabled = false; });
      });
    }
    var acmeCaAssignmentsForm = document.getElementById('acmeCaAssignmentsForm');
    if (acmeCaAssignmentsForm) {
      acmeCaAssignmentsForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var patternInput = document.getElementById('acmeCaAssignmentPattern');
        var caSelect = document.getElementById('acmeCaAssignmentCa');
        var pattern = patternInput && patternInput.value ? patternInput.value.trim().toLowerCase() : '';
        var caId = caSelect && caSelect.value ? caSelect.value : '';
        if (!pattern) { showError('Bitte Domain oder Muster eingeben (z. B. example.com oder *.example.com)'); return; }
        if (!caId) { showError('Bitte eine CA auswählen'); return; }
        acmeCaAssignmentsForm.querySelector('button[type="submit"]').disabled = true;
        fetch('/api/acme-ca-assignments', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain_pattern: pattern, ca_id: caId }) })
          .then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); })
          .then(function(r) {
            if (r.ok) { patternInput.value = ''; caSelect.value = ''; location.reload(); } else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Zuordnung hinzufügen fehlgeschlagen'));
          })
          .catch(function(err) { showError(err && err.message ? err.message : 'Zuordnung hinzufügen fehlgeschlagen'); })
          .finally(function() { acmeCaAssignmentsForm.querySelector('button[type="submit"]').disabled = false; });
      });
    }
    var acmeDefaultIntermediateForm = document.getElementById('acmeDefaultIntermediateForm');
    if (acmeDefaultIntermediateForm) {
      acmeDefaultIntermediateForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var selectEl = document.getElementById('acmeDefaultIntermediateSelect');
        var id = selectEl && selectEl.value ? selectEl.value.trim() : null;
        acmeDefaultIntermediateForm.querySelector('button[type="submit"]').disabled = true;
        fetch('/api/acme-default-intermediate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id || null }) })
          .then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); })
          .then(function(r) {
            if (r.ok) location.reload(); else showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Standard-Intermediate setzen fehlgeschlagen'));
          })
          .catch(function(err) { showError(err && err.message ? err.message : 'Standard-Intermediate setzen fehlgeschlagen'); })
          .finally(function() { acmeDefaultIntermediateForm.querySelector('button[type="submit"]').disabled = false; });
      });
    }
    updateCaCard(initialData.caConfigured);
    function buildCertTreeHtml(certs, casList, intList) {
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
        var isExpired = cert.not_after ? new Date(cert.not_after) < new Date() : false;
        var isAcme = cert.ca_certificate_id != null && cert.ca_certificate_id !== 0;
        var isEv = cert.is_ev != null && cert.is_ev !== 0;
        var metaText = (isRevoked ? 'Widerrufen · Gültig bis ' + validUntil : 'Gültig bis ' + validUntil) + (isAcme ? ' · ACME' : '') + (isEv ? ' · EV' : '');
        var revokeBtn = (isRevoked || isExpired) ? '' : '<button type="button" class="btn btn-revoke" data-cert-id="' + cert.id + '" title="Zertifikat widerrufen">Widerrufen</button> ';
        var renewBtn = (isRevoked || isAcme) ? '' : '<button type="button" class="btn btn-renew" data-cert-id="' + cert.id + '" data-cert-domain="' + attrEscape(cert.domain) + '" title="Zertifikat erneuern">Erneuern</button> ';
        var actions = '<button type="button" class="btn btn-view-cert" data-cert-id="' + cert.id + '" data-cert-domain="' + attrEscape(cert.domain) + '" data-cert-not-after="' + attrEscape(validUntil) + '" data-cert-created-at="' + attrEscape(createdAt) + '" data-cert-issuer="' + attrEscape(issuerName) + '" title="Details anzeigen">View</button> ' + (cert.has_pem ? '<a href="/api/cert/download?id=' + cert.id + '" class="btn" download>Zertifikat</a> <a href="/api/cert/key?id=' + cert.id + '" class="btn" download>Schlüssel</a> ' : '') + revokeBtn + renewBtn + '<button type="button" class="btn btn-delete" data-cert-id="' + cert.id + '" title="Zertifikat löschen">Löschen</button>';
        var evBadge = isEv ? ' <span class="cert-tree__badge cert-tree__badge--ev" title="Extended Validation">EV</span>' : '';
        return '<li class="cert-tree__item cert-tree__item--depth-' + depth + (isRevoked ? ' cert-tree__item--revoked' : '') + '"><span class="cert-tree__label">' + htmlEscape(cert.domain) + evBadge + '</span><span class="cert-tree__meta">' + metaText + '</span><span class="cert-tree__actions">' + actions + '</span></li>';
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
          childParts.push('<li class="cert-tree__branch" data-branch-id="int-' + attrEscape(int.id) + '">' + togglerRow(1, htmlEscape(int.name) + ' <span class="cert-tree__meta">(Intermediate CA)</span>', 'Gültig bis ' + intValidUntil, intActions) + '<ul class="cert-tree__children">' + intChildRows + '</ul></li>');
        });
        certs.filter(function(c) { return c.issuer_id === root.id; }).forEach(function(c) { childParts.push(certRow(c, 1)); });
        parts.push('<li class="cert-tree__branch" data-branch-id="' + attrEscape(root.id) + '">' + togglerRow(0, htmlEscape(root.name) + ' <span class="cert-tree__meta">(Root-CA)</span>', (root.isActive ? 'Aktiv · ' : '') + 'Gültig bis ' + rootValidUntil, rootActions) + '<ul class="cert-tree__children">' + childParts.join('') + '</ul></li>');
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
    var lastCertTreeData = { certs: [], cas: [], ints: [] };
    function updateCertTree(certs, casList, intList) {
      var el = document.getElementById('certTree');
      if (!el) return;
      lastCertTreeData = { certs: certs || [], cas: casList || [], ints: intList || [] };
      el.innerHTML = buildCertTreeHtml(certs, casList, intList);
      applyStoredCollapsedState();
      drawCertHoneycomb(lastCertTreeData.certs, lastCertTreeData.cas, lastCertTreeData.ints);
    }
    function drawCertHoneycomb(certs, casList, intList) {
      var canvas = document.getElementById('certHoneycombCanvas');
      if (!canvas) return;
      var ctx = canvas.getContext('2d');
      if (!ctx) return;
      casList = casList || [];
      intList = intList || [];
      certs = certs || [];
      var HEX_SIZE = 14;
      var SQ3 = Math.sqrt(3);
      function hexToPixel(q, r) {
        var x = HEX_SIZE * (SQ3 * q + SQ3 / 2 * r);
        var y = HEX_SIZE * (3 / 2 * r);
        return { x: x, y: y };
      }
      var dirs = [{ q: 0, r: -1 }, { q: 1, r: -1 }, { q: 1, r: 0 }, { q: 0, r: 1 }, { q: -1, r: 1 }, { q: -1, r: 0 }];
      var nodes = [];
      var used = {};
      function takeHex(q, r) {
        var key = q + ',' + r;
        if (used[key]) return false;
        used[key] = true;
        return true;
      }
      function hexDist(q1, r1, q2, r2) {
        return (Math.abs(q1 - q2) + Math.abs(r1 - r2) + Math.abs(q1 + r1 - q2 - r2)) / 2;
      }
      /** Erzeugt Zellen in Ringen um (cq, cr): zuerst Ring fromRing, dann fromRing+1, … (ältere Ringe = näher, neuere weiter außen). */
      function cellsAroundCenter(cq, cr, fromRing, maxCells) {
        var visited = {};
        visited[cq + ',' + cr] = true;
        var frontier = [{ q: cq, r: cr }];
        var currentRing = 0;
        var out = [];
        while (out.length < maxCells && frontier.length > 0) {
          if (currentRing >= fromRing) {
            for (var i = 0; i < frontier.length && out.length < maxCells; i++) out.push({ q: frontier[i].q, r: frontier[i].r });
          }
          if (out.length >= maxCells) break;
          var next = [];
          for (var i = 0; i < frontier.length; i++) {
            var cell = frontier[i];
            for (var d = 0; d < 6; d++) {
              var nq = cell.q + dirs[d].q, nr = cell.r + dirs[d].r;
              var key = nq + ',' + nr;
              if (!visited[key]) { visited[key] = true; next.push({ q: nq, r: nr }); }
            }
          }
          frontier = next;
          currentRing++;
        }
        return out;
      }
      var rootOffsets = [];
      for (var ri = 0; ri < casList.length; ri++) rootOffsets.push({ q: ri - (casList.length - 1) / 2, r: 0 });
      casList.forEach(function(root, ri) {
        var o = rootOffsets[ri];
        var q = Math.round(o.q), r = Math.round(o.r);
        if (!takeHex(q, r)) { q = 0; r = 0; takeHex(0, 0); }
        nodes.push({ type: 'root', id: root.id, label: root.name, q: q, r: r, issuerId: null });
      });
      var rootNodes = nodes.slice();
      casList.forEach(function(root, ri) {
        var rootNode = nodes.find(function(n) { return n.type === 'root' && n.id === root.id; });
        if (!rootNode) return;
        var ints = intList.filter(function(i) { return i.parentCaId === root.id; });
        var directCerts = certs.filter(function(c) { return c.issuer_id === root.id; });
        directCerts = directCerts.slice().sort(function(a, b) {
          var ta = (a.created_at && new Date(a.created_at).getTime()) || 0;
          var tb = (b.created_at && new Date(b.created_at).getTime()) || 0;
          return ta - tb;
        });
        var ring1 = [];
        for (var d = 0; d < 6; d++) ring1.push({ q: rootNode.q + dirs[d].q, r: rootNode.r + dirs[d].r });
        var idx = 0;
        ints.forEach(function(int) {
          var cell = ring1[idx % ring1.length];
          idx++;
          if (!takeHex(cell.q, cell.r)) return;
          nodes.push({ type: 'intermediate', id: int.id, label: int.name, q: cell.q, r: cell.r, issuerId: root.id });
        });
        var rawCellsDirect = cellsAroundCenter(rootNode.q, rootNode.r, 2, directCerts.length * 3);
        var cellsForDirect = rawCellsDirect.filter(function(cell) {
          return rootNodes.every(function(rn) { return hexDist(cell.q, cell.r, rn.q, rn.r) >= 2; });
        });
        var cellIdx = 0;
        directCerts.forEach(function(c) {
          while (cellIdx < cellsForDirect.length) {
            var cell = cellsForDirect[cellIdx++];
            if (takeHex(cell.q, cell.r)) {
              nodes.push({ type: 'cert', id: String(c.id), label: c.domain, q: cell.q, r: cell.r, issuerId: root.id, revoked: c.revoked, not_after: c.not_after });
              break;
            }
          }
        });
      });
      intList.forEach(function(int) {
        var intNode = nodes.find(function(n) { return n.type === 'intermediate' && n.id === int.id; });
        if (!intNode) return;
        var parentRoot = nodes.find(function(n) { return n.type === 'root' && n.id === int.parentCaId; });
        var childCerts = certs.filter(function(c) { return c.issuer_id === int.id; });
        childCerts = childCerts.slice().sort(function(a, b) {
          var ta = (a.created_at && new Date(a.created_at).getTime()) || 0;
          var tb = (b.created_at && new Date(b.created_at).getTime()) || 0;
          return ta - tb;
        });
        var rawCellsChild = cellsAroundCenter(intNode.q, intNode.r, 1, childCerts.length * 3);
        var cellsForChild = rawCellsChild.filter(function(cell) {
          if (!parentRoot) return true;
          return hexDist(cell.q, cell.r, parentRoot.q, parentRoot.r) >= 2;
        });
        var cellIdx = 0;
        childCerts.forEach(function(c) {
          while (cellIdx < cellsForChild.length) {
            var cell = cellsForChild[cellIdx++];
            if (takeHex(cell.q, cell.r)) {
              nodes.push({ type: 'cert', id: String(c.id), label: c.domain, q: cell.q, r: cell.r, issuerId: int.id, revoked: c.revoked, not_after: c.not_after });
              break;
            }
          }
        });
      });
      var certsNoIssuer = certs.filter(function(c) { return !c.issuer_id; });
      if (certsNoIssuer.length > 0 && casList.length === 0) {
        certsNoIssuer.forEach(function(c, ci) {
          var d = dirs[ci % 6];
          var q = d.q * (ci + 1), r = d.r * (ci + 1);
          if (!takeHex(q, r)) return;
          nodes.push({ type: 'cert', id: String(c.id), label: c.domain, q: q, r: r, issuerId: null, revoked: c.revoked, not_after: c.not_after });
        });
      }
      if (nodes.length === 0) {
        ctx.fillStyle = 'var(--gh-canvas-subtle)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = 'var(--gh-fg-muted)';
        ctx.font = '14px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText('Keine CAs oder Zertifikate', canvas.width / 2, canvas.height / 2);
        return;
      }
      var minQ = nodes[0].q, maxQ = nodes[0].q, minR = nodes[0].r, maxR = nodes[0].r;
      nodes.forEach(function(n) {
        if (n.q < minQ) minQ = n.q; if (n.q > maxQ) maxQ = n.q;
        if (n.r < minR) minR = n.r; if (n.r > maxR) maxR = n.r;
      });
      var pad = HEX_SIZE * 2;
      var p0 = hexToPixel(minQ, minR);
      var p1 = hexToPixel(maxQ, maxR);
      var w = p1.x - p0.x + 2 * pad;
      var h = p1.y - p0.y + 2 * pad;
      var fitScale = Math.min((canvas.width - 2 * pad) / w, (canvas.height - 2 * pad) / h);
      var scale = Math.max(1.1, fitScale);
      var cx = (minQ + maxQ) / 2, cy = (minR + maxR) / 2;
      var centerPx = hexToPixel(cx, cy);
      var offsetX = canvas.width / 2 - centerPx.x * scale;
      var offsetY = canvas.height / 2 - centerPx.y * scale;
      function toScreen(q, r) {
        var p = hexToPixel(q, r);
        return { x: offsetX + p.x * scale, y: offsetY + p.y * scale };
      }
      var maxDist = 0;
      nodes.forEach(function(n) {
        var d = (Math.abs(n.q) + Math.abs(n.r) + Math.abs(n.q + n.r)) / 2;
        if (d > maxDist) maxDist = d;
      });
      maxDist = Math.max(maxDist, 1);
      var nodeKeys = {};
      nodes.forEach(function(n) { nodeKeys[n.q + ',' + n.r] = true; });
      function hexDist(q1, r1, q2, r2) {
        return (Math.abs(q1 - q2) + Math.abs(r1 - r2) + Math.abs(q1 + r1 - q2 - r2)) / 2;
      }
      var bgCells = [];
      var bgSeen = {};
      function addBg(q, r) {
        var key = q + ',' + r;
        if (nodeKeys[key] || bgSeen[key]) return;
        bgSeen[key] = true;
        bgCells.push({ q: q, r: r });
      }
      nodes.forEach(function(n) {
        for (var d = 0; d < 6; d++) addBg(n.q + dirs[d].q, n.r + dirs[d].r);
      });
      var ring1Count = bgCells.length;
      for (var bi = 0; bi < ring1Count; bi++) {
        var c = bgCells[bi];
        for (var d = 0; d < 6; d++) addBg(c.q + dirs[d].q, c.r + dirs[d].r);
      }
      var rootColor = '#0969da';
      try { var v = getComputedStyle(document.documentElement).getPropertyValue('--gh-accent').trim(); if (v) rootColor = v; } catch (e) {}
      var rootHex = rootColor.indexOf('var(') >= 0 ? '#0969da' : rootColor;
      var certRedHex = '#cf2222';
      try { var danger = getComputedStyle(document.documentElement).getPropertyValue('--gh-danger').trim(); if (danger) certRedHex = danger; } catch (e) {}
      if (certRedHex.indexOf('var(') >= 0) certRedHex = '#cf2222';
      function lighten(hex, pct) {
        var num = parseInt(hex.slice(1), 16); if (isNaN(num)) return '#58a6ff';
        var r = (num >> 16) & 255, g = (num >> 8) & 255, b = num & 255;
        r = Math.min(255, Math.round(r + (255 - r) * pct)); g = Math.min(255, Math.round(g + (255 - g) * pct)); b = Math.min(255, Math.round(b + (255 - b) * pct));
        return '#' + (r << 16 | g << 8 | b).toString(16).padStart(6, '0');
      }
      function blendHex(hex1, hex2, t) {
        t = Math.max(0, Math.min(1, t));
        var n1 = parseInt(hex1.slice(1), 16), n2 = parseInt(hex2.slice(1), 16);
        if (isNaN(n1) || isNaN(n2)) return hex1;
        var r = Math.round(((n1 >> 16) & 255) * (1 - t) + ((n2 >> 16) & 255) * t);
        var g = Math.round(((n1 >> 8) & 255) * (1 - t) + ((n2 >> 8) & 255) * t);
        var b = Math.round((n1 & 255) * (1 - t) + (n2 & 255) * t);
        return '#' + (r << 16 | g << 8 | b).toString(16).padStart(6, '0');
      }
      var certFillHex = lighten(rootHex, 0.6);
      var strokeColor = 'rgba(0,0,0,0.35)';
      try { var border = getComputedStyle(document.documentElement).getPropertyValue('--gh-border-default').trim(); if (border) strokeColor = border; } catch (e) {}
      if (strokeColor.indexOf('var(') >= 0) strokeColor = 'rgba(0,0,0,0.35)';
      var hexRadius = HEX_SIZE * scale;
      function drawHexAt(q, r, fillStyle, strokeOpacity) {
        var center = toScreen(q, r);
        ctx.beginPath();
        for (var i = 0; i < 6; i++) {
          var a = (Math.PI / 2) - (i * Math.PI / 3);
          var sx = center.x + hexRadius * Math.cos(a);
          var sy = center.y + hexRadius * Math.sin(a);
          if (i === 0) ctx.moveTo(sx, sy); else ctx.lineTo(sx, sy);
        }
        ctx.closePath();
        ctx.fillStyle = fillStyle;
        ctx.fill();
        ctx.strokeStyle = strokeOpacity != null ? strokeColor.replace('0.35', String(strokeOpacity)) : strokeColor;
        if (strokeOpacity != null && strokeColor.indexOf('rgba') === -1) ctx.strokeStyle = 'rgba(0,0,0,' + strokeOpacity + ')';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      bgCells.forEach(function(c) {
        var dist = Infinity;
        nodes.forEach(function(n) { var d = hexDist(c.q, c.r, n.q, n.r); if (d < dist) dist = d; });
        var opacity = Math.max(0, 0.35 - dist * 0.12);
        if (opacity <= 0) return;
        var fill = certFillHex;
        var num = parseInt(fill.slice(1), 16);
        if (!isNaN(num)) {
          var r = (num >> 16) & 255, g = (num >> 8) & 255, b = num & 255;
          ctx.fillStyle = 'rgba(' + r + ',' + g + ',' + b + ',' + opacity + ')';
        } else ctx.fillStyle = fill;
        var center = toScreen(c.q, c.r);
        ctx.beginPath();
        for (var i = 0; i < 6; i++) {
          var a = (Math.PI / 2) - (i * Math.PI / 3);
          var sx = center.x + hexRadius * Math.cos(a);
          var sy = center.y + hexRadius * Math.sin(a);
          if (i === 0) ctx.moveTo(sx, sy); else ctx.lineTo(sx, sy);
        }
        ctx.closePath();
        ctx.fill();
        ctx.strokeStyle = 'rgba(0,0,0,' + (opacity * 0.6) + ')';
        ctx.lineWidth = 1;
        ctx.stroke();
      });
      var now = Date.now();
      var expireWarnDays = 30;
      nodes.forEach(function(n) {
        var dist = (Math.abs(n.q) + Math.abs(n.r) + Math.abs(n.q + n.r)) / 2;
        var fade = 1 - (dist / maxDist) * 0.5;
        var base = n.type === 'root' ? rootHex : n.type === 'intermediate' ? lighten(rootHex, 0.35) : lighten(rootHex, 0.6);
        if (n.type === 'cert') {
          if (n.revoked) base = certRedHex;
          else if (n.not_after) {
            var notAfterMs = new Date(n.not_after).getTime();
            var daysLeft = (notAfterMs - now) / (24 * 60 * 60 * 1000);
            if (daysLeft <= 0) base = certRedHex;
            else if (daysLeft < expireWarnDays) {
              var redAmount = 1 - daysLeft / expireWarnDays;
              base = blendHex(certFillHex, certRedHex, redAmount);
            }
          }
        }
        var fill = base;
        if (fade < 1) {
          var num = parseInt(base.slice(1), 16);
          if (!isNaN(num)) {
            var r = (num >> 16) & 255, g = (num >> 8) & 255, b = num & 255;
            r = Math.round(r + (255 - r) * (1 - fade)); g = Math.round(g + (255 - g) * (1 - fade)); b = Math.round(b + (255 - b) * (1 - fade));
            fill = '#' + (r << 16 | g << 8 | b).toString(16).padStart(6, '0');
          }
        }
        drawHexAt(n.q, n.r, fill);
      });
    }
    var certTreeEl = document.getElementById('certTree');
    if (certTreeEl) certTreeEl.addEventListener('click', function(e) {
      var clickEl = e.target && e.target.nodeType === 3 ? e.target.parentElement : e.target;
      if (!clickEl || !clickEl.closest) return;
      var delCaBtn = clickEl.closest('.btn-delete-ca');
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
      var viewBtn = clickEl.closest('.btn-view-cert');
      var certId = viewBtn ? viewBtn.getAttribute('data-cert-id') : null;
      if (viewBtn && certId) {
        e.preventDefault();
        e.stopPropagation();
        var modal = document.getElementById('certViewModal');
        if (!modal) return;
        modal.classList.add('open');
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
          document.getElementById('certViewSubject').innerHTML = formatDnForDisplay(d.subject);
          document.getElementById('certViewIssuer').innerHTML = formatIssuerForDisplay(d.subject, d.issuer);
          document.getElementById('certViewSerial').textContent = fmt(d.serialNumber);
          document.getElementById('certViewNotBefore').textContent = fmt(d.notBefore);
          document.getElementById('certViewNotAfter').textContent = fmt(d.notAfter);
          document.getElementById('certViewFingerprint').textContent = fmt(d.fingerprint256);
          document.getElementById('certViewKeyType').textContent = fmt(d.keyType);
          document.getElementById('certViewKeyInfo').textContent = fmt(d.keyInfo);
          document.getElementById('certViewSignatureAlgorithm').textContent = fmt(d.signatureAlgorithm);
          document.getElementById('certViewBasicConstraints').textContent = fmt(d.basicConstraints);
          document.getElementById('certViewSubjectKeyIdentifier').textContent = fmt(d.subjectKeyIdentifier);
          document.getElementById('certViewKeyUsage').textContent = fmt(d.keyUsage);
          document.getElementById('certViewSan').textContent = fmt(d.subjectAltName);
          document.getElementById('certViewCreatedAt').textContent = d.createdAt ? new Date(d.createdAt).toLocaleString() : '—';
          document.getElementById('certViewId').textContent = fmt(d.id);
          document.getElementById('certViewPem').textContent = d.pem || '—';
          var dl = document.getElementById('certViewDownloads');
          dl.innerHTML = '<a href="/api/cert/download?id=' + encodeURIComponent(d.id) + '" class="btn" download>Zertifikat herunterladen</a> <a href="/api/cert/key?id=' + encodeURIComponent(d.id) + '" class="btn" download>Schlüssel herunterladen</a>';
        }).catch(function(err) { showError(err && err.message ? err.message : 'Laden fehlgeschlagen'); document.getElementById('certViewPem').textContent = '—'; });
        return;
      }
      var viewCaBtn = clickEl.closest('.btn-view-ca');
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
          document.getElementById('certViewSubject').innerHTML = formatDnForDisplay(d.subject);
          document.getElementById('certViewIssuer').innerHTML = formatIssuerForDisplay(d.subject, d.issuer);
          document.getElementById('certViewSerial').textContent = fmt(d.serialNumber);
          document.getElementById('certViewNotBefore').textContent = fmt(d.notBefore);
          document.getElementById('certViewNotAfter').textContent = fmt(d.notAfter);
          document.getElementById('certViewFingerprint').textContent = fmt(d.fingerprint256);
          document.getElementById('certViewKeyType').textContent = fmt(d.keyType);
          document.getElementById('certViewKeyInfo').textContent = fmt(d.keyInfo);
            document.getElementById('certViewSignatureAlgorithm').textContent = fmt(d.signatureAlgorithm);
            document.getElementById('certViewBasicConstraints').textContent = fmt(d.basicConstraints);
            document.getElementById('certViewSubjectKeyIdentifier').textContent = fmt(d.subjectKeyIdentifier);
            document.getElementById('certViewKeyUsage').textContent = fmt(d.keyUsage);
            document.getElementById('certViewCreatedAt').textContent = d.createdAt ? new Date(d.createdAt).toLocaleString() : '—';
            document.getElementById('certViewId').textContent = fmt(d.id);
            document.getElementById('certViewPem').textContent = d.pem || '—';
            var dl = document.getElementById('certViewDownloads');
            dl.innerHTML = '<a href="/api/ca-cert?id=' + encodeURIComponent(d.id) + '" class="btn" download>Zertifikat herunterladen</a>';
        }).catch(function(err) { showError(err && err.message ? err.message : 'Laden fehlgeschlagen'); document.getElementById('certViewPem').textContent = '—'; });
        return;
      }
      var renewBtn = clickEl.closest('.btn-renew');
      if (renewBtn) {
        e.preventDefault();
        e.stopPropagation();
        var certId = renewBtn.getAttribute('data-cert-id');
        var domain = renewBtn.getAttribute('data-cert-domain');
        if (certId && domain != null) {
          document.getElementById('certRenewDomain').textContent = domain.replace(/&quot;/g, '"');
          var confirmBtn = document.getElementById('certRenewConfirmBtn');
          if (confirmBtn) { confirmBtn.setAttribute('data-cert-id', certId); }
          document.getElementById('certRenewModal').classList.add('open');
        }
        return;
      }
      var revokeBtn = clickEl.closest('.btn-revoke');
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
      var delBtn = clickEl.closest('.btn-delete');
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
      var toggler = clickEl.closest('.cert-tree__toggler');
      if (!toggler || clickEl.closest('.cert-tree__actions')) return;
      var branch = toggler.closest('.cert-tree__branch');
      if (!branch) return;
      var expanded = branch.classList.toggle('cert-tree__branch--collapsed');
      toggler.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      var arrow = toggler.querySelector('.cert-tree__toggle');
      if (arrow) arrow.textContent = expanded ? '▶' : '▼';
      saveCollapsedState();
    });
    if (certTreeEl) certTreeEl.addEventListener('keydown', function(e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var keyEl = e.target && e.target.nodeType === 3 ? e.target.parentElement : e.target;
      var toggler = keyEl && keyEl.closest ? keyEl.closest('.cert-tree__toggler') : null;
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
    resizeAndDrawHoneycomb = function() {
      var canvas = document.getElementById('certHoneycombCanvas');
      var wrap = canvas && canvas.closest('.cert-honeycomb-wrap');
      if (canvas && wrap && wrap.offsetWidth) {
        canvas.width = wrap.offsetWidth;
        canvas.height = Math.min(360, Math.max(200, Math.round(wrap.offsetWidth * 0.45)));
      }
      var data = lastCertTreeData || { certs: initialData.certificates || [], cas: initialData.cas || [], ints: initialData.intermediates || [] };
      drawCertHoneycomb(data.certs, data.cas, data.ints);
    };
    resizeAndDrawHoneycomb();
    window.addEventListener('resize', resizeAndDrawHoneycomb);
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
        name: getFormVal(form, 'name') || getFormVal(form, 'commonName') || '${escapeForScript(defaultCommonNameIntermediate)}',
        commonName: getFormVal(form, 'commonName') || '${escapeForScript(defaultCommonNameIntermediate)}',
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
      var evCheck = document.getElementById('certCreateEv');
      var evFields = document.getElementById('certCreateEvFields');
      if (evCheck) { evCheck.checked = false; }
      if (evFields) { evFields.style.display = 'none'; }
      document.getElementById('certCreateModal').classList.add('open');
    }
    (function certCreateEvToggle() {
      var evCheck = document.getElementById('certCreateEv');
      var evFields = document.getElementById('certCreateEvFields');
      if (evCheck && evFields) {
        evCheck.addEventListener('change', function() { evFields.style.display = this.checked ? 'block' : 'none'; });
      }
    })();
    function openCaUploadModal() {
      var typeSel = document.getElementById('caUploadType');
      var parentWrap = document.getElementById('caUploadParentWrap');
      var parentSel = document.getElementById('caUploadParentId');
      if (parentWrap) parentWrap.style.display = (typeSel && typeSel.value === 'intermediate') ? 'block' : 'none';
      if (parentSel) {
        parentSel.innerHTML = '<option value="">– Bitte wählen –</option>';
        (initialData.cas || []).forEach(function(c) {
          var opt = document.createElement('option');
          opt.value = c.id;
          opt.textContent = c.name + (c.commonName && c.commonName !== c.name ? ' (' + c.commonName + ')' : '');
          parentSel.appendChild(opt);
        });
      }
      document.getElementById('caUploadSuccess').style.display = 'none';
      document.getElementById('caUploadForm').reset();
      document.getElementById('caUploadModal').classList.add('open');
    }
    (function caUploadTypeToggle() {
      var typeSel = document.getElementById('caUploadType');
      var parentWrap = document.getElementById('caUploadParentWrap');
      if (typeSel && parentWrap) {
        typeSel.addEventListener('change', function() { parentWrap.style.display = this.value === 'intermediate' ? 'block' : 'none'; });
      }
    })();
    function openCertUploadModal() {
      var sel = document.getElementById('certUploadIssuerId');
      if (sel) {
        sel.innerHTML = '<option value="">– Keine / Unbekannt –</option>';
        (initialData.cas || []).forEach(function(c) {
          var opt = document.createElement('option');
          opt.value = c.id;
          opt.textContent = c.name + (c.commonName && c.commonName !== c.name ? ' (' + c.commonName + ')' : '') + ' (Root)';
          sel.appendChild(opt);
        });
        (initialData.intermediates || []).forEach(function(c) {
          var opt = document.createElement('option');
          opt.value = c.id;
          opt.textContent = (c.name || c.id) + ' (Intermediate)';
          sel.appendChild(opt);
        });
      }
      document.getElementById('certUploadSuccess').style.display = 'none';
      document.getElementById('certUploadForm').reset();
      document.getElementById('certUploadModal').classList.add('open');
    }
    async function submitCaUpload(ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      var type = document.getElementById('caUploadType').value;
      var certPem = (document.getElementById('caUploadCertPem').value || '').trim();
      var keyPem = (document.getElementById('caUploadKeyPem').value || '').trim();
      var name = (document.getElementById('caUploadName').value || '').trim();
      var body = { type: type, certPem: certPem, keyPem: keyPem };
      if (name) body.name = name;
      if (type === 'intermediate') {
        var parentId = (document.getElementById('caUploadParentId').value || '').trim();
        if (!parentId) { showError('Bitte übergeordnete CA wählen.'); return false; }
        body.parentCaId = parentId;
      }
      var btn = document.getElementById('caUploadSubmitBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Wird hochgeladen…'; }
      try {
        var res = await fetch('/api/ca/upload', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await res.json().catch(function() { return {}; });
        if (!res.ok) {
          if (btn) { btn.disabled = false; btn.textContent = 'Hochladen'; }
          showError('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        document.getElementById('caUploadSuccess').style.display = 'block';
        document.getElementById('caUploadSuccessId').textContent = 'ID: ' + data.id;
        if (btn) { btn.disabled = false; btn.textContent = 'Hochladen'; }
        setTimeout(function() { closeModal('caUploadModal'); location.reload(); }, 1500);
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Hochladen'; }
        showError(e && e.message ? e.message : String(e));
      }
      return false;
    }
    async function submitCertUpload(ev) {
      if (ev && ev.preventDefault) ev.preventDefault();
      var certPem = (document.getElementById('certUploadCertPem').value || '').trim();
      var keyPem = (document.getElementById('certUploadKeyPem').value || '').trim();
      var issuerId = (document.getElementById('certUploadIssuerId').value || '').trim() || null;
      var body = { certPem: certPem, keyPem: keyPem };
      if (issuerId) body.issuerId = issuerId;
      var btn = document.getElementById('certUploadSubmitBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Wird hochgeladen…'; }
      try {
        var res = await fetch('/api/cert/upload', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await res.json().catch(function() { return {}; });
        if (!res.ok) {
          if (btn) { btn.disabled = false; btn.textContent = 'Hochladen'; }
          showError('Fehler: ' + (data.error || res.statusText));
          return false;
        }
        var certId = data.id;
        document.getElementById('certUploadSuccess').style.display = 'block';
        document.getElementById('certUploadDownloadCert').href = '/api/cert/download?id=' + certId;
        document.getElementById('certUploadDownloadKey').href = '/api/cert/key?id=' + certId;
        if (btn) { btn.disabled = false; btn.textContent = 'Hochladen'; }
        setTimeout(function() { closeModal('certUploadModal'); location.reload(); }, 1500);
      } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Hochladen'; }
        showError(e && e.message ? e.message : String(e));
      }
      return false;
    }
    var certRenewConfirmBtn = document.getElementById('certRenewConfirmBtn');
    if (certRenewConfirmBtn) {
      certRenewConfirmBtn.addEventListener('click', function() {
        var certId = this.getAttribute('data-cert-id');
        if (!certId) return;
        this.disabled = true;
        fetch('/api/cert/renew', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: parseInt(certId, 10) }) })
          .then(function(res) { return res.json().then(function(data) { return { ok: res.ok, data: data }; }); })
          .then(function(r) {
            if (r.ok) { closeModal('certRenewModal'); location.reload(); } else { showError('Fehler: ' + (r.data && r.data.error ? r.data.error : 'Erneuern fehlgeschlagen')); }
          })
          .catch(function(err) { showError(err && err.message ? err.message : 'Erneuern fehlgeschlagen'); })
          .finally(function() { certRenewConfirmBtn.disabled = false; });
      });
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
      var keyAlgorithm = (form && form.elements.keyAlgorithm && form.elements.keyAlgorithm.value) || 'rsa-2048';
      var hashAlgo = (form && form.elements.hashAlgo && form.elements.hashAlgo.value) || 'sha256';
      var ev = !!(form && form.elements.ev && form.elements.ev.checked);
      var body = { issuerId: issuerId, domain: domain, sanDomains: sanDomains, validityDays: validityDays, keyAlgorithm: keyAlgorithm, hashAlgo: hashAlgo };
      var org = (form && form.elements.organization && form.elements.organization.value) ? form.elements.organization.value.trim() : '';
      var ou = (form && form.elements.organizationalUnit && form.elements.organizationalUnit.value) ? form.elements.organizationalUnit.value.trim() : '';
      var country = (form && form.elements.country && form.elements.country.value) ? form.elements.country.value.trim() : '';
      var locality = (form && form.elements.locality && form.elements.locality.value) ? form.elements.locality.value.trim() : '';
      var stateOrProvince = (form && form.elements.stateOrProvince && form.elements.stateOrProvince.value) ? form.elements.stateOrProvince.value.trim() : '';
      var email = (form && form.elements.email && form.elements.email.value) ? form.elements.email.value.trim() : '';
      if (org) body.organization = org;
      if (ou) body.organizationalUnit = ou;
      if (country) body.country = country;
      if (locality) body.locality = locality;
      if (stateOrProvince) body.stateOrProvince = stateOrProvince;
      if (email) body.email = email;
      if (ev) {
        body.ev = true;
        body.policyOidBase = (form.elements.policyOidBase && form.elements.policyOidBase.value) ? form.elements.policyOidBase.value.trim() : '';
        body.policyOidSub = (form.elements.policyOidSub && form.elements.policyOidSub.value) ? form.elements.policyOidSub.value.trim() : '';
        body.businessCategory = (form.elements.businessCategory && form.elements.businessCategory.value) ? form.elements.businessCategory.value.trim() : '';
        body.jurisdictionCountryName = (form.elements.jurisdictionCountryName && form.elements.jurisdictionCountryName.value) ? form.elements.jurisdictionCountryName.value.trim() : '';
        body.serialNumber = (form.elements.serialNumber && form.elements.serialNumber.value) ? form.elements.serialNumber.value.trim() : '';
      }
      var btn = document.getElementById('certCreateSubmitBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Wird erstellt…'; }
      try {
        var res = await fetch('/api/cert/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
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
        var detailsLink = document.getElementById('certCreateViewDetails');
        if (detailsLink) { detailsLink.setAttribute('data-cert-id', String(certId)); }
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
        name: getFormVal(form, 'name') || getFormVal(form, 'commonName') || '${escapeForScript(defaultCommonNameRoot)}',
        commonName: getFormVal(form, 'commonName') || '${escapeForScript(defaultCommonNameRoot)}',
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
    (function initLogTerminal() {
      var pre = document.getElementById('logTerminal');
      var wrap = pre && pre.closest('.log-terminal-wrap');
      if (!pre || !wrap) return;
      function appendLine(line) {
        var text = pre.textContent || '';
        pre.textContent = text ? text + '\\n' + line : line;
        wrap.scrollTop = wrap.scrollHeight;
      }
      fetch('/api/log').then(function(res) { return res.json(); }).then(function(data) {
        var lines = data.lines || [];
        pre.textContent = lines.join('\\n') || '(Keine Log-Einträge)';
        wrap.scrollTop = wrap.scrollHeight;
      }).catch(function() { pre.textContent = '(Log konnte nicht geladen werden)'; });
      var logEs = new EventSource('/api/log/stream');
      logEs.onmessage = function(e) {
        try {
          var line = typeof e.data === 'string' ? JSON.parse(e.data) : e.data;
          if (line) appendLine(line);
        } catch (err) {}
      };
    })();
    const es = new EventSource('/api/events');
    es.onmessage = (e) => {
      const d = JSON.parse(e.data);
      const s = d.summary;
      document.getElementById('certsTotal').textContent = s.certsTotal;
      document.getElementById('certsValid').textContent = s.certsValid;
      document.getElementById('timeUtc').textContent = s.timeUtc;
      document.getElementById('timeLocal').textContent = s.timeLocal;
      document.getElementById('letsEncryptEmail').textContent = s.letsEncrypt ? s.letsEncrypt.email : 'coming soon';
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
          : ch.map(function(c) { return '<tr><td><code>' + htmlEscape(c.token) + '</code></td><td>' + htmlEscape(c.domain) + '</td><td>' + (c.expires_at ? new Date(c.expires_at).toLocaleString() : '-') + '</td><td><button type="button" class="btn btn-delete btn-delete-challenge" data-challenge-id="' + c.id + '" title="Challenge löschen">Löschen</button></td></tr>'; }).join('');
      }
      var acmeChallengesEl = document.getElementById('acmeChallenges');
      if (acmeChallengesEl && d.acmeChallenges) {
        var ach = d.acmeChallenges;
        var valStatus = d.acmeValidationStatus || [];
        function acmeRow(ac) {
          var val = valStatus.find(function(s) { return s.challengeId === ac.challengeId; });
          var validationCell;
          var displayStatus = ac.status;
          if (ac.acceptedAt != null) {
            var acceptedExpireAt = ac.acceptedAt * 1000 + 60000;
            var secsAcc = Math.max(0, Math.ceil((acceptedExpireAt - Date.now()) / 1000));
            var ringOffsetAcc = 100 * (1 - Math.min(60, secsAcc) / 60);
            validationCell = '<span class="acme-validation-progress acme-validation-accept-timer" data-next-at="' + acceptedExpireAt + '" data-timer-max="60"><span class="acme-validation-circle-wrap"><svg class="acme-validation-circle" viewBox="0 0 36 36" aria-hidden="true"><circle class="acme-validation-ring-bg" cx="18" cy="18" r="16"/><circle class="acme-validation-ring-fill" cx="18" cy="18" r="16" style="stroke-dashoffset:' + ringOffsetAcc + '"/></svg></span><span class="acme-validation-text">Manuell akzeptiert</span><span>Löschung in <span class="acme-validation-countdown" data-next-at="' + acceptedExpireAt + '">' + secsAcc + '</span> s (wenn nicht eingelöst)</span></span>';
            displayStatus = 'akzeptiert';
          } else if (val) {
            var secs = Math.max(0, Math.ceil((val.nextAttemptAt - Date.now()) / 1000));
            var ringOffset = 100 * (1 - Math.min(5, secs) / 5);
            validationCell = '<span class="acme-validation-progress" data-next-at="' + val.nextAttemptAt + '"><span class="acme-validation-circle-wrap"><svg class="acme-validation-circle" viewBox="0 0 36 36" aria-hidden="true"><circle class="acme-validation-ring-bg" cx="18" cy="18" r="16"/><circle class="acme-validation-ring-fill" cx="18" cy="18" r="16" style="stroke-dashoffset:' + ringOffset + '"/></svg></span><span class="acme-validation-text">Versuch ' + val.attemptCount + '/' + val.maxAttempts + '</span><span>nächster in <span class="acme-validation-countdown" data-next-at="' + val.nextAttemptAt + '">' + secs + '</span> s</span></span>';
          } else if (ac.status === 'pending') {
            validationCell = '<span class="acme-validation-progress acme-validation-waiting"><span class="acme-validation-text">Versuch —/5</span><span class="acme-validation-hint">Warte auf Auslösung (Certbot: Enter)</span></span>';
          } else {
            validationCell = '—';
          }
          var acceptBtn = ac.status !== 'valid' ? '<button type="button" class="btn btn-accept-acme btn-accept-acme-authz" data-authz-id="' + attrEscape(ac.authzId) + '" title="Challenge manuell als gültig markieren">Manuell annehmen</button> ' : '';
          return '<tr data-authz-id="' + attrEscape(ac.authzId) + '" data-challenge-id="' + attrEscape(ac.challengeId) + '"><td>' + htmlEscape(ac.domain) + '</td><td><code>' + htmlEscape(ac.token) + '</code></td><td>' + htmlEscape(displayStatus) + '</td><td class="acme-validation-cell">' + validationCell + '</td><td>' + acceptBtn + '<button type="button" class="btn btn-delete btn-delete-acme-authz" data-authz-id="' + attrEscape(ac.authzId) + '" title="ACME-Challenge löschen">Löschen</button></td></tr>';
        }
        acmeChallengesEl.innerHTML = ach.length === 0
          ? '<tr><td colspan="5" class="empty-table">Keine offenen ACME-Challenges</td></tr>'
          : ach.map(acmeRow).join('');
      }
      var acmeWhitelistEl = document.getElementById('acmeWhitelistDomains');
      if (acmeWhitelistEl && d.acmeWhitelistDomains) {
        var wl = d.acmeWhitelistDomains;
        acmeWhitelistEl.innerHTML = wl.length === 0
          ? '<tr><td colspan="2" class="empty-table">Keine Einträge</td></tr>'
          : wl.map(function(w) { return '<tr data-whitelist-id="' + attrEscape(String(w.id)) + '"><td><code>' + htmlEscape(w.domain || '') + '</code></td><td><button type="button" class="btn btn-delete btn-delete-acme-whitelist" data-id="' + attrEscape(String(w.id)) + '" title="Aus Whitelist löschen">Löschen</button></td></tr>'; }).join('');
      }
      var acmeCaAssignmentsEl = document.getElementById('acmeCaAssignments');
      if (acmeCaAssignmentsEl && d.acmeCaDomainAssignments) {
        var casList = d.cas || [];
        var intList = d.intermediates || [];
        function caDisplayName(caId) {
          var r = casList.find(function(c) { return c.id === caId; });
          if (r) return r.name + (r.commonName && r.commonName !== r.name ? ' (' + r.commonName + ')' : '') + ' (Root)';
          var i = intList.find(function(c) { return c.id === caId; });
          if (i) return (i.name || i.id) + ' (Intermediate)';
          return caId;
        }
        var assign = d.acmeCaDomainAssignments;
        acmeCaAssignmentsEl.innerHTML = assign.length === 0
          ? '<tr><td colspan="3" class="empty-table">Keine Zuordnungen. Standard-CA wird verwendet.</td></tr>'
          : assign.map(function(a) { return '<tr data-pattern="' + attrEscape(a.domainPattern) + '"><td><code>' + htmlEscape(a.domainPattern) + '</code></td><td>' + htmlEscape(caDisplayName(a.caId)) + '</td><td><button type="button" class="btn btn-delete btn-delete-acme-ca-assignment" data-pattern="' + attrEscape(a.domainPattern) + '" title="Zuordnung löschen">Löschen</button></td></tr>'; }).join('');
      }
      // Standard-Intermediate-Dropdown nicht per SSE überschreiben, damit die Nutzerauswahl
      // nicht sofort wieder verschwindet; Wert kommt beim Laden und nach Reload (nach Speichern).
      if (d.defaultCommonNameRoot) initialData.defaultCommonNameRoot = d.defaultCommonNameRoot;
      if (d.defaultCommonNameIntermediate) initialData.defaultCommonNameIntermediate = d.defaultCommonNameIntermediate;
      (function updateStats() {
        var certs = d.certificates || [];
        var now = Date.now();
        var valid = certs.filter(function(c) { return !c.revoked && c.not_after && new Date(c.not_after).getTime() > now; }).length;
        var expired = certs.filter(function(c) { return !c.revoked && c.not_after && new Date(c.not_after).getTime() <= now; }).length;
        var revoked = certs.filter(function(c) { return c.revoked; }).length;
        function set(id, val) { var el = document.getElementById(id); if (el) el.textContent = val; }
        set('statsCertsTotal', certs.length);
        set('statsCertsValid', valid);
        set('statsCertsExpired', expired);
        set('statsCertsRevoked', revoked);
        set('statsRootCas', (d.cas || []).length);
        set('statsIntermediates', (d.intermediates || []).length);
        set('statsAcmeChallenges', (d.acmeChallenges || []).length);
        set('statsWhitelist', (d.acmeWhitelistDomains || []).length);
      })();
    };
    document.addEventListener('DOMContentLoaded', function() {
      var total = document.getElementById('certsTotal');
      var valid = document.getElementById('certsValid');
      if (total) document.getElementById('statsCertsTotal').textContent = total.textContent;
      if (valid) document.getElementById('statsCertsValid').textContent = valid.textContent;
    });
  </script>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}
