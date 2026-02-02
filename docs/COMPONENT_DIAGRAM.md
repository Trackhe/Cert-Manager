# Komponentendiagramm Cert-Manager

Überblick über die Hauptkomponenten und ihre Abhängigkeiten.

```mermaid
flowchart TB
  subgraph Entry["Einstieg"]
    index["index.ts"]
  end

  subgraph Server["Server-Schicht"]
    server["server.ts\n(createRequestHandler)"]
  end

  subgraph Handlers["Request-Handler"]
    acme["acme.ts\n(ACME-Protokoll)"]
    api["api.ts\n(REST-API)"]
    dashboard["dashboard.ts\n(HTML-Dashboard)"]
    acmeChallenge["acme-challenge.ts\n(HTTP-01 Endpoint)"]
  end

  subgraph Domain["Domain-Logik"]
    ca["ca.ts\n(CA / Intermediate)"]
    leafCert["leaf-certificate.ts\n(Leaf-Zertifikate)"]
    acmeValidation["acme-validation-state.ts"]
  end

  subgraph Infrastruktur["Infrastruktur"]
    database["database.ts\n(SQLite + Migrationen)"]
    paths["paths.js\n(Pfade)"]
    config["config.ts\n(Umgebung)"]
    constants["constants.ts"]
    crypto["crypto.ts\n(Forge-Wrapper)"]
    logger["logger.ts"]
    escape["escape.ts"]
  end

  subgraph Daten["Daten / Auswertung"]
    summary["summary.ts\n(getSummaryData)"]
  end

  index --> server
  index --> database
  index --> paths
  server --> acme
  server --> api
  server --> dashboard
  server --> acmeChallenge
  acme --> database
  acme --> paths
  acme --> ca
  acme --> acmeValidation
  api --> database
  api --> paths
  api --> ca
  api --> leafCert
  api --> summary
  dashboard --> database
  dashboard --> paths
  dashboard --> summary
  dashboard --> escape
  acmeChallenge --> database
  ca --> database
  ca --> paths
  ca --> crypto
  leafCert --> database
  leafCert --> paths
  leafCert --> crypto
  summary --> database
  summary --> acmeValidation
```

## Legende

| Komponente | Verantwortung |
|------------|---------------|
| **index.ts** | Start, DB-Migrationen, Server starten, Validation-Polling starten |
| **server.ts** | Routing: `/` → Dashboard, `/acme/*` → ACME, `/api/*` → API, `/.well-known/acme-challenge/*` → Challenge |
| **acme.ts** | ACME Directory, new-order, chall, finalize, authz, order, cert, CA-URL; Challenge-Validierung + Cleanup |
| **api.ts** | REST-Endpunkte für CA, Zertifikate, Challenges, Whitelist, Events (SSE) |
| **dashboard.ts** | HTML-Render des Dashboards, initialData, Client-Script (Events, UI) |
| **acme-challenge.ts** | Liefert `key_authorization` unter `/.well-known/acme-challenge/:token` |
| **ca.ts** | Root-CA und Intermediate-CA anlegen, Schlüssel/Zertifikate (Forge) |
| **leaf-certificate.ts** | Leaf-Zertifikat ausstellen (Dashboard/API), Forge + Signer-CA |
| **acme-validation-state.ts** | In-Memory-State für Validierungsversuche und Cooldown |
| **database.ts** | SQLite-Erstellung, Schema, Migrationen (ensureColumn) |
| **summary.ts** | Aggregation für Dashboard/Events (Zertifikate, Challenges, CAS, Whitelist) |
| **paths.ts** | Pfade für CA/Intermediate/Leaf-Dateien (Keys, Certs) |
| **config.ts** | DATA_DIR, DB_PATH, PORT aus Umgebung |
| **crypto.ts** | Hash für Signatur (getDigestForSigning), Subject-Attribute (buildSubjectAttributes) |
| **escape.ts** | htmlEscape, attrEscape, escapeForScript (XSS/JSON) |
