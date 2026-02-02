# Ablaufdiagramme Cert-Manager

## 1. HTTP-Request-Routing (Server)

```mermaid
flowchart LR
  A[Request] --> B{pathname?}
  B -->|"/.well-known/acme-challenge/*"| C[acme-challenge.ts]
  B -->|"/acme/*"| D[acme.ts]
  B -->|"/api/*"| E[api.ts]
  B -->|"/"| F[dashboard.ts]
  B -->|sonst| G[404]
  C --> H[Response]
  D --> H
  E --> H
  F --> H
  G --> H
```

## 2. ACME: Zertifikat anfordern (Certbot-Flow)

```mermaid
sequenceDiagram
  participant C as Certbot
  participant S as Cert-Manager (ACME)
  participant D as Dashboard

  C->>S: GET /acme/directory
  S-->>C: newNonce, newAccount, newOrder

  C->>S: POST /acme/new-account (optional)
  S-->>C: Account + Location

  C->>S: POST /acme/new-order (identifiers)
  S-->>C: Order (pending), authorizations[], finalize URL

  Note over S: Pro Domain: Authz + Challenge (http-01) angelegt.<br/>Whitelist-Domains sofort valid.

  C->>S: GET /acme/authz/:id (oder POST-as-GET)
  S-->>C: status, challenges[] (token, url)

  opt Manuell oder Whitelist
    D->>S: POST /api/acme-challenge/accept?id=authzId
    S-->>D: ok
  end

  C->>S: POST /acme/chall/:id (Validierung auslösen)
  S-->>C: status valid (oder 400 bei Fehler)

  Note over S: Hintergrund-Polling prüft pending Challenges<br/>oder 60s-Timer löscht nicht eingelöste.

  C->>S: POST /acme/order/:id (Polling)
  S-->>C: status ready (wenn alle Authz valid)

  C->>S: POST /acme/finalize/:orderId (CSR)
  S-->>C: status valid, certificate URL

  C->>S: POST /acme/cert/:orderId (Zertifikat abholen)
  S-->>C: PEM-Kette (Leaf + Intermediate + Root)
```

## 3. ACME: Challenge-Validierung (HTTP-01)

```mermaid
flowchart TB
  A[Challenge pending] --> B{Whitelist?}
  B -->|ja| C[status = valid, accepted_at = now]
  B -->|nein| D[Domain per HTTP aufrufen]
  D --> E{key_authorization OK?}
  E -->|ja| F[status = valid, accepted_at = now]
  E -->|nein| G{Versuche < 5?}
  G -->|ja| H[Warten, erneut versuchen]
  H --> D
  G -->|nein| I[status = invalid, Cooldown]
  C --> J[Authz status = valid]
  F --> J
  I --> K[Authz status = invalid]
```

## 4. Dashboard laden (Server-Render + Events)

```mermaid
flowchart LR
  A[GET /] --> B[renderDashboard]
  B --> C[getSummaryData]
  C --> D[(DB)]
  C --> E[acmeValidationStatus]
  B --> F[HTML mit initialData]
  F --> G[Browser]

  G --> H[EventSource /api/events]
  H --> I[getSummaryData]
  I --> D
  I --> J[JSON an Client]
  J --> G
  G --> K[DOM aktualisieren]
```

## 5. CA erstellen (Setup)

```mermaid
flowchart TB
  A[POST /api/ca/setup] --> B[ca.createRootCa]
  B --> C[Forge: RSA-Keypair]
  C --> D[Zertifikat (self-signed)]
  D --> E[Schreiben: Key + Cert]
  E --> F[DB: cas]
  F --> G[Falls keine aktive CA: active_ca_id setzen]
```

## 6. Leaf-Zertifikat ausstellen (API)

```mermaid
flowchart TB
  A[POST /api/cert/create] --> B[getSignerCa]
  B --> C[Intermediate oder Root]
  C --> D[Forge: RSA-Keypair]
  D --> E[Zertifikat signieren]
  E --> F[DB: certificates]
  F --> G[Key-Datei schreiben]
```

## 7. ACME Finalize (CSR → Zertifikat)

```mermaid
flowchart TB
  A[POST /acme/finalize/:orderId] --> B[CSR base64url → PEM]
  B --> C{node-forge: CSR parsen}
  C -->|RSA| D[Forge: Zertifikat aus CSR]
  C -->|ECDSA / Fehler| E[badCSR]
  D --> F[Signatur mit Signer-CA]
  F --> G[ca_certificates + certificates]
  G --> H[Challenges/Authorizations löschen]
  H --> I[Response: certificate URL]
```
