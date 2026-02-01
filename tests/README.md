# Tests – Überblick

## Was wird aktuell getestet

| Bereich | Tests |
|--------|--------|
| **Escape (Unit)** | `htmlEscape`, `attrEscape`, `escapeForScript` – Sonderzeichen, script-Tag |
| **Dashboard** | GET / liefert HTML mit „Dashboard“ und „Zertifikate“ |
| **CA Cert Download** | GET /api/ca-cert ohne `id` (aktive CA), mit unbekannter `id` → 404 |
| **Intermediate CA** | Parent anlegen → Intermediate anlegen → Zertifikat herunterladen; 400 ohne `parentCaId`; 404 bei unbekannter Parent |
| **Full Flow** | Root-CA → Leaf-Zertifikat (mit SAN) → Download Zertifikat + Schlüssel (PEM-Struktur) |
| **Leaf Cert Create** | 400 ohne `issuerId`, ohne `domain`, unbekannte CA → Fehlermeldung |
| **Cert Download** | 400 ohne `id`; 404 für /api/cert/download und /api/cert/key bei unbekannter id |
| **CA Activate** | 400 ohne `id`; 404 bei unbekannter CA; **Erfolg**: aktivierte CA, danach GET /api/ca-cert ohne id liefert deren PEM |
| **SSE** | GET /api/events → 200, Content-Type text/event-stream |
| **404** | Unbekannte Pfade /unknown und /api/unknown → 404 |
| **ACME (ohne JWS)** | GET /acme/directory → JSON mit newNonce/newAccount/newOrder; HEAD /acme/new-nonce → 204 + Replay-Nonce |
| **ACME HTTP-01** | GET /.well-known/acme-challenge/unknown → 404; mit eingetragener Challenge → 200 + key_authorization |
| **Leaf von Intermediate** | Zertifikat von Intermediate-CA ausstellen und herunterladen |
| **Ungültige Parameter** | /api/cert/download?id=abc und /api/cert/key?id=abc → 400 |

## Was (noch) nicht getestet wird

- **ACME voller Ablauf**: new-account (JWS), new-order, Challenge-Validierung, finalize, cert-Abruf (benötigt JWS-Signatur mit Test-Key).
- **Dashboard-Inhalt**: dass CA-Namen mit `<`, `"` etc. im HTML escaped sind (Escape-Funktionen sind unit-getestet).
- **Config**: `getDataDir`, `getDbPath`, `getPort` mit/ohne Umgebungsvariablen.
- **DB-Migrationen**: z. B. alte ca-key.pem → default CA (aufwändiger, temporäre Dateien).
