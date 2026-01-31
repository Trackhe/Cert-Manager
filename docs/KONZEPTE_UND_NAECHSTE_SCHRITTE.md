# Reinprogrammierte Konzepte & nächste Schritte

## Was ist aktuell fest einprogrammiert?

### Konfiguration & Umgebung
- **Eine aktive CA**: Config-Key `active_ca_id` (in `src/constants.ts` als `CONFIG_KEY_ACTIVE_CA_ID`) – es gibt genau eine CA, die für den ACME-Server genutzt wird.
- **Port**: Default 3000 (nur über `PORT` änderbar).
- **Base-URL**: Aus `Host`-Header abgeleitet; `localhost` → `http://`, sonst `https://`.
- **Pfade**: `/`, `/acme/*`, `/api/*`, `/.well-known/acme-challenge/*` – fest im Router, kein Prefix/BASE_PATH.

### Krypto- & Zertifikats-Defaults
- **Defaults** stehen zentral in `src/constants.ts` (Key-Größe 2048, Hash SHA-256, Gültigkeit 10 Jahre / 365 Tage, Common Names). Werte werden in ca, leaf-certificate, api, database und Dashboard daraus gelesen.

### Daten & Anzeige
- **Let’s Encrypt im Summary**: Dashboard/Summary fragt fest `provider = 'letsencrypt'`; andere ACME-Accounts erscheinen nicht.
- **Sprache**: Alle Texte (UI, Fehlermeldungen, Platzhalter) auf Deutsch.

### Technik
- **Datenbank**: SQLite, Schema und Tabellennamen fest in `database.ts`.
- **DB-Migration**: Gemeint ist der Code in `database.ts` → `runMigrations()`. Beim Start werden alte Einzel-CA-Dateien (`ca-key.pem`, `ca-cert.pem`) in die erste CA mit id `default` überführt; dabei werden die Namen aus den Konstanten (`DEFAULT_CA_NAME_MIGRATION`, `DEFAULT_COMMON_NAME_ROOT`) und der Config-Key `active_ca_id` gesetzt. Zusätzlich werden fehlende Spalten (z. B. `certificates.not_after`, `certificates.pem`, `cas.not_after`) nachgetragen.
- **ACME**: RSA-SHA256 für JWS, JWK-Thumbprint; Ablauf (Directory, Nonce, Account, Order, Challenge, Finalize, Cert) fest verdrahtet. **Bibliotheken:** Für einen **ACME-Server** (nicht Client) gibt es wenig fertige npm-Module. **acme-client** / **@peculiar/acme-client** sind **ACME-Clients** (zum Anfordern von Zertifikaten bei Let’s Encrypt etc.). **acme-ts** (PeculiarVentures) bietet laut Dokumentation sowohl Client- als auch Server-Implementierung (RFC 8555) in TypeScript – bei Bedarf könnte man prüfen, ob sich der eigene ACME-Server-Code durch Nutzung von acme-ts vereinfachen oder ablösen lässt. Die aktuelle Eigenimplementierung bleibt verständlich und testbar.

---

## Umgesetzt (Stand Refaktor)

- **Konstanten zentral**: `src/constants.ts` mit Config-Key, Default Common Names, Key-Größe, Gültigkeit, Hash; Verwendung in ca, leaf-certificate, api, database, dashboard.
- **API-Routing**: In `src/api.ts` Route-Tabelle `API_ROUTES` (method + path → Handler); 404 zentral, neue Endpoints nur eintragen.
- **„Aktive CA“**: In `constants.ts` Kommentar und Konstante `CONFIG_KEY_ACTIVE_CA_ID`; Konzept damit dokumentiert.
- **NPM-Texte**: Erwähnung von Nginx Proxy Manager aus dem Dashboard entfernt; Hilfetexte sind jetzt allgemein (ACME-Client / Reverse-Proxy).

---

## Was (optional) als Nächstes?

### Summary provider-agnostisch oder konfigurierbar (priorität niedrig)
**Problem:** Summary/Dashboard zeigt nur den Account mit `provider = 'letsencrypt'`. Weitere ACME-Provider sind im Datenmodell möglich, aber im UI unsichtbar.

**Vorschlag:** Entweder „erster/einziger ACME-Account“ anzeigen oder einen konfigurierbaren Provider-Namen (z. B. aus Config/Env) für die Anzeige nutzen.

### Base-Pfad / Reverse-Proxy (priorität optional)
**Problem:** App läuft nur „an der Wurzel“. Ein Deployment unter einem Prefix (z. B. `/cert-manager/`) würde alle Links brechen.

**Vorschlag:** Erst bei konkretem Bedarf: `BASE_PATH` aus Config, in Router und in allen Links voranstellen.

### ACME-Server mit Bibliothek (optional)
**Vorschlag:** Falls Wartung oder Erweiterung des ACME-Servers aufwendig wird: **acme-ts** (PeculiarVentures) auf Eignung prüfen (Server-Teil, Anbindung an eigene CA/DB).

---

## Kurzfassung

| Thema | Status |
|-------|--------|
| Defaults & Magic Strings | Erledigt: `src/constants.ts` |
| API-Routing | Erledigt: Route-Tabelle in `api.ts` |
| „Eine aktive CA“ | Erledigt: Konstante + Kommentar in `constants.ts` |
| NPM-Texte | Erledigt: entfernt, allgemeine Formulierung |
| DB-Migration | Klarstellung: `runMigrations()` in `database.ts` |
| ACME-Bibliothek | Hinweis: acme-ts (Server); optional prüfen |
| Let’s Encrypt im Summary | Optional: provider-agnostisch |
| Base-Pfad | Optional: bei Bedarf |
| Sprache | Deutsch, ausreichend |
