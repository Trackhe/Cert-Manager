# Docker Hub – Beschreibungstext (Full Description)

Unten stehenden Text bei Docker Hub unter **Repository** → **Edit** → **Full Description** einfügen.

---

## Cert-Manager

Eigene **Certificate Authority (CA)** mit Web-Dashboard und **ACME-Server**. Ermöglicht die Ausstellung von Zertifikaten über ACME-Clients wie **Certbot** oder **Nginx Proxy Manager** – ideal für lokale Entwicklung und interne Dienste.

**Quellcode & Dokumentation:** [GitHub – Trackhe/Cert-Manager](https://github.com/Trackhe/Cert-Manager)

---

### Quick Start

```bash
docker run -d \
  --name cert-manager \
  -p 3000:3000 \
  -v cert-manager-data:/data \
  -e DATA_DIR=/data \
  -e DB_PATH=/data/cert-manager.db \
  trackhe/cert-manager:latest
```

- **Dashboard:** http://localhost:3000  
- **ACME-Directory (für Certbot/NPM):** http://localhost:3000/acme/directory  

Daten (Datenbank, CA-Zertifikate, Keys) liegen im Volume `/data` und bleiben beim Neustart des Containers erhalten.

---

### Umgebungsvariablen

| Variable | Beschreibung | Standard |
|----------|--------------|----------|
| `PORT` | HTTP-Port | `3000` |
| `HOST` | Bind-Adresse (z. B. `0.0.0.0` für alle Interfaces) | `0.0.0.0` |
| `DATA_DIR` | Verzeichnis für Daten (DB, CA, Zertifikate) | `/data` |
| `DB_PATH` | Pfad zur SQLite-Datenbank | `/data/cert-manager.db` |
| `LOG_LEVEL` | Log-Level (`debug`, `info`, `warn`, `error`) | `debug` |

---

### Plattformen

Image wird für **linux/amd64** und **linux/arm64** (z. B. Apple Silicon, Raspberry Pi) bereitgestellt.

---

### Lizenz

MIT – [Lizenz auf GitHub](https://github.com/Trackhe/Cert-Manager/blob/main/LICENSE)
