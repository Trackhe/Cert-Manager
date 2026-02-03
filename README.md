# Cert-Manager

Eigene Certificate Authority (CA) mit Web-Dashboard und ACME-Server. Ermöglicht die Ausstellung von Zertifikaten über ACME-Clients wie Certbot oder Nginx Proxy Manager – ideal für lokale Entwicklung und interne Dienste.

![Dashboard](docs/screenshot.png)

## Voraussetzungen

- [Bun](https://bun.sh) (JavaScript-Runtime)

## Installation

```bash
bun install
```

## Start

```bash
bun run index.ts
```

Die Anwendung startet standardmäßig unter **http://localhost:3000**. Im Browser öffnest du das Dashboard; die ACME-Directory-URL für Clients ist `http://localhost:3000/acme/directory`.

## Umgebungsvariablen

| Variable    | Beschreibung                          | Standard     |
|------------|---------------------------------------|--------------|
| `PORT`     | HTTP-Port des Servers                 | `3000`       |
| `HOST`     | Hostname/Bind-Adresse (z. B. `0.0.0.0` für alle Interfaces) | `0.0.0.0` |
| `DATA_DIR` | Verzeichnis für CA-Zertifikate, Keys, Zertifikate | `./data` |
| `DB_PATH`  | Pfad zur SQLite-Datenbank             | `./data.db`  |
| `LOG_LEVEL`| Log-Level (`debug`, `info`, `warn`, `error`) | `debug` |

Beispiel:

```bash
PORT=8080 HOST=127.0.0.1 DATA_DIR=./mydata bun run index.ts
```

## Docker

**Öffentliches Image:** [trackhe/cert-manager auf Docker Hub](https://hub.docker.com/r/trackhe/cert-manager)

### Container starten (mit öffentlichem Image)

```bash
docker run -d \
  --name cert-manager \
  -p 3000:3000 \
  -v cert-manager-data:/data \
  -e DATA_DIR=/data \
  -e DB_PATH=/data/cert-manager.db \
  trackhe/cert-manager:latest
```

Dashboard: **http://localhost:3000**, ACME-Directory: **http://localhost:3000/acme/directory**.

Port anpassen (z. B. 8080):

```bash
docker run -d -p 8080:3000 -v cert-manager-data:/data -e DATA_DIR=/data -e DB_PATH=/data/cert-manager.db trackhe/cert-manager:latest
```

### Image-Labels (OCI)

Das Image enthält folgende [OCI-Labels](https://github.com/opencontainers/image-spec/blob/main/annotations.md) (auf Docker Hub unter „Labels“ sichtbar):

| Label | Beschreibung |
|-------|--------------|
| `org.opencontainers.image.source` | GitHub-Repository-URL |
| `org.opencontainers.image.revision` | Git-Commit (bei CI-Build) |
| `org.opencontainers.image.version` | Version/Tag (z. B. bei Release) |

### Image selbst bauen

**Nur für deine Architektur (z. B. Apple Silicon):**

```bash
docker build -t cert-manager .
```

**Multi-Platform (ARM64 + AMD64) und Push zu Docker Hub:**

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t trackhe/cert-manager:latest \
  --push .
```

### CI/CD (GitHub Actions)

Bei **Release-Tags** (z. B. `v1.0.0`) baut und pusht der Workflow [`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml) das Image automatisch für **linux/amd64** und **linux/arm64** nach Docker Hub.

**Voraussetzung:** In den GitHub-Repository-Einstellungen unter „Secrets and variables“ → Actions die Secrets anlegen:

- `DOCKERHUB_USERNAME` – dein Docker-Hub-Benutzername (z. B. `trackhe`)
- `DOCKERHUB_TOKEN` – ein [Docker Hub Access Token](https://hub.docker.com/settings/security) (mit Lese-/Schreibrechten für das Repo)

Nach dem Anlegen eines Releases (z. B. Tag `v1.0.0` erstellen und optional „Publish release“) wird das Image mit den Tags `latest` und `v1.0.0` gebaut und gepusht.

## Testen mit Certbot

Zum Testen eines Zertifikats mit Certbot (manueller Modus, eigene CA als Server):

1. Cert-Manager starten (siehe oben).
2. Im Dashboard eine Root-CA anlegen und aktivieren, falls noch nicht geschehen.
3. Certbot mit folgender Directory-URL und deinen gewünschten Pfaden ausführen:

```bash
certbot certonly \
  --manual \
  --server http://localhost:3000/acme/directory \
  --config-dir ~/Desktop/certtest/config \
  --logs-dir ~/Desktop/certtest/logs \
  --work-dir ~/Desktop/certtest/work \
  --register-unsafely-without-email \
  -d test2.example.com
```

- Certbot zeigt die HTTP-01-Challenge an. Die Challenge kannst du im Dashboard **manuell annehmen** oder die Domain in die **Whitelist** eintragen (dann wird sie automatisch akzeptiert).
- Danach in Certbot mit Enter bestätigen; das Zertifikat wird ausgestellt und erscheint im Dashboard unter Zertifikate.

**Schlüsseltypen:** Certbot nutzt ab Version 2.0 standardmäßig **ECDSA** – das wird unterstützt (RSA- und ECDSA-CSRs werden mit node-forge bzw. @peculiar/x509 signiert). Optional kannst du `--key-type rsa` angeben.

## Dokumentation

- **[Komponentendiagramm](docs/COMPONENT_DIAGRAM.md)** – Überblick über Module und Abhängigkeiten (Mermaid)
- **[Ablaufdiagramme](docs/FLOW_DIAGRAMS.md)** – ACME-Flow, Challenge-Validierung, Dashboard, CA-Setup (Mermaid)

## Lizenz & Repo

- **Lizenz:** [MIT](LICENSE) – Nutzung und Weitergabe erlaubt; bei Weitergabe muss erkennbar sein, dass es sich nicht um die ursprüngliche Quelle handelt (z. B. Verweis auf das [Original-Repository](https://github.com/Trackhe/Cert-Manager) oder Hinweis „Fork“/„inoffizielle Kopie“).
- [Cert-Manager auf GitHub](https://github.com/Trackhe/Cert-Manager)
