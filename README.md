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
