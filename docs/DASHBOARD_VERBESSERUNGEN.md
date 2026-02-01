# Dashboard – was ich ändern würde

## Schnell umsetzbar

- **Tippfehler:** Button „Certificat erstellen“ → **„Zertifikat erstellen“** (steht an einer Stelle schon richtig, an anderer falsch).
- **Leere Tabellen:** Wenn keine Challenges / keine Zertifikate vorhanden sind, einen klaren Hinweis anzeigen (z. B. „Keine Einträge“) statt leerer Tabelle.
- **Directory-URL kopierbar machen:** Neben der Directory-URL einen „Kopieren“-Button, der die URL in die Zwischenablage schreibt (nur mit `navigator.clipboard.writeText` und Fallback).
- **Fehlermeldungen statt `alert()`:** Fehler unter dem Formular oder in einem kleinen Banner/Toast anzeigen statt `alert()` – besser lesbar und weniger störend.

## Struktur & Wartbarkeit

- **HTML/CSS/JS trennen:** Das Dashboard ist eine große Template-String-Datei mit HTML, CSS und ~250 Zeilen Inline-JS. Sinnvoll:
  - CSS in eine eigene Konstante oder (bei Build-Schritt) in eine statische Datei auslagern.
  - Client-JavaScript in eine separate `.js`-Datei auslagern und per `<script src="/static/dashboard.js">` einbinden; Initialdaten weiter per `<script type="application/json" id="initialData">` übergeben. Dann ist das Template kürzer und das JS testbar/überschaubar.
- **Inline-Styles reduzieren:** Viele `style="..."` (z. B. in Tabellen, Buttons, Modals) in CSS-Klassen auslagern, dann einheitlicher und änderbar an einer Stelle.

## Barrierefreiheit & UX

- **Seitenstruktur:** Ein `<main>` und eine klare **h1** (z. B. „Cert-Manager Dashboard“) für Überschrift und Hierarchie.
- **Modals:**
  - `role="dialog"`, `aria-modal="true"`, `aria-labelledby` auf das Modal-Element.
  - Beim Öffnen Fokus ins Modal setzen (z. B. erstes Eingabefeld), beim Schließen Fokus zurück auf den Button, der das Modal geöffnet hat.
  - **Escape schließt Modal** (keydown auf Escape → Modal schließen).
- **Fokus sichtbar:** Deutlichen Fokus-Ring für Tastatur-Navigation (z. B. `:focus-visible`) auf Buttons und Links, damit man sieht, wo man gerade ist.
- **Tabellen:** Bei vielen Einträgen optional Pagination oder „Zeige alle“; zumindest einen Hinweis, wenn 0 Einträge da sind (siehe oben).

## Sicherheit (SSE-Updates)

- **XSS bei Live-Updates:** Die per SSE aktualisierten Tabellen (Challenges, CAs, Intermediates, Zertifikate) bauen HTML per `innerHTML` aus Objekten wie `c.name`, `c.commonName`, `c.domain`. Diese Werte werden **nicht** escaped. Wenn jemand einen CA-Namen mit z. B. `<script>` oder bösartigem HTML in der DB hinterlässt, könnte das beim nächsten SSE-Update ausgeführt werden.  
  **Empfehlung:** Beim Zusammenbau der HTML-Strings für SSE-Updates alle Benutzerdaten escapen (z. B. gleiche Logik wie `htmlEscape`/`attrEscape` im Client) oder Inhalte per `textContent`/DOM-Konstruktion setzen statt `innerHTML` mit Konkatenation.

## Design & Responsive

- **Klares Layout:** Optional einen festen Header (Titel + evtl. Kurzinfos), dann Summary-Karten, dann Setup, dann Tabellen – mit einheitlichen Abständen und klaren visuellen Gruppen.
- **Mobile:** Tabellen auf kleinen Bildschirmen prüfen (horizontal scrollen oder umbauen zu Karten/Listen); Modals auf `width: 90%` oder `max-width` prüfen, damit sie auf dem Handy nutzbar bleiben.
- **Konsistente Buttons:** Eine Basis-Klasse für alle Buttons (z. B. `.btn`), sekundäre Aktionen (Abbrechen) mit `.btn-secondary` – das ist schon angelegt, könnte man durchgängig und ohne Inline-Styles nutzen.

## Optional / Später

- **Loading-Zustände:** Beim Erstellen von CA/Zertifikat den Button deaktivieren und Text „Wird erstellt…“ (ist schon da) – optional zusätzlich ein kleines Spinner-Icon.
- **Bestätigung vor Aktion:** Z. B. „CA wirklich aktivieren?“ nur wenn gewünscht; für ein Admin-Tool oft nicht nötig.
- **Dark Mode:** Wenn gewünscht, über CSS-Variablen und `prefers-color-scheme` oder einen Toggle.

---

**Priorität für den Anfang:** Tippfehler korrigieren, leere Tabellen-Hinweis, Fehleranzeige ohne `alert`, Escape schließt Modal, XSS bei SSE-Updates beheben (escapen). Danach optional: JS/CSS auslagern, Barrierefreiheit (Fokus, ARIA), Kopieren-Button für Directory-URL.
