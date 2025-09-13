
# cve_severity_classifier

NLP-Projekt zur automatisierten Klassifizierung des CVSS-Schweregrads von CVEs auf Basis ihrer Beschreibungstexte (Zielklassen: CRITICAL, HIGH, MEDIUM, LOW). Der Fokus liegt auf reproduzierbarer Datenerhebung, schlankem Datenschema und effizienter Aktualisierung.

## Pipeline Überblick

1. Datenerhebung (Fetcher, NVD CVE API v2.0)
2. Speicherung als JSON Lines (eine CVE pro Zeile, reduziertes Schema)
3. CSV-Extraktion je CVSS-Version (v4.0 / v3.1 / v3.0 / v2)
4. Modellaufbereitung (geplant / außerhalb dieses Abschnitts)

## Datenbeschaffung

Script: `scripts/nvd_cve_fetcher/nvd_cve_fetcher.py`

Eigenschaften:

* Vollständiger Erstabruf aller CVEs seit 1999 in veröffentlichten Zeitfenstern (<=120 Tage / Request)
* Resume über ID-Deduplikation beim Lesen bestehender JSONL-Datei
* Update-Modus über segmentierte lastModified-Fenster (<=120 Tage pro Segment) für neue & geänderte CVEs
* Append-only JSONL: letzte Zeile pro CVE-ID gewinnt; optionale heuristische Kompaktierung zur Entfernung älterer Duplikate
* State-Datei `<OUTPUT>.state.json` mit `lastModifiedISO`, Laufstatistik und Kompaktierungs-Metadaten
* Separate Statistikdatei (Standard: `data/raw/fetch_stats.json`)
* Rate-Limit Beachtung (5 oder 50 Requests / 30s) + Backoff bei 429/5xx
* Mindest-Update-Intervall (State-basiert) zur Vermeidung unnötiger API-Last
* Reduziertes Schema: CVE ID, published, lastModified, englische Beschreibung (erste), CVSS Metriken v4.0/v3.1/v3.0/v2 (Basis-Kernfelder)

### Ausgabe-Dateien

| Datei | Inhalt |
|-------|--------|
| `data/raw/cves.jsonl` | JSONL mit getrimmten CVE-Objekten |
| `data/raw/cves.jsonl.state.json` | State & letzte Fetch-Statistik |
| (entfallen) | Separate Stats-Datei entfernt – Laufinfos stehen im State unter `lastRun` |

## CSV Export

Script: `scripts/cves_json_to_csv.py`

Erzeugt CSVs:

* `cves_v40.csv`
* `cves_v31.csv`
* `cves_v30.csv`
* `cves_v2.csv`

Spalten: `cve_id,severity,description`

Regeln:

* Eine Zeile pro CVE und CVSS-Version (beste Metrik nach höchstem baseScore)
* CVSS v2 Severity abgeleitet falls kein Label
* Beschreibung: erste englische Beschreibung bereinigt (Whitespace reduziert)

## Notebook 01: Datenerhebung & Export

Notebook: `notebooks/01_fetch_and_prepare_dataset.ipynb`

Schritte:

1. Pfad-Setup & Skriptprüfung
2. Optionales Laden einer `.env` für API Key (erhöht Rate-Limit) und Kontakt-E-Mail
3. Ausführen des Fetchers (Initial oder Update)
4. Ausführen des CSV-Export Skripts
5. Anzeige einer Stichprobe der erzeugten CSV-Dateien

## Umgebungsvariablen (.env)

Aktuell ausgewertet:

| Variable | Pflicht | Zweck |
|----------|---------|-------|
| `NVD_API_KEY` | Nein | Erhöht Requests-Limit (50 statt 5 / 30s) |
| `CONTACT_EMAIL` | Nein | Ergänzt den User-Agent (Transparenz/Support) |

Nicht mehr verwendet (intern fest verdrahtet): `OUTPUT_MODE`, `LOG_LEVEL`, `STATS_FILE`.

Beispiel `.env` (optional):

```dotenv
NVD_API_KEY=
CONTACT_EMAIL=you@example.com
```

## Ausführung (minimal)

```bash
python scripts/nvd_cve_fetcher/nvd_cve_fetcher.py
python scripts/cves_json_to_csv.py
```

Oder über Notebook 01 (interaktiv).