
# cve_severity_classifier

NLP-Projekt zur automatisierten Klassifizierung des CVSS-Schweregrads von CVEs auf Basis ihrer Beschreibungstexte (Zielklassen: CRITICAL, HIGH, MEDIUM, LOW). Der Fokus liegt auf reproduzierbarer Datenerhebung, schlankem Datenschema und effizienter Aktualisierung.

## Forschungsfrage & Analyseplan

**Primäre Forschungsfrage**  
In welchem Umfang können unterschiedliche Repräsentationen (TF-IDF vs. sequenzbasierte Einbettungen) und Modellklassen (logistische Regression, Convolutional Neural Network) den CVE-Schweregrad robust und generalisierbar klassifizieren, und welche Parameter (Embedding-Dimension, Vokabulargröße, Frequenzschwellen) beeinflussen die Modellgüte am stärksten?

### Notebook-Übersicht (aktuell)

| Notebook | Zweck |
|----------|-------|
| `01_fetch_and_prepare_dataset.ipynb` | Datenabruf (NVD) & CSV-Export der Versionen v4.0/v3.1/v3.0/v2 |
| `02_preprocessing_variants.ipynb` | Generierung der Textvarianten (raw / clean / raw_lemma / clean_lemma) + Token-Statistiken |
| `03_classic_models.ipynb` | TF-IDF (Wort 1–2 + Zeichen 3–5 n-Gramme), LogReg & Naive Bayes, Variantenvergleich |
| `04_cnn_model.ipynb` | Aktuelles CNN Grundgerüst (noch experimentell) |

### Interpretierbarkeit (aktuell)

* Logistische Regression: Top positive / negative Gewichte je Klasse
* Naive Bayes: log P(token|class) Ranking

### Classic Models (aktuell umgesetzt)

Notebook: `03_classic_models.ipynb`

Merkmale:

* Kombination zweier TF-IDF Repräsentationen: (a) Wort-n-Gramme (1–2), (b) Zeichen-n-Gramme (3–5) → horizontales Sparse-Stacking
* Modelle: Logistische Regression (C-Sweep), Multinomial Naive Bayes (alpha-Sweep)
* Variantenvergleich: Lädt automatisch vorhandene Dateien (raw / clean / raw_lemma / clean_lemma) und benchmarkt identisches Pipeline-Setup
* Metriken: Macro-F1, Accuracy, Confusion Matrix; Trainingstime pro Modell
* Feature Importance:
	* LogReg: Top positive / negative Koeffizienten je Klasse (JSON Export)
	* Naive Bayes: Klassen-spezifische log P(token|class) Ranglisten
* Visualisierungen: Performance-Vergleich der Varianten, Effekt von Hyperparametern (z.B. C/alpha) in einfachen Facet-Plots
* Reproduzierbarkeit: Deterministischer Train/Test Split via fester Seed (scikit-learn RandomState)

Ausgaben in `results/` (ignoriert, nur Artefakte): Metrik-CSV, Feature-Rankings, optionale Diagramme.

### Verzeichnisstruktur (aktuell)

```text
data/
	raw/        # Original + CSV Exporte
	processed/  # Generierte Textvarianten
notebooks/    # Analyse- & Trainings-Notebooks
results/      # Laufzeit-Artefakte (ignored, reproduzierbar generierbar)
scripts/      # Fetch & Konvertierung
```

Prinzipien:

* `data/` = Eingabedaten & deterministische Ableitungen
* `results` = vergängliche, reproduzierbare Ausgaben

### Installation & Nutzung

Voraussetzungen: Python ≥ 3.10

1. Abhängigkeiten installieren:

```bash
pip install -r requirements.txt
```

2. (Optional) spaCy Modell für Lemmatization:

```bash
python -m spacy download en_core_web_sm
```

3. (Optional) NVD API Key & Kontakt hinterlegen: `.env` Datei erstellen.

4. Datenerhebung ausführen:

```bash
python scripts/nvd_cve_fetcher/nvd_cve_fetcher.py
python scripts/cves_json_to_csv.py
```

5. Preprocessing Varianten generieren: Notebook `02_preprocessing_variants.ipynb` ausführen.

6. Klassische Modelle: `03_classic_models.ipynb` (lädt Varianten automatisch).

7. CNN Grundmodell: `04_cnn_model.ipynb` (experimentell).

Falls `en_core_web_sm` fehlt, werden Lemma-Dateien übersprungen – die übrigen Varianten bleiben verfügbar.

### Reproduzierbarkeit & Seeds

* Fester `random_state` (Train/Test Split) in klassischen Modellen
* Deterministische Text-Vorverarbeitung
* Ergebnisse (Metriken, Feature-Rankings) reproduzierbar durch identische Eingabedaten

### Metriken & Berichterstattung

* Primär: Macro-F1 (Klassenausgleich)
* Sekundär: Accuracy, Confusion Matrix, Parameteranzahl, Trainingszeit pro Epoche
* Optional: ROC-AUC (binär aggregiert CRITICAL/HIGH vs. MEDIUM/LOW)

## Pipeline Überblick

1. Datenerhebung (Fetcher, NVD CVE API v2.0)
2. Speicherung als JSON Lines (eine CVE pro Zeile, reduziertes Schema)
3. CSV-Extraktion je CVSS-Version (v4.0 / v3.1 / v3.0 / v2)
4. Modellaufbereitung (geplant / außerhalb dieses Abschnitts)

### Preprocessing Varianten

Erzeugt durch `02_preprocessing_variants.ipynb` unter `data/processed/`:

| Variante | Datei | Beschreibung |
|----------|-------|--------------|
| raw | `cves_processed_text_raw.csv` | Minimal: lowercase + Whitespace Normalisierung |
| clean | `cves_processed_text_clean.csv` | Normalisierung, Acronym-Expansion, Stopwörter entfernt, optionale Lemmas (falls aktiviert) |
| raw_lemma | `cves_processed_text_raw_lemma.csv` | raw + nachträgliche Lemmatization (spaCy) |
| clean_lemma | `cves_processed_text_clean_lemma.csv` | clean + Lemmatization |

Hinweise:
* Lemmatization nur falls `en_core_web_sm` installiert
* Spalten: `cve_id,severity,severity_id,description_clean`
* Mapping: `low=0, medium=1, high=2, critical=3`
* Token-Top-Statistiken & Deltas (raw vs clean, raw_lemma vs clean_lemma)

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
