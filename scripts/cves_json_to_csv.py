#!/usr/bin/env python3
"""Konvertiert die (getrimmte) `cves.json` in mehrere CSV-Dateien. Eine pro CVSS Metrik-Version.

Eingabeformat (Elemente des Arrays):
{
  "cve": {
     "id": "CVE-XXXX-YYYY",
     "descriptions": [{"lang":"en","value":"..."}],
     "metrics": {
        "cvssMetricV40": [ { "cvssData": {"baseSeverity": "HIGH" , ...} }, ...],
        "cvssMetricV31": [...],
        "cvssMetricV30": [...],
        "cvssMetricV2":  [...]
     }
  }
}

Ausgabe:
- <out_dir>/cves_v40.csv
- <out_dir>/cves_v31.csv
- <out_dir>/cves_v30.csv
- <out_dir>/cves_v2.csv

Spalten je Datei:
  cve_id,severity,description

Regeln:
- Pro CVE und Metrik-Version maximal eine Zeile.
- Falls mehrere Einträge in einer Version vorhanden: wähle den mit höchstem baseScore; bei Gleichstand den ersten.
- Falls keine Beschreibung vorhanden -> leere Beschreibung.
- Fehlt baseSeverity -> leere severity.
- CVE ohne entsprechende Metrik-Version wird für diese Datei ignoriert.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import logging
from typing import Dict, Any, Iterator, List, Optional

try:
    from dotenv import dotenv_values  # type: ignore
    DOTENV_AVAILABLE = True
except ImportError:  # pragma: no cover
    DOTENV_AVAILABLE = False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Konvertiere cves.json in versionsspezifische CSVs (cve_id,severity,description)")
    p.add_argument("--input", default="data/raw/cves.json", help="Pfad zur JSON Datei (Array von Objekten)")
    p.add_argument("--out-dir", default="data/raw", help="Zielverzeichnis für CSV Dateien")
    p.add_argument("--encoding", default="utf-8", help="Datei-Encoding")
    p.add_argument("--separator", default=",", help="CSV Trennzeichen (Default ,)")
    p.add_argument("--limit", type=int, default=None, help="Optional: nur erste N Einträge verarbeiten (Debug)")
    p.add_argument("--quiet", action="store_true", help="Weniger Ausgaben (unterdrückt Fortschritts-Logs)")
    p.add_argument("--log-level", default="INFO", help="Logging Level (DEBUG, INFO, WARNING, ERROR)")
    p.add_argument("--progress-every", type=int, default=10000, help="Fortschrittsintervall in CVEs (Default 10000)")
    return p.parse_args()


def build_logger(level: str) -> logging.Logger:
    logger = logging.getLogger("cves_json_to_csv")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
    logger.setLevel(level.upper())
    return logger


def load_env_log_level(start_path: Optional[str] = None) -> Optional[str]:
    """Liest LOG_LEVEL aus einer .env (falls vorhanden) ohne globale env zu verändern.

    Suche: traversiert Elternverzeichnisse bis Projekt-Root Marker (requirements.txt/.git/pyproject.toml) oder Dateisystemwurzel.
    """
    if not DOTENV_AVAILABLE:
        return None
    if start_path is None:
        start_path = os.path.abspath(__file__)
    cur = os.path.dirname(start_path)
    markers = {"requirements.txt", ".git", "pyproject.toml"}
    visited = set()
    while True:
        if cur in visited:
            break
        visited.add(cur)
        for m in markers:
            if os.path.exists(os.path.join(cur, m)):
                env_path = os.path.join(cur, ".env")
                if os.path.isfile(env_path):
                    values = dotenv_values(env_path) or {}
                    lvl = values.get("LOG_LEVEL")
                    if lvl:
                        return str(lvl).strip().upper()
                return None
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def ensure_dir(path: str) -> None:
    d = os.path.abspath(path)
    os.makedirs(d, exist_ok=True)


def stream_array_objects(path: str, encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    """Streaming-Parser für JSON Top-Level Array.
    Erwartet: '[' <obj> (, <obj>)* ']'. Robust gegen Whitespace & neue Zeilen.
    """
    with open(path, "r", encoding=encoding) as f:
        # Warte bis '['
        ch = f.read(1)
        while ch and ch not in "[":
            ch = f.read(1)
        if not ch:
            return
        buf: List[str] = []
        depth = 0
        in_string = False
        esc = False
        collecting = False
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            for c in chunk:
                if collecting:
                    buf.append(c)
                    if in_string:
                        if esc:
                            esc = False
                        elif c == "\\":
                            esc = True
                        elif c == '"':
                            in_string = False
                    else:
                        if c == '"':
                            in_string = True
                        elif c == '{':
                            depth += 1
                        elif c == '}':
                            depth -= 1
                            if depth == 0:
                                # Objekt fertig
                                obj_txt = ''.join(buf).strip()
                                # trailing Komma entfernen
                                if obj_txt.endswith(','):
                                    obj_txt = obj_txt[:-1].rstrip()
                                try:
                                    yield json.loads(obj_txt)
                                except json.JSONDecodeError:
                                    pass
                                buf = []
                                collecting = False
                else:
                    if c == '{':
                        collecting = True
                        depth = 1
                        in_string = False
                        esc = False
                        buf = ['{']
        # Ende ignoriert (']')


def best_metric_entry(entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not entries:
        return None
    best = None
    best_score = -1.0
    for e in entries:
        cv = (e.get("cvssData") or {})
        score = cv.get("baseScore")
        if isinstance(score, (int, float)):
            if score > best_score:
                best_score = score
                best = e
        elif best is None:
            best = e
    return best


def extract_row(cve_obj: Dict[str, Any], version_key: str) -> Optional[tuple[str, str, str]]:
    cve = cve_obj.get("cve") or {}
    cid = cve.get("id")
    if not cid:
        return None
    metrics = (cve.get("metrics") or {}).get(version_key)
    if not metrics:
        return None
    best = best_metric_entry(metrics)
    cvss = (best or {}).get("cvssData") or {}
    severity = (cvss.get("baseSeverity") or "").upper()
    score = cvss.get("baseScore")
    if not severity and isinstance(score, (int, float)) and version_key == "cvssMetricV2":
        # CVSS v2 Schwellen (NVD Klassik): 0.0 None, <4.0 Low, <7.0 Medium, sonst High
        if score == 0.0:
            severity = "NONE"
        elif score < 4.0:
            severity = "LOW"
        elif score < 7.0:
            severity = "MEDIUM"
        else:
            severity = "HIGH"
    # Description
    desc = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            raw = d.get("value") or ""
            raw = raw.replace("\r", " ").replace("\n", " ")
            # Verwende regex falls verfügbar
            import re  # lokal für Geschwindigkeit bei seltenen Matches
            raw = re.sub(r"\s+", " ", raw).strip()
            desc = raw
            break
    return (cid, severity, desc)


def main() -> int:
    args = parse_args()
    # Falls Benutzer keinen expliziten Level gesetzt hat (Standard INFO) und .env einen definiert, übernehme ihn.
    env_level = load_env_log_level()
    if env_level and args.log_level.upper() == "INFO":
        args.log_level = env_level
    logger = build_logger(args.log_level)
    if env_level:
        logger.debug("LOG_LEVEL aus .env gelesen: %s", env_level)
    if not os.path.isfile(args.input):
        logger.error("Input nicht gefunden: %s", args.input)
        return 2
    ensure_dir(args.out_dir)
    version_map = [
        ("cvssMetricV40", "v40"),
        ("cvssMetricV31", "v31"),
        ("cvssMetricV30", "v30"),
        ("cvssMetricV2", "v2"),
    ]
    writers = {}
    files = {}
    logger.info("Start Konvertierung: input=%s out_dir=%s", args.input, args.out_dir)
    try:
        for key, label in version_map:
            path = os.path.join(args.out_dir, f"cves_{label}.csv")
            f = open(path, "w", encoding=args.encoding, newline="")
            files[key] = f
            w = csv.writer(f, delimiter=args.separator)
            w.writerow(["cve_id", "severity", "description"])
            writers[key] = w
            logger.debug("Datei vorbereitet: %s", path)
        count = 0
        written = {k: 0 for k, _ in version_map}
        for obj in stream_array_objects(args.input, args.encoding):
            row_obj = obj.get("cve") or {}
            if not row_obj:
                continue
            for key, _label in version_map:
                row = extract_row(obj, key)
                if row:
                    writers[key].writerow(row)
                    written[key] += 1
            count += 1
            if not args.quiet and args.progress_every > 0 and count % args.progress_every == 0:
                logger.info("Progress: %d CVEs verarbeitet", count)
            if args.limit and count >= args.limit:
                logger.info("Limit erreicht: %d", args.limit)
                break
        if not args.quiet:
            for key, label in version_map:
                logger.info("%s: %d Zeilen", label, written[key])
        logger.info("Fertig: total=%d", count)
    finally:
        for f in files.values():
            try:
                f.close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
