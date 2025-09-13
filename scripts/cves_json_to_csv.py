#!/usr/bin/env python3
"""Konvertiert die getrimmte CVE-Datei in mehrere CSV-Dateien (eine pro CVSS Metrik-Version).

Aktuelles Eingabeformat (Standard): JSON Lines (JSONL) – eine CVE pro Zeile:
    {"cve": {"id": "CVE-XXXX-YYYY", "descriptions": [...], "metrics": {...}}}\n

Rückwärtskompatibel: Erkennt automatisch das alte Array-Format ('[ ... ]') und streamt es ohne den gesamten Inhalt in den Speicher zu laden.

Ausgabe-Dateien:
    <out_dir>/cves_v40.csv
    <out_dir>/cves_v31.csv
    <out_dir>/cves_v30.csv
    <out_dir>/cves_v2.csv

Spalten pro Datei: cve_id,severity,description

Regeln:
    - Pro CVE und Metrik-Version maximal eine Zeile (beste Metrik anhand höchstem baseScore; bei Gleichstand erste).
    - Bei CVSS v2 wird Severity aus baseScore abgeleitet falls baseSeverity fehlt.
    - Fehlende Beschreibung => leere Zelle.
    - CVE ohne Metrik-Version wird für diese Datei ignoriert.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import logging
from typing import Dict, Any, Iterator, List, Optional


class Config:
    INPUT = "data/raw/cves.jsonl"          # JSONL oder altes Array
    OUT_DIR = "data/raw"
    ENCODING = "utf-8"
    CSV_SEPARATOR = ","
    LIMIT: int | None = None              # Debug: nur erste N CVEs verarbeiten
    QUIET = False                         # Fortschrittsausgaben unterdrücken
    LOG_LEVEL = "INFO"                    # Fester Log-Level
    PROGRESS_EVERY = 10000                # Fortschritt alle N CVEs


def build_logger(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("cves_json_to_csv")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
    logger.setLevel(level.upper())
    return logger


def ensure_dir(path: str) -> None:
    d = os.path.abspath(path)
    os.makedirs(d, exist_ok=True)


def stream_cve_objects(path: str, encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    """Streamt CVE-Objekte aus JSONL (Standard) oder altem Array-Format.

    Erkennung: erste nicht-leere Zeile. '[' => Array, sonst JSONL.
    """
    try:
        with open(path, "r", encoding=encoding) as fpeek:
            first = None
            for _line in fpeek:
                s = _line.strip()
                if not s:
                    continue
                first = s
                break
    except FileNotFoundError:
        return
    if first is None:
        return
    if first.startswith('['):
        yield from _stream_array(path, encoding)
    else:
        yield from _stream_jsonl(path, encoding)


def _stream_array(path: str, encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    """Einfacher Streaming-Parser für ein Top-Level JSON-Array."""
    with open(path, "r", encoding=encoding) as f:
        ch = f.read(1)
        while ch and ch not in '[':
            ch = f.read(1)
        if not ch:
            return
        buf: list[str] = []
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
                        elif c == '\\':
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
                                obj_txt = ''.join(buf).strip()
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
        # Schließende Klammer ignorieren


def _stream_jsonl(path: str, encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding=encoding) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield obj


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
        if score == 0.0:
            severity = "NONE"
        elif score < 4.0:
            severity = "LOW"
        elif score < 7.0:
            severity = "MEDIUM"
        else:
            severity = "HIGH"
    desc = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            raw = d.get("value") or ""
            raw = raw.replace("\r", " ").replace("\n", " ")
            import re
            raw = re.sub(r"\s+", " ", raw).strip()
            desc = raw
            break
    return (cid, severity, desc)


def main() -> int:
    logger = build_logger(Config.LOG_LEVEL)
    if not os.path.isfile(Config.INPUT):
        logger.error("Input nicht gefunden: %s", Config.INPUT)
        return 2
    ensure_dir(Config.OUT_DIR)
    version_map = [
        ("cvssMetricV40", "v40"),
        ("cvssMetricV31", "v31"),
        ("cvssMetricV30", "v30"),
        ("cvssMetricV2", "v2"),
    ]
    writers: dict[str, csv.writer] = {}
    files: dict[str, Any] = {}
    logger.info("Start Konvertierung: input=%s out_dir=%s", Config.INPUT, Config.OUT_DIR)
    try:
        for key, label in version_map:
            path = os.path.join(Config.OUT_DIR, f"cves_{label}.csv")
            f = open(path, "w", encoding=Config.ENCODING, newline="")
            files[key] = f
            w = csv.writer(f, delimiter=Config.CSV_SEPARATOR)
            w.writerow(["cve_id", "severity", "description"])
            writers[key] = w
            logger.debug("Datei vorbereitet: %s", path)
        count = 0
        written = {k: 0 for k, _ in version_map}
        for obj in stream_cve_objects(Config.INPUT, Config.ENCODING):
            row_obj = obj.get("cve") or {}
            if not row_obj:
                continue
            for key, _label in version_map:
                row = extract_row(obj, key)
                if row:
                    writers[key].writerow(row)
                    written[key] += 1
            count += 1
            if (not Config.QUIET) and Config.PROGRESS_EVERY > 0 and count % Config.PROGRESS_EVERY == 0:
                logger.info("Progress: %d CVEs verarbeitet", count)
            if Config.LIMIT and count >= Config.LIMIT:
                logger.info("Limit erreicht: %d", Config.LIMIT)
                break
        if not Config.QUIET:
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
        # Schließende Klammer ignorieren


def _stream_jsonl(path: str, encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding=encoding) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield obj


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
    logger = build_logger(Config.LOG_LEVEL)
    if not os.path.isfile(Config.INPUT):
        logger.error("Input nicht gefunden: %s", Config.INPUT)
        return 2
    ensure_dir(Config.OUT_DIR)
    version_map = [
        ("cvssMetricV40", "v40"),
        ("cvssMetricV31", "v31"),
        ("cvssMetricV30", "v30"),
        ("cvssMetricV2", "v2"),
    ]
    writers: dict[str, csv.writer] = {}
    files: dict[str, Any] = {}
    logger.info("Start Konvertierung: input=%s out_dir=%s", Config.INPUT, Config.OUT_DIR)
    try:
        for key, label in version_map:
            path = os.path.join(Config.OUT_DIR, f"cves_{label}.csv")
            f = open(path, "w", encoding=Config.ENCODING, newline="")
            files[key] = f
            w = csv.writer(f, delimiter=Config.CSV_SEPARATOR)
            w.writerow(["cve_id", "severity", "description"])
            writers[key] = w
            logger.debug("Datei vorbereitet: %s", path)
        count = 0
        written = {k: 0 for k, _ in version_map}
        for obj in stream_cve_objects(Config.INPUT, Config.ENCODING):
            row_obj = obj.get("cve") or {}
            if not row_obj:
                continue
            for key, _label in version_map:
                row = extract_row(obj, key)
                if row:
                    writers[key].writerow(row)
                    written[key] += 1
            count += 1
            if (not Config.QUIET) and Config.PROGRESS_EVERY > 0 and count % Config.PROGRESS_EVERY == 0:
                logger.info("Progress: %d CVEs verarbeitet", count)
            if Config.LIMIT and count >= Config.LIMIT:
                logger.info("Limit erreicht: %d", Config.LIMIT)
                break
        if not Config.QUIET:
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
