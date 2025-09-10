"""NVD CVE Fetcher – streamt, trimmt und aktualisiert CVE-Daten (CVE API v2.0).

Autor: Konrad Eckhardt (2025)

Kurzbeschreibung:
	- Initialer Vollabruf aller CVEs seit 1999 (fensterweise, <=120 Tage).
	- Resume: bestehende Datei wird gestreamt übernommen, neue CVEs werden angehängt.
	- Update: ausschließlich per CVE API lastModified-Range (chunked in <=120 Tage),
	  geänderte IDs werden ersetzt, neue angehängt.
	- Schreibweise: Streaming + atomare Renames; state.json hält lastModified und Zähler.

Dateien:
	- Output (Default): data/raw/cves.json (JSON-Array getrimmter CVEs)
	- State: data/raw/cves.json.state.json (oder _Config.STATE_FILE, falls gesetzt)

Konfiguration (.env im Projekt-Root, optional – erfordert python-dotenv):
	- NVD_API_KEY       – erhöhtes Rate-Limit (empfohlen)
	- CONTACT_EMAIL     – wird in den User-Agent aufgenommen
	- LOG_LEVEL         – Logging Level (DEBUG, INFO, WARNING, ERROR) überschreibt Standard

Benutzung:
	- Direktstart:        python scripts/nvd_cve_fetcher/nvd_cve_fetcher.py
	- Programmatic:       from scripts.nvd_cve_fetcher.nvd_cve_fetcher import run; run()
	- Ausgabeort ändern:  _Config.OUTPUT anpassen (im Skript)
	- State zurücksetzen: <output>.state.json löschen oder lastModifiedISO zurückdatieren

Hinweise:
	- Keine History-API mehr; Updates erfolgen nur über lastModified.
	- resultsPerPage bis 2000, Ratenbegrenzung gemäß NVD (5/30s ohne Key, 50/30s mit Key).
"""

from __future__ import annotations
import datetime as dt
import json
import os
import sys
import time
import random
from typing import Dict, Any, Iterable, Optional, Iterator
import logging
from collections import deque
from requests import Session
from pathlib import Path

import requests
try:
	from dotenv import dotenv_values  # type: ignore
	DOTENV_AVAILABLE = True
except ImportError:  # pragma: no cover
	DOTENV_AVAILABLE = False

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120          # API Limit
RESULTS_PER_PAGE_MAX = 2000    # API Limit
LOG_PREFIX = "fetch_nvd_cves"
APP_NAME = "nvd_cve_fetcher"   # Kurzform statt langem Prototyp-Namen
APP_VERSION = "1.0"
UPDATE_SLEEP_SECONDS = 6       # NVD Best Practice (Update/Segment-Pause)

# Offizielle Limits laut NIST (Rolling Window 30s): ohne Key 5, mit Key 50.
DEFAULT_SLEEP_NO_KEY = 2.5
DEFAULT_SLEEP_WITH_KEY = 1
WINDOW_SECONDS = 30
PREFETCH_WAIT_SECONDS = 2     # Freundliche Start-Verzögerung

__all__ = ["run"]

CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class _Config:
	OUTPUT = "data/raw/cves.json"
	STATE_FILE = None  # None -> Default (<output>.state.json)
	RETRIES = 3
	WINDOW_DAYS = MAX_WINDOW_DAYS
	RESULTS_PER_PAGE = RESULTS_PER_PAGE_MAX
	LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
	INITIAL_WAIT = True  # 10s Wartezeit vor Start (API-freundlich). Auf False setzen um zu überspringen.
	INCREMENTAL_SINCE = None  # z. B. "2024-01-01" – ansonsten None
	FAIL_ON_PARTIAL = False
	STATS_FILE = None  # z. B. "data/derived/fetch_stats.json"


def build_headers(api_key: Optional[str], user_agent: str) -> Dict[str, str]:
	h = {"User-Agent": user_agent}
	if api_key:
		h["apiKey"] = api_key
	return h


def parse_nvd_timestamp(s: Optional[str]) -> Optional[dt.datetime]:
	if not s:
		return None
	for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
		try:
			return dt.datetime.strptime(s, fmt)
		except ValueError:
			continue
	return None


def format_nvd_timestamp(ts: dt.datetime) -> str:
	return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ts.microsecond else ts.strftime("%Y-%m-%dT%H:%M:%SZ")

# Streaming eines JSON-Arrays mit Objekten (Top-Level)
def stream_array_objects(path: str) -> Iterator[Dict[str, Any]]:
	with open(path, "r", encoding="utf-8") as f:
		in_string = False
		esc = False
		brace_depth = 0
		collecting = False
		buf_chars: list[str] = []
		# Skip bis zur ersten '['
		while True:
			ch = f.read(1)
			if not ch or ch == '[':
				break
		while True:
			chunk = f.read(8192)
			if not chunk:
				break
			for ch in chunk:
				if collecting:
					buf_chars.append(ch)
					if in_string:
						if esc:
							esc = False
						elif ch == '\\':
							esc = True
						elif ch == '"':
							in_string = False
					else:
						if ch == '"':
							in_string = True
						elif ch == '{':
							brace_depth += 1
						elif ch == '}':
							brace_depth -= 1
							if brace_depth == 0:
								obj_txt = ''.join(buf_chars).strip()
								if obj_txt.endswith(','):
									obj_txt = obj_txt[:-1].rstrip()
								try:
									yield json.loads(obj_txt)
								except json.JSONDecodeError:
									pass
								buf_chars = []
								collecting = False
				else:
					if ch == '{':
						collecting = True
						brace_depth = 1
						in_string = False
						esc = False

# Ermittle vorhandene CVE IDs, max published (Date) & Count streaming
def collect_existing_state(path: str, logger: logging.Logger) -> tuple[set[str], Optional[dt.date], int]:
	ids: set[str] = set()
	max_pub: Optional[dt.date] = None
	count = 0
	if not os.path.isfile(path):
		return ids, max_pub, 0
	for obj in stream_array_objects(path):
		cve = obj.get("cve") or {}
		cid = cve.get("id")
		if cid:
			ids.add(cid)
		pub = cve.get("published")
		if pub:
			try:
				pdate = dt.datetime.strptime(pub.split("T")[0], "%Y-%m-%d").date()
				if not max_pub or pdate > max_pub:
					max_pub = pdate
			except ValueError:
				pass
		count += 1
	logger.debug("Bestehend: %d CVEs, max published=%s", count, max_pub)
	return ids, max_pub, count


# Sliding-Window Rate Limiter (deque-basiert) für exakte API-Limits
class RateLimiter:
	def __init__(self, max_requests: int, window_seconds: int = WINDOW_SECONDS):
		self.max_requests = max_requests
		self.window = window_seconds
		self._events: deque[float] = deque()

	def acquire(self, logger: logging.Logger) -> None:
		now = time.time()
		while self._events and self._events[0] <= now - self.window:
			self._events.popleft()
		if len(self._events) >= self.max_requests:
			wait_for = self._events[0] + self.window - now
			if wait_for > 0:
				logger.debug("RateLimiter blockiert %.2fs (Limit %s/%ss)", wait_for, self.max_requests, self.window)
				time.sleep(wait_for)
				now = time.time()
				while self._events and self._events[0] <= now - self.window:
					self._events.popleft()
		self._events.append(time.time())


def build_logger(level: str) -> logging.Logger:
	logger = logging.getLogger()  # Root-Logger
	if not logger.handlers:
		handler = logging.StreamHandler()
		# Format 2: Zeit + Level
		handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
		logger.addHandler(handler)
	logger.setLevel(level.upper())
	return logger

# Liest Konfig aus .env (erzwingt dotenv falls .env existiert)
def load_env_config(logger: logging.Logger) -> dict:

	# Suche nach einem Projekt-Root durch Marker-Dateien/-Ordner
	def find_project_root(markers=("pyproject.toml", "requirements.txt", ".git")) -> Path:
		
		start = Path(__file__).resolve()
		for parent in [start.parent] + list(start.parents):  # parent zuerst (Verzeichnis der Datei)
			for m in markers:
				if (parent / m).exists():
					return parent
		# Fallback wie zuvor: ../..
		try:
			return start.parents[2]
		except IndexError:
			return start.parent

	root = str(find_project_root())
	dotenv_path = os.path.join(root, ".env")
	logger.debug("Suche .env unter: %s (CWD=%s)", dotenv_path, os.getcwd())
	cfg = {"api_key": None, "contact_email": None, "log_level": None}
	if not os.path.isfile(dotenv_path):
		logger.info("Keine .env (%s) – ohne API Key & Kontakt.", dotenv_path)
		return cfg
	if not DOTENV_AVAILABLE:
		logger.error(".env vorhanden aber 'python-dotenv' nicht installiert – Installation erforderlich")
		raise RuntimeError("python-dotenv fehlt für .env Verarbeitung")
	def _clean(val: str) -> str:
		val = val.strip()
		if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
			val = val[1:-1].strip()
		return val
	values = dotenv_values(dotenv_path) or {}
	present = {k: ("JA" if values.get(k) else "NEIN") for k in ("NVD_API_KEY", "CONTACT_EMAIL")}
	logger.debug(".env geladen – NVD_API_KEY=%s CONTACT_EMAIL=%s", present["NVD_API_KEY"], present["CONTACT_EMAIL"])
	if values.get("NVD_API_KEY"):
		cfg["api_key"] = _clean(values["NVD_API_KEY"])
	elif "NVD_API_KEY" in values:
		logger.warning("NVD_API_KEY leer in .env")
	if values.get("CONTACT_EMAIL"):
		cfg["contact_email"] = _clean(values["CONTACT_EMAIL"])
	if values.get("LOG_LEVEL"):
		cfg["log_level"] = _clean(values["LOG_LEVEL"]).upper()
	return cfg


def build_user_agent(cfg: dict) -> str:
	ua = f"{APP_NAME}/{APP_VERSION}"
	if cfg.get("contact_email"):
		ua += f" (+mailto:{cfg['contact_email']})"
	return ua


def ensure_dir(path: str) -> None:
	d = os.path.dirname(path)
	if d:
		os.makedirs(d, exist_ok=True)


def parse_date(date_str: str) -> dt.date:
	return dt.datetime.strptime(date_str, "%Y-%m-%d").date()


# Standardzeitraum zurückgeben (1999-01-01 .. heute).
def default_date_range() -> tuple[dt.date, dt.date]:
	today = dt.date.today()
	start = dt.date(1999, 1, 1)
	return start, today

# Zeitraum in maximal zulässige Intervalle (<=120 Tage) aufteilen.
def chunk_date_range(start: dt.date, end: dt.date, max_days: int) -> Iterable[tuple[dt.date, dt.date]]:
	current = start
	delta = dt.timedelta(days=max_days - 1)  # inklusives Fenster
	while current <= end:
		window_end = min(end, current + delta)
		yield current, window_end
		current = window_end + dt.timedelta(days=1)


def iso_date(d: dt.date, start: bool) -> str:
	"""UTC Zeitstempel im NVD-Format zurückgeben (Start oder Ende des Tages)."""
	time_part = "00:00:00" if start else "23:59:59"
	return f"{d.isoformat()}T{time_part}Z"

# CVE-Objekt extrahieren (schemaorientiert, Zugriffe minimal)
def trim_vulnerability(v: Dict[str, Any]) -> Dict[str, Any]:
	cve = v.get("cve", {}) or {}
	# Basisfelder direkt
	result: Dict[str, Any] = {
		"id": cve.get("id"),
		"published": cve.get("published"),
		"lastModified": cve.get("lastModified"),
	}
	# Beschreibung (erste EN falls vorhanden)
	for d in (cve.get("descriptions") or []):
		if d.get("lang") == "en":
			val = d.get("value")
			if val:
				result["descriptions"] = [{"lang": "en", "value": val}]
			break
	# CVSS Metriken (v4.0, v3.1, v3.0, v2) – nur definierte Kernwerte
	metrics = cve.get("metrics") or {}
	metrics_out: Dict[str, Any] = {}
	for key in CVSS_METRIC_KEYS:
		entries = metrics.get(key)
		if not entries:
			continue
		trimmed_entries = []
		for e in entries:
			cvss = e.get("cvssData") or {}
			vs = cvss.get("vectorString")
			bs = cvss.get("baseScore")
			bv = cvss.get("baseSeverity")
			pairs = [("vectorString", vs), ("baseScore", bs), ("baseSeverity", bv)]
			inner = {k: val for k, val in pairs if val is not None}
			if inner:
				trimmed_entries.append({"cvssData": inner})
		if trimmed_entries:
			metrics_out[key] = trimmed_entries
	if metrics_out:
		result["metrics"] = metrics_out
	return {"cve": result}


# Primärer Fenster-Fetch (Paginierung über published)
def request_cves_window(
		pub_start: dt.date,
		pub_end: dt.date,
		base_sleep: float,
		retries: int,
		limiter: RateLimiter,
		results_per_page: int,
		session: Session,
		api_key: Optional[str],
		user_agent: str,
		logger: logging.Logger,
):
	start_iso = iso_date(pub_start, True)
	end_iso = iso_date(pub_end, False)
	start_index = 0
	headers = build_headers(api_key, user_agent)

	page_total = None
	page_count = 0
	total_yielded = 0

	while True:
		params = {
			"pubStartDate": start_iso,
			"pubEndDate": end_iso,
			"startIndex": start_index,
			"resultsPerPage": results_per_page,
		}
		attempt = 0
		while True:
			limiter.acquire(logger)
			req_t0 = time.time()
			resp = None
			try:
				resp = session.get(BASE_URL, params=params, headers=headers, timeout=60)
				lat = time.time() - req_t0
				status = resp.status_code
				if status == 429:
					retry_after = resp.headers.get("Retry-After")
					delay = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt) + random.uniform(0, 1)
					logger.warning("429 erhalten – warte %.2fs (Versuch %d)", delay, attempt + 1)
					time.sleep(delay)
					attempt += 1
					if attempt > retries:
						raise RuntimeError("Zu viele 429 Antworten – Abbruch")
					continue
				if status >= 500 and attempt < retries:
					delay = (2 ** attempt) + random.uniform(0, 0.5)
					logger.warning("Serverfehler %s – Retry in %.2fs", status, delay)
					time.sleep(delay)
					attempt += 1
					continue
				resp.raise_for_status()
				data = resp.json()
				logger.debug("Fenster %s -> %s startIndex=%d Latenz=%.2fs Versuch=%d Status=%d", pub_start, pub_end, start_index, lat, attempt + 1, status)
				break
			except (requests.RequestException, json.JSONDecodeError) as e:
				attempt += 1
				if attempt > retries:
					raise RuntimeError(f"Fehlgeschlagen nach {retries} Versuchen: {e}") from e
				delay = (2 ** attempt) + random.uniform(0, 0.5)
				logger.warning("Fehler '%s' – Retry in %.2fs (Versuch %d)", e, delay, attempt)
				time.sleep(delay)
			finally:
				if resp is not None:
					resp.close()

		if page_total is None:
			page_total = data.get("totalResults", 0)
		vulns = data.get("vulnerabilities", [])
		if not vulns:
			break
		page_count += 1
		for v in vulns:
			total_yielded += 1
			yield v
		start_index += len(vulns)
		logger.info("Fenster %s -> %s Seite %d: %d neue (gesamt %d/%d)", pub_start, pub_end, page_count, len(vulns), total_yielded, page_total)
		if page_total is not None and start_index >= page_total:
			break
		jit = random.uniform(0, base_sleep * 0.3)
		planned = base_sleep + jit
		logger.debug("Schlafe %.2fs (Basis %.2f + Jitter %.2f)", planned, base_sleep, jit)
		time.sleep(planned)

# Liefert neue/aktualisierte CVEs seit last_mod_start, chunked in <=120 Tage Fenster
def fetch_updates_last_modified(
	last_mod_start: dt.datetime,
	limiter: RateLimiter,
	session: Session,
	api_key: Optional[str],
	user_agent: str,
	logger: logging.Logger,
	max_retries: int = 3,
) -> Iterable[Dict[str, Any]]:
	
	headers = build_headers(api_key, user_agent)
	def fmt(ts: dt.datetime) -> str:
		return ts.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
	window_delta = dt.timedelta(days=MAX_WINDOW_DAYS - 1)
	segment_start = last_mod_start
	end_global = dt.datetime.now(dt.UTC).replace(tzinfo=None)
	segment_index = 0
	while segment_start < end_global:
		segment_index += 1
		segment_end = min(end_global, segment_start + window_delta)
		logger.info("Update Segment %d: %s -> %s", segment_index, fmt(segment_start), fmt(segment_end))
		start_index = 0
		total_results = None
		page = 0
		while True:
			params = {
				"lastModStartDate": fmt(segment_start),
				"lastModEndDate": fmt(segment_end),
				"startIndex": start_index,
				"resultsPerPage": 2000,
			}
			attempt = 0
			while True:
				limiter.acquire(logger)
				resp = None
				try:
					t0 = time.time()
					resp = session.get(BASE_URL, params=params, headers=headers, timeout=60)
					status = resp.status_code
					if status == 429:
						retry_after = resp.headers.get("Retry-After")
						delay = float(retry_after) if retry_after and retry_after.isdigit() else min(60, (2 ** attempt))
						logger.warning("Update 429 – warte %.2fs", delay)
						time.sleep(delay)
						attempt += 1
						if attempt > max_retries:
							raise RuntimeError("Zu viele 429 im Update-Modus")
						continue
					if status >= 500 and attempt < max_retries:
						delay = min(60, (2 ** attempt))
						logger.warning("Update Serverfehler %s – Retry in %.2fs", status, delay)
						time.sleep(delay)
						attempt += 1
						continue
					resp.raise_for_status()
					data = resp.json()
					logger.debug("Update seg=%d startIndex=%d Latenz=%.2fs Status=%d", segment_index, start_index, time.time() - t0, status)
					break
				except (requests.RequestException, json.JSONDecodeError) as e:  # noqa: PERF203
					attempt += 1
					if attempt > max_retries:
						raise RuntimeError(f"Update fehlgeschlagen nach {max_retries} Versuchen: {e}") from e
					delay = min(60, (2 ** attempt))
					logger.warning("Update Fehler '%s' – Retry in %.2fs", e, delay)
					time.sleep(delay)
				finally:
					if resp is not None:
						resp.close()
			if total_results is None:
				total_results = data.get("totalResults", 0)
				logger.info("Update totalResults=%s Segment %d", total_results, segment_index)
			vulns = data.get("vulnerabilities", []) or []
			if not vulns:
				break
			page += 1
			logger.info("Update Segment %d Seite %d: %d Einträge (startIndex=%d)", segment_index, page, len(vulns), start_index)
			for v in vulns:
				yield v
			start_index += len(vulns)
			if total_results is not None and start_index >= total_results:
				break
			logger.debug("Update Sleep %ds", UPDATE_SLEEP_SECONDS)
			time.sleep(UPDATE_SLEEP_SECONDS)
		# nächstes Segment
		segment_start = segment_end
		if segment_start == segment_end:  # Schritt gegen Endlosschleife
			segment_start += dt.timedelta(seconds=1)


def stream_fetch(
		start_date: dt.date,
		end_date: dt.date,
		window_days: int,
		results_per_page: int,
		base_sleep: float,
		retries: int,
		limiter: RateLimiter,
		api_key: Optional[str],
		output_path: str,
		stats: Dict[str, Any],
		incremental_since: Optional[dt.date],
		user_agent: str,
		logger: logging.Logger,
) -> Dict[str, Any]:
	
	# Streamt CVEs fensterweise und schreibt getrimmt in eine temporäre Datei (JSON Array)
	t0 = time.time()
	cve_ids_seen = set()
	trimmed_count = 0
	existing_count = 0
	partial = False
	temp_path = output_path + ".tmp"
	ensure_dir(output_path)
	with open(temp_path, "w", encoding="utf-8") as out_f:
		out_f.write("[\n")
		first = True
		# Resume (vorhandene Datei) streamen und direkt wieder rausschreiben
		if os.path.isfile(output_path) and os.path.getsize(output_path) > 2:
			logger.info("Resume: existierende Datei wird gestreamt übernommen")
			for obj in stream_array_objects(output_path):
				cid = (obj.get("cve") or {}).get("id")
				if cid:
					cve_ids_seen.add(cid)
				if not first:
					out_f.write(",\n")
				json.dump(obj, out_f, ensure_ascii=False)
				first = False
				existing_count += 1
		with requests.Session() as session:
			for idx, (w_start, w_end) in enumerate(chunk_date_range(start_date, end_date, window_days), start=1):
				logger.info("Fenster %d: %s -> %s", idx, w_start, w_end)
				try:
					for raw in request_cves_window(w_start, w_end, base_sleep, retries, limiter, results_per_page, session, api_key, user_agent, logger):
						trimmed = trim_vulnerability(raw)
						cid = trimmed["cve"].get("id")
						if not cid:
							continue
						if incremental_since:
							pub = trimmed["cve"].get("published")
							try:
								if pub and dt.datetime.strptime(pub.split("T")[0], "%Y-%m-%d").date() < incremental_since:
									continue
							except ValueError:
								pass
						if cid in cve_ids_seen:
							continue
						cve_ids_seen.add(cid)
						if not first:
							out_f.write(",\n")
						first = False
						json.dump(trimmed, out_f, ensure_ascii=False)
						trimmed_count += 1
				except KeyboardInterrupt:
					partial = True
					logger.warning("Benutzerabbruch während Fenster – partielle Daten werden abgeschlossen")
					break
		out_f.write("\n]\n")
	os.replace(temp_path, output_path)
	stats.update({
		"totalCVEs": existing_count + trimmed_count,
		"previousCVEs": existing_count,
		"newCVEs": trimmed_count,
		"uniqueCVEs": existing_count + trimmed_count,
		"durationSeconds": round(time.time() - t0, 2),
		"requestsPerformed": len(limiter._events),
		"effectiveReqPerSec": round(len(limiter._events) / max(1e-6, time.time() - t0), 3),
		"partial": partial,
	})
	return stats

def update_mode(
	output_path: str,
	limiter: RateLimiter,
	api_key: Optional[str],
	user_agent: str,
	logger: logging.Logger,
	state_file: Optional[str],
) -> Dict[str, Any]:
	"""Update nur über CVE API (lastModified Range).

	Ablauf:
	 1. lastModStart aus State oder Datei (Streaming-Scan) bestimmen.
	 2. Alle CVEs seit lastModStart via fetch_updates_last_modified holen (pagination).
	 3. Re-streame bestehende Datei: ersetze geänderte IDs, hänge neue an.
	 4. State-Datei aktualisieren.
	"""
	if state_file is None:
		state_file = output_path + ".state.json"
	# lastModStart bestimmen
	last_mod_start: Optional[dt.datetime] = None
	if os.path.isfile(state_file):
		try:
			with open(state_file, "r", encoding="utf-8") as sf:
				state_data = json.load(sf)
			val = state_data.get("lastModifiedISO")
			last_mod_start = parse_nvd_timestamp(val)
			if last_mod_start:
				logger.info("State-Datei gefunden: lastModified=%s", val)
		except Exception as e:  # noqa: BLE001
			logger.warning("State-Datei unlesbar (%s) – ignoriere", e)
	if last_mod_start is None and os.path.isfile(output_path):
		logger.info("Bestimme lastModified Basis durch Streaming-Scan")
		for obj in stream_array_objects(output_path):
			cve = obj.get("cve") or {}
			lm = cve.get("lastModified") or cve.get("published")
			pts = parse_nvd_timestamp(lm)
			if pts and (last_mod_start is None or pts > last_mod_start):
				last_mod_start = pts
	if last_mod_start is None:
		last_mod_start = dt.datetime(1999, 1, 1)
	last_mod_start = max(dt.datetime(1999, 1, 1), last_mod_start - dt.timedelta(seconds=5))
	logger.info("Update-Modus: Basis lastModified=%s", format_nvd_timestamp(last_mod_start))

	replacements: Dict[str, Dict[str, Any]] = {}
	max_last_modified: Optional[dt.datetime] = None
	new_count = 0
	replaced = 0
	interrupted = False
	with requests.Session() as session:
		try:
			for raw in fetch_updates_last_modified(last_mod_start, limiter, session, api_key, user_agent, logger):
				trimmed = trim_vulnerability(raw)
				cid = (trimmed.get("cve") or {}).get("id")
				if not cid:
					continue
				lm = (trimmed.get("cve") or {}).get("lastModified") or (trimmed.get("cve") or {}).get("published")
				pts = parse_nvd_timestamp(lm)
				if pts and (max_last_modified is None or pts > max_last_modified):
					max_last_modified = pts
				replacements[cid] = trimmed
		except KeyboardInterrupt:
			logger.warning("Abbruch während Update-Fetch – verwende bis dahin geladene Änderungen (partial)")
			interrupted = True

	if not replacements:
		logger.info("Keine Änderungen seit letztem Stand")
		_write_state(state_file, last_mod_start, logger)
		total_existing = 0
		if os.path.isfile(output_path):
			for _ in stream_array_objects(output_path):
				total_existing += 1
		return {"new": 0, "replaced": 0, "total": total_existing, "partial": interrupted}

	temp_path = output_path + ".tmp"
	ensure_dir(output_path)
	partial = False
	written = 0
	try:
		with open(temp_path, "w", encoding="utf-8") as wf:
			wf.write("[\n")
			first = True
			seen_ids = set()
			if os.path.isfile(output_path):
				for obj in stream_array_objects(output_path):
					cve = obj.get("cve") or {}
					cid = cve.get("id")
					if cid and cid in replacements:
						obj = replacements.pop(cid)
						replaced += 1
					if cid:
						seen_ids.add(cid)
					lm = (obj.get("cve") or {}).get("lastModified") or (obj.get("cve") or {}).get("published")
					pts = parse_nvd_timestamp(lm)
					if pts and (max_last_modified is None or pts > max_last_modified):
						max_last_modified = pts
					if not first:
						wf.write(",\n")
					first = False
					json.dump(obj, wf, ensure_ascii=False)
					written += 1
			# Verbleibende neue CVEs (nicht in bestehender Datei)
			for cid, obj in replacements.items():
				if cid in seen_ids:
					continue
				if not first:
					wf.write(",\n")
				first = False
				json.dump(obj, wf, ensure_ascii=False)
				written += 1
				new_count += 1
			wf.write("\n]\n")
	except KeyboardInterrupt:
		partial = True
		logger.warning("Abbruch während Schreibphase – partielle tmp verworfen")
		try:
			os.remove(temp_path)
		except OSError:
			pass
		return {"new": new_count, "replaced": replaced, "total": None, "partial": True}

	os.replace(temp_path, output_path)
	logger.info("Update abgeschlossen: neu=%d ersetzt=%d gesamt=%d", new_count, replaced, written)
	if max_last_modified is None:
		max_last_modified = last_mod_start
	_write_state(state_file, max_last_modified, logger, written)
	return {"new": new_count, "replaced": replaced, "total": written, "partial": (partial or interrupted)}


def _write_state(state_file: str, max_last_modified: dt.datetime, logger: logging.Logger, total_cves: Optional[int] = None) -> None:
	ensure_dir(state_file)
	state_tmp = state_file + ".tmp"
	data = {
		"lastModifiedISO": format_nvd_timestamp(max_last_modified),
		# Zeitzonen-sicherer Zeitstempel (UTC)
		"updatedUTC": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
	}
	if total_cves is not None:
		data["totalCVEs"] = total_cves
	with open(state_tmp, "w", encoding="utf-8") as sf:
		json.dump(data, sf, ensure_ascii=False, indent=2)
		sf.write("\n")
	os.replace(state_tmp, state_file)
	logger.info("State aktualisiert: %s", state_file)


def run() -> int:
	"""Startet den Fetch ohne CLI: Initial -> Resume -> Update.

	Rückgabe-Codes:
	    0   Erfolg (vollständig)
	    1   Teilabbruch + FAIL_ON_PARTIAL aktiv
	    2   Konfigurations-/Startfehler (z.B. fehlendes python-dotenv bei vorhandener .env)
	  130   Teilweise Daten (Benutzerabbruch), aber gültige JSON-Ausgabe
	"""
	logger = build_logger(_Config.LOG_LEVEL)
	logger.info("NVD CVE Fetcher for CVE Severity Classification (Prototyp)")
	start_date, end_date = default_date_range()
	try:
		cfg = load_env_config(logger)
	except RuntimeError as e:  # fehlende python-dotenv bei vorhandener .env
		logger.error(str(e))
		return 2
	# Falls LOG_LEVEL in .env gesetzt wurde nachträglich Logger-Level anpassen
	if cfg.get("log_level") and cfg["log_level"] != _Config.LOG_LEVEL.upper():
		logger.setLevel(cfg["log_level"])
		logger.info("Log-Level aus .env gesetzt: %s", cfg["log_level"])
	api_key = cfg.get("api_key")
	user_agent = build_user_agent(cfg)
	base_sleep = DEFAULT_SLEEP_WITH_KEY if api_key else DEFAULT_SLEEP_NO_KEY
	window_days = max(1, min(_Config.WINDOW_DAYS, MAX_WINDOW_DAYS))
	results_per_page = max(1, min(_Config.RESULTS_PER_PAGE, RESULTS_PER_PAGE_MAX))
	limiter = RateLimiter(50 if api_key else 5, WINDOW_SECONDS)
	logger.info("================== Konfiguration ==================")
	logger.info("Zeitraum: %s -> %s", start_date, end_date)
	logger.info("API Key: %s", "JA" if api_key else "NEIN")
	logger.info("Kontakt: %s", cfg.get("contact_email") or "—")
	logger.info("User-Agent: %s", user_agent)
	logger.info("Limit: %d/%ds", limiter.max_requests, limiter.window)
	logger.info("Basis-Schlaf: %.2fs (Jitter bis %.2fs)", base_sleep, base_sleep * 0.3)
	logger.info("Fenster: erlaubt %d | genutzt %d", MAX_WINDOW_DAYS, window_days)
	logger.info("Results/Page: erlaubt %d | genutzt %d", RESULTS_PER_PAGE_MAX, results_per_page)
	logger.info("Output: %s", _Config.OUTPUT)
	logger.info("===================================================")
	if _Config.INITIAL_WAIT:
		logger.info("Start in %ds", PREFETCH_WAIT_SECONDS)
		try:
			time.sleep(PREFETCH_WAIT_SECONDS)
		except KeyboardInterrupt:
			logger.info("Abbruch vor Start")
			return 130

	def _scan_max_published(path: str) -> Optional[dt.date]:
		if not os.path.isfile(path):
			return None
		try:
			with open(path, "r", encoding="utf-8") as f:
				data = json.load(f)
			max_pub = None
			for obj in data:
				cve = (obj.get("cve") or {})
				pub = cve.get("published")
				if not pub:
					continue
				try:
					pdate = dt.datetime.strptime(pub.split("T")[0], "%Y-%m-%d").date()
				except ValueError:
					continue
				if not max_pub or pdate > max_pub:
					max_pub = pdate
			return max_pub
		except Exception:
			return None

	output_path = _Config.OUTPUT
	existing_file = os.path.isfile(output_path) and os.path.getsize(output_path) > 2
	resume_start = None
	if existing_file:
		max_pub = _scan_max_published(output_path)
		if max_pub and max_pub < end_date:
			resume_start = max_pub
		elif max_pub and max_pub >= end_date:
			logger.info("Alle CVEs bis heute vorhanden – wechsle in Update-Modus")
			res = update_mode(output_path, limiter, api_key, user_agent, logger, _Config.STATE_FILE)
			return 130 if res.get("partial") else 0

	stats = {"start": (resume_start or start_date).isoformat(), "end": end_date.isoformat(), "apiKey": bool(api_key), "windowDays": window_days, "resultsPerPage": results_per_page, "since": _Config.INCREMENTAL_SINCE}
	incremental_since = None
	if _Config.INCREMENTAL_SINCE:
		try:
			incremental_since = parse_date(_Config.INCREMENTAL_SINCE)
		except ValueError:
			logger.error("INCREMENTAL_SINCE ungültig – ignoriere")

	# Bestimme Startpunkt ohne gesamtes JSON zu laden (Streaming übernimmt vorhandene Daten)
	if resume_start is None and not existing_file:
		logger.info("Initialer Vollabruf startet …")
		fetch_start = start_date
	else:
		if resume_start is not None:
			logger.info("Resume ab %s …", resume_start)
			fetch_start = resume_start
		else:
			fetch_start = start_date
	try:
		stats = stream_fetch(fetch_start, end_date, window_days, results_per_page, base_sleep, _Config.RETRIES, limiter, api_key, output_path, stats, incremental_since, user_agent, logger)
	except KeyboardInterrupt:
		stats["partial"] = True
		logger.warning("Abbruch – partial")
	logger.info("Fertig (Basis-Fetch): total=%d (neu=%d, vorher=%d) in %ss (Requests %d, Rate %.2f req/s)%s", stats.get("totalCVEs", 0), stats.get("newCVEs", 0), stats.get("previousCVEs", 0), stats.get("durationSeconds"), stats.get("requestsPerformed"), stats.get("effectiveReqPerSec"), " PARTIAL" if stats.get("partial") else "")
	# State nach Basis-Fetch schreiben (falls nicht direkt in Update-Modus gewechselt wurde)
	try:
		state_file = _Config.STATE_FILE or (output_path + ".state.json")
		# Ermittle größtes lastModified/published über Streaming (für konsistente Fortsetzung)
		max_lm: Optional[dt.datetime] = None
		for obj in stream_array_objects(output_path):
			cve = (obj.get("cve") or {})
			lm = cve.get("lastModified") or cve.get("published")
			pts = parse_nvd_timestamp(lm)
			if pts and (max_lm is None or pts > max_lm):
				max_lm = pts
		if max_lm:
			_write_state(state_file, max_lm, logger, stats.get("totalCVEs"))
	except Exception as e:  # noqa: BLE001
		logger.warning("State konnte nach Basis-Fetch nicht geschrieben werden: %s", e)
	if _Config.STATS_FILE:
		ensure_dir(_Config.STATS_FILE)
		with open(_Config.STATS_FILE, "w", encoding="utf-8") as sf:
			json.dump(stats, sf, ensure_ascii=False, indent=2)
		logger.info("Stats gespeichert: %s", _Config.STATS_FILE)
	if stats.get("partial") and _Config.FAIL_ON_PARTIAL:
		return 1
	return 130 if stats.get("partial") else 0


if __name__ == "__main__":
	sys.exit(run())
