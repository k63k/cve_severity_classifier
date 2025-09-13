"""NVD CVE Fetcher (CVE API v2.0)

Aufgaben:
	- Vollständiger Erstabruf aller CVEs ab 1999 über veröffentlichte Zeitfenster (<= 120 Tage pro Anfrage).
	- Fortsetzung (Resume) durch Einlesen vorhandener JSONL-Datei und Deduplikation anhand CVE-ID (nur neue Einträge werden angehängt).
	- Aktualisierung (Update) über lastModified-Fenster (<= 120 Tage Segmente) zur Erfassung neuer und geänderter CVEs.
	- Speicherung jeder CVE als einzelne Zeile im reduzierten Schema (`Config.OUTPUT`).
	- Zustandsdatei (<OUTPUT>.state.json) mit lastModifiedISO, Laufstatistik und Metadaten.
	- Separate Statistikdatei (`Config.STATS_FILE`).
	- Optionale Kompaktierung zur Entfernung älterer Duplikate (nur letzte Version pro CVE-ID bleibt).

Eigenschaften:
	- JSONL-Append-only Ansatz (idempotent mit anschließender Kompaktierung bei Bedarf).
	- Rate-Limit-Steuerung (Sliding Window) für API-konformes Abrufverhalten.
	- Retry-Mechanismen und Backoff bei temporären Fehlern (429/5xx).
	- Minimales Update-Intervall mit Übersprung früher Läufe (State-basierte Prüfung).
	- Reduziertes CVE-Schema (ID, Zeiten, englische Beschreibung, CVSS Metriken v4.0/v3.1/v3.0/v2 Kernfelder).
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

class Config:
	APP_NAME = "nvd_cve_fetcher"
	APP_VERSION = "1.0"
	BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	MAX_WINDOW_DAYS = 120          # API Limit
	RESULTS_PER_PAGE_MAX = 2000    # API Limit
	UPDATE_SLEEP_SECONDS = 6       # NVD Empfehlung zwischen Update-Seiten
	WINDOW_SECONDS = 30			   # Rate Limits (Rolling Window 30s)
	DEFAULT_SLEEP_NO_KEY = 2.5
	DEFAULT_SLEEP_WITH_KEY = 1
	PREFETCH_WAIT_SECONDS = 2

	OUTPUT = "data/raw/cves.jsonl"
	STATE_FILE: str | None = None  # None -> <OUTPUT>.state.jsonl
	LOG_MODE = "FULL" 		 	   # Fester Log-Modus (FULL | SILENT)
	INITIAL_WAIT = True
	INCREMENTAL_SINCE: str | None = None
	FAIL_ON_PARTIAL = False

	# Kompaktierung JSONL
	AUTO_COMPACT_JSONL = True
	COMPACT_DUP_RATIO = 1.10
	COMPACT_MIN_NEW = 5000

	# Fetch Parameter
	RETRIES = 3
	WINDOW_DAYS = MAX_WINDOW_DAYS
	RESULTS_PER_PAGE = RESULTS_PER_PAGE_MAX

__all__ = ["run"]

CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

def _jsonl_iter(path: str) -> Iterator[Dict[str, Any]]:
	with open(path, "r", encoding="utf-8") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue
			try:
				yield json.loads(line)
			except json.JSONDecodeError:
				continue

def _jsonl_compact(path: str, logger: logging.Logger) -> tuple[int, int]:
	if not os.path.isfile(path):
		return (0, 0)
	latest: dict[str, Dict[str, Any]] = {}
	total = 0
	for obj in _jsonl_iter(path):
		cve = obj.get("cve") or {}
		cid = cve.get("id")
		if not cid:
			continue
		latest[cid] = obj
		total += 1
	tmp = path + ".compact_tmp"
	with open(tmp, "w", encoding="utf-8") as out:
		for obj in latest.values():
			out.write(json.dumps(obj, ensure_ascii=False) + "\n")
	os.replace(tmp, path)
	logger.info("JSONL Kompaktierung: gelesen=%d einzigartig=%d reduziert=%s%%", total, len(latest), round(100 - (len(latest)/total*100) if total else 0, 2))
	return total, len(latest)

def _maybe_compact_jsonl(path: str, state_file: str, logger: logging.Logger) -> None:
	if Config.AUTO_COMPACT_JSONL is not True:
		return
	last_unique = None
	last_total = None
	try:
		if os.path.isfile(state_file):
			with open(state_file, "r", encoding="utf-8") as sf:
				st = json.load(sf)
				last_unique = st.get("totalCVEs")
				last_total = st.get("lastTotalLines")
	except Exception:  
		pass
	line_count = 0
	unique_ids: set[str] = set()
	for obj in _jsonl_iter(path):
		cid = (obj.get("cve") or {}).get("id")
		if cid:
			unique_ids.add(cid)
		line_count += 1
		if line_count > 10000 and line_count / max(1, len(unique_ids)) < Config.COMPACT_DUP_RATIO * 0.7:
			break
	dup_ratio = line_count / max(1, len(unique_ids)) if unique_ids else 0
	should = False
	if dup_ratio >= Config.COMPACT_DUP_RATIO:
		should = True
	if last_unique is not None and len(unique_ids) - last_unique >= Config.COMPACT_MIN_NEW:
		should = True
	if not should:
		logger.debug("Keine Kompaktierung nötig (ratio=%.3f unique=%d lines=%d)", dup_ratio, len(unique_ids), line_count)
		return
	logger.info("Starte Kompaktierung (ratio=%.3f unique=%d lines=%d) …", dup_ratio, len(unique_ids), line_count)
	total, uniq = _jsonl_compact(path, logger)
	try:
		if os.path.isfile(state_file):
			with open(state_file, "r", encoding="utf-8") as sf:
				data = json.load(sf)
		else:
			data = {}
		data["lastTotalLines"] = total
		data["totalCVEs"] = uniq
		data["compactedUTC"] = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
		tmp2 = state_file + ".tmp2"
		with open(tmp2, "w", encoding="utf-8") as wf:
			json.dump(data, wf, ensure_ascii=False, indent=2)
			wf.write("\n")
		os.replace(tmp2, state_file)
	except Exception as e: 
		logger.warning("Konnte Kompaktierungs-Metadaten nicht schreiben: %s", e)


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

 # Sliding-Window Rate Limiter (deque-basiert) für exakte API-Limits
class RateLimiter:
	def __init__(self, max_requests: int, window_seconds: int | None = None):
		self.max_requests = max_requests
		self.window = window_seconds or Config.WINDOW_SECONDS
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


def build_logger(mode: str) -> logging.Logger:
	logger = logging.getLogger()
	if not logger.handlers:
		handler = logging.StreamHandler()
		handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
		logger.addHandler(handler)
	level = logging.INFO if mode != "SILENT" else logging.WARNING
	logger.setLevel(level)
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
	cfg = {"api_key": None, "contact_email": None}
	if not os.path.isfile(dotenv_path):
		logger.info("Keine .env (%s) – fahre ohne API Key.", dotenv_path)
		return cfg
	if not DOTENV_AVAILABLE:
		logger.warning(".env gefunden aber python-dotenv nicht installiert – ignoriere Datei (ohne API Key).")
		return cfg
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
	# Nur API Key & Kontakt zurückgeben
	return cfg


def build_user_agent(cfg: dict) -> str:
	ua = f"{Config.APP_NAME}/{Config.APP_VERSION}"
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
			logger.info("HTTP Request (published window) %s -> %s startIndex=%d attempt=%d", start_iso, end_iso, start_index, attempt + 1)
			req_t0 = time.time()
			resp = None
			try:
				resp = session.get(Config.BASE_URL, params=params, headers=headers, timeout=60)
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
	"""Hole aktualisierte CVEs seit last_mod_start über lastModified-Fenster (<=120 Tage)."""
	headers = build_headers(api_key, user_agent)
	def fmt(ts: dt.datetime) -> str:
		return ts.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
	window_delta = dt.timedelta(days=Config.MAX_WINDOW_DAYS - 1)
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
				logger.info("HTTP Request (update) seg=%d startIndex=%d attempt=%d", segment_index, start_index, attempt + 1)
				resp = None
				try:
					t0 = time.time()
					resp = session.get(Config.BASE_URL, params=params, headers=headers, timeout=60)
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
			logger.debug("Update Sleep %ds", Config.UPDATE_SLEEP_SECONDS)
			time.sleep(Config.UPDATE_SLEEP_SECONDS)
		segment_start = segment_end
		if segment_start == segment_end:
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
	# JSONL Append: eine CVE pro Zeile
	t0 = time.time()
	cve_ids_seen = set()
	max_last_modified: Optional[dt.datetime] = None
	trimmed_count = 0
	existing_count = 0
	partial = False
	ensure_dir(output_path)
	if not os.path.isfile(output_path):
		logger.info("Initial: neue JSONL Datei")
		open(output_path, "w").close()
	else:
		logger.info("Resume: bestehende JSONL – lese IDs für Deduplikation")
		with open(output_path, "r", encoding="utf-8") as rf:
			for line in rf:
				line = line.strip()
				if not line:
					continue
				try:
					obj = json.loads(line)
				except json.JSONDecodeError:
					continue
				cid = (obj.get("cve") or {}).get("id")
				if cid:
					cve_ids_seen.add(cid)
				existing_count += 1
	with requests.Session() as session, open(output_path, "a", encoding="utf-8") as out_f:
		for idx, (w_start, w_end) in enumerate(chunk_date_range(start_date, end_date, window_days), start=1):
			logger.info("Fenster %d: %s -> %s", idx, w_start, w_end)
			try:
				for raw in request_cves_window(w_start, w_end, base_sleep, retries, limiter, results_per_page, session, api_key, user_agent, logger):
					trimmed = trim_vulnerability(raw)
					cid = trimmed["cve"].get("id")
					if not cid:
						continue
					lm = trimmed["cve"].get("lastModified") or trimmed["cve"].get("published")
					pts = parse_nvd_timestamp(lm)
					if pts and (max_last_modified is None or pts > max_last_modified):
						max_last_modified = pts
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
					out_f.write(json.dumps(trimmed, ensure_ascii=False) + "\n")
					trimmed_count += 1
			except KeyboardInterrupt:
				partial = True
				logger.warning("Benutzerabbruch während Fenster – partielle Daten werden abgeschlossen")
				break
	stats.update({
		"totalCVEs": existing_count + trimmed_count,
		"previousCVEs": existing_count,
		"newCVEs": trimmed_count,
		"durationSeconds": round(time.time() - t0, 2),
		"requestsPerformed": len(limiter._events),
		"effectiveReqPerSec": round(len(limiter._events) / max(1e-6, time.time() - t0), 3),
		"partial": partial,
	})
	# ISO 8601 mit Z erzwingen (parse_nvd_timestamp erwartet 'Z')
	if max_last_modified:
		# Normalisiere auf Sekundenauflösung wenn keine Mikrosekunden nötig
		iso = max_last_modified.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if max_last_modified.microsecond else max_last_modified.strftime("%Y-%m-%dT%H:%M:%SZ")
		stats["_maxLastModified"] = iso
	else:
		stats["_maxLastModified"] = None
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
		logger.info("Bestimme lastModified Basis durch Scan (JSONL)")
		try:
			with open(output_path, "r", encoding="utf-8") as rf:
				for line in rf:
					line=line.strip()
					if not line:
						continue
					try:
						obj=json.loads(line)
					except json.JSONDecodeError:
						continue
					cve=obj.get("cve") or {}
					lm=cve.get("lastModified") or cve.get("published")
					pts=parse_nvd_timestamp(lm)
					if pts and (last_mod_start is None or pts>last_mod_start):
						last_mod_start=pts
		except Exception:
			pass
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
		_write_state(state_file, last_mod_start, logger, stats={"newCVEs":0,"replaced":0})
		total_existing = 0
		if os.path.isfile(output_path):
			try:
				with open(output_path, "r", encoding="utf-8") as rf:
					for line in rf:
						if line.strip():
							total_existing += 1
			except Exception:
				pass
		return {"new": 0, "replaced": 0, "total": total_existing, "partial": interrupted}

	# JSONL only: ersetzte IDs werden neu angehängt, Kompaktierung später
	# partial Flag entfällt (interrupted reicht)
	written = 0
	ensure_dir(output_path)
	existing_ids: set[str] = set()
	if os.path.isfile(output_path):
		try:
			with open(output_path, "r", encoding="utf-8") as rf:
				for line in rf:
					line = line.strip()
					if not line:
						continue
					try:
						obj = json.loads(line)
					except json.JSONDecodeError:
						continue
					cid_existing = (obj.get("cve") or {}).get("id")
					if cid_existing:
						existing_ids.add(cid_existing)
		except Exception:
			pass
	with open(output_path, "a", encoding="utf-8") as wf:
		for cid, obj in replacements.items():
			wf.write(json.dumps(obj, ensure_ascii=False) + "\n")
			written += 1
			if cid in existing_ids:
				replaced += 1
			else:
				new_count += 1
	logger.info("Update: appended=%d neu=%d ersetzt=%d", written, new_count, replaced)
	# Abschluss
	if max_last_modified is None:
		max_last_modified = last_mod_start
	_write_state(state_file, max_last_modified, logger, None, stats={"newCVEs": new_count, "replaced": replaced})
	try:
		_maybe_compact_jsonl(output_path, state_file, logger)
	except Exception as e:  # noqa: BLE001
		logger.warning("Kompaktierung (Update) fehlgeschlagen: %s", e)
	return {"new": new_count, "replaced": replaced, "total": None, "partial": interrupted}

def _write_state(state_file: str, max_last_modified: dt.datetime, logger: logging.Logger, total_cves: Optional[int] = None, stats: Optional[Dict[str, Any]] = None) -> None:
	"""Schreibt State-Datei. Integriert (optional) aktuelle Statistik.

	stats: Dict mit Feldern wie start,end,newCVEs,... (wird unter key "runStats" gespeichert)
	"""
	ensure_dir(state_file)
	# Vorherige State laden um kumulative Felder zu behalten
	old: Dict[str, Any] = {}
	if os.path.isfile(state_file):
		try:
			with open(state_file, "r", encoding="utf-8") as sf:
				old = json.load(sf) or {}
		except Exception:  # noqa: BLE001
			old = {}
	data = old
	data.update({
		"lastModifiedISO": format_nvd_timestamp(max_last_modified),
		"updatedUTC": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
		# storageMode entfernt (immer JSONL)
	})
	if total_cves is not None:
		data["totalCVEs"] = total_cves
	if stats:
		# Schlankerer Key-Name
		data["lastRun"] = {k: stats[k] for k in ("start","end","previousCVEs","newCVEs","durationSeconds","requestsPerformed","partial") if k in stats}
	state_tmp = state_file + ".tmp"
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
	logger = build_logger(Config.LOG_MODE)
	logger.info("NVD CVE Fetcher for CVE Severity Classification (Prototyp)")
	start_date, end_date = default_date_range()
	try:
		cfg = load_env_config(logger)
	except RuntimeError as e:  # fehlende python-dotenv bei vorhandener .env
		logger.error(str(e))
		return 2
	# LOG_MODE wird nur beim Start gesetzt (FULL|SILENT). Keine Laufzeit-Anpassung.
	api_key = cfg.get("api_key")
	user_agent = build_user_agent(cfg)
	base_sleep = Config.DEFAULT_SLEEP_WITH_KEY if api_key else Config.DEFAULT_SLEEP_NO_KEY
	window_days = max(1, min(Config.WINDOW_DAYS, Config.MAX_WINDOW_DAYS))
	results_per_page = max(1, min(Config.RESULTS_PER_PAGE, Config.RESULTS_PER_PAGE_MAX))
	limiter = RateLimiter(50 if api_key else 5, Config.WINDOW_SECONDS)
	logger.info("================== Konfiguration ==================")
	logger.info("Zeitraum: %s -> %s", start_date, end_date)
	logger.info("API Key: %s", "JA" if api_key else "NEIN")
	logger.info("Kontakt: %s", cfg.get("contact_email") or "—")
	logger.info("User-Agent: %s", user_agent)
	logger.info("Limit: %d/%ds", limiter.max_requests, limiter.window)
	logger.info("Basis-Schlaf: %.2fs (Jitter bis %.2fs)", base_sleep, base_sleep * 0.3)
	logger.info("Fenster: erlaubt %d | genutzt %d", Config.MAX_WINDOW_DAYS, window_days)
	logger.info("Results/Page: erlaubt %d | genutzt %d", Config.RESULTS_PER_PAGE_MAX, results_per_page)
	logger.info("Output: %s", Config.OUTPUT)
	logger.info("===================================================")
	if Config.INITIAL_WAIT:
		logger.info("Start in %ds", Config.PREFETCH_WAIT_SECONDS)
		try:
			time.sleep(Config.PREFETCH_WAIT_SECONDS)
		except KeyboardInterrupt:
			logger.info("Abbruch vor Start")
			return 130

	output_path = Config.OUTPUT
	existing_file = os.path.isfile(output_path) and os.path.getsize(output_path) > 0
	resume_start = None  # published-Scan entfernt – JSONL Resume via ID-Deduplikation

	state_file_path = Config.STATE_FILE or (output_path + ".state.json")
	last_state_mod: Optional[dt.datetime] = None
	last_state_lm: Optional[dt.datetime] = None
	if os.path.isfile(state_file_path):
		try:
			with open(state_file_path, "r", encoding="utf-8") as sf:
				st = json.load(sf)
				ls = st.get("updatedUTC")
				lm_iso = st.get("lastModifiedISO")
				if ls:
					last_state_mod = parse_nvd_timestamp(ls)
					if last_state_mod and last_state_mod.tzinfo is None:
						# Normalisiere auf UTC aware
						last_state_mod = last_state_mod.replace(tzinfo=dt.UTC)
				if lm_iso:
					last_state_lm = parse_nvd_timestamp(lm_iso)
					if last_state_lm and last_state_lm.tzinfo is None:
						last_state_lm = last_state_lm.replace(tzinfo=dt.UTC)
		except Exception:  # noqa: BLE001
			pass

	def _min_update_interval_seconds() -> int:
		# Policy: 2 Stunden laut NVD Best Practice (no more than once every two hours)
		return 7200

	now_utc = dt.datetime.now(dt.UTC)
	if last_state_mod:
		last_run_partial = False
		try:
			with open(state_file_path, "r", encoding="utf-8") as _sf:
				_js = json.load(_sf) or {}
				# Kompatibilität: altes Feld runStats oder neues lastRun
				lr = _js.get("lastRun") or _js.get("runStats") or {}
				last_run_partial = bool(lr.get("partial"))
		except Exception:  # noqa: BLE001
			last_run_partial = False
		elapsed = (now_utc - last_state_mod).total_seconds()
		needed = _min_update_interval_seconds()
		if not last_run_partial and elapsed < needed:
			next_allowed = last_state_mod + dt.timedelta(seconds=needed)
			remaining = int((next_allowed - now_utc).total_seconds())
			if remaining < 0:
				remaining = 0
			next_str_utc = next_allowed.strftime("%Y-%m-%d %H:%M:%S UTC")
			# Lokale Zeit (System-TZ) für Anwenderverständnis
			try:
				local_dt = next_allowed.astimezone()
				next_str_local = local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
			except Exception:  # noqa: BLE001
				next_str_local = "(lokale Zeit nicht bestimmbar)"
			logger.info(
				"Letzter vollständiger Lauf vor %.0fs (<%ds) – überspringe (Intervall). Nächster Update: %s | Lokal: %s (in %ds). Basis-State: %s",
				elapsed,
				needed,
				next_str_utc,
				next_str_local,
				remaining,
				last_state_mod.strftime("%Y-%m-%d %H:%M:%S UTC"),
			)
			return 0

	stats = {"start": (resume_start or start_date).isoformat(), "end": end_date.isoformat(), "apiKey": bool(api_key), "windowDays": window_days, "resultsPerPage": results_per_page, "since": Config.INCREMENTAL_SINCE}
	incremental_since = None

	if Config.INCREMENTAL_SINCE:
		try:
			incremental_since = parse_date(Config.INCREMENTAL_SINCE)
		except ValueError:
			logger.error("INCREMENTAL_SINCE ungültig – ignoriere")

	# Direkt-Update möglich? (Datei + State vorhanden + nicht leer)
	can_direct_update = existing_file and os.path.isfile(state_file_path)
	if can_direct_update:
		logger.info("Direkter Update-Lauf (überspringe Basis-Fetch)")
		try:
			upd = update_mode(output_path, limiter, api_key, user_agent, logger, state_file_path)
			logger.info("Update abgeschlossen: neu=%s ersetzt=%s", upd.get("new"), upd.get("replaced"))
			return 0
		except KeyboardInterrupt:
			logger.warning("Abbruch während Direkt-Update")
			return 130
		except Exception as e:  # noqa: BLE001
			logger.warning("Direkter Update-Versuch fehlgeschlagen (%s) – falle zurück auf Vollabruf", e)
	# Fallback: Basis-Fetch nötig
	if resume_start is None and not existing_file:
		logger.info("Initialer Vollabruf startet …")
		fetch_start = start_date
	else:
		fetch_start = resume_start or start_date
	try:
		stats = stream_fetch(fetch_start, end_date, window_days, results_per_page, base_sleep, Config.RETRIES, limiter, api_key, output_path, stats, incremental_since, user_agent, logger)
	except KeyboardInterrupt:
		stats["partial"] = True
		logger.warning("Abbruch – partial")
	logger.info("Fertig (Basis-Fetch): total=%d (neu=%d, vorher=%d) in %ss (Requests %d, Rate %.2f req/s)%s", stats.get("totalCVEs", 0), stats.get("newCVEs", 0), stats.get("previousCVEs", 0), stats.get("durationSeconds"), stats.get("requestsPerformed"), stats.get("effectiveReqPerSec"), " PARTIAL" if stats.get("partial") else "")
	# Falls keine neuen CVEs (neu=0) und wir bereits Daten hatten -> direkt in Update-Modus wechseln statt erneut alles zu streamen
	if existing_file and stats.get("newCVEs", 0) == 0 and not stats.get("partial"):
		logger.info("Keine neuen CVEs im Basislauf erkannt – wechsle in inkrementellen Update-Modus …")
		try:
			upd = update_mode(output_path, limiter, api_key, user_agent, logger, state_file_path)
			logger.info("Update-Modus abgeschlossen: neu=%s ersetzt=%s", upd.get("new"), upd.get("replaced"))
		except Exception as e:  # noqa: BLE001
			logger.warning("Update-Modus fehlgeschlagen: %s", e)
	# JSONL Kompaktierung ggf. auslösen
	if stats.get("newCVEs", 0) > 0:
		try:
			state_file_comp = Config.STATE_FILE or (output_path + ".state.json")
			_maybe_compact_jsonl(output_path, state_file_comp, logger)
		except Exception as e:  # noqa: BLE001
			logger.warning("Kompaktierung (Basis-Fetch) fehlgeschlagen: %s", e)
	# State nach Basis-Fetch schreiben (falls nicht direkt in Update-Modus gewechselt wurde)
	try:
		state_file = Config.STATE_FILE or (output_path + ".state.json")
		# Primärer Timestamp aus Stats
		max_lm: Optional[dt.datetime] = None
		max_lm_iso = stats.get("_maxLastModified")
		if isinstance(max_lm_iso, str):
			max_lm = parse_nvd_timestamp(max_lm_iso)
		# Fallback: falls None und Datei existiert & nicht leer -> letzte Zeile scannen
		if max_lm is None and os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
			try:
				with open(output_path, "rb") as rf:
					rf.seek(0, os.SEEK_END)
					size = rf.tell()
					# Rückwärts lesen bis Zeilenende gefunden
					chunk = b""
					offset = 0
					while size - offset > 0 and len(chunk.splitlines()) < 2:
						offset = min(size, offset + 2048)
						rf.seek(size - offset)
						chunk = rf.read(offset) + chunk
					for line in reversed(chunk.splitlines()):
						line = line.strip()
						if not line:
							continue
						try:
							obj = json.loads(line.decode("utf-8", "ignore"))
							cve = (obj.get("cve") or {})
							lm = cve.get("lastModified") or cve.get("published")
							max_lm = parse_nvd_timestamp(lm)
							if max_lm:
								break
						except Exception:
							continue
			except Exception:
				pass
		# Letzter Fallback: definierter Epoch-Start falls weiterhin None (signalisiert unvollständigen Lauf)
		if max_lm is None:
			max_lm = dt.datetime(1999,1,1)
		_write_state(state_file, max_lm, logger, stats.get("totalCVEs"), stats=stats)
	except Exception as e:  # noqa: BLE001
		logger.warning("State konnte nach Basis-Fetch nicht geschrieben werden: %s", e)
	# (Entfallen) Separate Stats-Datei entfernt – alle Infos im State.
	logger.info("Run-Infos im State aktualisiert (keine separate Stats-Datei mehr)")
	if stats.get("partial") and Config.FAIL_ON_PARTIAL:
		return 1
	return 130 if stats.get("partial") else 0


if __name__ == "__main__":
	sys.exit(run())
