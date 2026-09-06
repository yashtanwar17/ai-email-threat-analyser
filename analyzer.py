

from __future__ import annotations

import argparse
import hashlib
import os
import json
import re
import shutil
import subprocess
import sys
import tempfile
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


# ============================================================
# API TOKENS / CREDENTIALS / SETTINGS
# Put every API key, token, and API-related setting here.
# ============================================================

VIRUSTOTAL_API_KEY = ""

CENSYS_API_TOKEN = " "
CENSYS_ORGANIZATION_ID = "" #opt

URLSCAN_API_KEY = " "
URLSCAN_SUBMIT = False
URLSCAN_VISIBILITY = "unlisted"

FACHA_API_TOKEN = ""

# OpenPhish does not provide a public arbitrary-URL lookup API.
# Configure this only with an authorized feed/database endpoint.
OPENPHISH_FEED_URL = ""

# API endpoints
CENSYS_API_BASE = "https://api.platform.censys.io/v3"
URLSCAN_API_BASE = "https://urlscan.io/api/v1"
CRT_SH_BASE = "https://crt.sh/"
FACHA_API_BASE = "https://api.facha.dev"

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse


# -----------------------------
# Configuration
# -----------------------------

DEFAULT_TIMEOUT = 90

API_TIMEOUT = 30


URL_RE = re.compile(
    r"""(?ix)
    \b(?:
        https?://
        |www\.
    )
    [^\s<>"'()\[\]]+
    """
)

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

# Conservative domain candidate extraction. We later remove common false positives.
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)

OFFICE_EXTS = {".doc", ".docm", ".docx", ".dot", ".dotm", ".xls", ".xlsm",
               ".xlsx", ".xltm", ".ppt", ".pptm", ".pptx", ".rtf"}

PDF_EXTS = {".pdf"}
PE_EXTS = {".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx", ".msi"}

TOOL_CANDIDATES = {
    "checkdmarc": ["checkdmarc"],
    "clamscan": ["clamscan"],
    "clamdscan": ["clamdscan"],
    "yara": ["yara"],
    "oleid": ["oleid", "oleid.py"],
    "olevba": ["olevba", "olevba.py"],
    "oleobj": ["oleobj", "oleobj.py"],
    "rtfobj": ["rtfobj", "rtfobj.py"],
    "pdfid": ["pdfid.py", "pdfid"],
    "pdf_parser": ["pdf-parser.py", "pdf-parser"],
    "floss": ["floss"],
    "capa": ["capa"],
    "sigcheck": ["sigcheck.exe", "sigcheck"],
    "emldump": ["emldump.py", "emldump"],
}


@dataclass
class CommandResult:
    tool: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def unique(items):
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def which_any(candidates: list[str]) -> str | None:
    for candidate in candidates:
        p = shutil.which(candidate)
        if p:
            return p
    return None


def tool_path(tool_name: str) -> str | None:
    """Return the exact Windows path configured for each forensic tool."""
    fixed_paths = {
        "checkdmarc": r"C:\Users\yash\AppData\Local\Python\pythoncore-3.14-64\Scripts\checkdmarc.exe",
        "oleid": r"C:\Users\yash\AppData\Local\Python\pythoncore-3.14-64\Scripts\oleid.exe",
        "olevba": r"C:\Users\yash\AppData\Local\Python\pythoncore-3.14-64\Scripts\olevba.exe",
        "oleobj": r"C:\Users\yash\AppData\Local\Python\pythoncore-3.14-64\Scripts\oleobj.exe",
        "rtfobj": r"C:\Users\yash\AppData\Local\Python\pythoncore-3.14-64\Scripts\rtfobj.exe",
        "pdfid": r"C:\Users\yash\security-tools\python-tools\pdfid.py",
        "pdf_parser": r"C:\Users\yash\security-tools\python-tools\pdf-parser.py",
        "floss": r"C:\Users\yash\security-tools\bin\floss.exe",
        "capa": r"C:\Users\yash\security-tools\bin\capa.exe",
        "sigcheck": r"C:\Users\yash\security-tools\bin\sigcheck.exe",
        "emldump": r"C:\Users\yash\security-tools\python-tools\emldump.py",
    }

    path = fixed_paths.get(tool_name)
    if path and Path(path).exists():
        return path
    return None


def run_command(
    tool: str,
    cmd: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Path | None = None,
) -> CommandResult:
    # Windows cannot execute a downloaded .py file directly with CreateProcess.
    # Route Python scripts through the exact interpreter running this analyzer.
    actual_cmd = list(cmd)
    if actual_cmd and str(actual_cmd[0]).lower().endswith(".py"):
        actual_cmd.insert(0, sys.executable)

    try:
        p = subprocess.run(
            actual_cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        return CommandResult(
            tool=tool,
            command=actual_cmd,
            returncode=p.returncode,
            stdout=p.stdout[-50000:],
            stderr=p.stderr[-20000:],
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            tool=tool,
            command=actual_cmd,
            returncode=None,
            stdout=(e.stdout or "")[-50000:] if isinstance(e.stdout, str) else "",
            stderr=(e.stderr or "")[-20000:] if isinstance(e.stderr, str) else "",
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(tool, actual_cmd, None, "", "Tool not found")
    except Exception as e:
        return CommandResult(tool, actual_cmd, None, "", repr(e))


def hashes_for_file(path: Path) -> dict:
    result = {}
    for algo in ("md5", "sha1", "sha256"):
        h = hashlib.new(algo)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        result[algo] = h.hexdigest()
    return result


def clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)]}>")


def extract_text_from_message(msg) -> str:
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            try:
                content = part.get_content()
                if isinstance(content, str):
                    chunks.append(content)
            except Exception:
                try:
                    raw = part.get_payload(decode=True) or b""
                    chunks.append(raw.decode(part.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    pass
    else:
        try:
            content = msg.get_content()
            if isinstance(content, str):
                chunks.append(content)
        except Exception:
            pass
    return "\n\n".join(chunks)


def parse_eml(eml_path: Path, work_dir: Path) -> dict:
    with eml_path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = extract_text_from_message(msg)

    raw_headers = []
    for k, v in msg.raw_items():
        raw_headers.append({"name": k, "value": str(v)})

    received = [str(v) for v in msg.get_all("Received", [])]

    attachments = []
    for idx, part in enumerate(msg.iter_attachments(), start=1):
        filename = part.get_filename() or f"attachment_{idx}"
        safe_name = Path(filename).name
        destination = work_dir / safe_name

        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
        destination.write_bytes(payload)

        attachments.append({
            "filename": safe_name,
            "content_type": part.get_content_type(),
            "content_disposition": part.get_content_disposition(),
            "size": len(payload),
            "path": str(destination),
            "hashes": hashes_for_file(destination),
        })

    all_text = body + "\n" + "\n".join(v["value"] for v in raw_headers)
    urls = unique([clean_url(x) for x in URL_RE.findall(all_text)])

    url_domains = []
    for u in urls:
        try:
            host = urlparse(u if u.startswith(("http://", "https://")) else "http://" + u).hostname
            if host:
                url_domains.append(host.lower())
        except Exception:
            pass

    ips = unique(IP_RE.findall(all_text))
    domains = unique(DOMAIN_RE.findall(all_text))
    domains += [d for d in url_domains if d not in domains]
    domains = unique(domains)
    hashes = unique(HASH_RE.findall(all_text))

    return {
        "analyzed_at": utc_now(),
        "file": {
            "name": eml_path.name,
            "path": str(eml_path.resolve()),
            "size": eml_path.stat().st_size,
        },
        "headers": {
            "from": msg.get("From"),
            "to": msg.get("To"),
            "cc": msg.get("Cc"),
            "bcc": msg.get("Bcc"),
            "subject": msg.get("Subject"),
            "date": msg.get("Date"),
            "reply_to": msg.get("Reply-To"),
            "return_path": msg.get("Return-Path"),
            "message_id": msg.get("Message-ID"),
            "authentication_results": msg.get("Authentication-Results"),
            "dkim_signature": msg.get("DKIM-Signature"),
            "received": received,
            "all": raw_headers,
        },
        "body": {
            "text": body[:200000],
            "length": len(body),
        },
        "iocs": {
            "urls": urls,
            "domains": domains,
            "ipv4": ips,
            "hashes": hashes,
        },
        "attachments": attachments,
    }


def is_valid_hostname(value: str) -> bool:
    """Return True for DNS-like hostnames, excluding filenames and obvious artifacts."""
    value = value.strip().rstrip(".").lower()
    if not value or "/" in value or "@" in value or value.count(".") < 1:
        return False
    if any(ch in value for ch in " \\t\\r\\n"):
        return False
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return False
    return len(value) <= 253


def extract_checkdmarc_domains(evidence: dict) -> list[str]:
    """Prefer domains from actual email identities/URLs, not every regex match in the body."""
    candidates = []

    # Header email domains.
    for key in ("from", "to", "cc", "reply_to", "return_path"):
        value = evidence["headers"].get(key) or ""
        for match in re.findall(r"@([A-Za-z0-9.-]+)", value):
            candidates.append(match)

    # Domains belonging to extracted URLs.
    for url in evidence["iocs"].get("urls", []):
        try:
            host = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url).hostname
            if host:
                candidates.append(host)
        except Exception:
            pass

    # Fall back to the overall domain IOC list only if needed, but filter aggressively.
    if not candidates:
        candidates.extend(evidence["iocs"].get("domains", []))

    return unique([d.lower() for d in candidates if is_valid_hostname(d)])[:10]



def http_json(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: dict | None = None,
    timeout: int = API_TIMEOUT,
) -> dict | list | str:
    """Make a JSON HTTP request using only the Python standard library."""
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "EmailForensics/1.0",
    }
    if headers:
        request_headers.update(headers)

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    req = Request(url, data=data, headers=request_headers, method=method.upper())
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = raw
        return {
            "error": True,
            "http_status": e.code,
            "detail": detail,
        }
    except (URLError, TimeoutError, OSError) as e:
        return {
            "error": True,
            "detail": str(e),
        }


def run_nslookup(domains: list[str]) -> list[dict]:
    """Run Windows nslookup and keep its stdout/stderr in the JSON report."""
    results = []
    for domain in domains[:20]:
        result = run_command("nslookup", ["nslookup", domain], timeout=30)
        results.append(asdict(result))
    return results


def run_censys_lookup(evidence: dict) -> list[dict]:
    """
    Enrich resolved IPs with the current Censys Platform host endpoint.
    Requires CENSYS_API_TOKEN. Optional CENSYS_ORGANIZATION_ID is supported.
    """
    token = CENSYS_API_TOKEN
    if not token:
        return [{
            "status": "not_configured",
            "reason": "Set CENSYS_API_TOKEN to enable Censys Platform API enrichment."
        }]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
    }
    org_id = CENSYS_ORGANIZATION_ID
    if org_id:
        headers["X-Organization-ID"] = org_id

    ips = list(evidence["iocs"].get("ipv4", []))
    # Also resolve extracted domains so domain-based email IOCs can be enriched.
    for domain in evidence["iocs"].get("domains", [])[:20]:
        try:
            for item in socket.getaddrinfo(domain, None, socket.AF_INET):
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass

    results = []
    for ip in ips[:20]:
        url = f"{CENSYS_API_BASE}/global/asset/host/{ip}"
        params = f"?organization_id={org_id}" if org_id else ""
        payload = http_json(url + params, headers=headers)
        results.append({
            "target": ip,
            "endpoint": url,
            "result": payload,
        })
    return results


def run_urlscan_lookup(evidence: dict) -> list[dict]:
    """
    Search urlscan for existing scans of extracted URLs.
    Set URLSCAN_SUBMIT=true to additionally submit URLs for live scanning.
    """
    api_key = URLSCAN_API_KEY
    if not api_key:
        return [{
            "status": "not_configured",
            "reason": "Set URLSCAN_API_KEY to enable urlscan.io API enrichment."
        }]

    headers = {
        "api-key": api_key,
        "Accept": "application/json",
    }
    submit = URLSCAN_SUBMIT
    results = []

    for target_url in evidence["iocs"].get("urls", [])[:20]:
        search_query = urlencode({"q": f'page.url:"{target_url}"', "size": "10"})
        search_endpoint = f"{URLSCAN_API_BASE}/search/?{search_query}"
        search_result = http_json(search_endpoint, headers=headers)

        item = {
            "target": target_url,
            "search_endpoint": search_endpoint,
            "search_result": search_result,
        }

        if submit:
            submit_endpoint = f"{URLSCAN_API_BASE}/scan/"
            submit_result = http_json(
                submit_endpoint,
                method="POST",
                headers=headers,
                body={
                    "url": target_url,
                    "visibility": URLSCAN_VISIBILITY,
                },
            )
            item["submission_endpoint"] = submit_endpoint
            item["submission_result"] = submit_result

            uuid = submit_result.get("uuid") if isinstance(submit_result, dict) else None
            if uuid:
                # urlscan recommends waiting before polling result endpoints.
                time.sleep(10)
                result_endpoint = f"{URLSCAN_API_BASE}/result/{uuid}/"
                item["result_endpoint"] = result_endpoint
                item["result"] = http_json(result_endpoint, headers=headers)

        results.append(item)

    return results


def run_crtsh_lookup(evidence: dict) -> list[dict]:
    """Retrieve certificate-transparency JSON for extracted domains."""
    results = []
    for domain in extract_checkdmarc_domains(evidence)[:20]:
        query = urlencode({"q": f"%.{domain}", "output": "json"})
        endpoint = f"{CRT_SH_BASE}?{query}"
        result = http_json(endpoint, headers={"Accept": "application/json"})
        results.append({
            "target": domain,
            "endpoint": endpoint,
            "result": result,
        })
    return results


def run_facha_lookup(evidence: dict) -> list[dict]:
    """
    Check sender/Reply-To/Return-Path addresses with Facha's temporary-email API.
    The API can optionally use FACHA_API_TOKEN configured at the top of this script.
    """
    email_values = []
    for key in ("from", "reply_to", "return_path"):
        value = evidence["headers"].get(key) or ""
        email_values.extend(re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}",
            value,
        ))

    email_values = unique([x.lower() for x in email_values])
    if not email_values:
        return [{
            "status": "skipped_no_email_addresses",
            "reason": "No sender/reply-to/return-path email addresses were extracted."
        }]

    headers = {"Accept": "application/json"}
    if FACHA_API_TOKEN:
        headers["Authorization"] = f"Bearer {FACHA_API_TOKEN}"

    results = []
    for email_address in email_values[:20]:
        endpoint = f"{FACHA_API_BASE}/v1/email/temporary?{urlencode({'email': email_address})}"
        result = http_json(endpoint, headers=headers)
        results.append({
            "target": email_address,
            "endpoint": endpoint,
            "result": result,
        })
    return results





def run_virustotal_lookup(evidence: dict) -> list[dict]:
    """
    Search VirusTotal for extracted domains, IPs and file hashes.
    URL strings are also searched; the search endpoint accepts URLs,
    domains, IPs and hashes.
    """
    if not VIRUSTOTAL_API_KEY:
        return [{
            "status": "not_configured",
            "reason": "Set VIRUSTOTAL_API_KEY at the top of the script to enable VirusTotal enrichment."
        }]

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    targets = []
    for value in evidence["iocs"].get("urls", [])[:10]:
        targets.append(("url", value))
    for value in evidence["iocs"].get("domains", [])[:10]:
        targets.append(("domain", value))
    for value in evidence["iocs"].get("ipv4", [])[:10]:
        targets.append(("ip", value))
    for value in evidence["iocs"].get("hashes", [])[:20]:
        targets.append(("hash", value))

    # De-duplicate while preserving target type.
    seen = set()
    unique_targets = []
    for target_type, target in targets:
        key = (target_type, target.lower())
        if key not in seen:
            seen.add(key)
            unique_targets.append((target_type, target))

    results = []
    for target_type, target in unique_targets[:50]:
        endpoint = f"https://www.virustotal.com/api/v3/search?{urlencode({'query': target})}"
        result = http_json(endpoint, headers=headers)
        results.append({
            "type": target_type,
            "target": target,
            "endpoint": endpoint,
            "result": result,
        })

    return results



def run_api_enrichment(evidence: dict) -> dict:
    """Collect external enrichment results for inclusion in forensic_result.json."""
    return {
        "nslookup": run_nslookup(evidence["iocs"].get("domains", [])),
        "censys": run_censys_lookup(evidence),
        "urlscan_io": run_urlscan_lookup(evidence),
        "crt_sh": run_crtsh_lookup(evidence),
        "facha_api": run_facha_lookup(evidence),
        "virustotal": run_virustotal_lookup(evidence)
    }


def run_local_analysis(evidence: dict, output_dir: Path) -> list[dict]:
    results: list[dict] = []
    attachment_paths = [Path(a["path"]) for a in evidence["attachments"]]

    def add(res: CommandResult):
        results.append(asdict(res))

    # Email/domain authentication
    checkdmarc = tool_path("checkdmarc")
    if checkdmarc:
        for domain in extract_checkdmarc_domains(evidence):
            add(run_command("checkdmarc", [checkdmarc, domain], timeout=60))

    # Deep raw email inspection
    emldump = tool_path("emldump")
    if emldump:
        add(run_command("emldump", [emldump, "-H", evidence["file"]["path"]], timeout=60))

    # YARA
    yara = tool_path("yara")
    if yara:
        rules = Path(__file__).with_name("rules.yar")
        if rules.exists():
            for attachment in attachment_paths:
                add(run_command("yara", [yara, str(rules), str(attachment)], timeout=60))
        else:
            results.append({
                "tool": "yara",
                "status": "installed_but_skipped",
                "reason": f"No rules.yar found beside {Path(__file__).name}",
            })

    # ClamAV
    #
    # Prefer clamscan because it works as a standalone scanner and does not
    # require clamd/clamdscan to be running as a Windows service.
    # Fall back to clamdscan if clamscan is unavailable.
    clamscan = tool_path("clamscan")
    clamdscan = tool_path("clamdscan")

    if not attachment_paths:
        results.append({
            "tool": "clamav",
            "status": "skipped_no_attachments",
            "reason": "No file attachments were extracted from this email.",
        })
    elif clamscan:
        for attachment in attachment_paths:
            add(run_command(
                "clamscan",
                [clamscan, "--no-summary", str(attachment)],
                timeout=120,
            ))
    elif clamdscan:
        for attachment in attachment_paths:
            add(run_command(
                "clamdscan",
                [clamdscan, str(attachment)],
                timeout=120,
            ))
    else:
        results.append({
            "tool": "clamav",
            "status": "not_installed",
            "reason": (
                "Neither clamscan.exe nor clamdscan.exe was found. "
                "Install ClamAV for Windows and place it in PATH or "
                "under C:\\Program Files\\ClamAV."
            ),
        })

    # Office / RTF
    for attachment in attachment_paths:
        if attachment.suffix.lower() in OFFICE_EXTS:
            oleid = tool_path("oleid")
            olevba = tool_path("olevba")
            oleobj = tool_path("oleobj")
            rtfobj = tool_path("rtfobj")

            if oleid:
                add(run_command("oleid", [oleid, str(attachment)], timeout=60))
            if olevba:
                add(run_command("olevba", [olevba, "--decode", str(attachment)], timeout=90))
            if oleobj:
                add(run_command("oleobj", [oleobj, str(attachment)], timeout=90))
            if rtfobj and attachment.suffix.lower() == ".rtf":
                add(run_command("rtfobj", [rtfobj, str(attachment)], timeout=90))

        if attachment.suffix.lower() in PDF_EXTS:
            pdfid = tool_path("pdfid")
            pdf_parser = tool_path("pdf_parser")
            if pdfid:
                add(run_command("pdfid", [pdfid, str(attachment)], timeout=60))
            if pdf_parser:
                add(run_command("pdf-parser", [pdf_parser, str(attachment)], timeout=90))

        if attachment.suffix.lower() in PE_EXTS:
            floss = tool_path("floss")
            capa = tool_path("capa")
            sigcheck = tool_path("sigcheck")

            if floss:
                add(run_command("floss", [floss, str(attachment)], timeout=180))
            if capa:
                add(run_command("capa", [capa, str(attachment)], timeout=180))
            if sigcheck:
                add(run_command(
                    "sigcheck",
                    [sigcheck, "-a", "-h", "-i", str(attachment)],
                    timeout=60
                ))

    return results


def build_summary(evidence: dict, tool_results: list[dict]) -> dict:
    suspicious = []

    auth = evidence["headers"]
    text = json.dumps(evidence, ensure_ascii=False).lower()

    if auth.get("reply_to") and auth.get("from"):
        suspicious.append({
            "indicator": "reply_to_present",
            "detail": "Review whether Reply-To differs from the visible sender."
        })

    if evidence["iocs"]["urls"]:
        suspicious.append({
            "indicator": "urls_present",
            "detail": f"{len(evidence['iocs']['urls'])} URL(s) extracted for reputation/sandbox checks."
        })

    high_signal_terms = [
        "urgent", "verify your account", "password", "invoice",
        "payment", "wire transfer", "gift card", "login", "credential",
        "mfa", "security alert"
    ]
    hits = [x for x in high_signal_terms if x in text]
    if hits:
        suspicious.append({
            "indicator": "social_engineering_terms",
            "detail": ", ".join(hits[:10])
        })

    return {
        "tool_count": len(tool_results),
        "attachments": len(evidence["attachments"]),
        "urls": len(evidence["iocs"]["urls"]),
        "domains": len(evidence["iocs"]["domains"]),
        "ips": len(evidence["iocs"]["ipv4"]),
        "hashes": len(evidence["iocs"]["hashes"]),
        "initial_indicators": suspicious,
    }


def write_report(evidence: dict, results: list[dict], api_results: dict, out_dir: Path):
    package = {
        "summary": build_summary(evidence, results),
        "evidence": evidence,
        "tool_results": results,
        "api_enrichment": api_results,
    }

    json_path = out_dir / "forensic_result.json"
    json_path.write_text(json.dumps(package, indent=2, ensure_ascii=True), encoding="utf-8")

    report_lines = [
        "EMAIL FORENSICS REPORT",
        "=" * 70,
        f"Analyzed: {evidence['analyzed_at']}",
        f"EML:      {evidence['file']['path']}",
        "",
        "[HEADERS]",
        f"From:       {evidence['headers'].get('from')}",
        f"To:         {evidence['headers'].get('to')}",
        f"Reply-To:   {evidence['headers'].get('reply_to')}",
        f"Return-Path:{evidence['headers'].get('return_path')}",
        f"Subject:    {evidence['headers'].get('subject')}",
        f"Date:       {evidence['headers'].get('date')}",
        f"Message-ID: {evidence['headers'].get('message_id')}",
        "",
        f"Received hops: {len(evidence['headers'].get('received', []))}",
        "",
        "[IOCs]",
        f"URLs:   {len(evidence['iocs']['urls'])}",
        f"Domains:{len(evidence['iocs']['domains'])}",
        f"IPs:    {len(evidence['iocs']['ipv4'])}",
        f"Hashes: {len(evidence['iocs']['hashes'])}",
    ]

    if evidence["iocs"]["urls"]:
        report_lines += ["", "URLs:"]
        report_lines += [f"  - {x}" for x in evidence["iocs"]["urls"][:100]]

    if evidence["iocs"]["ipv4"]:
        report_lines += ["", "IPv4:"]
        report_lines += [f"  - {x}" for x in evidence["iocs"]["ipv4"]]

    report_lines += ["", "[ATTACHMENTS]"]
    for a in evidence["attachments"]:
        report_lines += [
            f"- {a['filename']} | {a['content_type']} | {a['size']} bytes",
            f"  SHA256: {a['hashes']['sha256']}",
        ]

    report_lines += ["", "[TOOL RESULTS]"]
    for r in results:
        if isinstance(r, dict) and "tool" in r:
            report_lines += [
                f"\n### {r['tool']}",
                f"command: {r.get('command')}",
                f"returncode: {r.get('returncode')}",
                f"timed_out: {r.get('timed_out')}",
                r.get("stdout", "")[:5000],
                r.get("stderr", "")[:3000],
            ]

    txt_path = out_dir / "forensic_report.txt"
    txt_path.write_text("\n".join(report_lines), encoding="utf-8")

    return json_path, txt_path


def main():
    parser = argparse.ArgumentParser(description="Analyze an .eml with local security CLI tools.")
    parser.add_argument("eml", nargs="?", default="temp.eml", help="Path to .eml file (default: temp.eml)")
    parser.add_argument("--out", default="email_forensics_output", help="Output directory")
    parser.add_argument("--no-tools", action="store_true", help="Only parse/extract; don't invoke local tools")
    args = parser.parse_args()

    eml_path = Path(args.eml).resolve()
    if not eml_path.exists():
        print(f"[!] EML not found: {eml_path}")
        print("    Put temp.eml beside this script or pass a path:")
        print("    python email_forensics.py C:\\path\\to\\mail.eml")
        sys.exit(2)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Each run gets an isolated attachment directory.
    work_dir = out_dir / "attachments"
    work_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Parsing: {eml_path}")
    evidence = parse_eml(eml_path, work_dir)

    print(f"[+] URLs: {len(evidence['iocs']['urls'])}")
    print(f"[+] Domains: {len(evidence['iocs']['domains'])}")
    print(f"[+] IPs: {len(evidence['iocs']['ipv4'])}")
    print(f"[+] Attachments: {len(evidence['attachments'])}")

    if args.no_tools:
        results = []
    else:
        results = run_local_analysis(evidence, out_dir)

    print("[+] Running API enrichment...")
    api_results = run_api_enrichment(evidence)

    json_path, txt_path = write_report(evidence, results, api_results, out_dir)

    print("\n[+] Done")
    print(f"[+] JSON:   {json_path}")
    print(f"[+] Report: {txt_path}")
    print("\n[!] No attachment is executed by this script.")
    print("[!] Use an isolated VM/sandbox for dynamic analysis.")


if __name__ == "__main__":
    main()
