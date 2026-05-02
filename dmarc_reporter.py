#!/usr/bin/env python3
"""
dmarc_reporter.py — DMARC Abuse Reporter

Parses DMARC CSV export files, performs WHOIS/rDNS lookups,
writes a correlated full report, and sends abuse notification emails.

Usage:
    python dmarc_reporter.py <date_prefix>
    python dmarc_reporter.py 2MAY2026
    python dmarc_reporter.py 2MAY2026 --skip-lookup   # reuse existing full CSV

Expected input files in the reports/ directory:
    <date_prefix>_source.csv  — columns: IP Address, Reverse DNS, Base Domain, Country, Messages
    <date_prefix>_spf.csv     — columns: Header From, Envelope From, SPF Result, SPF Aligned, Reverse DNS Base, Messages
    <date_prefix>_dkim.csv    — columns: Header From, DKIM Selector, DKIM Domain, DKIM Result, DKIM Aligned, Reverse DNS Base, Messages

Join key: source["Base Domain"] == spf/dkim["Reverse DNS Base"]

Output files:
    reports/<date_prefix>_full.csv
    reports/Report_History.csv

Dependencies:
    pip install ipwhois
"""

from __future__ import annotations

import argparse
import configparser
import csv
import ipaddress
import os
import re
import smtplib
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError
except ImportError:
    print("ERROR: ipwhois library not installed.")
    print("       Install it with:  pip install ipwhois")
    sys.exit(1)


# =============================================================================
# CONFIG LOADER
# =============================================================================

CONFIG_FILE = Path(__file__).parent / ".config"


def _parse_ignore_prefixes(raw: str) -> list:
    """Parse a multi-line string of CIDR prefixes into ip_network objects."""
    networks = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            print(f"WARNING: Invalid CIDR prefix in .config [ignore]: '{line}' — skipped")
    return networks


def is_ignored(ip_str: str, ignore_prefixes: list) -> bool:
    """Return True if ip_str falls within any configured ignore prefix."""
    if not ignore_prefixes:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in ignore_prefixes)
    except ValueError:
        return False


def load_config() -> dict:
    """
    Read all settings from .config (INI format).
    Required sections: [smtp], [reporter]
    Optional sections: [ignore], [settings], [source_cols], [spf_cols], [dkim_cols]
    Aborts with a clear message if the file is missing or malformed.
    The SMTP_PASSWORD environment variable overrides the password field.
    """
    if not CONFIG_FILE.exists():
        old = Path(__file__).parent / ".smtp_config"
        if old.exists():
            print(f"ERROR: Configuration file not found: {CONFIG_FILE}")
            print("       Found legacy .smtp_config — rename it:  mv .smtp_config .config")
        else:
            print(f"ERROR: Configuration file not found: {CONFIG_FILE}")
            print("       Copy .config.example to .config and fill in your settings.")
        sys.exit(1)

    if os.name == "posix":
        mode = CONFIG_FILE.stat().st_mode & 0o777
        if mode & 0o077:
            print(f"ERROR: .config has unsafe permissions ({oct(mode)}).")
            print("       Run:  chmod 600 .config")
            sys.exit(1)

    cp = configparser.ConfigParser()
    cp.read(CONFIG_FILE)

    if "smtp" not in cp:
        print("ERROR: .config is missing the required [smtp] section.")
        sys.exit(1)
    if "reporter" not in cp:
        print("ERROR: .config is missing the required [reporter] section.")
        print("       Add a [reporter] section with name, email, and org fields.")
        sys.exit(1)

    s = cp["smtp"]
    r = cp["reporter"]
    try:
        cfg = {
            # SMTP connection and auth
            "host":         s.get("host", "").strip(),
            "port":         s.getint("port", 587),
            "use_starttls": s.getboolean("use_starttls", True),
            "use_ssl":      s.getboolean("use_ssl", False),
            "username":     s.get("username", "").strip(),
            "password":     s.get("password", "").strip(),
            "sender_name":  s.get("sender_name", "").strip(),
            "sender_email": s.get("sender_email", "").strip(),
            # Reporter identity (appears in email body and signature)
            "reporter_name":  r.get("name", "").strip(),
            "reporter_email": r.get("email", "").strip(),
            "reporter_org":   r.get("org", "").strip(),
            # Parsed ignore prefixes
            "ignore_prefixes": _parse_ignore_prefixes(
                cp["ignore"].get("prefixes", "") if "ignore" in cp else ""
            ),
        }
    except (ValueError, configparser.Error) as exc:
        print(f"ERROR: Could not parse .config: {exc}")
        sys.exit(1)

    env_pw = os.environ.get("SMTP_PASSWORD", "").strip()
    if env_pw:
        cfg["password"] = env_pw

    if not cfg["host"]:
        print("ERROR: .config [smtp] host is empty.")
        sys.exit(1)
    if not cfg["reporter_name"]:
        print("ERROR: .config [reporter] name is empty.")
        sys.exit(1)
    if not cfg["reporter_email"]:
        print("ERROR: .config [reporter] email is empty.")
        sys.exit(1)
    if not cfg["reporter_org"]:
        print("ERROR: .config [reporter] org is empty.")
        sys.exit(1)

    # [settings] — operational parameters; all are optional with built-in defaults
    st = cp["settings"] if "settings" in cp else {}
    try:
        cfg["reports_dir"]   = st.get("reports_dir", "reports").strip() or "reports"
        cfg["cooldown_days"] = int(st.get("cooldown_days", "30"))
        cfg["whois_delay"]   = float(st.get("whois_delay", "2.0"))
    except (ValueError, configparser.Error) as exc:
        print(f"ERROR: Could not parse .config [settings]: {exc}")
        sys.exit(1)

    # Column name mappings — each section is optional; defaults match the standard
    # DMARC reporting tool export headers. Override only if your tool uses different
    # column names. Only keys present in the section override the default; omitted
    # keys retain their default value.
    def _load_cols(section_name: str, defaults: dict) -> dict:
        if section_name not in cp:
            return dict(defaults)
        result = dict(defaults)
        for key in defaults:
            val = cp[section_name].get(key, "").strip()
            if val:
                result[key] = val
        return result

    cfg["source_cols"] = _load_cols("source_cols", {
        "source_ip":   "IP Address",
        "base_domain": "Base Domain",
        "country":     "Country",
        "count":       "Messages",
    })
    cfg["spf_cols"] = _load_cols("spf_cols", {
        "header_from":      "Header From",
        "envelope_from":    "Envelope From",
        "spf_result":       "SPF Result",
        "spf_aligned":      "SPF Aligned",
        "reverse_dns_base": "Reverse DNS Base",
        "count":            "Messages",
    })
    cfg["dkim_cols"] = _load_cols("dkim_cols", {
        "header_from":      "Header From",
        "dkim_selector":    "DKIM Selector",
        "dkim_domain":      "DKIM Domain",
        "dkim_result":      "DKIM Result",
        "dkim_aligned":     "DKIM Aligned",
        "reverse_dns_base": "Reverse DNS Base",
        "count":            "Messages",
    })

    return cfg


# =============================================================================
# INPUT VALIDATION
# =============================================================================

def validate_date_prefix(prefix: str) -> None:
    """
    Abort if prefix contains characters that could enable path traversal.
    Only alphanumerics, hyphens, and underscores are accepted.
    """
    if not prefix or not re.fullmatch(r"[A-Za-z0-9_\-]+", prefix):
        print(
            f"ERROR: Invalid date_prefix '{prefix}'.\n"
            "       Use only letters, digits, hyphens, and underscores (e.g. 2MAY2026)."
        )
        sys.exit(1)


# =============================================================================
# EMAIL TEMPLATE LOADER
# =============================================================================

EMAIL_TEMPLATE_FILE = Path(__file__).parent / "email_template.txt"


def load_email_template(path: Path) -> tuple:
    """
    Load the email subject and body from a plain-text template file.

    Format:
        Line 1:  subject (supports {placeholder} substitution)
        Line 2:  blank separator
        Line 3+: body    (supports {placeholder} substitution)

    Available placeholders: {header_from}, {source_ip}, {reverse_dns},
                            {message_count}, {envelope_senders}

    Exits with an error if the file is missing or improperly formatted.
    """
    if not path.exists():
        print(f"ERROR: Email template file not found: {path}")
        sys.exit(1)

    text = path.read_text(encoding="utf-8")
    parts = text.split("\n\n", 1)

    if len(parts) != 2 or not parts[0].strip():
        print(
            f"ERROR: {path} must have a non-empty subject line followed by "
            "a blank line and then the message body."
        )
        sys.exit(1)

    subject = parts[0].strip()
    body    = parts[1]
    return subject, body


# =============================================================================
# RIR WHOIS SERVER MAP
# =============================================================================

RIR_WHOIS = {
    "arin":    "whois.arin.net",
    "ripe":    "whois.ripe.net",
    "apnic":   "whois.apnic.net",
    "afrinic": "whois.afrinic.net",
    "lacnic":  "whois.lacnic.net",
}


# =============================================================================
# DNS / WHOIS HELPERS
# =============================================================================

def get_reverse_dns(ip: str) -> str:
    """Return the PTR record for ip via dig, falling back to socket. Returns 'N/A' on failure."""
    try:
        result = subprocess.run(
            ["dig", "+short", "-x", ip],
            capture_output=True, text=True, timeout=10,
        )
        rdns = result.stdout.strip().rstrip(".")
        if rdns:
            return rdns
    except FileNotFoundError:
        pass  # dig not available; fall through to socket
    except Exception:
        pass
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def _run_whois(ip: str, server: str = None) -> str:
    """Run the system whois command and return stdout, or '' on error."""
    cmd = ["whois"]
    if server:
        cmd += ["-h", server]
    cmd.append(ip)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout
    except Exception:
        return ""


def _parse_abuse_email(text: str) -> str | None:
    """Extract the first abuse-contact email from raw whois output."""
    if not text:
        return None
    # Named-field patterns tried in priority order
    named_patterns = [
        r"OrgAbuseEmail:\s*([\w.+\-]+@[\w.\-]+\.\w+)",   # ARIN
        r"abuse-mailbox:\s*([\w.+\-]+@[\w.\-]+\.\w+)",    # RIPE / APNIC / AFRINIC
        r"AbuseEmail:\s*([\w.+\-]+@[\w.\-]+\.\w+)",       # generic
    ]
    for pat in named_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    # Fallback: any email address that contains the word "abuse"
    for email in re.findall(r"[\w.+\-]+@[\w.\-]+\.\w+", text):
        if "abuse" in email.lower():
            return email
    return None


def get_whois_info(ip: str) -> dict:
    """
    Look up WHOIS data for an IP address.

    Strategy:
      1. ipwhois RDAP (structured, RIR-routed)
      2. Direct query to the detected RIR whois server
      3. Plain `whois` command fallback

    Returns dict with keys: abuse_email, rir, org_name, asn.
    """
    info: dict = {"abuse_email": None, "rir": None, "org_name": None, "asn": None}

    # ---- Step 1: RDAP via ipwhois -------------------------------------------
    try:
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)

        info["rir"]      = (rdap.get("asn_registry") or "").upper() or None
        info["asn"]      = rdap.get("asn")
        info["org_name"] = (rdap.get("network") or {}).get("name")

        # Search RDAP objects for one with role == "abuse"
        for _, odata in (rdap.get("objects") or {}).items():
            if "abuse" in (odata.get("roles") or []):
                for entry in (odata.get("contact") or {}).get("email") or []:
                    val = entry.get("value") if isinstance(entry, dict) else entry
                    if val and "@" in val:
                        info["abuse_email"] = val
                        break
            if info["abuse_email"]:
                break

        # Also scan network-level remarks for embedded email addresses
        if not info["abuse_email"]:
            for remark in (rdap.get("network") or {}).get("remarks") or []:
                for desc in remark.get("description") or []:
                    for e in re.findall(r"[\w.+\-]+@[\w.\-]+\.\w+", desc):
                        if "abuse" in e.lower():
                            info["abuse_email"] = e
                            break
                if info["abuse_email"]:
                    break

    except (IPDefinedError, Exception):
        pass

    # ---- Step 2: Direct RIR whois server ------------------------------------
    if not info["abuse_email"] and info["rir"]:
        server = RIR_WHOIS.get(info["rir"].lower())
        if server:
            info["abuse_email"] = _parse_abuse_email(_run_whois(ip, server))

    # ---- Step 3: Plain whois fallback ---------------------------------------
    if not info["abuse_email"]:
        raw = _run_whois(ip)
        info["abuse_email"] = _parse_abuse_email(raw)
        # Try to detect RIR from the raw text if still unknown
        if not info["rir"] and raw:
            for rir in RIR_WHOIS:
                if rir.upper() in raw.upper():
                    info["rir"] = rir.upper()
                    break

    return info


# =============================================================================
# CSV UTILITIES
# =============================================================================

def _safe_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def read_csv(path: Path) -> list:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_history(path: Path) -> dict:
    """Load Report_History.csv. Returns {ip_str: datetime}."""
    history: dict = {}
    if not path.exists():
        return history
    for row in read_csv(path):
        ip = (row.get("source_ip") or "").strip()
        ds = (row.get("last_reported_date") or "").strip()
        if ip and ds:
            try:
                history[ip] = datetime.strptime(ds, "%Y-%m-%d")
            except ValueError:
                pass
    return history


def save_history(path: Path, history: dict) -> None:
    # Write to a temp file then atomically replace the target so a crash
    # mid-write never leaves a truncated or empty Report_History.csv.
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["source_ip", "last_reported_date"])
            w.writeheader()
            for ip, dt in sorted(history.items()):
                w.writerow({"source_ip": ip, "last_reported_date": dt.strftime("%Y-%m-%d")})
        tmp.replace(path)  # atomic on POSIX; best-effort on Windows
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# =============================================================================
# REPORT CORRELATION
# =============================================================================

FULL_CSV_FIELDS = [
    "source_ip", "header_from", "message_count", "country", "base_domain", "reverse_dns",
    "abuse_email", "rir", "org_name", "asn",
    "envelope_senders", "spf_results", "dkim_domains", "dkim_results",
]


def correlate(source_rows: list, spf_rows: list, dkim_rows: list,
              source_cols: dict, spf_cols: dict, dkim_cols: dict) -> dict:
    """
    Join the three CSV row lists.

    Join key: source["Base Domain"] == spf/dkim["Reverse DNS Base"]
    header_from is extracted from SPF/DKIM rows, not from source.

    Returns a dict keyed by IP with aggregated sets for multi-valued fields.
    """
    spf_idx: dict  = defaultdict(list)
    dkim_idx: dict = defaultdict(list)

    for r in spf_rows:
        key = (r.get(spf_cols["reverse_dns_base"]) or "").strip()
        if key:
            spf_idx[key].append(r)

    for r in dkim_rows:
        key = (r.get(dkim_cols["reverse_dns_base"]) or "").strip()
        if key:
            dkim_idx[key].append(r)

    combined: dict = {}

    for row in source_rows:
        ip        = (row.get(source_cols["source_ip"])   or "").strip()
        base_dom  = (row.get(source_cols["base_domain"]) or "").strip()
        country   = (row.get(source_cols["country"])     or "").strip()
        raw_count = row.get(source_cols["count"], "0") or "0"
        count     = int(raw_count) if str(raw_count).isdigit() else 0

        if not ip:
            continue

        if ip not in combined:
            combined[ip] = {
                "source_ip":        ip,
                "base_domain":      base_dom,
                "country":          country,
                "header_from":      set(),
                "message_count":    0,
                "envelope_senders": {},   # domain -> message count
                "spf_results":      set(),
                "dkim_domains":     set(),
                "dkim_results":     set(),
            }

        combined[ip]["message_count"] += count

        for sr in spf_idx.get(base_dom, []):
            hf        = (sr.get(spf_cols["header_from"])   or "").strip()
            ef        = (sr.get(spf_cols["envelope_from"]) or "").strip()
            res       = (sr.get(spf_cols["spf_result"])    or "").strip()
            raw_sc    = sr.get(spf_cols["count"], "0") or "0"
            spf_count = int(raw_sc) if str(raw_sc).isdigit() else 0
            if hf:
                combined[ip]["header_from"].add(hf)
            if ef:
                combined[ip]["envelope_senders"][ef] = (
                    combined[ip]["envelope_senders"].get(ef, 0) + spf_count
                )
            if res:
                combined[ip]["spf_results"].add(res)

        for dr in dkim_idx.get(base_dom, []):
            hf  = (dr.get(dkim_cols["header_from"]) or "").strip()
            dom = (dr.get(dkim_cols["dkim_domain"])  or "").strip()
            res = (dr.get(dkim_cols["dkim_result"])  or "").strip()
            if hf:
                combined[ip]["header_from"].add(hf)
            if dom and dom != "__missing__":
                combined[ip]["dkim_domains"].add(dom)
            if res and res != "__missing__":
                combined[ip]["dkim_results"].add(res)

    return combined


def build_full_report(combined: dict, whois_delay: float) -> list:
    """
    Perform rDNS and WHOIS lookups for every unique IP and return a list
    of flat dicts suitable for writing to the full CSV.
    """
    ips = list(combined.keys())
    print(f"\n[*] Performing rDNS/WHOIS lookups for {len(ips)} unique source IP(s)...")

    ip_cache: dict = {}
    for ip in ips:
        print(f"    {ip} ...", end=" ", flush=True)
        rdns = get_reverse_dns(ip)
        time.sleep(0.3)
        info = get_whois_info(ip)
        time.sleep(whois_delay)
        ip_cache[ip] = {
            "reverse_dns": rdns,
            "abuse_email": info["abuse_email"] or "UNKNOWN",
            "rir":         info["rir"]         or "UNKNOWN",
            "org_name":    info["org_name"]    or "UNKNOWN",
            "asn":         info["asn"]         or "UNKNOWN",
        }
        print(
            f"rDNS={rdns}  "
            f"abuse={info['abuse_email'] or 'N/A'}  "
            f"RIR={info['rir'] or 'N/A'}"
        )

    rows = []
    for ip, data in combined.items():
        c = ip_cache[ip]
        header_from_list = sorted(data["header_from"])
        rows.append({
            "source_ip":        ip,
            "header_from":      "|".join(header_from_list),
            "message_count":    data["message_count"],
            "country":          data.get("country", ""),
            "base_domain":      data.get("base_domain", ""),
            "reverse_dns":      c["reverse_dns"],
            "abuse_email":      c["abuse_email"],
            "rir":              c["rir"],
            "org_name":         c["org_name"],
            "asn":              c["asn"],
            "envelope_senders": "|".join(
                f"{d}:{c}" for d, c in sorted(data["envelope_senders"].items())
            ),
            "spf_results":      "|".join(sorted(data["spf_results"])),
            "dkim_domains":     "|".join(sorted(data["dkim_domains"])),
            "dkim_results":     "|".join(sorted(data["dkim_results"])),
        })
    return rows


# =============================================================================
# EMAIL
# =============================================================================

def _sanitize_header(value: str) -> str:
    """Strip CR/LF to prevent email header injection."""
    return re.sub(r"[\r\n]+", " ", value).strip()


def _escape_braces(s) -> str:
    """Escape literal curly braces so untrusted values are safe inside str.format()."""
    return str(s).replace("{", "{{").replace("}", "}}")


def _is_valid_email(addr: str) -> bool:
    """Return True if addr looks like a plausible single email address."""
    return bool(re.fullmatch(r"[\w.+\-]+@[\w.\-]+\.\w{2,}", addr))


def format_email(group: dict, subject_tmpl: str, body_tmpl: str, cfg: dict) -> tuple:
    """Return (subject, body) strings for one consolidated IP group."""
    header_from = group["header_from"].split("|")[0]

    ip_lines = []
    for entry in group["ip_entries"]:
        count = _safe_int(entry.get("message_count", 0))
        suffix = "message" if count == 1 else "messages"
        ip_lines.append(
            f"  - {entry['source_ip']} (rDNS: {entry['reverse_dns']}) — {count} {suffix}"
        )
    ip_list = "\n".join(ip_lines)

    env_lines = []
    for domain in (s.strip() for s in group["envelope_senders"].split("|") if s.strip()):
        env_lines.append(f"  - {domain}")
    env_block = "\n".join(env_lines) if env_lines else "  (none recorded)"

    values = dict(
        header_from=_escape_braces(header_from),
        ip_list=_escape_braces(ip_list),
        envelope_senders=_escape_braces(env_block),
        reporter_name=_escape_braces(cfg["reporter_name"]),
        org_name=_escape_braces(cfg["reporter_org"]),
        contact_email=_escape_braces(cfg["reporter_email"]),
    )
    return subject_tmpl.format(**values), body_tmpl.format(**values)


def send_email(to_addr: str, subject: str, body: str, cfg: dict) -> tuple:
    """
    Send a plain-text email via the SMTP server described in cfg.
    Returns (success: bool, error_message: str).
    All values placed into RFC2822 headers are sanitized to prevent injection.
    """
    to_clean      = _sanitize_header(to_addr)
    subject_clean = _sanitize_header(subject)
    from_name     = _sanitize_header(cfg["sender_name"])
    from_addr     = _sanitize_header(cfg["sender_email"])

    if not _is_valid_email(to_clean):
        return False, f"Refusing to send — '{to_clean}' is not a valid email address"

    msg = MIMEMultipart("alternative")
    msg["From"]    = f"{from_name} <{from_addr}>"
    msg["To"]      = to_clean
    msg["Subject"] = subject_clean
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        if cfg["use_ssl"]:
            srv = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=30)
        else:
            srv = smtplib.SMTP(cfg["host"], cfg["port"], timeout=30)
            if cfg["use_starttls"]:
                srv.starttls()

        password = cfg.get("password", "")
        if cfg.get("username") and password and password != "YOUR_PASSWORD_HERE":
            srv.login(cfg["username"], password)

        srv.sendmail(from_addr, to_clean, msg.as_string())
        srv.quit()
        return True, ""
    except Exception as exc:
        return False, str(exc)


def test_smtp_connection(cfg: dict) -> None:
    """
    Connect, optionally authenticate, then immediately disconnect.
    Exits with an error message if anything fails, so credential problems
    are caught before the WHOIS lookups and interactive loop begin.
    """
    print("[*] Testing SMTP connection ...", end=" ", flush=True)
    try:
        if cfg["use_ssl"]:
            srv = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15)
        else:
            srv = smtplib.SMTP(cfg["host"], cfg["port"], timeout=15)
            if cfg["use_starttls"]:
                srv.starttls()

        password = cfg.get("password", "")
        if cfg.get("username") and password and password != "YOUR_PASSWORD_HERE":
            srv.login(cfg["username"], password)

        srv.quit()
        print("OK")
    except Exception as exc:
        print(f"FAILED\nERROR: SMTP connection test failed: {exc}")
        sys.exit(1)


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="DMARC Abuse Reporter — parse reports and send abuse notifications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python dmarc_reporter.py 2MAY2026",
    )
    parser.add_argument(
        "date_prefix",
        help="Date prefix used in report filenames, e.g. 2MAY2026",
    )
    parser.add_argument(
        "--skip-lookup",
        action="store_true",
        help="Skip WHOIS/rDNS lookups and reuse an existing full CSV",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview reports and prompts but do not send any emails or update history",
    )
    args = parser.parse_args()

    cfg                     = load_config()
    subject_tmpl, body_tmpl = load_email_template(EMAIL_TEMPLATE_FILE)
    prefix                  = args.date_prefix
    dry_run                 = args.dry_run
    ignore_prefixes         = cfg["ignore_prefixes"]

    validate_date_prefix(prefix)

    if dry_run:
        print("[*] DRY RUN mode — no emails will be sent and history will not be updated")
    else:
        test_smtp_connection(cfg)

    rdir      = Path(cfg["reports_dir"])
    rdir.mkdir(exist_ok=True)

    src_path   = rdir / f"{prefix}_source.csv"
    spf_path   = rdir / f"{prefix}_spf.csv"
    dkim_path  = rdir / f"{prefix}_dkim.csv"
    full_path  = rdir / f"{prefix}_full.csv"
    hist_path  = rdir / "Report_History.csv"

    # -------------------------------------------------------------------------
    # Build (or reload) the full correlated CSV
    # -------------------------------------------------------------------------
    if args.skip_lookup:
        if not full_path.exists():
            print(f"ERROR: --skip-lookup specified but {full_path} does not exist.")
            sys.exit(1)
        print(f"[*] Reloading existing full report from {full_path}")
        full_rows = read_csv(full_path)
    else:
        for p in (src_path, spf_path, dkim_path):
            if not p.exists():
                print(f"ERROR: Required input file not found: {p}")
                sys.exit(1)

        print(f"[*] Loading CSV files for prefix '{prefix}' ...")
        src_rows  = read_csv(src_path)
        spf_rows  = read_csv(spf_path)
        dkim_rows = read_csv(dkim_path)
        print(
            f"    Source: {len(src_rows)} row(s)  "
            f"SPF: {len(spf_rows)} row(s)  "
            f"DKIM: {len(dkim_rows)} row(s)"
        )

        combined  = correlate(src_rows, spf_rows, dkim_rows,
                              cfg["source_cols"], cfg["spf_cols"], cfg["dkim_cols"])
        print(f"[*] Correlated into {len(combined)} unique source IP(s)")

        full_rows = build_full_report(combined, cfg["whois_delay"])

        with open(full_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FULL_CSV_FIELDS)
            w.writeheader()
            w.writerows(full_rows)
        print(f"[*] Full report saved: {full_path}")

    # -------------------------------------------------------------------------
    # Filter: blank header_from and configured ignore prefixes
    # -------------------------------------------------------------------------
    pre_filter = len(full_rows)
    full_rows = [
        r for r in full_rows
        if r.get("header_from", "").strip()
        and not is_ignored(r["source_ip"], ignore_prefixes)
    ]
    filtered = pre_filter - len(full_rows)
    if filtered:
        print(f"[*] Filtered {filtered} row(s) (blank spoofed domain or ignored prefix)")

    # -------------------------------------------------------------------------
    # Filter against report history (skip IPs reported within the cooldown)
    # -------------------------------------------------------------------------
    history = load_history(hist_path)
    if history:
        print(f"[*] History: {len(history)} previously reported IP(s) on record")
    else:
        print("[*] No history file found — this appears to be the first run")

    cutoff    = datetime.now() - timedelta(days=cfg["cooldown_days"])
    to_report = []
    skipped   = []

    for row in full_rows:
        ip        = row["source_ip"]
        last_seen = history.get(ip)
        if last_seen and last_seen >= cutoff:
            skipped.append((ip, last_seen))
        else:
            to_report.append(row)

    if skipped:
        print(
            f"\n[*] Skipping {len(skipped)} IP(s) reported within the last "
            f"{cfg['cooldown_days']} days:"
        )
        for ip, dt in skipped:
            print(f"    {ip}  (last reported {dt.strftime('%Y-%m-%d')})")

    if not to_report:
        print("\n[*] Nothing to report — all IPs are within the cooldown window.")
        return

    # -------------------------------------------------------------------------
    # Consolidate: group eligible IPs by abuse_email so that each abuse
    # contact receives exactly one email listing all their IPs, regardless
    # of how many base domains those IPs span.
    # -------------------------------------------------------------------------
    groups: dict = defaultdict(list)
    for row in to_report:
        key = row.get("abuse_email", "UNKNOWN")
        groups[key].append(row)

    consolidated = []
    for abuse_email, rows in groups.items():
        first = rows[0]
        # Union all multi-valued fields across every row in this group.
        header_from_set    = set()
        env_sender_domains = set()
        spf_results_set    = set()
        dkim_domains_set   = set()
        dkim_results_set   = set()
        for r in rows:
            for v in r.get("header_from", "").split("|"):
                v = v.strip()
                if v:
                    header_from_set.add(v)
            for entry in r.get("envelope_senders", "").split("|"):
                entry = entry.strip()
                if entry:
                    domain = entry.rpartition(":")[0] if ":" in entry else entry
                    if domain:
                        env_sender_domains.add(domain)
            for v in r.get("spf_results", "").split("|"):
                v = v.strip()
                if v:
                    spf_results_set.add(v)
            for v in r.get("dkim_domains", "").split("|"):
                v = v.strip()
                if v:
                    dkim_domains_set.add(v)
            for v in r.get("dkim_results", "").split("|"):
                v = v.strip()
                if v:
                    dkim_results_set.add(v)
        consolidated.append({
            "abuse_email":      abuse_email,
            "header_from":      "|".join(sorted(header_from_set)),
            "envelope_senders": "|".join(sorted(env_sender_domains)),
            "spf_results":      "|".join(sorted(spf_results_set)),
            "dkim_domains":     "|".join(sorted(dkim_domains_set)),
            "dkim_results":     "|".join(sorted(dkim_results_set)),
            "org_name":         first.get("org_name", "UNKNOWN"),
            "rir":              first.get("rir", "UNKNOWN"),
            "asn":              first.get("asn", "UNKNOWN"),
            "ip_entries": [
                {
                    "source_ip":     r["source_ip"],
                    "reverse_dns":   r.get("reverse_dns", "N/A"),
                    "message_count": r.get("message_count", 0),
                }
                for r in rows
            ],
            "total_message_count": sum(
                _safe_int(r.get("message_count", 0)) for r in rows
            ),
        })

    ip_count = sum(len(g["ip_entries"]) for g in consolidated)
    if ip_count > len(consolidated):
        print(
            f"\n[*] {ip_count} eligible IP(s) consolidated into "
            f"{len(consolidated)} report(s)"
        )
    else:
        print(f"\n[*] {len(consolidated)} report(s) ready")

    # -------------------------------------------------------------------------
    # Interactive confirmation and send loop — one email per consolidated group
    # -------------------------------------------------------------------------
    sent = skipped_by_user = failed = 0
    SEP  = "=" * 72
    DASH = "-" * 72

    for group in consolidated:
        abuse_email = group["abuse_email"]
        ip_entries  = group["ip_entries"]

        subject, body = format_email(group, subject_tmpl, body_tmpl, cfg)

        print(f"\n{SEP}")
        print(f"  IPs:")
        for entry in ip_entries:
            count = _safe_int(entry.get("message_count", 0))
            suffix = "message" if count == 1 else "messages"
            print(f"    {entry['source_ip']} (rDNS: {entry['reverse_dns']}) — {count} {suffix}")
        print(f"  Organization : {group.get('org_name', 'N/A')}")
        print(f"  RIR          : {group.get('rir', 'N/A')}")
        print(f"  ASN          : {group.get('asn', 'N/A')}")
        print(f"  Domain(s)    : {group.get('header_from', 'N/A')}")
        print(f"  Total Msgs   : {group['total_message_count']}")
        print(f"  Abuse Email  : {abuse_email}")
        print(f"  Subject      : {subject}")
        print(DASH)
        print(body)
        print(SEP)

        if abuse_email == "UNKNOWN":
            print("  [!] WARNING: No abuse contact found.")

        while True:
            try:
                ans = input(f"\nSend report to {abuse_email}? [Y/N]: ").strip().upper()
            except (EOFError, KeyboardInterrupt):
                print("\n\n[!] Interrupted — exiting.")
                if not dry_run:
                    save_history(hist_path, history)
                    print(f"    History saved: {hist_path}")
                sys.exit(0)
            if ans in ("Y", "N"):
                break
            print("    Please enter Y or N.")

        if ans == "Y":
            if dry_run:
                print(f"  [DRY RUN] Would send to {abuse_email} — skipped")
                sent += 1
            else:
                ok, err = send_email(abuse_email, subject, body, cfg)
                if ok:
                    print(f"  [+] Sent successfully to {abuse_email}")
                    for entry in ip_entries:
                        history[entry["source_ip"]] = datetime.now()
                    sent += 1
                else:
                    print(f"  [!] Send FAILED: {err}")
                    failed += 1
        else:
            print("  [-] Skipped by user — not sent")
            skipped_by_user += 1

    # -------------------------------------------------------------------------
    # Persist updated history and print final summary
    # -------------------------------------------------------------------------
    if not dry_run:
        save_history(hist_path, history)

    print(f"\n{SEP}")
    if dry_run:
        print(f"  [DRY RUN] Would have sent: {sent}   Skipped by user: {skipped_by_user}")
        print(f"  History was NOT updated (dry run)")
    else:
        print(f"  Summary  Sent: {sent}   Skipped by user: {skipped_by_user}   Failed: {failed}")
        print(f"  Report history updated: {hist_path}")
    print(SEP)


if __name__ == "__main__":
    main()
