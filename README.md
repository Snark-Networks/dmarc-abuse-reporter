# DMARC Abuse Reporter

Parses DMARC aggregate report exports, performs WHOIS and reverse-DNS lookups, builds a correlated full report, and sends abuse notification emails to network operators — one email per offending source IP, with interactive confirmation before each send.

---

## Requirements

- Python 3.8 or later
- `dig` (part of `bind-utils` / `dnsutils` — used for reverse DNS)
- `whois` system command (used as a fallback lookup method)
- Python dependencies:

```bash
pip install -r requirements.txt
```

---

## First-Time Setup

**1. Copy and configure the SMTP config file:**

```bash
cp .smtp_config.example .smtp_config
chmod 600 .smtp_config
```

Then edit `.smtp_config` with your mail server details and identity:

```ini
[smtp]
host         = mail.example.com
port         = 587
use_starttls = true
use_ssl      = false
username     = abuse@example.com
password     = YOUR_PASSWORD_HERE
sender_name  = Your Name
sender_email = abuse@example.com
org_name     = Your Organisation Name (ASxxxxx)
```

`.smtp_config` is listed in `.gitignore` and will never be accidentally committed. The script checks permissions on POSIX systems and refuses to start if the file is readable by group or others.

**To avoid storing the password in the file at all**, leave `password` blank and set the `SMTP_PASSWORD` environment variable instead — it takes precedence:

```bash
export SMTP_PASSWORD="yourpassword"
```

**2. Edit the email template** (`email_template.txt`) to review the default wording. The `{reporter_name}`, `{org_name}`, and `{contact_email}` placeholders are filled in automatically from `.smtp_config` at runtime — no changes needed unless you want to alter the text itself.

---

## CSV Column Names

The script expects specific column header names in each input file. If your DMARC tool exports different names, update the three column-mapping dicts near the top of the script:

```python
SOURCE_COLS = {
    "source_ip":   "IP Address",   # <-- change right-hand values to match your headers
    "base_domain": "Base Domain",
    "country":     "Country",
    "count":       "Messages",
}

SPF_COLS = {
    "header_from":      "Header From",
    "envelope_from":    "Envelope From",
    "spf_result":       "SPF Result",
    "spf_aligned":      "SPF Aligned",
    "reverse_dns_base": "Reverse DNS Base",
    "count":            "Messages",
}

DKIM_COLS = {
    "header_from":      "Header From",
    "dkim_selector":    "DKIM Selector",
    "dkim_domain":      "DKIM Domain",
    "dkim_result":      "DKIM Result",
    "dkim_aligned":     "DKIM Aligned",
    "reverse_dns_base": "Reverse DNS Base",
    "count":            "Messages",
}
```

The join key is `source["Base Domain"]` matched against `spf["Reverse DNS Base"]` and `dkim["Reverse DNS Base"]`. There is no IP address column in the SPF or DKIM files; `Header From` (the spoofed domain) is sourced from those files rather than from the source file.

---

## File Layout

```
dmarc-abuse-reporter/
├── dmarc_reporter.py
├── email_template.txt            ← edit to customise the abuse email wording
├── requirements.txt
├── LICENSE
├── .smtp_config.example          ← committed template — copy this to get started
├── .smtp_config                  ← your real credentials (gitignored, never committed)
├── .gitignore
├── README.md
├── AGENTS.md
└── reports/
    ├── .instructions             ← explains what belongs in this directory
    ├── 2MAY2026_source.csv       ← input: one row per source IP       (gitignored)
    ├── 2MAY2026_spf.csv          ← input: SPF results per source IP   (gitignored)
    ├── 2MAY2026_dkim.csv         ← input: DKIM results per source IP  (gitignored)
    ├── 2MAY2026_full.csv         ← output: correlated report          (gitignored)
    └── Report_History.csv        ← auto-created: last-reported dates  (gitignored)
```

Place all three input files in the `reports/` directory before running. The directory is created automatically if it does not exist. All `*.csv` files in `reports/` are gitignored.

### Input file column reference

| File | Required columns |
|------|-----------------|
| `_source.csv` | `IP Address`, `Base Domain`, `Country`, `Messages` |
| `_spf.csv` | `Header From`, `Envelope From`, `SPF Result`, `SPF Aligned`, `Reverse DNS Base`, `Messages` |
| `_dkim.csv` | `Header From`, `DKIM Selector`, `DKIM Domain`, `DKIM Result`, `DKIM Aligned`, `Reverse DNS Base`, `Messages` |

**Join key:** `source["Base Domain"]` is matched against `spf["Reverse DNS Base"]` and `dkim["Reverse DNS Base"]`. The spoofed domain (`Header From`) is pulled from the SPF/DKIM files. A live reverse-DNS lookup is performed for each source IP even though `_source.csv` already contains a `Reverse DNS` column, because PTR records can change between the time the report was generated and now.

### Output: `_full.csv` columns

| Column | Description |
|--------|-------------|
| `source_ip` | Sending IP address |
| `header_from` | Spoofed domain(s), pipe-separated if multiple |
| `message_count` | Total messages from this IP in the report |
| `country` | Country code from the source report |
| `reverse_dns` | Live PTR record for the IP (looked up at run time), or `N/A` |
| `abuse_email` | Abuse contact found via WHOIS, or `UNKNOWN` |
| `rir` | Regional Internet Registry (ARIN, RIPE, APNIC, etc.) |
| `org_name` | Network/org name from WHOIS |
| `asn` | Autonomous System Number |
| `envelope_senders` | Envelope-From domains with message counts, pipe-separated as `domain:count` |
| `spf_results` | SPF result values seen, pipe-separated |
| `dkim_domains` | DKIM signing domains seen, pipe-separated |
| `dkim_results` | DKIM result values seen, pipe-separated |

---

## Running the Script

### Normal run

Reads the three input CSVs, performs all lookups, writes the full CSV, then steps through each eligible IP interactively:

```bash
python3 dmarc_reporter.py 2MAY2026
```

### Dry run — preview without sending

Runs the full workflow including WHOIS lookups, confirmation prompts, and email previews, but does not call the mail server and does not update `Report_History.csv`. Use this to verify everything looks correct before committing to a real send.

```bash
python3 dmarc_reporter.py 2MAY2026 --dry-run
```

### Skip lookups (re-use existing full CSV)

Useful if you already ran the lookup phase and just want to re-do the email step, or if you manually edited the full CSV:

```bash
python3 dmarc_reporter.py 2MAY2026 --skip-lookup
```

Flags can be combined:

```bash
python3 dmarc_reporter.py 2MAY2026 --skip-lookup --dry-run
```

---

## What Happens at Runtime

1. **Startup checks** — the script validates the `date_prefix` argument (rejects path-traversal characters), checks `.smtp_config` file permissions, loads the email template, and tests the SMTP connection before doing any work. In `--dry-run` mode the SMTP test is skipped.

2. **Correlation** — the three input CSVs are joined on `source_ip`. Message counts are summed. Envelope senders, SPF results, DKIM domains, and DKIM results are collected as unique sets per IP.

3. **WHOIS lookup** — for each unique IP, the script attempts to find an abuse contact using three methods in order:
   - RDAP via `ipwhois` (structured, RIR-routed)
   - Direct query to the RIR's whois server (`whois.arin.net`, `whois.ripe.net`, `whois.apnic.net`, `whois.afrinic.net`, or `whois.lacnic.net`)
   - Plain `whois` command fallback

4. **Reverse DNS** — each IP is looked up via `dig +short -x`, falling back to a Python socket lookup.

5. **Full CSV** — all correlated data plus WHOIS/rDNS results are written to `reports/<prefix>_full.csv`.

6. **History check** — any IP found in `reports/Report_History.csv` with a last-reported date within the past 30 days is skipped automatically.

7. **Interactive send loop** — for each eligible IP, the script prints a full summary and the complete email body, then prompts:

   ```
   Send report to abuse@example.net? [Y/N]:
   ```

   - **Y** — sends the email (or prints `[DRY RUN]` if `--dry-run`) and records today's date in `Report_History.csv`
   - **N** — skips this IP (history is not updated, so it will appear again next run)

   Pressing `Ctrl-C` at any prompt saves history (unless `--dry-run`) and exits cleanly.

8. **Summary** — after all IPs are processed, a count of sent / skipped / failed is printed and `Report_History.csv` is saved atomically.

---

## Editing the Email Template

The abuse email subject and body live in `email_template.txt`. Open it in any text editor to change the wording.

**File format** — the file has three parts, in order:

1. **Subject line** — the entire first line; supports `{placeholder}` substitution
2. **Blank line** — one empty line separating subject from body (required)
3. **Body** — everything after the blank line; supports `{placeholder}` substitution

Available placeholders:

| Placeholder | Value |
|-------------|-------|
| `{header_from}` | The spoofed domain (first alphabetically if multiple) |
| `{source_ip}` | The offending IP address |
| `{reverse_dns}` | PTR record for the IP |
| `{message_count}` | Total messages seen from this IP |
| `{envelope_senders}` | Bulleted list of envelope-from domains |
| `{reporter_name}` | Your name (`sender_name` in `.smtp_config`) |
| `{org_name}` | Your organisation name (`org_name` in `.smtp_config`) |
| `{contact_email}` | Your abuse contact address (`sender_email` in `.smtp_config`) |

The `{reporter_name}`, `{org_name}`, and `{contact_email}` placeholders are sourced from `.smtp_config` automatically — update them there, not by editing the template.

The script exits with a clear error if the file is missing or the blank-line separator is absent.

---

## Report History

`reports/Report_History.csv` contains two columns:

```
source_ip,last_reported_date
1.2.3.4,2026-05-02
```

- Created automatically on the first run.
- Updated only when an email is successfully sent (not when skipped by the user).
- IPs with a `last_reported_date` within the past 30 days are silently skipped before the interactive loop begins.
- The cooldown period can be changed by editing `REPORT_COOLDOWN_DAYS` at the top of the script.

---

## Adjustable Settings

Identity and credentials live in `.smtp_config`. Everything else is in the `CONFIGURATION` section near the top of `dmarc_reporter.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `.smtp_config` | *(see above)* | Mail server, sender identity, and org name |
| `REPORTS_DIR` | `reports` | Directory containing all report files |
| `SOURCE_COLS` / `SPF_COLS` / `DKIM_COLS` | *(see above)* | CSV column name mappings |
| `REPORT_COOLDOWN_DAYS` | `30` | Days before re-reporting the same IP |
| `WHOIS_DELAY` | `2.0` | Seconds between WHOIS queries |

---

## Troubleshooting

**Script exits with "SMTP config file not found"**
Run `cp .smtp_config.example .smtp_config`, fill in your settings, then run `chmod 600 .smtp_config`.

**Script exits with "unsafe permissions"**
Run `chmod 600 .smtp_config`. The script refuses to start if the credentials file is readable by group or others.

**Script exits with "org_name is empty"**
Add `org_name = Your Organisation Name` to the `[smtp]` section of `.smtp_config`.

**Script exits with "SMTP connection test failed"**
Check that `host`, `port`, `use_starttls`, and `use_ssl` in `.smtp_config` match your mail server's requirements. Authentication errors mean a wrong username or password. The full error is printed on the line after `FAILED`. Use `--dry-run` to skip the SMTP test while debugging other parts of the workflow.

**`abuse_email` shows `UNKNOWN` for an IP**
The WHOIS data for that IP did not contain a recognizable abuse contact. You can manually edit `reports/<prefix>_full.csv` before re-running with `--skip-lookup`, or answer `N` at the prompt to skip that IP.

**Send fails with "not a valid email address"**
The abuse contact returned by WHOIS failed basic validation (likely garbage data or a placeholder). Edit the `abuse_email` field in the full CSV and re-run with `--skip-lookup`.

**Script exits immediately with "Nothing to report"**
All IPs in the report are within the 30-day cooldown window. Check `reports/Report_History.csv` to confirm, or manually remove rows if you need to re-report an IP sooner.

**`dig` not found**
Install `bind-utils` (RHEL/CentOS) or `dnsutils` (Debian/Ubuntu). The script falls back to Python's `socket.gethostbyaddr()` automatically if `dig` is unavailable, so this is not fatal.
