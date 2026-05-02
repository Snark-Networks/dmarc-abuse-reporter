# DMARC Abuse Reporter

Parses DMARC aggregate report exports, performs WHOIS and reverse-DNS lookups, builds a correlated full report, and sends abuse notification emails to network operators — one email per abuse contact, consolidating all offending IPs, with interactive confirmation before each send.

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

**1. Copy and configure the config file:**

```bash
cp .config.example .config
chmod 600 .config
```

Then edit `.config` with your mail server details and identity. The two required sections are `[smtp]` and `[reporter]`; the remaining sections are optional and have built-in defaults:

```ini
[smtp]
host         = mail.example.com
port         = 587
use_starttls = true
use_ssl      = false
username     = outbound@example.com
password     = YOUR_PASSWORD_HERE
sender_name  = DMARC Abuse Reporter
sender_email = outbound@example.com

[reporter]
name  = Your Name
email = abuse@example.com
org   = Your Organisation Name (ASxxxxx)

[ignore]
; CIDR prefixes to exclude from reports (one per line, indented)
prefixes =
    10.0.0.0/8
    192.168.1.0/24
    fd00::/8
```

`.config` is listed in `.gitignore` and will never be accidentally committed. The script checks permissions on POSIX systems and refuses to start if the file is readable by group or others.

The `[smtp]` section controls the outbound mail server and the `From:` header. The `[reporter]` section controls your name, contact address, and organisation name as they appear in the email body — these can differ from the SMTP sender. The `[ignore]` section lists CIDR prefixes (IPv4 or IPv6) whose IPs will be silently excluded from all reports.

**To avoid storing the password in the file at all**, leave `password` blank and set the `SMTP_PASSWORD` environment variable instead — it takes precedence:

```bash
export SMTP_PASSWORD="yourpassword"
```

**2. Edit the email template** (`email_template.txt`) to review the default wording. The `{reporter_name}`, `{org_name}`, and `{contact_email}` placeholders are filled in automatically from `.config` at runtime — no changes needed unless you want to alter the text itself.

---

## CSV Column Names

The script expects specific column header names in each input file. If your DMARC tool exports different names, add the relevant section(s) to `.config` and change the right-hand values:

```ini
[source_cols]
source_ip   = IP Address   ; <-- change right-hand values to match your headers
base_domain = Base Domain
country     = Country
count       = Messages

[spf_cols]
header_from      = Header From
envelope_from    = Envelope From
spf_result       = SPF Result
spf_aligned      = SPF Aligned
reverse_dns_base = Reverse DNS Base
count            = Messages

[dkim_cols]
header_from      = Header From
dkim_selector    = DKIM Selector
dkim_domain      = DKIM Domain
dkim_result      = DKIM Result
dkim_aligned     = DKIM Aligned
reverse_dns_base = Reverse DNS Base
count            = Messages
```

These sections are optional — omitting them uses the defaults shown above. The left-hand keys are internal names used by the script and must not be changed.

The join key is `source["Base Domain"]` matched against `spf["Reverse DNS Base"]` and `dkim["Reverse DNS Base"]`. There is no IP address column in the SPF or DKIM files; `Header From` (the spoofed domain) is sourced from those files rather than from the source file.

---

## File Layout

```
dmarc-abuse-reporter/
├── dmarc_reporter.py
├── email_template.txt            ← edit to customise the abuse email wording
├── requirements.txt
├── LICENSE
├── .config.example               ← committed template — copy this to get started
├── .config                       ← your real credentials (gitignored, never committed)
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
| `base_domain` | rDNS base domain used as the correlation join key |
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

1. **Startup checks** — the script validates the `date_prefix` argument (rejects path-traversal characters), checks `.config` file permissions, loads the email template, and tests the SMTP connection before doing any work. In `--dry-run` mode the SMTP test is skipped.

2. **Correlation** — the three input CSVs are joined on `Base Domain` / `Reverse DNS Base`. Message counts are summed per IP. Envelope senders (stored as `domain:count` pairs), SPF results, DKIM domains, and DKIM results are collected per base domain group.

3. **WHOIS lookup** — for each unique IP, the script attempts to find an abuse contact using three methods in order:
   - RDAP via `ipwhois` (structured, RIR-routed)
   - Direct query to the RIR's whois server (`whois.arin.net`, `whois.ripe.net`, `whois.apnic.net`, `whois.afrinic.net`, or `whois.lacnic.net`)
   - Plain `whois` command fallback

4. **Reverse DNS** — each IP is looked up via `dig +short -x`, falling back to a Python socket lookup.

5. **Full CSV** — all correlated data plus WHOIS/rDNS results are written to `reports/<prefix>_full.csv`.

6. **Filtering** — IPs with a blank spoofed domain (no match in SPF/DKIM files) and IPs falling within any CIDR prefix listed under `[ignore]` in `.config` are removed before the send loop.

7. **History check** — any IP found in `reports/Report_History.csv` with a last-reported date within the cooldown window (default 30 days, configurable via `[settings]` `cooldown_days`) is skipped automatically.

8. **Consolidation** — eligible IPs are grouped by `abuse_email`. All IPs from the same abuse contact are combined into a single report regardless of which base domains they span, so each abuse contact receives exactly one email per run.

9. **Interactive send loop** — for each consolidated group, the script prints a full summary and the complete email body, then prompts:

   ```
   Send report to abuse@example.net? [Y/N]:
   ```

   - **Y** — sends the email (or prints `[DRY RUN]` if `--dry-run`) and records today's date in `Report_History.csv` for every IP in the group
   - **N** — skips this group (history is not updated, so all IPs in the group will appear again next run)

   Pressing `Ctrl-C` at any prompt saves history (unless `--dry-run`) and exits cleanly.

10. **Summary** — after all groups are processed, a count of sent / skipped / failed emails is printed and `Report_History.csv` is saved atomically.

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
| `{ip_list}` | Bulleted list of offending IPs with rDNS and per-IP message counts |
| `{envelope_senders}` | Bulleted list of envelope-from domains |
| `{reporter_name}` | Your name (`name` in `.config` `[reporter]`) |
| `{org_name}` | Your organisation name (`org` in `.config` `[reporter]`) |
| `{contact_email}` | Your abuse contact address (`email` in `.config` `[reporter]`) |

The `{reporter_name}`, `{org_name}`, and `{contact_email}` placeholders are sourced from `.config` automatically — update them there, not by editing the template.

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
- IPs with a `last_reported_date` within the cooldown window are silently skipped before the interactive loop begins.
- The cooldown period is set by `cooldown_days` under `[settings]` in `.config` (default: 30 days).

---

## Adjustable Settings

All settings live in `.config`. Nothing needs to be edited in the script itself.

| Setting | Default | Description |
|---------|---------|-------------|
| `[smtp]` | *(see above)* | Mail server and SMTP sender address |
| `[reporter]` | *(see above)* | Your name, contact email, and org name (appear in email body) |
| `[ignore]` `prefixes` | *(empty)* | CIDR prefixes to exclude from all reports |
| `[settings]` `reports_dir` | `reports` | Directory containing all report files |
| `[settings]` `cooldown_days` | `30` | Days before re-reporting the same IP |
| `[settings]` `whois_delay` | `2.0` | Seconds between WHOIS queries |
| `[source_cols]` | *(see above)* | Column name mappings for the source CSV |
| `[spf_cols]` | *(see above)* | Column name mappings for the SPF CSV |
| `[dkim_cols]` | *(see above)* | Column name mappings for the DKIM CSV |

---

## Troubleshooting

**Script exits with "Configuration file not found"**
Run `cp .config.example .config`, fill in your settings, then run `chmod 600 .config`. If you have a legacy `.smtp_config`, rename it: `mv .smtp_config .config` and add the `[reporter]` section.

**Script exits with "unsafe permissions"**
Run `chmod 600 .config`. The script refuses to start if the credentials file is readable by group or others.

**Script exits with "reporter … is empty"**
Check that the `[reporter]` section in `.config` has non-empty `name`, `email`, and `org` fields.

**Script exits with "SMTP connection test failed"**
Check that `host`, `port`, `use_starttls`, and `use_ssl` in `.config` `[smtp]` match your mail server's requirements. Authentication errors mean a wrong username or password. The full error is printed on the line after `FAILED`. Use `--dry-run` to skip the SMTP test while debugging other parts of the workflow.

**`abuse_email` shows `UNKNOWN` for an IP**
The WHOIS data for that IP did not contain a recognizable abuse contact. You can manually edit `reports/<prefix>_full.csv` before re-running with `--skip-lookup`, or answer `N` at the prompt to skip that IP.

**Send fails with "not a valid email address"**
The abuse contact returned by WHOIS failed basic validation (likely garbage data or a placeholder). Edit the `abuse_email` field in the full CSV and re-run with `--skip-lookup`.

**Script exits immediately with "Nothing to report"**
All IPs in the report are within the cooldown window. Check `reports/Report_History.csv` to confirm, or manually remove rows if you need to re-report an IP sooner.

**`dig` not found**
Install `bind-utils` (RHEL/CentOS) or `dnsutils` (Debian/Ubuntu). The script falls back to Python's `socket.gethostbyaddr()` automatically if `dig` is unavailable, so this is not fatal.
