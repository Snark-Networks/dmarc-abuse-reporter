# AGENTS.md — Context for AI Assistants

This file describes the project, its conventions, and guidance for any AI assistant (Claude or otherwise) working in this repository in future sessions.

---

## Project Overview

This is a single-script Python tool (`dmarc_reporter.py`) that automates the abuse-reporting workflow for DMARC failures. It:

1. Parses three DMARC aggregate report CSV exports (source, SPF, DKIM)
2. Correlates them by source IP
3. Performs WHOIS and reverse-DNS lookups for each source IP
4. Writes a correlated full report CSV
5. Cross-references a persistent report history to enforce a 30-day cooldown per IP
6. Presents each eligible IP interactively and sends one plain-text abuse email per IP on confirmation

The operator is **Chris Hesselrode** at **Snark Networks / Snark Holding Corp. (AS62787)**. The abuse contact is `abuse@snarknetworks.com`.

---

## Repository Layout

```
dmarc-abuse-reporter/
├── dmarc_reporter.py       ← the entire tool; all logic lives here
├── email_template.txt      ← abuse email subject + body; edit freely, no script changes needed
├── requirements.txt        ← pip dependencies (ipwhois>=1.3.0)
├── LICENSE                 ← MIT
├── .config.example         ← committed template; copy to .config to use
├── .config                 ← NOT committed (in .gitignore); real credentials + identity
├── .gitignore
├── README.md               ← user-facing documentation
├── AGENTS.md               ← this file
└── reports/                ← runtime data directory; *.csv files are gitignored
    ├── .instructions       ← committed; explains the directory contents
    ├── <prefix>_source.csv
    ├── <prefix>_spf.csv
    ├── <prefix>_dkim.csv
    ├── <prefix>_full.csv
    └── Report_History.csv
```

There is no package structure, no tests directory, and no build system. Keep it that way unless the operator explicitly asks to expand scope.

---

## Key Design Decisions

**Single-file, no framework.** All logic (correlation, WHOIS, email, CSV I/O) is in one script. Do not split into modules or add a `setup.py` / `pyproject.toml` unless asked.

**One third-party dependency.** Only `ipwhois` (PyPI) is required. Do not introduce additional dependencies without being asked.

**WHOIS lookup strategy — three tiers.** `get_whois_info()` tries in order:
1. `ipwhois` RDAP (structured JSON, handles RIR routing automatically)
2. Direct query to the detected RIR's whois server (`whois.arin.net`, `whois.ripe.net`, etc.)
3. Plain system `whois` command as a last resort

Do not collapse or reorder this strategy. The tiered approach is intentional — RDAP is most reliable but some networks only respond to legacy whois.

**One email per abuse contact.** All eligible IPs that share the same `abuse_email` are combined into a single consolidated report, regardless of how many base domains those IPs span. This means a provider whose IPs appear under several different rDNS base domains receives exactly one email per run.

**History is updated only on successful send.** A user answering N at the prompt does not update `Report_History.csv`. The IP will reappear on the next run. This is correct behavior.

**History writes are atomic.** `save_history()` writes to `Report_History.tmp` then calls `Path.replace()` (atomic on POSIX, best-effort on Windows). This prevents a truncated history file if the process is killed mid-write.

**Multi-valued CSV fields are pipe-separated (`|`).** `envelope_senders`, `spf_results`, `dkim_domains`, `dkim_results`, and `header_from` (when an IP spoofs multiple domains) are stored as `|`-delimited strings in the full CSV. The `format_email()` function splits on `|` before rendering the template. `envelope_senders` uses a `domain:count` encoding (e.g. `spammer.net:142|other.com:7`) so per-sender message counts are preserved; `format_email()` parses these, sorts by count descending, and renders each as `"  - domain (N messages)"` in the email body.

**`header_from` in the email template uses the first domain alphabetically** when multiple are present for one IP. This is a simplification; a future enhancement could send separate emails per domain.

**Credentials and identity live in `.config`, not the script.** `load_config()` reads the INI file (sections: `[smtp]`, `[reporter]`, `[ignore]`) at the start of `main()` and returns a `cfg` dict passed to `send_email()` and `format_email()`. `[smtp]` fields: `host`, `port`, `use_starttls`, `use_ssl`, `username`, `password`, `sender_name`, `sender_email`. `[reporter]` fields: `reporter_name`, `reporter_email`, `reporter_org`. The `SMTP_PASSWORD` environment variable overrides the password field. The sentinel check `password != "YOUR_PASSWORD_HERE"` skips auth if the example value was left unchanged.

**`.config` permissions are enforced on POSIX.** `load_config()` checks `st_mode & 0o077`; if any group or other bits are set it prints a `chmod 600` reminder and exits. This check is skipped on Windows (`os.name != "posix"`).

**All values placed in RFC2822 headers are sanitized.** `_sanitize_header()` strips `\r` and `\n` before any value is assigned to `msg["To"]`, `msg["From"]`, or `msg["Subject"]`. `send_email()` additionally calls `_is_valid_email()` on the `To` address and returns an error tuple (rather than attempting the send) if it fails.

**Correlation joins on `Base Domain` / `Reverse DNS Base`, not on IP.** The SPF and DKIM CSV exports contain no IP address column; the join key is `source["Base Domain"]` matched against `spf["Reverse DNS Base"]` and `dkim["Reverse DNS Base"]`. `header_from` (the spoofed domain) is extracted from SPF/DKIM rows, not from the source file. `country` is carried from the source file. A live rDNS lookup is still performed for each IP even though `_source.csv` includes a `Reverse DNS` column, because PTR records can change.

**`date_prefix` is validated against a strict allowlist.** `validate_date_prefix()` accepts only `[A-Za-z0-9_\-]+`. This prevents path traversal (e.g. `../../etc/passwd`) via the argument that is interpolated into file paths.

**SMTP is tested at startup, before the lookup phase.** `test_smtp_connection()` connects, optionally authenticates, and immediately quits. This surfaces credential problems before the WHOIS lookups and confirmation prompts begin. The test is skipped in `--dry-run` mode.

**`--dry-run` flag.** When set, the script runs the full workflow (lookups, CSV write, confirmation prompts, email preview) but skips `srv.sendmail()`, does not update `Report_History.csv`, and labels all output with `[DRY RUN]`. History is also not saved on `Ctrl-C` in this mode.

**`reports/*.csv` files are gitignored.** Report files may contain sensitive IP, WHOIS, and abuse-contact data. Only `reports/.instructions` is committed. The `reports/` directory itself is created automatically by the script.

---

## Configuration Locations

**All credentials, identity, and ignore rules** — `.config` (INI format, three sections). Gitignored, never committed. `.config.example` is the committed template. Edit `.config` only; do not put credentials or identity back into the script.

`[smtp]` fields:

| Key | Purpose |
|-----|---------|
| `host`, `port`, `use_starttls`, `use_ssl` | Mail server connection |
| `username`, `password` | SMTP auth (`SMTP_PASSWORD` env var overrides `password`) |
| `sender_name` | Display name in the outgoing `From:` header |
| `sender_email` | SMTP envelope From address |

`[reporter]` fields (appear in the email body and signature):

| Key | Purpose |
|-----|---------|
| `name` | Maps to `{reporter_name}` in the email template |
| `email` | Maps to `{contact_email}` in the email template |
| `org` | Maps to `{org_name}` in the email template |

`[ignore]` fields:

| Key | Purpose |
|-----|---------|
| `prefixes` | Multi-line list of CIDR prefixes (IPv4 or IPv6) to exclude from all reports |

**All other settings** — `CONFIGURATION` section of `dmarc_reporter.py`:

- `REPORTS_DIR` — defaults to `"reports"`
- `SOURCE_COLS`, `SPF_COLS`, `DKIM_COLS` — CSV column name mappings
- `REPORT_COOLDOWN_DAYS` — default 30
- `WHOIS_DELAY` — default 2.0 seconds

---

## Email Template

The template lives in `email_template.txt` (project root, committed to version control). It is loaded once at startup by `load_email_template()` and the resulting `(subject_tmpl, body_tmpl)` tuple is passed as arguments to `format_email()`.

**File format:** first line = subject, one blank line separator, remaining lines = body. The script exits with an error if the file is missing or the blank-line separator is absent.

**Placeholders** — standard Python `.format()` keys passed via `**values` in `format_email()`:

| Placeholder | Source |
|-------------|--------|
| `{header_from}` | First (alphabetically) domain in `group["header_from"]` |
| `{ip_list}` | Formatted bulleted list of IPs with rDNS and per-IP counts, built in `format_email()` |
| `{envelope_senders}` | Formatted bulleted list of envelope-from domains (domain names only, no counts) |
| `{reporter_name}` | `cfg["reporter_name"]` from `.config` `[reporter]` `name` |
| `{org_name}` | `cfg["reporter_org"]` from `.config` `[reporter]` `org` |
| `{contact_email}` | `cfg["reporter_email"]` from `.config` `[reporter]` `email` |

`format_email()` now receives a consolidated `group` dict (not a single CSV row). The group has an `ip_entries` list of `{source_ip, reverse_dns, message_count}` dicts used to build `{ip_list}`. To change wording, edit `email_template.txt` only. To change reporter identity, edit `.config` only. Do not rename or remove any placeholder without also updating `format_email()`.

---

## Report History Format

`reports/Report_History.csv` has exactly two columns:

```
source_ip,last_reported_date
```

Dates are stored as `YYYY-MM-DD`. The file is read by `load_history()` and written by `save_history()`. Do not add columns to this file without updating both functions and the `DictWriter` fieldnames list.

---

## Common Tasks

**Operator wants to change SMTP settings or reporter identity**
Edit `.config`. SMTP connection/auth fields are in `[smtp]`; reporter name, email, and org are in `[reporter]`. Do not put credentials or identity fields back into the script. Remember to run `chmod 600 .config` after editing.

**Operator wants to exclude specific IPs or networks from reports**
Add CIDR prefixes to the `prefixes` key under `[ignore]` in `.config`, one per line (indented). A `/32` or bare IPv4 address excludes a single host; `/24` excludes a /24 block. IPv6 works the same way.

**Operator wants to test the workflow without sending real emails**
Run with `--dry-run`. All lookups, CSV output, prompts, and email previews behave normally; only the actual `sendmail` call and history update are suppressed.

**Operator wants to change the cooldown period**
Edit `REPORT_COOLDOWN_DAYS` in the configuration block.

**Operator wants to adjust the email body or subject**
Edit `email_template.txt`. No script changes needed. The first line is the subject; everything after the first blank line is the body. Keep all six `{placeholder}` names intact, or update `format_email()` accordingly.

**Operator's DMARC tool uses different CSV column names**
Update the right-hand values in `SOURCE_COLS`, `SPF_COLS`, and/or `DKIM_COLS`. The left-hand keys are internal names used by the script and must not change. The join is on `source["Base Domain"]` == `spf/dkim["Reverse DNS Base"]`; if those column names change, update both `SOURCE_COLS["base_domain"]` and `SPF_COLS["reverse_dns_base"]` / `DKIM_COLS["reverse_dns_base"]` together.

**An IP's abuse contact was not found (shows UNKNOWN) or fails the email validation check**
The operator can manually edit the `abuse_email` field in `_full.csv` and re-run with `--skip-lookup`. Alternatively, extend `_parse_abuse_email()` to handle a new whois field pattern for the specific RIR.

**Operator wants to add a new RIR**
Add an entry to the `RIR_WHOIS` dict (key = lowercase RIR name, value = whois hostname). The RDAP tier via `ipwhois` handles routing automatically, so this only affects the tier-2 direct fallback.

**Operator wants to send HTML email instead of plain text**
In `send_email()`, change `MIMEText(body, "plain", "utf-8")` to `MIMEText(html_body, "html", "utf-8")` and add a corresponding HTML rendering step in `format_email()`.

---

## What Not to Do

- Do not add a database, ORM, or message queue. CSV files are the intentional persistence layer.
- Do not add async/await. WHOIS queries are rate-limited by design; concurrency would defeat that.
- Do not add a web UI or REST API. This is a CLI tool run manually by the operator.
- Do not rename or reorder the `FULL_CSV_FIELDS` list without also updating every place that writes or reads the full CSV: `build_full_report()` (builds the row dicts, currently includes `country` and `base_domain`), the inline `csv.DictWriter` block in `main()` (writes the file), the consolidation grouping in `main()` (reads `base_domain`), and the `--skip-lookup` reload path (reads the CSV back into dicts).
- Do not add retries with exponential backoff to WHOIS without operator approval — hammering RIR servers risks IP-level rate limiting.
- Do not weaken the input validation in `validate_date_prefix()` or the header sanitization in `_sanitize_header()` / `_is_valid_email()` without operator approval.
- Do not remove the `.config` permissions check — it is a deliberate security gate, not defensive boilerplate.
- Do not move `reporter_name`, `org_name`, or `contact_email` back into the script or template as hardcoded values — they belong in `.config` `[reporter]`.
