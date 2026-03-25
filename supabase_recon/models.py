from dataclasses import dataclass, field, asdict
from datetime import datetime


SEVERITY: dict[str, str] = {
    "jwt_key":       "HIGH",
    "inline_config": "MEDIUM",
    "header":        "LOW",
    "supabase_url":  "INFO",
    "create_client": "INFO",
}


@dataclass
class Finding:
    type: str       # jwt_key | supabase_url | create_client | inline_config | header
    value: str
    source: str     # URL where this was found
    context: str = ""

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.type, "INFO")


@dataclass
class TargetResult:
    target: str
    scanned_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    reachable: bool = False
    supabase_detected: bool = False
    js_files_scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Populated only in deep mode
    deep_scan: dict | None = field(default=None)

    def add_finding(self, ftype: str, value: str, source: str, context: str = "") -> None:
        self.findings.append(Finding(ftype, value, source, context))
        self.supabase_detected = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d