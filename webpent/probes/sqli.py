import re
import uuid

from ..core.models import Finding, Severity
from ..core.targets import Target, replace_query_param, replace_body_param
from .base import BaseProbe

ERROR_SIGNATURES = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"warning.*mysql_", re.I), "MySQL"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"microsoft ole db provider for odbc drivers", re.I), "MSSQL"),
    (re.compile(r"pg_query\(|pg_exec\(|PostgreSQL.*ERROR", re.I), "PostgreSQL"),
    (re.compile(r"ORA-\d{5}", re.I), "Oracle"),
    (re.compile(r"sqlite3\.OperationalError|SQLite/JDBCDriver|unrecognized token", re.I), "SQLite"),
    (re.compile(r"SQLSTATE\[", re.I), "Generic PDO"),
    (re.compile(r"javax\.servlet\.SQLException|java\.sql\.SQLException", re.I), "Java/SQL"),
]

QUOTES = ["'", "\"", "')", "\"')", "1'", "1'--", "1' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]

BOOL_TRUE_TOKEN = uuid.uuid4().hex[:8]
BOOL_FALSE_TOKEN = uuid.uuid4().hex[:8]


class SqliProbe(BaseProbe):
    name = "sqli"
    description = "SQL injection via error-based and boolean-discrepancy detection"

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        params = list(target.params.keys())
        if target.data:
            params += [k for k in target.data if k not in params]

        for param in params:
            finding = self._error_based(target, param)
            if finding:
                findings.append(finding)
                continue
            finding = self._boolean_based(target, param)
            if finding:
                findings.append(finding)
        return findings

    def _send(self, target: Target, param: str, value: str):
        if target.data is not None and param in target.data:
            return self.client.request(
                target.method, target.url, data=replace_body_param(target.data, param, value)
            )
        return self.client.request(
            target.method, replace_query_param(target.url, param, value), data=target.data
        )

    def _error_based(self, target: Target, param: str) -> Finding | None:
        try:
            baseline = self.client.request(target.method, target.url, data=target.data)
        except Exception:
            return None
        base_len = len(baseline.text or "")

        for payload in QUOTES:
            try:
                resp = self._send(target, param, payload)
            except Exception:
                continue
            text = resp.text or ""
            if abs(len(text) - base_len) < 10:
                continue
            for regex, dbms in ERROR_SIGNATURES:
                m = regex.search(text)
                if m:
                    return self.finding(
                        probe=self.name,
                        severity=Severity.CRITICAL,
                        title=f"SQL injection (error-based) in parameter '{param}'",
                        url=target.url,
                        param=param,
                        payload=payload,
                        evidence=f"{dbms} error reflected: {m.group(0)[:160]}",
                        remediation="Use parameterized queries / prepared statements; never concatenate user input into SQL.",
                        confidence="high",
                        extra={"dbms": dbms},
                    )
        return None

    def _boolean_based(self, target: Target, param: str) -> Finding | None:
        try:
            true_payload = f"1 AND 1=1 /*{BOOL_TRUE_TOKEN}*/"
            false_payload = f"1 AND 1=2 /*{BOOL_FALSE_TOKEN}*/"
            rt = self._send(target, param, true_payload)
            rf = self._send(target, param, false_payload)
        except Exception:
            return None

        t, f = rt.text or "", rf.text or ""
        if not t or not f or t == f:
            return None
        if abs(len(t) - len(f)) < max(20, int(0.05 * len(t))):
            return None

        return self.finding(
            probe=self.name,
            severity=Severity.HIGH,
            title=f"Possible boolean-based SQL injection in parameter '{param}'",
            url=target.url,
            param=param,
            payload=true_payload,
            evidence=(
                f"TRUE response ({len(t)} bytes) differs from FALSE response ({len(f)} bytes) "
                f"under tautology/contradiction payloads — differential content suggests query logic is attacker-influenced"
            ),
            remediation="Use parameterized queries / prepared statements; never concatenate user input into SQL.",
            confidence="medium",
            extra={"true_len": len(t), "false_len": len(f)},
        )
