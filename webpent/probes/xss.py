import re
import uuid

from ..core.models import Finding, Severity
from ..core.targets import Target, replace_query_param, replace_body_param
from .base import BaseProbe

XSS_PAYLOADS = [
    '"><wgpt{c}x>',
    "'><wgpt{c}x>",
    "<wgpt{c}x>",
    "\" onfocus=wgpt{c} autofocus=\"",
]

REFLECTED_RE = re.compile(r"wgpt[0-9a-f]{8}x?")


class XssProbe(BaseProbe):
    name = "xss"
    description = "Reflected cross-site scripting via unencoded parameter reflection"

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        params = list(target.params.keys())
        if target.data:
            params += [k for k in target.data if k not in params]

        for param in params:
            canary = uuid.uuid4().hex[:8]
            marker = f"wgpt{canary}x"
            payloads = [p.format(c=canary) for p in XSS_PAYLOADS]

            for payload in payloads:
                try:
                    body = target.data
                    if body is not None and param in body:
                        url, body = target.url, replace_body_param(body, param, payload)
                        resp = self.client.request(target.method, url, data=body)
                    else:
                        url = replace_query_param(target.url, param, payload)
                        resp = self.client.request(target.method, url, data=target.data)
                except Exception:
                    continue

                text = resp.text or ""
                if not REFLECTED_RE.search(text):
                    continue

                # encoded anywhere? raw hit means no output encoding
                raw_hit = marker in text or payload in text
                if raw_hit:
                    findings.append(
                        self.finding(
                            probe=self.name,
                            severity=Severity.HIGH,
                            title=f"Reflected XSS in parameter '{param}'",
                            url=target.url,
                            param=param,
                            payload=payload,
                            evidence=f"Payload reflected unencoded in HTTP {resp.status_code} response (marker: {canary})",
                            remediation="Context-aware output encoding (HTML/JS/attr) or a strict CSP.",
                            confidence="high",
                            extra={"marker": canary, "response_len": len(text)},
                        )
                    )
                    break
        return findings
