import re
from urllib.parse import urlparse

from ..core.models import Finding, Severity
from ..core.targets import Target, replace_query_param, replace_body_param
from .base import BaseProbe

REDIRECT_PARAMS = re.compile(r"(redir|redirect|next|return|returnurl|return_url|goto|dest|destination|continue|url|target|callback|back|forward|rurl|u)", re.I)

CANARY = "webpent-canary.invalid"
EXTERNAL = f"https://{CANARY}/out"


class RedirectProbe(BaseProbe):
    name = "redirect"
    description = "Open redirect via URL/return parameters"

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        params = list(target.params.keys())
        if target.data:
            params += [k for k in target.data if k not in params]

        for param in params:
            if not REDIRECT_PARAMS.search(param):
                continue
            try:
                if target.data is not None and param in target.data:
                    resp = self.client.request(
                        target.method,
                        target.url,
                        data=replace_body_param(target.data, param, EXTERNAL),
                        allow_redirects=False,
                    )
                else:
                    resp = self.client.request(
                        target.method,
                        replace_query_param(target.url, param, EXTERNAL),
                        data=target.data,
                        allow_redirects=False,
                    )
            except Exception:
                continue

            loc = resp.headers.get("Location", "")
            if not loc:
                continue

            host = urlparse(loc).netloc
            if CANARY in loc or (host and CANARY not in urlparse(target.url).netloc and CANARY in host):
                findings.append(
                    self.finding(
                        probe=self.name,
                        severity=Severity.MEDIUM,
                        title=f"Open redirect in parameter '{param}'",
                        url=target.url,
                        param=param,
                        payload=EXTERNAL,
                        evidence=f"HTTP {resp.status_code} Location: {loc}",
                        remediation="Allowlist redirect destinations or validate against a relative-path pattern.",
                        confidence="high",
                    )
                )
        return findings
