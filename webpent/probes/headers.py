from ..core.models import Finding, Severity
from ..core.targets import Target
from .base import BaseProbe

# header -> (severity, recommendation)
SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Deploy a Content-Security-Policy to mitigate XSS and data injection.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Set 'X-Frame-Options: DENY' (or use CSP frame-ancestors) to prevent clickjacking.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Set 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Set 'Permissions-Policy' to disable unused browser features.",
    ),
}

COOKIE_FLAGS = [
    ("httponly", Severity.MEDIUM, "Set the HttpOnly flag on session cookies."),
    ("secure", Severity.MEDIUM, "Set the Secure flag on session cookies."),
    ("samesite", Severity.LOW, "Set SameSite=Lax or Strict on session cookies."),
]


class HeaderProbe(BaseProbe):
    name = "headers"
    description = "Missing security headers and insecure cookie attributes"

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = self.client.request(target.method, target.url, data=target.data)
        except Exception as e:
            return [
                self.finding(
                    probe=self.name,
                    severity=Severity.INFO,
                    title="Request failed",
                    url=target.url,
                    evidence=str(e),
                    confidence="high",
                )
            ]

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for hdr, (sev, fix) in SECURITY_HEADERS.items():
            if hdr not in headers:
                findings.append(
                    self.finding(
                        probe=self.name,
                        severity=sev,
                        title=f"Missing security header: {hdr}",
                        url=target.url,
                        evidence=f"Response {resp.status_code} lacks '{hdr}' header",
                        remediation=fix,
                        confidence="high",
                    )
                )

        if "server" in headers:
            findings.append(
                self.finding(
                    probe=self.name,
                    severity=Severity.INFO,
                    title="Server version disclosure",
                    url=target.url,
                    evidence=f"Server: {headers['server']}",
                    remediation="Remove or genericize the Server header.",
                    confidence="high",
                )
            )

        set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        if not set_cookies and "set-cookie" in headers:
            set_cookies = [headers["set-cookie"]]

        for cookie in set_cookies:
            low = cookie.lower()
            if "session" not in low and "auth" not in low and "token" not in low and "sid" not in low:
                continue
            name = cookie.split("=", 1)[0]
            for flag, sev, fix in COOKIE_FLAGS:
                if flag == "samesite":
                    if "samesite" not in low:
                        findings.append(
                            self.finding(
                                probe=self.name,
                                severity=sev,
                                title=f"Cookie '{name}' missing SameSite attribute",
                                url=target.url,
                                evidence=cookie.split(";")[0],
                                remediation=fix,
                                confidence="high",
                            )
                        )
                elif flag not in low:
                    findings.append(
                        self.finding(
                            probe=self.name,
                            severity=sev,
                            title=f"Cookie '{name}' missing {flag} flag",
                            url=target.url,
                            evidence=cookie.split(";")[0],
                            remediation=fix,
                            confidence="high",
                        )
                    )
        return findings
