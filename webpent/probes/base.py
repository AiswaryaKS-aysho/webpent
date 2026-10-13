from ..core.models import Finding, Severity
from ..core.targets import Target


class BaseProbe:
    name = "base"
    description = ""

    def __init__(self, client):
        self.client = client

    def run(self, target: Target) -> list[Finding]:
        raise NotImplementedError

    @staticmethod
    def finding(**kw) -> Finding:
        return Finding(**kw)
