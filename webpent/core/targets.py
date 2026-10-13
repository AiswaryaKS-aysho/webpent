from dataclasses import dataclass
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


@dataclass
class Target:
    url: str
    method: str = "GET"
    data: dict[str, str] | None = None

    @property
    def params(self) -> dict[str, str]:
        return dict(parse_qsl(urlparse(self.url).query, keep_blank_values=True))

    @property
    def has_query_params(self) -> bool:
        return bool(self.params)


def replace_query_param(url: str, key: str, value: str) -> str:
    parts = urlparse(url)
    q = [(k, value if k == key else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if key not in dict(q):
        q.append((key, value))
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


def replace_body_param(data: dict[str, str], key: str, value: str) -> dict[str, str]:
    out = dict(data)
    out[key] = value
    return out
