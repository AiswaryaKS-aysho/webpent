import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_UA = "webpent/0.1 (authorized-security-testing)"


class HttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.0,
        verify: bool = True,
        user_agent: str = DEFAULT_UA,
        proxies: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ):
        self.timeout = timeout
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({"User-Agent": user_agent})
        if cookies:
            self.session.cookies.update(cookies)
        if proxies:
            self.session.proxies.update(proxies)
        self._verify = verify

    def request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        allow_redirects: bool | None = None,
    ) -> requests.Response:
        if self.delay:
            time.sleep(self.delay)
        if allow_redirects is None:
            allow_redirects = self.follow_redirects
        return self.session.request(
            method.upper(),
            url,
            params=params,
            data=data,
            timeout=self.timeout,
            verify=self._verify,
            allow_redirects=allow_redirects,
        )

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)
