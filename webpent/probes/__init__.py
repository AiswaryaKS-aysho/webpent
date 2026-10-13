from .headers import HeaderProbe
from .redirect import RedirectProbe
from .sqli import SqliProbe
from .ssrf import SsrfProbe
from .xss import XssProbe

ALL_PROBES = {
    "headers": HeaderProbe,
    "xss": XssProbe,
    "sqli": SqliProbe,
    "ssrf": SsrfProbe,
    "redirect": RedirectProbe,
}
