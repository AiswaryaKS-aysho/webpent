#!/usr/bin/env python3
"""webpent — web application pentest helper CLI."""
import argparse
import logging
import sys
from datetime import datetime, timezone

from . import __version__
from .core.http import HttpClient
from .core.models import ScanResult
from .core.targets import Target
from .probes import ALL_PROBES
from .report import print_summary, write_json, write_markdown

log = logging.getLogger("webpent")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webpent",
        description="Web application pentest helper — XSS/SQLi/SSRF/redirect/header probes with JSON & Markdown reports.",
        epilog="Only test systems you are authorized to assess.",
    )
    p.add_argument("url", help="Target URL (include query params to test them)")
    p.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    p.add_argument("-d", "--data", help="POST body as key=value&key2=value2 (implies --method POST)")
    p.add_argument("--probes", default="all", help=f"Comma-separated probe list or 'all' ({','.join(ALL_PROBES)})")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests seconds (default: 0)")
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--cookie", help="Cookie header value, e.g. 'sid=abc; token=xyz'")
    p.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--user-agent", help="Custom User-Agent")
    p.add_argument("--json", dest="json_out", metavar="PATH", help="Write JSON report to PATH")
    p.add_argument("--md", dest="md_out", metavar="PATH", help="Write Markdown report to PATH")
    p.add_argument("-o", "--output", metavar="PREFIX", help="Write PREFIX.json and PREFIX.md")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--version", action="version", version=f"webpent {__version__}")
    return p


def parse_cookies(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    out = {}
    for pair in raw.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def select_probes(spec: str) -> list[str]:
    if spec.strip().lower() == "all":
        return list(ALL_PROBES)
    wanted = [s.strip() for s in spec.split(",") if s.strip()]
    unknown = [w for w in wanted if w not in ALL_PROBES]
    if unknown:
        raise SystemExit(f"Unknown probe(s): {', '.join(unknown)}. Available: {', '.join(ALL_PROBES)}")
    return wanted


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    method = args.method
    data = None
    if args.data:
        data = dict(kv.split("=", 1) for kv in args.data.split("&") if "=" in kv)
        method = "POST"

    target = Target(url=args.url, method=method, data=data)
    if not target.params and method == "GET" and not data:
        log.warning("No query parameters found — only non-parameter probes (headers) will have input.")

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    ua_kwargs = {"user_agent": args.user_agent} if args.user_agent else {}

    client = HttpClient(
        timeout=args.timeout,
        delay=args.delay,
        verify=not args.insecure,
        proxies=proxies,
        cookies=parse_cookies(args.cookie),
        **ua_kwargs,
    )

    probe_names = select_probes(args.probes)
    result = ScanResult(
        target=target.url,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        probes_run=probe_names,
    )

    for name in probe_names:
        probe = ALL_PROBES[name](client)
        log.info("Running probe: %s (%s)", name, probe.description)
        try:
            findings = probe.run(target)
            result.findings.extend(findings)
            log.info("  -> %d finding(s)", len(findings))
        except Exception as e:
            result.errors.append(f"{name}: {e}")
            log.error("  probe %s failed: %s", name, e)

    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if args.output:
        args.json_out = args.json_out or f"{args.output}.json"
        args.md_out = args.md_out or f"{args.output}.md"

    if args.json_out:
        write_json(result, args.json_out)
        log.info("JSON report: %s", args.json_out)
    if args.md_out:
        write_markdown(result, args.md_out)
        log.info("Markdown report: %s", args.md_out)

    print_summary(result)
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
