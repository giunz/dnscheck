"""DNS and HTTP scanner for bulk domain analysis.

This script reads a list of domains from ``input.csv`` (or a custom path) and
performs DNS lookups plus HTTP/HTTPS checks. It records resource records (A,
CNAME, MX, SOA), status codes, and attempts to identify WAF/CDN/cloud hosting
providers based on response headers, cookies, and hostname patterns. Results
are written to ``output.csv`` and detailed log entries are stored in
``scan_log.txt``.

You can also scan a single domain with ``--domain example.com`` to quickly
inspect cloud and DNS ownership (e.g., SOA values like
``azuredns-hostmaster.microsoft.com``).
"""

from __future__ import annotations

import argparse
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List

import dns.resolver
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright
import pandas as pd
import requests
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# Input/Output files
DEFAULT_INPUT = "input.csv"
DEFAULT_OUTPUT = "output.csv"

# Use Cloudflare DNS
resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"]
resolver.lifetime = 3

# Realistic headers for human-like behavior
headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
}

# WAF signatures
WAF_SIGNATURES: Dict[str, List[str] | str] = {
    "X-Sucuri-ID": "Sucuri",
    "X-CDN": "Akamai",
    "X-Akamai": "Akamai",
    "X-Cloudflare": "Cloudflare",
    "X-WAF": "Generic WAF",
    "X-Mod-Security": "ModSecurity",
    "Server": ["ModSecurity", "Barracuda", "F5 BIG-IP", "Imperva", "Incapsula"],
}

# WAF detection via cookies
WAF_COOKIE_PATTERNS = {
    "visid_incap": "Imperva/Incapsula",
    "incap_ses": "Imperva/Incapsula",
    "cfduid": "Cloudflare",
    "sucuri_cloudproxy": "Sucuri",
}

# CDN patterns
CDN_PATTERNS = {
    "impervadns.net": "Imperva CDN",
    "cloudflare.net": "Cloudflare CDN",
    "akamai.net": "Akamai CDN",
    "edgekey.net": "Akamai CDN",
    "fastly.net": "Fastly CDN",
}

# Cloud provider patterns
CLOUD_PATTERNS = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS",
    "azure.com": "Azure",
    "azure-dns.com": "Azure",
    "microsoft.com": "Azure",
    "azuredns-hostmaster.microsoft.com": "Azure",
    "azurewebsites.net": "Azure",
    "azurefd.net": "Azure",
    "azureedge.net": "Azure",
    "trafficmanager.net": "Azure",
    "cloudapp.net": "Azure",
    "windows.net": "Azure",
    "googleusercontent.com": "GCP",
    "googleapis.com": "GCP",
}

AZURE_HTTP_SIGNATURES = {
    "x-azure-ref": "Azure",
    "x-msedge-ref": "Azure",
    "x-ms-request-id": "Azure",
    "x-azure-socketextn": "Azure",
    "x-azure-fdid": "Azure",
}

AZURE_COOKIE_PATTERNS = {
    "arraffinity": "Azure",
    "arraffinitysame": "Azure",
    "afd-session": "Azure",
    "afd-state": "Azure",
    "x-ms-routing-name": "Azure",
}


def get_dns_records(domain: str) -> Dict[str, List[str] | str]:
    logging.info(f"[DNS] Checking DNS records for {domain}")
    records: Dict[str, List[str] | str] = {"A": [], "CNAME": [], "MX": [], "SOA": ""}

    try:
        # Follow full CNAME chain
        current_domain = domain
        while True:
            try:
                cname_records = resolver.resolve(current_domain, "CNAME")
                cname_target = cname_records[0].target.to_text()
                records["CNAME"].append(cname_target)
                current_domain = cname_target
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
            except Exception:
                break

        # A records for final domain
        try:
            a_records = resolver.resolve(current_domain, "A")
            records["A"] = [r.address for r in a_records]
        except Exception:
            pass
    except Exception:
        pass

    try:
        mx_records = resolver.resolve(domain, "MX")
        records["MX"] = [r.exchange.to_text() for r in mx_records]
    except Exception:
        pass

    try:
        soa_record = resolver.resolve(domain, "SOA")
        records["SOA"] = soa_record[0].mname.to_text()
    except Exception:
        pass

    # Ensure defaults if empty
    if not records["A"]:
        records["A"] = ["Not Found"]
    if not records["CNAME"]:
        records["CNAME"] = ["Not Found"]
    if not records["MX"]:
        records["MX"] = ["Not Found"]
    if not records["SOA"]:
        records["SOA"] = "Not Found"

    return records


def check_http(domain: str, protocol: str = "http"):
    url = f"{protocol}://{domain}"
    logging.info(f"[HTTP] Checking {protocol.upper()} for {domain}")
    try:
        session = requests.Session()
        session.headers.update(headers)
        response = session.get(url, timeout=10, allow_redirects=True)
        normalized_headers = {k.lower(): v for k, v in response.headers.items()}
        normalized_cookies = {k.lower(): v for k, v in session.cookies.get_dict().items()}
        return response.status_code, normalized_headers, normalized_cookies, str(response.url)
    except requests.exceptions.RequestException:
        return "Error", {}, {}, url


def check_with_playwright(domain: str) -> Dict[str, str | int]:
    logging.info(f"[Playwright] Checking site existence for {domain}")
    result: Dict[str, str | int] = {
        "Playwright_Status": "Not Checked",
        "Playwright_Protocol": "",
        "Playwright_Title": "",
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            for protocol in ("https", "http"):
                url = f"{protocol}://{domain}"
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=8000)
                    result["Playwright_Status"] = response.status if response else "No Response"
                    result["Playwright_Protocol"] = protocol
                    result["Playwright_Title"] = page.title()
                    logging.info(
                        f"[Playwright] {domain} reachable via {protocol.upper()} (status: {result['Playwright_Status']})"
                    )
                    break
                except PlaywrightTimeoutError:
                    logging.warning(f"[Playwright] Timeout reaching {url}")
                except Exception as exc:
                    logging.warning(f"[Playwright] Error reaching {url}: {exc}")

            browser.close()
    except Exception as exc:
        logging.warning(f"[Playwright] Failed to launch browser for {domain}: {exc}")
        result["Playwright_Status"] = "Playwright Error"

    if result["Playwright_Status"] == "Not Checked":
        result["Playwright_Status"] = "Unreachable"
    return result


def detect_waf(headers_dict: Dict[str, str], cookies: Dict[str, str]) -> str:
    normalized_headers = {k.lower(): v for k, v in headers_dict.items()}
    for key, value in WAF_SIGNATURES.items():
        header_key = key.lower()
        if header_key in normalized_headers:
            if isinstance(value, list):
                for v in value:
                    if v.lower() in normalized_headers[header_key].lower():
                        return v
            else:
                return value

    for cookie_name in cookies.keys():
        for pattern, waf_name in WAF_COOKIE_PATTERNS.items():
            if pattern in cookie_name.lower():
                return waf_name
    return "None"


def detect_cdn(cname_list: Iterable[str]) -> str:
    for cname in cname_list:
        for pattern, cdn_name in CDN_PATTERNS.items():
            if pattern in cname.lower():
                return cdn_name
    return "None"


def detect_cloud(
    records: Dict[str, List[str] | str], http_signals: Dict[str, Dict[str, str] | List[str]] | None = None
) -> str:
    soa_value = str(records["SOA"]).lower()
    for pattern, provider in CLOUD_PATTERNS.items():
        if pattern in soa_value:
            return provider

    for cname in records["CNAME"]:
        for pattern, provider in CLOUD_PATTERNS.items():
            if pattern in cname.lower():
                return provider

    for ip in records["A"]:
        try:
            host = socket.gethostbyaddr(ip)[0]
            for pattern, provider in CLOUD_PATTERNS.items():
                if pattern in host.lower():
                    return provider
        except Exception:
            continue

    http_signals = http_signals or {}
    merged_headers = {k.lower(): v for k, v in http_signals.get("headers", {}).items()}
    merged_cookies = {k.lower(): v for k, v in http_signals.get("cookies", {}).items()}
    visited_urls = [u.lower() for u in http_signals.get("urls", []) if u]

    for url in visited_urls:
        for pattern, provider in CLOUD_PATTERNS.items():
            if pattern in url:
                return provider

    for header_name, provider in AZURE_HTTP_SIGNATURES.items():
        if header_name in merged_headers:
            return provider

    for cookie_name in merged_cookies.keys():
        for pattern, provider in AZURE_COOKIE_PATTERNS.items():
            if pattern in cookie_name:
                return provider

    server_header = merged_headers.get("server", "")
    if server_header and "envoy" in server_header.lower():
        return "Azure"

    return "None"


def process_domain(row: pd.Series) -> Dict[str, str]:
    domain = row["URLs"]
    logging.info(f"--- Processing {domain} ---")
    dns_info = get_dns_records(domain)
    http_status, http_headers, http_cookies, http_url = check_http(domain, "http")
    https_status, https_headers, https_cookies, https_url = check_http(domain, "https")
    playwright_result = check_with_playwright(domain)

    waf_detect = detect_waf({**http_headers, **https_headers}, {**http_cookies, **https_cookies})
    cdn_detect = detect_cdn(dns_info["CNAME"])
    cloud_hosting = detect_cloud(
        dns_info,
        {
            "headers": {**http_headers, **https_headers},
            "cookies": {**http_cookies, **https_cookies},
            "urls": [http_url, https_url],
        },
    )

    logging.info(
        f"[DONE] {domain} | WAF: {waf_detect} | CDN: {cdn_detect} | Cloud: {cloud_hosting} | SOA: {dns_info['SOA']}"
    )

    return {
        "URLs": domain,
        "WAF Technology": row.get("WAF Technology", ""),
        "Group": row.get("Group", ""),
        "DNS_A": ", ".join(dns_info["A"]),
        "DNS_CNAME": ", ".join(dns_info["CNAME"]),
        "DNS_MX": ", ".join(dns_info["MX"]),
        "DNS_SOA": dns_info["SOA"],
        "HTTP_Status": http_status,
        "HTTPS_Status": https_status,
        "auto_WAF_detect": waf_detect,
        "CDN_detect": cdn_detect,
        "Cloud_Hosting": cloud_hosting,
        "Playwright_Status": playwright_result["Playwright_Status"],
        "Playwright_Protocol": playwright_result["Playwright_Protocol"],
        "Playwright_Title": playwright_result["Playwright_Title"],
    }


def run_scan(df: pd.DataFrame) -> tuple[List[Dict[str, str]], bool]:
    results: List[Dict[str, str]] = []
    interrupted = False
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(process_domain, row) for _, row in df.iterrows()]
        try:
            for future in tqdm(
                as_completed(futures), total=len(futures), desc="Processing Domains"
            ):
                results.append(future.result())
        except KeyboardInterrupt:
            interrupted = True
            logging.warning("Scan interrupted by user. Cancelling remaining tasks.")
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
    return results, interrupted


def load_input(input_path: Path, single_domain: str | None = None) -> pd.DataFrame:
    if single_domain:
        return pd.DataFrame([[single_domain, "", ""]], columns=["URLs", "WAF Technology", "Group"])
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    return pd.read_csv(input_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DNS + HTTP scanner")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to CSV containing a column named 'URLs'")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Where to save the scan results CSV")
    parser.add_argument("--domain", help="Scan a single domain instead of a CSV input file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    df = load_input(input_path, args.domain)

    try:
        results, interrupted = run_scan(df)
    except KeyboardInterrupt:
        logging.warning("Second interrupt received. Exiting without saving results.")
        print("❌ Scan cancelled before saving results.")
        return

    output_df = pd.DataFrame(results)
    output_df.to_csv(args.output, index=False)

    logging.info(f"Results saved to {args.output}")
    if interrupted:
        print(
            f"⚠️ Scan interrupted by user. Partial results saved to {args.output}. Logs in scan_log.txt"
        )
    else:
        print(f"✅ Scan complete! Results saved to {args.output}. Logs in scan_log.txt")


if __name__ == "__main__":
    main()
