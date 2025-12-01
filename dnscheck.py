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
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List

import dns.resolver
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
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    ),
]

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.6",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "no-cache",
}

COOKIE_CONSENT_COOKIE = ("cookie_consent", "accepted")

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
    "azurefd.net": "Azure",
    "azureedge.net": "Azure",
    "azurewebsites.net": "Azure",
    "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure",
    "windows.net": "Azure",
    "microsoft.com": "Azure",
    "azuredns-hostmaster.microsoft.com": "Azure",
    "googleusercontent.com": "GCP",
    "googleapis.com": "GCP",
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


def build_browser_headers() -> Dict[str, str]:
    return {"User-Agent": random.choice(USER_AGENTS), **BROWSER_HEADERS}


def check_http(domain: str, protocol: str = "http"):
    url = f"{protocol}://{domain}"
    logging.info(f"[HTTP] Checking {protocol.upper()} for {domain}")
    try:
        session = requests.Session()
        session.headers.update(build_browser_headers())
        try:
            session.cookies.set(COOKIE_CONSENT_COOKIE[0], COOKIE_CONSENT_COOKIE[1], domain=domain)
        except Exception:
            session.cookies.set(COOKIE_CONSENT_COOKIE[0], COOKIE_CONSENT_COOKIE[1])
        time.sleep(random.uniform(0.2, 0.6))
        response = session.get(url, timeout=8, allow_redirects=True)
        return response.status_code, response.headers, session.cookies.get_dict()
    except requests.exceptions.RequestException:
        return "Error", {}, {}


def detect_waf(headers_dict: Dict[str, str], cookies: Dict[str, str]) -> str:
    for key, value in WAF_SIGNATURES.items():
        if key in headers_dict:
            if isinstance(value, list):
                for v in value:
                    if v.lower() in headers_dict[key].lower():
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


def detect_cloud(records: Dict[str, List[str] | str]) -> str:
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
    return "None"


def process_domain(row: pd.Series) -> Dict[str, str]:
    domain = row["URLs"]
    logging.info(f"--- Processing {domain} ---")
    dns_info = get_dns_records(domain)
    http_status, http_headers, http_cookies = check_http(domain, "http")
    https_status, https_headers, https_cookies = check_http(domain, "https")

    waf_detect = detect_waf({**http_headers, **https_headers}, {**http_cookies, **https_cookies})
    cdn_detect = detect_cdn(dns_info["CNAME"])
    cloud_hosting = detect_cloud(dns_info)

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
    }


def run_scan(df: pd.DataFrame) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(process_domain, row) for _, row in df.iterrows()]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing Domains"):
            results.append(future.result())
    return results


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

    results = run_scan(df)
    output_df = pd.DataFrame(results)
    output_df.to_csv(args.output, index=False)

    logging.info(f"Results saved to {args.output}")
    print(f"✅ Scan complete! Results saved to {args.output}. Logs in scan_log.txt")


if __name__ == "__main__":
    main()
