
import dns.resolver
import requests
import pandas as pd
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)

# Input/Output files
input_file = "input.csv"
output_file = "output.csv"

# Load input CSV
df = pd.read_csv(input_file)

# Use Cloudflare DNS
resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"]
resolver.lifetime = 3

# Realistic headers for human-like behavior
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

# WAF signatures
WAF_SIGNATURES = {
    "X-Sucuri-ID": "Sucuri",
    "X-CDN": "Akamai",
    "X-Akamai": "Akamai",
    "X-Cloudflare": "Cloudflare",
    "X-WAF": "Generic WAF",
    "X-Mod-Security": "ModSecurity",
    "Server": ["ModSecurity", "Barracuda", "F5 BIG-IP", "Imperva", "Incapsula"]
}

# WAF detection via cookies
WAF_COOKIE_PATTERNS = {
    "visid_incap": "Imperva/Incapsula",
    "incap_ses": "Imperva/Incapsula",
    "cfduid": "Cloudflare",
    "sucuri_cloudproxy": "Sucuri"
}

# CDN patterns
CDN_PATTERNS = {
    "impervadns.net": "Imperva CDN",
    "cloudflare.net": "Cloudflare CDN",
    "akamai.net": "Akamai CDN",
    "edgekey.net": "Akamai CDN",
    "fastly.net": "Fastly CDN"
}

# Cloud provider patterns
CLOUD_PATTERNS = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS",
    "azure.com": "Azure",
    "microsoft.com": "Azure",
    "googleusercontent.com": "GCP",
    "googleapis.com": "GCP"
}


import dns.resolver
import requests
import pandas as pd
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)

# Input/Output files
input_file = "input.csv"
output_file = "output.csv"

# Load input CSV
df = pd.read_csv(input_file)

# Use Cloudflare DNS
resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"]
resolver.lifetime = 3

# Realistic headers for human-like behavior
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

# WAF signatures
WAF_SIGNATURES = {
    "X-Sucuri-ID": "Sucuri",
    "X-CDN": "Akamai",
    "X-Akamai": "Akamai",
    "X-Cloudflare": "Cloudflare",
    "X-WAF": "Generic WAF",
    "X-Mod-Security": "ModSecurity",
    "Server": ["ModSecurity", "Barracuda", "F5 BIG-IP", "Imperva", "Incapsula"]
}

# WAF detection via cookies
WAF_COOKIE_PATTERNS = {
    "visid_incap": "Imperva/Incapsula",
    "incap_ses": "Imperva/Incapsula",
    "cfduid": "Cloudflare",
    "sucuri_cloudproxy": "Sucuri"
}

# CDN patterns
CDN_PATTERNS = {
    "impervadns.net": "Imperva CDN",
    "cloudflare.net": "Cloudflare CDN",
    "akamai.net": "Akamai CDN",
    "edgekey.net": "Akamai CDN",
    "fastly.net": "Fastly CDN"
}

# Cloud provider patterns
CLOUD_PATTERNS = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS",
    "azure.com": "Azure",
    "microsoft.com": "Azure",
    "googleusercontent.com": "GCP",
    "googleapis.com": "GCP"
}

def get_dns_records(domain):
    logging.info(f"[DNS] Checking DNS records for {domain}")
    records = {"A": [], "CNAME": [], "MX": [], "SOA": ""}
    try:
        # Follow full CNAME chain
        current_domain = domain
        while True:
            try:
                cname_records = resolver.resolve(current_domain, 'CNAME')
                cname_target = cname_records[0].target.to_text()
                records['CNAME'].append(cname_target)
                current_domain = cname_target
            except dns.resolver.NoAnswer:
                break
            except dns.resolver.NXDOMAIN:
                break
            except:
                break
        # A records for final domain
        try:
            a_records = resolver.resolve(current_domain, 'A')
            records['A'] = [r.address for r in a_records]
        except:
            pass
    except:
        pass
    try:
        mx_records = resolver.resolve(domain, 'MX')
        records['MX'] = [r.exchange.to_text() for r in mx_records]
    except:
        pass
    try:
        soa_record = resolver.resolve(domain, 'SOA')
        records['SOA'] = soa_record[0].mname.to_text()
    except:
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

def check_http(domain, protocol="http"):
    url = f"{protocol}://{domain}"
    logging.info(f"[HTTP] Checking {protocol.upper()} for {domain}")
    try:
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=8, allow_redirects=True)
        return response.status_code, response.headers, session.cookies.get_dict()
    except requests.exceptions.RequestException:
        return "Error", {}, {}

def detect_waf(headers, cookies):
    for key, value in WAF_SIGNATURES.items():
        if key in headers:
            if isinstance(value, list):
                for v in value:
                    if v.lower() in headers[key].lower():
                        return v
            else:
                return value
    for cookie_name in cookies.keys():
        for pattern, waf_name in WAF_COOKIE_PATTERNS.items():
            if pattern in cookie_name.lower():
                return waf_name
    return "None"

def detect_cdn(cname_list):
    for cname in cname_list:
        for pattern, cdn_name in CDN_PATTERNS.items():
            if pattern in cname.lower():
                return cdn_name
    return "None"

def detect_cloud(records):
    soa = records["SOA"].lower()
    if any(x in soa for x in ["azure-dns.com", "azuredns-hostmaster.microsoft.com", "bdm.microsoftonline.com"]):
        return "Azure"
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
        except:
            continue
    return "None"

def process_domain(row):
    domain = row["URLs"]
    logging.info(f"--- Processing {domain} ---")
    dns_info = get_dns_records(domain)
    http_status, http_headers, http_cookies = check_http(domain, "http")
    https_status, https_headers, https_cookies = check_http(domain, "https")
    waf_detect = detect_waf({**http_headers, **https_headers}, {**http_cookies, **https_cookies})
    cdn_detect = detect_cdn(dns_info["CNAME"])
    cloud_hosting = detect_cloud(dns_info)
    logging.info(f"[DONE] {domain} | WAF: {waf_detect} | CDN: {cdn_detect} | Cloud: {cloud_hosting}")
    return {
        "URLs": domain,
        "WAF Technology": row["WAF Technology"],
        "Group": row["Group"],
        "DNS_A": ", ".join(dns_info["A"]),
        "DNS_CNAME": ", ".join(dns_info["CNAME"]),  # FULL CHAIN
        "DNS_MX": ", ".join(dns_info["MX"]),
        "DNS_SOA": dns_info["SOA"],
        "HTTP_Status": http_status,
        "HTTPS_Status": https_status,
        "auto_WAF_detect": waf_detect,
        "CDN_detect": cdn_detect,
        "Cloud_Hosting": cloud_hosting
    }

# Multithreading with progress bar
results = []
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(process_domain, row) for _, row in df.iterrows()]
    for future in tqdm(as_completed(futures), total=len(futures), desc="Processing Domains"):
        results.append(future.result())



def check_http(domain, protocol="https"):
    url = f"{protocol}://{domain}"
    logging.info(f"[HTTP] Checking {protocol.upper()} for {domain}")
    try:
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=8, allow_redirects=True)
        return response.status_code, response.headers, session.cookies.get_dict()
    except requests.exceptions.RequestException:
        return "Error", {}, {}

def detect_waf(headers, cookies):
    for key, value in WAF_SIGNATURES.items():
        if key in headers:
            if isinstance(value, list):
                for v in value:
                    if v.lower() in headers[key].lower():
                        return v
            else:
                return value
    for cookie_name in cookies.keys():
        for pattern, waf_name in WAF_COOKIE_PATTERNS.items():
            if pattern in cookie_name.lower():
                return waf_name
    return "None"

def detect_cdn(cname_list):
    for cname in cname_list:
        for pattern, cdn_name in CDN_PATTERNS.items():
            if pattern in cname.lower():
                return cdn_name
    return "None"

def detect_cloud(records):
    soa = records["SOA"].lower()
    if any(x in soa for x in ["azure-dns.com", "azuredns-hostmaster.microsoft.com", "bdm.microsoftonline.com"]):
        return "Azure"
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
        except:
            continue
    return "None"

def process_domain(row):
    domain = row["URLs"]
    logging.info(f"--- Processing {domain} ---")
    dns_info = get_dns_records(domain)
    http_status, http_headers, http_cookies = check_http(domain, "http")
    https_status, https_headers, https_cookies = check_http(domain, "https")
    waf_detect = detect_waf({**http_headers, **https_headers}, {**http_cookies, **https_cookies})
    cdn_detect = detect_cdn(dns_info["CNAME"])
    cloud_hosting = detect_cloud(dns_info)
    logging.info(f"[DONE] {domain} | WAF: {waf_detect} | CDN: {cdn_detect} | Cloud: {cloud_hosting}")
    return {
        "URLs": domain,
        "WAF Technology": row["WAF Technology"],
        "Group": row["Group"],
        "DNS_A": ", ".join(dns_info["A"]),
        "DNS_CNAME": ", ".join(dns_info["CNAME"]),  # FULL CHAIN
        "DNS_MX": ", ".join(dns_info["MX"]),
        "DNS_SOA": dns_info["SOA"],
        "HTTP_Status": http_status,
        "HTTPS_Status": https_status,
        "auto_WAF_detect": waf_detect,
        "CDN_detect": cdn_detect,
        "Cloud_Hosting": cloud_hosting
    }

# Multithreading with progress bar
results = []
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(process_domain, row) for _, row in df.iterrows()]
    for future in tqdm(as_completed(futures), total=len(futures), desc="Processing Domains"):
        results.append(future.result())

# Save to CSV
output_df = pd.DataFrame(results)
output_df.to_csv(output_file, index=False)
logging.info(f"Results saved to {output_file}")
print(f"✅ Scan complete! Results saved to {output_file}. Logs in scan_log.txt")

