# dnscheck

`dnscheck.py` performs bulk DNS and HTTP/HTTPS checks for a list of domains (or a single domain), saving structured results to `output.csv` and a detailed log to `scan_log.txt`.

## Features
- Resolves A, CNAME, MX, and SOA records using Cloudflare DNS (`1.1.1.1`).
- Follows full CNAME chains to improve CDN/cloud detection.
- Performs HTTP and HTTPS requests with realistic headers.
- Detects common WAFs, CDNs, and cloud providers via headers, cookies, and DNS data (including Azure SOA values such as `azuredns-hostmaster.microsoft.com`).
- Processes domains concurrently with a progress bar.

## Requirements
Install Python dependencies:

```bash
pip install dnspython requests pandas tqdm
```

## Usage
### Scan domains from a CSV
1. Prepare `input.csv` with at least the following columns:
   - `URLs`: domain names to scan
   - `WAF Technology`: existing WAF label (kept in output)
   - `Group`: grouping metadata (kept in output)
2. Run the script from the repository root:

```bash
python dnscheck.py --input input.csv --output output.csv
```

3. Review outputs:
   - `output.csv` contains DNS answers, HTTP/HTTPS status codes, and detected WAF/CDN/cloud providers.
   - `scan_log.txt` contains per-domain processing details.

### Scan a single domain quickly
Use `--domain` to inspect one host without creating a CSV. This is useful for confirming SOA ownership (e.g., Azure-hosted zones showing `azuredns-hostmaster.microsoft.com`).

```bash
python dnscheck.py --domain ua.coca-colahellenic.com --output single-result.csv
```

## Notes
- The script uses a 3-second DNS resolver lifetime and 8-second HTTP timeouts.
- Network errors are recorded as `Error` status codes.
- Adjust `max_workers` in the thread pool if you need to tune concurrency.
