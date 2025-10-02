# subfinder_py

Lightweight Python subdomain enumerator inspired by **subfinder**.  
Combines passive collection (crt.sh) and streaming bruteforce (low-RAM) with DNS resolution (A / AAAA / CNAME + CNAME follow).  
Designed for learning and small-scale recon. Use responsibly and only against domains you own or have permission to test.

---

## Features
- Passive collection from Certificate Transparency (`crt.sh`) with filtering and retries.  
- Streaming bruteforce of very large wordlists **without** loading the whole file into RAM.  
- DNS resolution of A, AAAA and CNAME records, following CNAME chains (configurable depth).  
- Configurable concurrency, DNS servers, and timeouts.  
- Outputs: JSON, TXT, CSV.  
- Lightweight, single-file CLI entrypoint (`cli.py`) plus modular `core/` code.

---

## Quick start

### 1) Requirements
- Python 3.10+ (3.12 tested in development)  
- Git (optional)  

### 2) Create and activate a virtual environment

**Windows (PowerShell)**
```powershell
python -m venv venv
.
env\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

**Linux / macOS**
```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Usage

Create a small test wordlist `wordlists/subdomains.txt`:
```
www
mail
api
dev
test
```

Example commands:

**Small test run (verbose, show progress)**
```powershell
python cli.py -d example.com -w wordlists\subdomains.txt -o results.json -c 6 --max-pending 100 --timeout 2.0 -v --progress-every 50
```

**Full run (110k wordlist, quiet)**
```powershell
python cli.py -d example.com -w wordlists\subdomains-top1million-110000.txt -o results.json -c 40 --max-pending 1500 --timeout 3.0
```

**Use custom DNS servers**
```powershell
python cli.py -d example.com -w wordlists\subdomains.txt --dns-servers 1.1.1.1 8.8.8.8 -o results.json
```

**Download a remote wordlist before running**
```powershell
python cli.py -d example.com -D "https://raw.githubusercontent.com/..." -o results.json
```

---

## CLI flags (summary)
- `-d, --domain` (required) — target domain (e.g., `example.com`)  
- `-w, --wordlist` — path to wordlist (default: `wordlists/subdomains.txt`)  
- `-D, --download-wordlist` — download a wordlist from URL and use it  
- `-o, --out` — output file (use `.json`, `.txt`, or `.csv`)  
- `-c, --concurrency` — thread pool size for DNS queries (default: 30)  
- `--max-pending` — max outstanding futures (default: 1000)  
- `--timeout` — per-DNS query timeout in seconds (default: 5.0)  
- `--http-timeout` — HTTP timeout for passive collectors (default: 15.0)  
- `--dns-servers` — list of DNS servers (space-separated)  
- `--no-passive` — skip passive collectors (crt.sh)  
- `-v, --verbose` — enable verbose logging (debug)  
- `--progress-every` — print a brief progress line every N processed words (0 = off)

---

## Output formats
- **JSON** (default when `.json` used): list of objects with `name` and `ips` fields, e.g.:
```json
[
  { "name": "www.example.com", "ips": ["93.184.216.34"] },
  { "name": "mail.example.com", "ips": ["93.184.216.35"] }
]
```
- **TXT**: newline-separated hostnames.  
- **CSV**: two columns (`name`, `ips`) with `ips` as comma-separated string.

---

## Tips & troubleshooting
- If the tool appears to hang: try lowering `--concurrency` and lowering `--max-pending`, or shorten `--timeout`.  
- If crt.sh is slow or times out, increase `--http-timeout` or run the passive collector manually with cURL to verify connectivity.  
- If DNS responses are inconsistent, use `--dns-servers 1.1.1.1 8.8.8.8` to force public resolvers.  
- Use the `--progress-every` flag to get periodic progress updates for large lists without per-hit spam.

---

## Implementation notes & limits
- This is **not** a replacement for highly-optimized tools (e.g., massdns-based pipelines). It is meant for education, light recon, and small/medium runs.  
- The bruteforce engine streams the list and only keeps outstanding requests in memory. Memory mainly grows with `--max-pending` and the threadpool overhead.  
- Passive collection is limited to `crt.sh` by default (no API keys). Adding more passive sources or authenticated APIs (VirusTotal, SecurityTrails, Censys) requires storing API keys and implementing rate-limiting.

---
