# cli.py
import argparse
import sys
import traceback
from pathlib import Path
import re
import logging

from core import collector, bruteforce, resolver, output, utils

logger = logging.getLogger("subfinder_py")

def is_valid_domain(domain: str) -> bool:
    """Validate domain format (e.g., example.com)."""
    return bool(re.match(
        r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$',
        domain, re.I))

def parse_args():
    p = argparse.ArgumentParser(prog="subfinder_py", description="Simple subdomain enumerator (CLI)")
    p.add_argument("--domain", "-d", required=True, help="Target domain (e.g., example.com)")
    p.add_argument("--wordlist", "-w", default=str(Path("wordlists/subdomains.txt")), help="Path to wordlist file")
    p.add_argument("--download-wordlist", "-D", help="Download wordlist from URL to wordlists/ and use it")
    p.add_argument("--out", "-o", default="results.json", help="Output file (.json for JSON, .txt for text, .csv for CSV)")
    p.add_argument("--concurrency", "-c", type=int, default=30, help="Thread pool size for DNS queries (1–100, default: 30)")
    p.add_argument("--max-pending", type=int, default=1000, help="Max pending futures for streaming bruteforce (default: 1000)")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS resolution timeout in seconds (default: 5.0)")
    p.add_argument("--http-timeout", type=float, default=15.0, help="HTTP request timeout in seconds (default: 15.0)")
    p.add_argument("--dns-servers", nargs="*", default=["8.8.8.8", "1.1.1.1"], help="Custom DNS servers (default: 8.8.8.8, 1.1.1.1)")
    p.add_argument("--no-passive", action="store_true", help="Disable passive collectors (crt.sh)")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    p.add_argument("--progress-every", type=int, default=0, help="Print brief progress every N words processed (0=off)")
    return p.parse_args()

def download_wordlist(url: str, dest: Path, timeout: float):
    import requests
    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Downloading wordlist from: {url}")
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        dest.write_text(r.text, encoding="utf-8")
        logger.info(f"Saved wordlist to: {dest}")
        return str(dest)
    except Exception as e:
        logger.error(f"Failed to download wordlist: {e}")
        raise

def safe_path(path: str) -> Path:
    """Ensure path is within working directory (prevents accidental writes outside)."""
    p = Path(path).resolve()
    # is_relative_to exists in Python 3.9+
    if not p.is_relative_to(Path.cwd()):
        raise ValueError(f"Path {path} is outside working directory")
    return p

def main():
    args = parse_args()
    utils.setup_logging(args.verbose)
    domain = args.domain.strip().lower()
    if not is_valid_domain(domain):
        logger.error(f"Invalid domain: {domain}")
        sys.exit(1)
    logger.info(f"Target domain: {domain}")

    # Configure resolver nameservers globally
    try:
        resolver.set_nameservers(args.dns_servers)
        logger.debug(f"Using DNS servers: {args.dns_servers}")
    except Exception as e:
        logger.warning(f"Could not set custom DNS servers: {e}")

    # Download wordlist if requested
    if args.download_wordlist:
        try:
            args.wordlist = download_wordlist(args.download_wordlist, Path("wordlists/subdomains.txt"), args.http_timeout)
        except Exception as e:
            logger.error(f"Failed to download wordlist: {e}")
            sys.exit(1)

    # Passive collection
    collected = set()
    if not args.no_passive:
        try:
            passive = collector.crt_sh_collect(domain, timeout=args.http_timeout)
            logger.info(f"Passive found: {len(passive)} (sample): {passive[:10]}")
            collected.update(passive)
        except Exception as e:
            logger.error(f"Passive collector failed: {e}")
    else:
        logger.info("Passive collectors disabled by user (--no-passive).")

    # Streaming bruteforce
    try:
        count_found = 0
        for found in bruteforce.bruteforce_stream(
            domain,
            args.wordlist,
            concurrency=args.concurrency,
            max_pending=args.max_pending,
            skip_set=collected,
            timeout=args.timeout,
            progress_every=args.progress_every
        ):
            if found not in collected:
                collected.add(found)
                count_found += 1
                logger.debug(f"Bruteforce discovered: {found}")
        logger.info(f"Bruteforce discovered total: {count_found}")
    except Exception as e:
        logger.error(f"Bruteforce failed: {e}")
        logger.debug(traceback.format_exc())

    # Normalize and dedupe
    names = sorted(list(utils.dedupe(collected)))
    logger.info(f"Unique normalized candidates: {len(names)}")

    # Wildcard detection
    try:
        has_wildcard, wildcard_ips = resolver.detect_wildcard(domain, tries=2, timeout=args.timeout, nameservers=args.dns_servers)
        logger.info(f"Wildcard detected: {has_wildcard}, IPs/targets: {wildcard_ips}")
    except Exception as e:
        logger.error(f"Wildcard detection failed: {e}")
        wildcard_ips = set()
        has_wildcard = False

    # Resolve everything
    results = []
    if names:
        try:
            res_map = resolver.bulk_resolve(names, concurrency=args.concurrency, timeout=args.timeout, nameservers=args.dns_servers)
            for name, ips in res_map.items():
                if ips:
                    try:
                        if has_wildcard and wildcard_ips and set(ips).issubset(set(wildcard_ips)):
                            logger.debug(f"Skipping likely wildcard result: {name} -> {ips}")
                            continue
                    except Exception:
                        # ignore any comparison errors
                        pass
                    results.append({"name": name, "ips": ips})
        except Exception as e:
            logger.error(f"Error during bulk_resolve: {e}")
            logger.debug(traceback.format_exc())

    # Output results
    try:
        out_path = safe_path(args.out)
        fmt = "json" if args.out.endswith(".json") else "csv" if args.out.endswith(".csv") else "txt"
        output.write_output(out_path, results, format=fmt)
        logger.info(f"Wrote results to {args.out}")
    except Exception as e:
        logger.error(f"Error writing output: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
