# core/collector.py
import requests
import time
from typing import List
from ratelimit import limits, sleep_and_retry
from .utils import normalize, dedupe, logger, is_likely_subdomain

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
DEFAULT_CALLS_PER_MINUTE = 60
_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF_BASE = 1.5  # seconds, exponential backoff multiplier

def make_rate_limited_get(calls_per_minute: int):
    period = 60
    @sleep_and_retry
    @limits(calls=calls_per_minute, period=period)
    def _get(url: str, timeout: float):
        # Use requests.get here; crt.sh doesn't require special headers
        return requests.get(url, timeout=timeout)
    return _get

def crt_sh_collect(domain: str, timeout: float = 15.0, calls_per_minute: int = DEFAULT_CALLS_PER_MINUTE) -> List[str]:
    """
    Collect subdomains from crt.sh for the given domain. Filters non-host entries.
    Retries a few times with exponential backoff on transient failures.
    """
    rate_limited_get = make_rate_limited_get(calls_per_minute)
    url = CRT_SH_URL.format(domain=domain)

    last_exc = None
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            resp = rate_limited_get(url, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                logger.warning(f"Unexpected response format from crt.sh: {data}")
                return []
            # success -> break out
            last_exc = None
            break
        except Exception as e:
            last_exc = e
            logger.debug(f"crt.sh attempt {attempt} failed: {e}")
            if attempt < _RETRY_ATTEMPTS:
                backoff = (_RETRY_BACKOFF_BASE ** (attempt - 1))
                logger.info(f"Retrying crt.sh in {backoff:.1f}s (attempt {attempt+1}/{_RETRY_ATTEMPTS})")
                time.sleep(backoff)
            else:
                logger.error(f"Failed to fetch from crt.sh after {attempt} attempts: {e}")

    if last_exc is not None:
        return []

    hosts = []
    for item in data:
        nv = item.get("name_value", "")
        if not isinstance(nv, str):
            continue
        for line in nv.splitlines():
            line = line.strip()
            if not line:
                continue
            # skip emails or things with @
            if "@" in line:
                continue
            candidate = line.lstrip("*.").rstrip(".").lower()
            if candidate.endswith(domain) and is_likely_subdomain(candidate):
                hosts.append(normalize(candidate))
    return list(dedupe(hosts))
