# core/resolver.py
"""
DNS resolver utilities (with global nameserver setter).

Provides:
- set_nameservers(list_of_ips) to set a global resolver list
- resolve_name_any(name, timeout, nameservers, max_depth)
- bulk_resolve(names, concurrency, timeout, nameservers)
- detect_wildcard(domain, tries, timeout, nameservers)
"""
from typing import List, Set, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from .utils import random_label, logger
import time

# Global override for nameservers; CLI can call set_nameservers()
_GLOBAL_NAMESERVERS: Optional[List[str]] = None

def set_nameservers(nameservers: Optional[List[str]]):
    """Set global nameservers used by resolver functions (overrides per-call nameservers)."""
    global _GLOBAL_NAMESERVERS
    if nameservers:
        _GLOBAL_NAMESERVERS = [str(n) for n in nameservers]
    else:
        _GLOBAL_NAMESERVERS = None
    logger.debug(f"Global nameservers set to: {_GLOBAL_NAMESERVERS}")

def _get_resolver(nameservers: Optional[List[str]], lifetime: float) -> dns.resolver.Resolver:
    """Create a dns.resolver.Resolver configured with optional nameservers and lifetime."""
    r = dns.resolver.Resolver()
    r.lifetime = lifetime
    # preference: explicit param > global override > system defaults
    ns = nameservers if nameservers is not None else _GLOBAL_NAMESERVERS
    if ns:
        r.nameservers = [str(n) for n in ns]
    return r

def _safe_resolve(resolver: dns.resolver.Resolver, name: str, rdtype: str, lifetime: float = 5.0) -> List[str]:
    """Resolve a single record type and return textual results; log failures at debug level."""
    try:
        answers = resolver.resolve(name, rdtype, lifetime=lifetime)
        return [r.to_text().rstrip('.') for r in answers]
    except Exception as e:
        logger.debug(f"DNS {rdtype} lookup failed for {name}: {e}")
        return []

def resolve_name_any(name: str,
                     timeout: float = 5.0,
                     nameservers: Optional[List[str]] = None,
                     max_depth: int = 3) -> List[str]:
    """
    Resolve name for A, AAAA, and CNAME records, following CNAME chains up to max_depth.

    Returns a list of ip strings and/or CNAME targets (deduplicated).
    """
    resolver = _get_resolver(nameservers, timeout)
    results: List[str] = []
    seen: Set[str] = set()

    # Resolve A and AAAA
    a = _safe_resolve(resolver, name, "A", lifetime=timeout)
    if a:
        results.extend(a)
    aaaa = _safe_resolve(resolver, name, "AAAA", lifetime=timeout)
    if aaaa:
        results.extend(aaaa)

    # Helper to follow CNAME chain
    def resolve_cname(target_name: str, depth: int = 0) -> None:
        if depth >= max_depth:
            return
        cnames = _safe_resolve(resolver, target_name, "CNAME", lifetime=timeout)
        for t in cnames:
            t = t.rstrip('.')
            if t not in seen:
                # include the CNAME target as provenance
                results.append(t)
                seen.add(t)
                # try to resolve its A/AAAA
                t_a = _safe_resolve(resolver, t, "A", lifetime=timeout)
                if t_a:
                    results.extend(t_a)
                t_aaaa = _safe_resolve(resolver, t, "AAAA", lifetime=timeout)
                if t_aaaa:
                    results.extend(t_aaaa)
                # recurse one level deeper
                resolve_cname(t, depth + 1)

    # Follow CNAMEs of original name
    resolve_cname(name, depth=0)

    # Deduplicate while preserving order
    deduped: List[str] = []
    for x in results:
        if x not in deduped:
            deduped.append(x)
    return deduped

def bulk_resolve(names: List[str],
                 concurrency: int = 20,
                 timeout: float = 5.0,
                 nameservers: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """
    Concurrently resolve a list of names using resolve_name_any.
    Returns mapping: name -> list[str]
    """
    results: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(resolve_name_any, n, timeout, nameservers): n for n in names}
        for fut in as_completed(futures):
            n = futures[fut]
            try:
                ips = fut.result()
            except Exception as e:
                logger.debug(f"bulk_resolve exception for {n}: {e}")
                ips = []
            results[n] = ips
    return results

def detect_wildcard(domain: str,
                    tries: int = 3,
                    timeout: float = 5.0,
                    nameservers: Optional[List[str]] = None) -> Tuple[bool, Set[str]]:
    """
    Detect wildcard by resolving a few random subdomains. Returns (has_wildcard, combined_set).
    """
    ips_sets: List[Set[str]] = []
    for _ in range(tries):
        label = random_label(14)
        name = f"{label}.{domain}"
        ips = resolve_name_any(name, timeout=timeout, nameservers=nameservers)
        ips_sets.append(set(ips))
    combined = set().union(*ips_sets)
    has = any(len(s) > 0 for s in ips_sets)
    return has, combined
