# core/utils.py
import re
import logging
import random
import string
from typing import Iterable

logger = logging.getLogger("subfinder_py")

def setup_logging(verbose: bool):
    """Configure logging with verbose option."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=level, force=True)

def normalize(name: str) -> str:
    """Normalize a hostname by stripping and lowercasing."""
    if not name:
        return name
    name = name.strip().lower()
    if name.endswith('.'):
        name = name[:-1]
    return name

def dedupe(iterable: Iterable[str]) -> Iterable[str]:
    """Deduplicate normalized hostnames."""
    seen = set()
    for item in iterable:
        if item:
            n = normalize(item)
            if n and n not in seen:
                seen.add(n)
                yield n

def random_label(length: int = 12) -> str:
    """Generate a random label for wildcard detection."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def is_likely_subdomain(s: str) -> bool:
    """Check if string looks like a valid subdomain."""
    return bool(re.match(r'^[a-z0-9\-\.]+$', s))
