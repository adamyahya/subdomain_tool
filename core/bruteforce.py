# core/bruteforce.py
"""
Streaming bruteforce with optional pre-filtering to skip already-known candidates.
"""
from typing import Iterable, Generator, Optional, Tuple, List
from concurrent.futures import ThreadPoolExecutor, Future
from .resolver import resolve_name_any
from .utils import normalize, logger
from pathlib import Path
import time

def bruteforce_stream(
    domain: str,
    wordlist_path: str,
    concurrency: int = 30,
    max_pending: int = 1000,
    skip_set: Optional[Iterable[str]] = None,
    timeout: float = 5.0,
    progress_every: int = 0
) -> Generator[str, None, None]:
    """
    Stream words from wordlist_path; for each word create candidate <word>.<domain>.
    Submit resolution tasks to a thread pool (resolve_name_any).
    Yield normalized discovered hostnames as they are found.

    Args:
        skip_set: Optional iterable of normalized hostnames to skip.
        progress_every: print a brief report every N processed words (0=off).
    """
    wordlist_path = str(Path(wordlist_path).resolve())
    if not Path(wordlist_path).exists():
        logger.warning(f"Wordlist not found: {wordlist_path}")
        return

    skip_names = set(normalize(s) for s in skip_set if s) if skip_set else set()

    processed = 0
    start = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        pending_futures: List[Tuple[Future, str]] = []
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                processed += 1
                w = raw.strip()
                if not w or w.startswith("#"):
                    continue
                candidate = f"{w}.{domain}"           # original candidate (not normalized)
                cand_norm = normalize(candidate)      # normalized for skip & output
                if cand_norm in skip_names:
                    if progress_every and processed % progress_every == 0:
                        logger.info(f"[brute] processed={processed}, pending={len(pending_futures)}, elapsed={time.time()-start:.1f}s")
                    continue
                fut = ex.submit(resolve_name_any, candidate, timeout)
                pending_futures.append((fut, candidate))

                if len(pending_futures) >= max_pending:
                    new_pending = []
                    for fut, cand in pending_futures:
                        if fut.done():
                            try:
                                res = fut.result()
                            except Exception:
                                res = []
                            if res:
                                yield normalize(cand)
                        else:
                            new_pending.append((fut, cand))
                    pending_futures = new_pending

                if progress_every and processed % progress_every == 0:
                    logger.info(f"[brute] processed={processed}, pending={len(pending_futures)}, elapsed={time.time()-start:.1f}s")

            # drain remaining
            for fut, cand in pending_futures:
                try:
                    res = fut.result()
                except Exception:
                    res = []
                if res:
                    yield normalize(cand)
