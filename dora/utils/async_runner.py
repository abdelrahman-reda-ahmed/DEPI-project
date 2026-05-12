from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from tqdm.asyncio import tqdm


async def run_concurrently(
    tasks: list[Coroutine[Any, Any, Any]],
    max_concurrent: int = 20,
    desc: str = "Running",
    show_progress: bool = True,
) -> list[Any]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def worker(coro: Coroutine[Any, Any, Any]) -> Any:
        async with semaphore:
            return await coro

    wrapped = [worker(t) for t in tasks]

    if show_progress:
        results = []
        for coro in tqdm.as_completed(wrapped, desc=desc):
            result = await coro
            results.append(result)
        return results
    else:
        return await asyncio.gather(*wrapped, return_exceptions=True)


def rate_limited(max_per_second: float):
    interval = 1.0 / max_per_second if max_per_second > 0 else 0
    last_call = 0.0

    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            nonlocal last_call
            now = asyncio.get_event_loop().time()
            wait = interval - (now - last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            last_call = asyncio.get_event_loop().time()
            return await func(*args, **kwargs)
        return wrapper
    return decorator
