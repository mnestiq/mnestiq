"""The long fuzzing tier: many workers, millions of mutated files, every crashing input saved.

    python tests/fuzz/run_long.py --minutes 480 --out fuzz-found

Each kind of problem is saved a few times, so a common one cannot fill the disk. A saved case holds the file, its
seed and what broke, and goes in tests/fuzz/corpus/ to become a regression test. Exit code 1 means something was found.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import json
import multiprocessing as mp
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz.engine import Checker, Violation, build_seeds, mutate, page_script, run_page_batch, save_case

PAGE_EVERY = 25  # every n-th file also goes through the dashboard page
PAGE_BATCH = 200
REPORT_EVERY = 200
STALL_S = 180


def worker(
    index: int,
    base: int,
    deadline: float,
    limit: int,
    slow_s: float,
    out: Path,
    keep: int,
    queue: mp.Queue,
    current: mp.Value,
) -> None:
    import dashboard_path

    seeds = build_seeds()
    saved: collections.Counter = collections.Counter()
    tally: collections.Counter = collections.Counter()
    with tempfile.TemporaryDirectory(prefix=f"fuzz{index}-") as tmp:
        work = Path(tmp)
        checker = Checker(work / "check", slow_s)
        page = work / "page.js"
        page.write_text(page_script(dashboard_path.html()), "utf-8")
        payloads: list[tuple] = []
        n, done_since = base + (index << 40), 0
        while time.time() < deadline and done_since < limit:
            n += 1
            done_since += 1
            current.value = n
            case = mutate(seeds[n % len(seeds)], n)
            found = checker.check(case)
            if n % PAGE_EVERY == 0:
                from mnestiq.dashboard import EvidenceStore

                path = work / "check" / "view" / "target.jsonl"
                with contextlib.suppress(Exception):  # already reported by the checker as a crash
                    payloads.append((case, EvidenceStore(path, [case.seed.pub]).load(path).payload))
            if len(payloads) >= PAGE_BATCH:
                for bad in run_page_batch(page, [p for _, p in payloads], work):
                    which = payloads[bad["n"]][0] if bad["n"] >= 0 else case
                    extra = Violation("page", "dashboard page", f"{bad['error']} at {bad['where']} :: ")
                    _record(which, [extra], out, keep, saved, tally)
                payloads = []
            if found:
                _record(case, found, out, keep, saved, tally)
            if done_since % REPORT_EVERY == 0:
                queue.put((index, REPORT_EVERY, dict(tally)))
                tally = collections.Counter()
        queue.put((index, done_since % REPORT_EVERY, dict(tally)))


def _record(case, found, out, keep, saved, tally) -> None:
    for v in found:
        tally[v.signature] += 1
    fresh = [v for v in found if saved[v.signature] < keep]
    if fresh:
        for v in fresh:
            saved[v.signature] += 1
        save_case(case, fresh, out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--minutes", type=float, default=60)
    ap.add_argument("--files", type=int, default=0, help="stop after this many files in total (0: no limit)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument(
        "--base", type=int, default=int(time.time()), help="the run's number: use the same one to repeat it"
    )
    ap.add_argument("--out", type=Path, default=Path("fuzz-found"))
    ap.add_argument("--keep", type=int, default=5, help="cases saved per kind of problem and worker")
    ap.add_argument("--slow", type=float, default=20, help="report one surface taking longer than this many seconds")
    args = ap.parse_args()

    deadline = time.time() + args.minutes * 60
    limit = (args.files // args.jobs + 1) if args.files else 2**62
    queue: mp.Queue = mp.Queue()
    started, total, seen = time.time(), 0, collections.Counter()
    slots = [mp.Value("Q", 0) for _ in range(args.jobs)]

    def spawn(i: int, base: int) -> mp.Process:
        p = mp.Process(target=worker, args=(i, base, deadline, limit, args.slow, args.out, args.keep, queue, slots[i]))
        p.start()
        return p

    procs = [spawn(i, args.base) for i in range(args.jobs)]
    last_seen = [(time.time(), 0) for _ in procs]
    restarts, printed = 0, time.time()
    while any(p.is_alive() for p in procs) or not queue.empty():
        while not queue.empty():
            _, n, tally = queue.get()
            total += n
            seen.update(tally)
        now = time.time()
        for i, p in enumerate(procs):
            value = slots[i].value
            if value != last_seen[i][1]:
                last_seen[i] = (now, value)
            elif p.is_alive() and now - last_seen[i][0] > STALL_S:
                seen[f"hang|worker|case {value}"] += 1
                _save_hang(value, i, args.out)
                p.terminate()
                restarts += 1
                procs[i] = spawn(i, value - (i << 40))
                last_seen[i] = (now, value)
            elif not p.is_alive() and p.exitcode not in (0, None) and now < deadline:
                seen[f"worker_died|exit {p.exitcode}|case {value}"] += 1
                _save_hang(value, i, args.out)
                restarts += 1
                procs[i] = spawn(i, value - (i << 40))
                last_seen[i] = (now, value)
        if now - printed > 60:
            printed = now
            print(
                f"{(now - started) / 60:.1f} min  {total:,} files  {total / (now - started):.0f}/s  "
                f"{sum(seen.values())} problems of {len(seen)} kinds",
                flush=True,
            )
        time.sleep(1)
    for p in procs:
        p.join()
    summary = {
        "files": total,
        "seconds": round(time.time() - started),
        "jobs": args.jobs,
        "base": args.base,
        "per_second": round(total / max(1, time.time() - started)),
        "restarts": restarts,
        "problems": dict(seen.most_common()),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1), "utf-8")
    print(json.dumps(summary, indent=1))
    return 1 if seen else 0


def _save_hang(number: int, index: int, out: Path) -> None:
    """A case that hung or killed its worker: made again from its number, since the worker cannot save it."""
    seeds = build_seeds()  # new keys: the file's shape and mutations repeat, its signatures differ
    out.mkdir(parents=True, exist_ok=True)
    case = mutate(seeds[number % len(seeds)], number)
    save_case(case, [Violation("hang", f"worker {index}", f"case {number} :: ")], out)


if __name__ == "__main__":
    sys.exit(main())
