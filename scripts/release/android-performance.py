#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path


def run(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        list(args),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}"
        )
    return result.stdout


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("no samples")
    rank = max(1, math.ceil(len(ordered) * quantile))
    return ordered[rank - 1]


def parse_startup(output: str) -> int:
    match = re.search(r"(?m)^TotalTime:\s*(\d+)\s*$", output)
    if not match:
        match = re.search(r"(?m)^WaitTime:\s*(\d+)\s*$", output)
    if not match:
        raise RuntimeError("adb am start output did not contain TotalTime/WaitTime:\n" + output)
    return int(match.group(1))


def parse_total_pss(output: str) -> int:
    patterns = [
        r"TOTAL PSS:\s*(\d+)",
        r"(?m)^\s*TOTAL\s+(\d+)\s+",
    ]
    for pattern in patterns:
        match = re.search(pattern, output)
        if match:
            return int(match.group(1))
    raise RuntimeError("dumpsys meminfo output did not contain TOTAL PSS")


def measure(args: argparse.Namespace) -> int:
    apk = Path(args.apk)
    if not apk.is_file():
        raise SystemExit(f"APK not found: {apk}")

    component = f"{args.package}/{args.activity}"
    run(args.adb, "install", "-r", str(apk))
    try:
        device = {
            "model": run(args.adb, "shell", "getprop", "ro.product.model").strip(),
            "api": run(args.adb, "shell", "getprop", "ro.build.version.sdk").strip(),
            "abi": run(args.adb, "shell", "getprop", "ro.product.cpu.abi").strip(),
            "fingerprint": run(
                args.adb, "shell", "getprop", "ro.build.fingerprint"
            ).strip(),
        }

        for _ in range(args.warmups):
            parse_startup(
                run(
                    args.adb,
                    "shell",
                    "am",
                    "start",
                    "-S",
                    "-W",
                    "-n",
                    component,
                )
            )
            time.sleep(0.25)

        startup_ms: list[int] = []
        pss_kb: list[int] = []
        for _ in range(args.runs):
            startup_ms.append(
                parse_startup(
                    run(
                        args.adb,
                        "shell",
                        "am",
                        "start",
                        "-S",
                        "-W",
                        "-n",
                        component,
                    )
                )
            )
            time.sleep(0.4)
            pss_kb.append(
                parse_total_pss(
                    run(args.adb, "shell", "dumpsys", "meminfo", args.package)
                )
            )

        report = {
            "schema": 1,
            "label": args.label,
            "device": device,
            "runs": args.runs,
            "warmups": args.warmups,
            "artifactBytes": apk.stat().st_size,
            "startupMs": {
                "samples": startup_ms,
                "p50": percentile(startup_ms, 0.50),
                "p95": percentile(startup_ms, 0.95),
            },
            "totalPssKb": {
                "samples": pss_kb,
                "median": int(statistics.median(pss_kb)),
                "p95": percentile(pss_kb, 0.95),
            },
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(
            f"{args.label}: p50={report['startupMs']['p50']}ms "
            f"p95={report['startupMs']['p95']}ms "
            f"pss={report['totalPssKb']['median']}KB "
            f"bytes={report['artifactBytes']}"
        )
        return 0
    finally:
        run(args.adb, "uninstall", args.package, check=False)


def overhead_percent(baseline: int, protected: int) -> float:
    if baseline <= 0:
        raise ValueError("baseline must be positive")
    return max(0.0, (protected - baseline) * 100.0 / baseline)


def compare(args: argparse.Namespace) -> int:
    baseline = json.loads(Path(args.baseline).read_text())
    protected = json.loads(Path(args.protected).read_text())

    if baseline["device"] != protected["device"]:
        raise SystemExit("performance comparison failed: device identity changed")

    startup_overhead = overhead_percent(
        baseline["startupMs"]["p95"], protected["startupMs"]["p95"]
    )
    memory_overhead = overhead_percent(
        baseline["totalPssKb"]["median"], protected["totalPssKb"]["median"]
    )
    size_overhead = overhead_percent(
        baseline["artifactBytes"], protected["artifactBytes"]
    )
    startup_absolute_delta = max(
        0, protected["startupMs"]["p95"] - baseline["startupMs"]["p95"]
    )

    passed = (
        startup_overhead <= args.max_startup_percent
        and startup_absolute_delta <= args.max_startup_delta_ms
        and memory_overhead <= args.max_memory_percent
        and size_overhead <= args.max_size_percent
    )

    result = {
        "schema": 1,
        "environment": protected["device"],
        "baseline": {
            "startupP50Ms": baseline["startupMs"]["p50"],
            "startupP95Ms": baseline["startupMs"]["p95"],
            "memoryMedianPssKb": baseline["totalPssKb"]["median"],
            "artifactBytes": baseline["artifactBytes"],
        },
        "protected": {
            "startupP50Ms": protected["startupMs"]["p50"],
            "startupP95Ms": protected["startupMs"]["p95"],
            "memoryMedianPssKb": protected["totalPssKb"]["median"],
            "artifactBytes": protected["artifactBytes"],
        },
        "overhead": {
            "startupP95Percent": round(startup_overhead, 2),
            "startupP95DeltaMs": startup_absolute_delta,
            "memoryMedianPercent": round(memory_overhead, 2),
            "artifactSizePercent": round(size_overhead, 2),
        },
        "budgets": {
            "maxStartupP95Percent": args.max_startup_percent,
            "maxStartupP95DeltaMs": args.max_startup_delta_ms,
            "maxMemoryMedianPercent": args.max_memory_percent,
            "maxArtifactSizePercent": args.max_size_percent,
        },
        "passed": passed,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["overhead"], sort_keys=True))
    if not passed:
        raise SystemExit("Android stable performance budget failed")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    measure_parser = commands.add_parser("measure")
    measure_parser.add_argument("--adb", default="adb")
    measure_parser.add_argument("--apk", required=True)
    measure_parser.add_argument("--package", required=True)
    measure_parser.add_argument("--activity", required=True)
    measure_parser.add_argument("--label", required=True)
    measure_parser.add_argument("--output", required=True)
    measure_parser.add_argument("--warmups", type=int, default=5)
    measure_parser.add_argument("--runs", type=int, default=20)
    measure_parser.set_defaults(func=measure)

    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--baseline", required=True)
    compare_parser.add_argument("--protected", required=True)
    compare_parser.add_argument("--output", required=True)
    compare_parser.add_argument("--max-startup-percent", type=float, default=100.0)
    compare_parser.add_argument("--max-startup-delta-ms", type=int, default=250)
    compare_parser.add_argument("--max-memory-percent", type=float, default=75.0)
    compare_parser.add_argument("--max-size-percent", type=float, default=100.0)
    compare_parser.set_defaults(func=compare)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"android-performance: {error}", file=sys.stderr)
        raise
