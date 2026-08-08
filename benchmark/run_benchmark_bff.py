#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ROOT_DIR = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT_DIR / "benchmark"
RESULTS_DIR = BENCH_DIR / "results"
LOCUST_FILE = BENCH_DIR / "locustfile_bff.py"

BFF_URL = os.getenv("BFF_URL", "https://127.0.0.1:5001")
USERNAME = os.getenv("BFF_TEST_USERNAME", "vinh")
PASSWORD = os.getenv("BFF_TEST_PASSWORD", "Vinh@123!")

LOCUST_SCENARIOS = [
    {"name": "locust_10", "users": 10, "spawn_rate": 2, "duration": "60s"},
    {"name": "locust_50", "users": 50, "spawn_rate": 5, "duration": "60s"},
    {"name": "locust_100", "users": 100, "spawn_rate": 10, "duration": "60s"},
]

WRK_CONNECTIONS = [10, 50, 100]
WRK_THREADS = 4
WRK_DURATION = "60s"


def run_cmd(
    cmd: list[str],
    *,
    cwd: Path = ROOT_DIR,
    env: dict[str, str] | None = None,
    log_file: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    print()
    print("=" * 80)
    print("[RUN]", " ".join(shlex.quote(x) for x in cmd))
    print("=" * 80)

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", encoding="utf-8", errors="replace") as f:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                env=merged_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            print(proc.stdout)
            f.write(proc.stdout)

            if check and proc.returncode != 0:
                raise RuntimeError(f"Command failed: {cmd}")

            return proc

    proc = subprocess.run(cmd, cwd=str(cwd), env=merged_env, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}")
    return proc


def check_prerequisites() -> None:
    print("[CHECK] Project root:", ROOT_DIR)

    if not LOCUST_FILE.is_file():
        raise FileNotFoundError(f"Missing {LOCUST_FILE}")

    for binary in ("docker", "wrk"):
        result = subprocess.run(
            ["which", binary],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Missing required command: {binary}")

    result = subprocess.run(
        [sys.executable, "-m", "locust", "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise RuntimeError("Locust is not installed in current Python environment")

    try:
        resp = requests.get(f"{BFF_URL}/", verify=False, timeout=5)
        print(f"[CHECK] BFF / status = {resp.status_code}")
        if resp.status_code != 200:
            raise RuntimeError("BFF is not responding with HTTP 200")
    except Exception as exc:
        raise RuntimeError(
            f"Cannot connect to BFF at {BFF_URL}. "
            f"Start BFF first: python3 -u client_app/app.py. Error: {exc}"
        ) from exc


def find_resource_container() -> str:
    proc = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    names = proc.stdout.splitlines()
    for name in names:
        if name in ("resource-api", "zero-trust-resource-api"):
            return name

    for name in names:
        if "resource" in name:
            return name

    raise RuntimeError("Cannot find Resource API container")


def docker_stats_collector(output_file: Path, stop_event: threading.Event) -> None:
    resource_container = find_resource_container()
    containers = [
        "zero-trust-gateway",
        "auth-service",
        resource_container,
    ]

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp",
            "container",
            "cpu_percent",
            "mem_usage",
            "mem_percent",
            "net_io",
            "block_io",
            "pids",
        ])

        while not stop_event.is_set():
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            cmd = [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}",
                *containers,
            ]

            proc = subprocess.run(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            for line in proc.stdout.splitlines():
                parts = line.split(",", maxsplit=6)
                if len(parts) == 7:
                    writer.writerow([ts, *parts])

            f.flush()
            time.sleep(1)


def run_with_stats(name: str, benchmark_func) -> None:
    stats_file = RESULTS_DIR / f"docker_stats_{name}.csv"
    stop_event = threading.Event()

    collector = threading.Thread(
        target=docker_stats_collector,
        args=(stats_file, stop_event),
        daemon=True,
    )

    print(f"[STATS] Collecting docker stats → {stats_file}")
    collector.start()

    try:
        benchmark_func()
    finally:
        stop_event.set()
        collector.join(timeout=3)
        print(f"[STATS] Saved docker stats → {stats_file}")


def run_locust_scenario(scenario: dict) -> None:
    name = scenario["name"]
    users = scenario["users"]
    spawn_rate = scenario["spawn_rate"]
    duration = scenario["duration"]

    env = {
        "BFF_TEST_USERNAME": USERNAME,
        "BFF_TEST_PASSWORD": PASSWORD,
    }

    csv_prefix = RESULTS_DIR / name
    html_report = RESULTS_DIR / f"{name}_report.html"
    log_file = RESULTS_DIR / f"{name}.log"

    def bench():
        run_cmd(
            [
                sys.executable,
                "-m",
                "locust",
                "-f",
                str(LOCUST_FILE),
                "--headless",
                "-u",
                str(users),
                "-r",
                str(spawn_rate),
                "-t",
                duration,
                "--host",
                BFF_URL,
                "--csv",
                str(csv_prefix),
                "--html",
                str(html_report),
                "--print-stats",
            ],
            env=env,
            log_file=log_file,
        )

    print(f"[LOCUST] Scenario {name}: users={users}, spawn_rate={spawn_rate}, duration={duration}")
    run_with_stats(name, bench)


def login_and_get_cookie() -> str:
    print("[LOGIN] Login to BFF for wrk protected session cookie")

    session = requests.Session()
    session.verify = False

    resp = session.post(
        f"{BFF_URL}/login",
        data={
            "username": USERNAME,
            "password": PASSWORD,
        },
        allow_redirects=True,
        timeout=10,
    )

    print("[LOGIN] HTTP", resp.status_code)

    if resp.status_code != 200:
        raise RuntimeError(f"Login failed: HTTP {resp.status_code}")

    cookie_value = session.cookies.get("session")

    if not cookie_value:
        raise RuntimeError("No session cookie returned from BFF")

    print("[LOGIN] Session cookie length:", len(cookie_value))
    return cookie_value


def run_wrk_public(connections: int) -> None:
    name = f"wrk_public_{connections}"
    log_file = RESULTS_DIR / f"{name}.log"

    def bench():
        run_cmd(
            [
                "wrk",
                "--latency",
                "-t",
                str(WRK_THREADS),
                "-c",
                str(connections),
                "-d",
                WRK_DURATION,
                f"{BFF_URL}/public",
            ],
            log_file=log_file,
        )

    print(f"[WRK] Public: connections={connections}, duration={WRK_DURATION}")
    run_with_stats(name, bench)


def run_wrk_protected(connections: int, session_cookie: str) -> None:
    name = f"wrk_protected_{connections}"
    log_file = RESULTS_DIR / f"{name}.log"

    def bench():
        run_cmd(
            [
                "wrk",
                "--latency",
                "-t",
                str(WRK_THREADS),
                "-c",
                str(connections),
                "-d",
                WRK_DURATION,
                "-H",
                f"Cookie: session={session_cookie}",
                f"{BFF_URL}/protected",
            ],
            log_file=log_file,
        )

    print(f"[WRK] Protected: connections={connections}, duration={WRK_DURATION}")
    run_with_stats(name, bench)


def parse_wrk_result(log_file: Path) -> dict[str, str]:
    """
    Parse wrk output.

    Important:
    - wrk only prints 50% / 75% / 90% / 99% when it is run with --latency.
    - This function extracts P90/P99 from the "Latency Distribution" section.
    """
    text = log_file.read_text(encoding="utf-8", errors="replace")

    result = {
        "file": log_file.name,
        "total_requests": "",
        "requests_sec": "",
        "avg_latency": "",
        "p90": "",
        "p99": "",
        "errors": "",
        "non_2xx_3xx": "",
    }

    m = re.search(r"(\d+)\s+requests in", text)
    if m:
        result["total_requests"] = m.group(1)

    m = re.search(r"Requests/sec:\s+([0-9.]+)", text)
    if m:
        result["requests_sec"] = m.group(1)

    # Example line:
    # Latency    12.34ms   10.20ms  98.76ms   88.00%
    m = re.search(r"^\s*Latency\s+([0-9.]+\s*[a-zA-Zµ]+)", text, re.MULTILINE)
    if m:
        result["avg_latency"] = m.group(1).replace(" ", "")

    # Example lines printed by wrk --latency:
    # 90%   15.23ms
    # 99%   45.10ms
    m = re.search(r"^\s*90%\s+([0-9.]+\s*[a-zA-Zµ]+)", text, re.MULTILINE)
    if m:
        result["p90"] = m.group(1).replace(" ", "")

    m = re.search(r"^\s*99%\s+([0-9.]+\s*[a-zA-Zµ]+)", text, re.MULTILINE)
    if m:
        result["p99"] = m.group(1).replace(" ", "")

    m = re.search(r"Socket errors:.*", text)
    if m:
        result["errors"] = m.group(0)

    m = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", text)
    if m:
        result["non_2xx_3xx"] = m.group(1)

    return result


def write_wrk_summary() -> None:
    summary_file = RESULTS_DIR / "wrk_summary.csv"

    rows = []
    for log_file in sorted(RESULTS_DIR.glob("wrk_*.log")):
        rows.append(parse_wrk_result(log_file))

    with summary_file.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "file",
            "total_requests",
            "requests_sec",
            "avg_latency",
            "p90",
            "p99",
            "errors",
            "non_2xx_3xx",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("[SUMMARY] wrk summary saved:", summary_file)


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("ZERO-TRUST BFF BENCHMARK RUNNER")
    print("=" * 80)
    print("BFF_URL =", BFF_URL)
    print("USERNAME =", USERNAME)
    print("RESULTS_DIR =", RESULTS_DIR)

    check_prerequisites()

    print()
    print("===== DOCKER CONTAINERS =====")
    run_cmd(
        ["docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"],
        check=False,
    )

    print()
    print("===== LOCUST BENCHMARKS =====")
    for scenario in LOCUST_SCENARIOS:
        run_locust_scenario(scenario)

    print()
    print("===== WRK PUBLIC BENCHMARKS =====")
    for c in WRK_CONNECTIONS:
        run_wrk_public(c)

    print()
    print("===== WRK PROTECTED BENCHMARKS =====")
    session_cookie = login_and_get_cookie()
    for c in WRK_CONNECTIONS:
        run_wrk_protected(c, session_cookie)

    write_wrk_summary()

    print()
    print("=" * 80)
    print("DONE. Results saved in:", RESULTS_DIR)
    print("=" * 80)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        raise SystemExit(130)
    except Exception as exc:
        print("\n[ERROR]", exc)
        raise SystemExit(1)
