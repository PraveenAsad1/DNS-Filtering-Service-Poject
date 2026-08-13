"""
Load-testing script for the DNS filtering proxy.
Fires concurrent DNS queries and measures real throughput + latency.

Usage:
    python benchmark.py --requests 200 --concurrency 20
"""

import argparse
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.message
import dns.query

DNS_SERVER = "127.0.0.1"
DNS_PORT = 1053

# Realistic mix: clean domains (forward path), blocklisted (sinkhole path),
# and suspicious-looking domains (heuristic scoring path) — matches the
# actual traffic patterns the proxy was designed to handle.
TEST_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
    "badguy.com", "malware.example.com", "phishing-test.com",
    "aa11-bb22-cc33-dd44-verylongrandomstring123456.tk",
    "x7k9z2m4q8w1r5t3y6u0i.ml",
    "free-download-crack-1234567890-abcdef.ga",
]

# Isolation subsets for root-cause diagnosis:
BLOCKLIST_ONLY = ["badguy.com", "malware.example.com", "phishing-test.com"]
CLEAN_ONLY = ["google.com", "github.com", "wikipedia.org", "stackoverflow.com"]


def send_query(domain):
    """Sends one DNS query and returns (success, latency_ms, error_message)."""
    query = dns.message.make_query(domain, "A")
    start = time.perf_counter()
    try:
        dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)
        latency_ms = (time.perf_counter() - start) * 1000
        return True, latency_ms, None
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return False, latency_ms, str(e)


def percentile(data, pct):
    """Simple percentile calculation without needing numpy."""
    sorted_data = sorted(data)
    index = int(len(sorted_data) * pct / 100)
    index = min(index, len(sorted_data) - 1)
    return sorted_data[index]


def run_benchmark(total_requests, concurrency, mode):
    if mode == "blocklist":
        pool = BLOCKLIST_ONLY
    elif mode == "clean":
        pool = CLEAN_ONLY
    else:
        pool = TEST_DOMAINS
    domains = [pool[i % len(pool)] for i in range(total_requests)]

    latencies = []
    errors = []

    print(f"Firing {total_requests} queries with {concurrency} concurrent workers...")
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_query, d) for d in domains]
        for future in as_completed(futures):
            success, latency_ms, error = future.result()
            if success:
                latencies.append(latency_ms)
            else:
                errors.append(error)

    total_duration = time.perf_counter() - start_time

    print("\n" + "=" * 50)
    print("BENCHMARK RESULTS")
    print("=" * 50)
    print(f"Total requests:      {total_requests}")
    print(f"Successful:          {len(latencies)}")
    print(f"Failed:              {len(errors)}")
    print(f"Total duration:      {total_duration:.2f}s")

    if latencies:
        throughput = len(latencies) / total_duration
        print(f"Throughput:          {throughput:.1f} queries/sec")
        print(f"Avg latency:         {statistics.mean(latencies):.2f} ms")
        print(f"Median (p50):        {percentile(latencies, 50):.2f} ms")
        print(f"p95 latency:         {percentile(latencies, 95):.2f} ms")
        print(f"p99 latency:         {percentile(latencies, 99):.2f} ms")
        print(f"Min / Max:           {min(latencies):.2f} ms / {max(latencies):.2f} ms")

    if errors:
        print(f"\nSample errors (up to 5): {errors[:5]}")

    print("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark the DNS filtering proxy")
    parser.add_argument("--requests", type=int, default=200, help="Total number of queries to send")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent workers")
    parser.add_argument("--mode", choices=["mixed", "blocklist", "clean"], default="mixed", help="Which domain set to test")
    args = parser.parse_args()

    run_benchmark(args.requests, args.concurrency, args.mode)
