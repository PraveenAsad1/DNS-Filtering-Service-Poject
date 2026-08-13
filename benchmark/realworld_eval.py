"""
Real-world evaluation: tests the DNS proxy against actual published threat
intel (URLhaus malicious domains) and actual popular clean domains (Cisco
Umbrella top list), instead of synthetic test strings.

Usage:
    python realworld_eval.py --malicious-sample 100 --clean-sample 100
"""

import argparse
import random
import dns.message
import dns.query

DNS_SERVER = "127.0.0.1"
DNS_PORT = 1053


def load_malicious_domains(path="urlhaus_raw.txt"):
    domains = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                domains.append(parts[1])
    return domains


def load_clean_domains(path="umbrella_data/top-1m.csv"):
    domains = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) == 2:
                domains.append(parts[1])
    return domains


def query_domain(domain):
    """Returns 'blocked', 'allowed', or 'error'."""
    try:
        query = dns.message.make_query(domain, "A")
        response = dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)
        for answer in response.answer:
            for item in answer.items:
                if hasattr(item, "address") and item.address == "0.0.0.0":
                    return "blocked"
        return "allowed"
    except Exception:
        return "error"


def run_evaluation(malicious_sample_size, clean_sample_size, seed=42):
    random.seed(seed)  # reproducible sampling

    malicious_domains = load_malicious_domains()
    clean_domains = load_clean_domains()

    print(f"Loaded {len(malicious_domains)} real malicious domains (URLhaus)")
    print(f"Loaded {len(clean_domains)} real clean domains (Cisco Umbrella)")

    malicious_sample = random.sample(malicious_domains, min(malicious_sample_size, len(malicious_domains)))
    clean_sample = random.sample(clean_domains, min(clean_sample_size, len(clean_domains)))

    print(f"\nTesting {len(malicious_sample)} malicious domains...")
    malicious_results = {"blocked": 0, "allowed": 0, "error": 0}
    for domain in malicious_sample:
        result = query_domain(domain)
        malicious_results[result] += 1

    print(f"Testing {len(clean_sample)} clean domains...")
    clean_results = {"blocked": 0, "allowed": 0, "error": 0}
    for domain in clean_sample:
        result = query_domain(domain)
        clean_results[result] += 1

    total_malicious_tested = len(malicious_sample) - malicious_results["error"]
    total_clean_tested = len(clean_sample) - clean_results["error"]

    detection_rate = (malicious_results["blocked"] / total_malicious_tested * 100) if total_malicious_tested else 0
    false_positive_rate = (clean_results["blocked"] / total_clean_tested * 100) if total_clean_tested else 0

    print("\n" + "=" * 55)
    print("REAL-WORLD EVALUATION RESULTS")
    print("=" * 55)
    print(f"\nMalicious domains (URLhaus, real active threat feed):")
    print(f"  Tested:              {len(malicious_sample)}")
    print(f"  Blocked (caught):    {malicious_results['blocked']}")
    print(f"  Allowed (missed):    {malicious_results['allowed']}")
    print(f"  Errors:              {malicious_results['error']}")
    print(f"  >> Detection rate:   {detection_rate:.1f}%")

    print(f"\nClean domains (Cisco Umbrella top popularity list):")
    print(f"  Tested:              {len(clean_sample)}")
    print(f"  Blocked (mistake):   {clean_results['blocked']}")
    print(f"  Allowed (correct):   {clean_results['allowed']}")
    print(f"  Errors:              {clean_results['error']}")
    print(f"  >> False positive rate: {false_positive_rate:.1f}%")

    print("=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-world evaluation against actual threat intel")
    parser.add_argument("--malicious-sample", type=int, default=100)
    parser.add_argument("--clean-sample", type=int, default=100)
    args = parser.parse_args()

    run_evaluation(args.malicious_sample, args.clean_sample)
