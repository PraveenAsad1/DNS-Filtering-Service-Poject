"""
Honest held-out evaluation: tests detection specifically against URLhaus domains
that were NEVER ingested into the blocklist (see split_holdout.py). Any domain
caught here is caught genuinely by the typosquat or heuristic layers, not by
blocklist lookup — this measures real detection capability on unseen threats,
not memorization.
"""

import random
import dns.message
import dns.query

DNS_SERVER = "127.0.0.1"
DNS_PORT = 1053


def load_domains(path):
    domains = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                domains.append(line)
    return domains


def load_clean_domains(path="umbrella_data/top-1m.csv", sample_size=100, seed=42):
    domains = []
    with open(path) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                domains.append(parts[1])
    random.seed(seed)
    return random.sample(domains, min(sample_size, len(domains)))


def query_domain(domain):
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


def run():
    heldout_malicious = load_domains("heldout_eval.txt")
    clean_sample = load_clean_domains()

    print(f"Held-out malicious domains (never in blocklist): {len(heldout_malicious)}")
    print(f"Clean domain sample: {len(clean_sample)}")

    print("\nTesting held-out malicious domains...")
    malicious_results = {"blocked": 0, "allowed": 0, "error": 0}
    for domain in heldout_malicious:
        result = query_domain(domain)
        malicious_results[result] += 1

    print("Testing clean domains...")
    clean_results = {"blocked": 0, "allowed": 0, "error": 0}
    for domain in clean_sample:
        result = query_domain(domain)
        clean_results[result] += 1

    tested_malicious = len(heldout_malicious) - malicious_results["error"]
    tested_clean = len(clean_sample) - clean_results["error"]

    detection_rate = (malicious_results["blocked"] / tested_malicious * 100) if tested_malicious else 0
    false_positive_rate = (clean_results["blocked"] / tested_clean * 100) if tested_clean else 0

    print("\n" + "=" * 60)
    print("HELD-OUT EVALUATION RESULTS")
    print("(measures typosquat + heuristic layers only — blocklist excluded)")
    print("=" * 60)
    print(f"\nHeld-out malicious domains (real URLhaus, never ingested):")
    print(f"  Tested:              {len(heldout_malicious)}")
    print(f"  Caught (blocked):    {malicious_results['blocked']}")
    print(f"  Missed (allowed):    {malicious_results['allowed']}")
    print(f"  Errors:              {malicious_results['error']}")
    print(f"  >> Detection rate:   {detection_rate:.1f}%")

    print(f"\nClean domains (Cisco Umbrella top popularity list):")
    print(f"  Tested:              {len(clean_sample)}")
    print(f"  Blocked (mistake):   {clean_results['blocked']}")
    print(f"  Allowed (correct):   {clean_results['allowed']}")
    print(f"  >> False positive rate: {false_positive_rate:.1f}%")
    print("=" * 60)


if __name__ == "__main__":
    run()
