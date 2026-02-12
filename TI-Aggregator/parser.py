from blocklist import generate_blocklists
import re

def parse_feed(file_path):
    iocs = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": [],
        "email": []
    }

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            # IP address
            if re.fullmatch(r"\b\d{1,3}(\.\d{1,3}){3}\b", line):
                iocs["ip"].append(line)

            # URL
            elif line.startswith("http://") or line.startswith("https://"):
                iocs["url"].append(line)

            # Email
            elif re.fullmatch(r"[^@]+@[^@]+\.[^@]+", line):
                iocs["email"].append(line)

            # Hash (MD5 / SHA1 / SHA256 by length)
            elif len(line) in [32, 40, 64]:
                iocs["hash"].append(line)

            # Domain
            else:
                iocs["domain"].append(line)

    return iocs


# Run parser on our feed
from normalizer import normalize_iocs
from correlator import correlate_iocs

all_normalized = []

feeds = {
    "feed1": "feeds/feed1.txt",
    "feed2": "feeds/feed2.txt"
}

for feed_name, path in feeds.items():
    parsed = parse_feed(path)
    normalized = normalize_iocs(parsed, feed_name)
    all_normalized.extend(normalized)

correlated = correlate_iocs(all_normalized)

print("\nCORRELATED IOCs:\n")

for indicator, data in correlated.items():
    print(f"{indicator}")
    print(f"  Type     : {data['type']}")
    print(f"  Seen in  : {data['count']} feeds")
    print(f"  Sources  : {', '.join(data['sources'])}")

    print(f"  Severity : {data['severity']}\n")

# ================= BLOCKLIST GENERATION =================

blocklists = generate_blocklists(correlated)

print("===== BLOCKLISTS GENERATED =====\n")

for bl_type, values in blocklists.items():
    print(f"{bl_type.upper()} BLOCKLIST ({len(values)} entries)")
    for v in values:
        print("  ", v)
    print()
