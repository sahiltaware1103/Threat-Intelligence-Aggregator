import os

def generate_blocklists(correlated_iocs, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    blocklists = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": []
    }

    for indicator, data in correlated_iocs.items():
        # Only block Medium & High severity
        if data["severity"] in ["Medium", "High"]:
            ioc_type = data["type"]

            if ioc_type in blocklists:
                blocklists[ioc_type].append(indicator)

    # Write blocklist files
    for ioc_type, values in blocklists.items():
        filename = f"{output_dir}/{ioc_type}_blocklist.txt"
        with open(filename, "w") as f:
            for v in sorted(set(values)):
                f.write(v + "\n")

    return blocklists
