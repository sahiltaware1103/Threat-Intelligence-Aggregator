from collections import defaultdict

def correlate_iocs(normalized_iocs):
    correlation = defaultdict(lambda: {
        "count": 0,
        "sources": set(),
        "type": "",
        "severity": "Low"
    })

    for item in normalized_iocs:
        key = item["indicator"]

        correlation[key]["count"] += 1
        correlation[key]["sources"].add(item["source"])
        correlation[key]["type"] = item["type"]

    # Assign severity
    for indicator, data in correlation.items():
        if data["count"] >= 4:
            data["severity"] = "High"
        elif data["count"] >= 2:
            data["severity"] = "Medium"
        else:
            data["severity"] = "Low"

    return correlation
