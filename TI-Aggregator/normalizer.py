from datetime import datetime

def normalize_iocs(parsed_iocs, source_name):
    normalized = []
    timestamp = datetime.utcnow().isoformat()

    for ioc_type, values in parsed_iocs.items():
        unique_values = set(values)  # remove duplicates

        for val in unique_values:
            record = {
                "indicator": val,
                "type": ioc_type,
                "source": source_name,
                "timestamp": timestamp,
                "severity": "unknown"
            }
            normalized.append(record)

    return normalized
