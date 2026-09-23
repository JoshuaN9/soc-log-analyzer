from collections import Counter


LOG_FILE = "logs/sample.log"


def read_logs():
    events = []

    with open(LOG_FILE, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) >= 5:
                date = parts[0]
                time = parts[1]
                status = parts[2]
                ip = parts[3]
                username = parts[4]

                events.append({
                    "date": date,
                    "time": time,
                    "status": status,
                    "ip": ip,
                    "username": username
                })

    return events


def analyze_logs(events):
    failed_logins = [
        event for event in events
        if event["status"] == "FAILED"
    ]

    successful_logins = [
        event for event in events
        if event["status"] == "SUCCESS"
    ]

    failed_ips = Counter(
        event["ip"] for event in failed_logins
    )

    return failed_logins, successful_logins, failed_ips


def display_report(events, failed_logins, successful_logins, failed_ips):

    print("=" * 50)
    print("             SECURITY LOG ANALYZER")
    print("=" * 50)

    print(f"\nTotal events: {len(events)}")
    print(f"Successful logins: {len(successful_logins)}")
    print(f"Failed logins: {len(failed_logins)}")

    print("\nTop IPs with failed logins:")

    for ip, count in failed_ips.most_common():
        print(f"{ip} -> {count} attempts")

    print("\nPotential brute-force activity:")

    found = False

    for ip, count in failed_ips.items():
        if count >= 5:
            print(f"{ip} -> {count} failed attempts")
            found = True

    if not found:
        print("No obvious brute-force activity detected.")

    print("\nRisk assessment:")

    if any(count >= 5 for count in failed_ips.values()):
        print("HIGH - Possible brute-force activity detected.")
    elif len(failed_logins) > 0:
        print("MEDIUM - Failed login activity detected.")
    else:
        print("LOW - No suspicious login activity detected.")


def main():

    events = read_logs()

    failed_logins, successful_logins, failed_ips = analyze_logs(events)

    display_report(
        events,
        failed_logins,
        successful_logins,
        failed_ips
    )


if __name__ == "__main__":
    main()