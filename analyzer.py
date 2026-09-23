import argparse
import csv
import os
from collections import Counter
from datetime import datetime


def read_logs(log_file):
    events = []

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                # Expected format:
                # DATE TIME STATUS IP USERNAME OS
                parts = line.split()

                if len(parts) >= 6:
                    date = parts[0]
                    time = parts[1]
                    status = parts[2]
                    ip = parts[3]
                    username = parts[4]
                    operating_system = parts[5]

                    try:
                        timestamp = datetime.strptime(
                            f"{date} {time}",
                            "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        continue

                    events.append({
                        "timestamp": timestamp,
                        "status": status,
                        "ip": ip,
                        "username": username,
                        "os": operating_system
                    })

    except FileNotFoundError:
        print(f"\n[ERROR] Log file not found: {log_file}")
        return []

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

    # Count failed login attempts by IP
    failed_ips = Counter(
        event["ip"] for event in failed_logins
    )

    # Count failed login attempts by username
    failed_users = Counter(
        event["username"] for event in failed_logins
    )

    # Count operating systems in all log events
    operating_systems = Counter(
        event["os"] for event in events
    )

    # Count failed login attempts by operating system
    failed_os = Counter(
        event["os"] for event in failed_logins
    )

    return (
        failed_logins,
        successful_logins,
        failed_ips,
        failed_users,
        operating_systems,
        failed_os
    )


def determine_severity(failed_count):
    if failed_count >= 20:
        return "CRITICAL"
    elif failed_count >= 10:
        return "HIGH"
    elif failed_count >= 5:
        return "MEDIUM"
    elif failed_count > 0:
        return "LOW"

    return "NONE"


def detect_bruteforce(failed_logins):
    alerts = []

    # Get unique IP addresses
    unique_ips = set(
        event["ip"] for event in failed_logins
    )

    for ip in unique_ips:

        # Get failed events for this IP
        ip_events = [
            event for event in failed_logins
            if event["ip"] == ip
        ]

        # Sort by time
        ip_events.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(len(ip_events)):

            count = 1
            start_time = ip_events[i]["timestamp"]

            for j in range(i + 1, len(ip_events)):

                time_difference = (
                    ip_events[j]["timestamp"]
                    - start_time
                ).total_seconds()

                if time_difference <= 60:
                    count += 1
                else:
                    break

            # Five or more failures within 60 seconds
            if count >= 5:

                alerts.append({
                    "ip": ip,
                    "attempts": count,
                    "start_time": start_time
                })

                break

    return alerts


def create_csv_report(
    failed_ips,
    failed_users,
    operating_systems,
    failed_os,
    alerts
):
    # Automatically create reports folder
    os.makedirs("reports", exist_ok=True)

    with open(
        "reports/security_report.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        # CSV header
        writer.writerow([
            "Type",
            "Indicator",
            "Count",
            "Severity"
        ])

        # Failed login IP addresses
        for ip, count in failed_ips.most_common():

            writer.writerow([
                "IP Address",
                ip,
                count,
                determine_severity(count)
            ])

        # Targeted usernames
        for username, count in failed_users.most_common():

            writer.writerow([
                "Username",
                username,
                count,
                determine_severity(count)
            ])

        # Operating system totals
        for operating_system, count in operating_systems.most_common():

            writer.writerow([
                "Operating System",
                operating_system,
                count,
                "INFO"
            ])

        # Failed attempts by operating system
        for operating_system, count in failed_os.most_common():

            writer.writerow([
                "Failed Login OS",
                operating_system,
                count,
                determine_severity(count)
            ])

        # Brute-force alerts
        for alert in alerts:

            writer.writerow([
                "Brute Force",
                alert["ip"],
                alert["attempts"],
                determine_severity(alert["attempts"])
            ])


def display_report(
    events,
    failed_logins,
    successful_logins,
    failed_ips,
    failed_users,
    operating_systems,
    failed_os,
    alerts
):

    print("\n" + "=" * 65)
    print("                  SOC LOG ANALYZER")
    print("=" * 65)

    print(f"\nTotal events:         {len(events)}")
    print(f"Successful logins:   {len(successful_logins)}")
    print(f"Failed logins:       {len(failed_logins)}")

    # --------------------------------------------------
    # TOP ATTACKING IPs
    # --------------------------------------------------

    print("\nTOP ATTACKING IPs")
    print("-" * 65)

    if failed_ips:

        for ip, count in failed_ips.most_common():

            severity = determine_severity(count)

            print(
                f"{ip:<18} "
                f"{count:<5} attempts "
                f"[{severity}]"
            )

    else:
        print("No failed login attempts detected.")

    # --------------------------------------------------
    # TARGETED USERNAMES
    # --------------------------------------------------

    print("\nTARGETED USERNAMES")
    print("-" * 65)

    if failed_users:

        for username, count in failed_users.most_common():

            severity = determine_severity(count)

            print(
                f"{username:<18} "
                f"{count:<5} attempts "
                f"[{severity}]"
            )

    else:
        print("No targeted usernames detected.")

    # --------------------------------------------------
    # OPERATING SYSTEMS
    # --------------------------------------------------

    print("\nOPERATING SYSTEMS")
    print("-" * 65)

    for operating_system, count in operating_systems.most_common():

        print(
            f"{operating_system:<20} "
            f"{count:<5} events"
        )

    # --------------------------------------------------
    # FAILED LOGINS BY OS
    # --------------------------------------------------

    print("\nFAILED LOGINS BY OPERATING SYSTEM")
    print("-" * 65)

    if failed_os:

        for operating_system, count in failed_os.most_common():

            severity = determine_severity(count)

            print(
                f"{operating_system:<20} "
                f"{count:<5} failed "
                f"[{severity}]"
            )

    else:
        print("No failed login activity detected.")

    # --------------------------------------------------
    # BRUTE FORCE ALERTS
    # --------------------------------------------------

    print("\nBRUTE-FORCE ALERTS")
    print("-" * 65)

    if alerts:

        for alert in alerts:

            severity = determine_severity(
                alert["attempts"]
            )

            print(
                f"{alert['ip']} -> "
                f"{alert['attempts']} attempts "
                f"within approximately 60 seconds "
                f"[{severity}]"
            )

    else:
        print("No brute-force pattern detected.")

    # --------------------------------------------------
    # REPORT
    # --------------------------------------------------

    print("\nREPORT")
    print("-" * 65)

    print(
        "CSV report saved to: "
        "reports/security_report.csv"
    )

    print("=" * 65)


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Analyze authentication logs for "
            "suspicious security activity."
        )
    )

    parser.add_argument(
        "-f",
        "--file",
        default="logs/sample.log",
        help="Path to the log file"
    )

    args = parser.parse_args()

    # Read the log file
    events = read_logs(args.file)

    if not events:
        return

    # Analyze events
    (
        failed_logins,
        successful_logins,
        failed_ips,
        failed_users,
        operating_systems,
        failed_os
    ) = analyze_logs(events)

    # Detect possible brute-force activity
    alerts = detect_bruteforce(
        failed_logins
    )

    # Create CSV report
    create_csv_report(
        failed_ips,
        failed_users,
        operating_systems,
        failed_os,
        alerts
    )

    # Display report
    display_report(
        events,
        failed_logins,
        successful_logins,
        failed_ips,
        failed_users,
        operating_systems,
        failed_os,
        alerts
    )


if __name__ == "__main__":
    main()