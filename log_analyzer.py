import re
import json
import csv
import argparse
import time
import os
import requests
import ipaddress
from collections import defaultdict

from rich.live import Live
from rich.table import Table
from rich.console import Console

# -----------------------------
# Argument Parser
# -----------------------------
parser = argparse.ArgumentParser(description="SOC SSH Log Analyzer")

parser.add_argument("--file", nargs="+", required=True, help="Log file path")
parser.add_argument("--monitor", action="store_true", help="Enable live monitoring")
parser.add_argument("--summary", action="store_true", help="Summary only")

args = parser.parse_args()

console = Console()

# -----------------------------
# Data Storage
# -----------------------------
failed_logins = 0
system_errors = 0

ip_attempts = defaultdict(int)
country_stats = defaultdict(int)

geo_cache = {}

# -----------------------------
# Private IP Detection
# -----------------------------
def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


# -----------------------------
# GeoIP Lookup (with caching)
# -----------------------------
def get_geoip(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    if is_private(ip):
        result = {
            "country": "Private Network",
            "city": "Internal",
            "isp": "Internal"
        }
        geo_cache[ip] = result
        return result

    try:
        url = f"http://ip-api.com/json/{ip}"
        r = requests.get(url, timeout=3)
        data = r.json()

        if data["status"] == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }

            geo_cache[ip] = result
            return result

    except:
        pass

    result = {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown"
    }

    geo_cache[ip] = result
    return result


# -----------------------------
# Process Log Line
# -----------------------------
def process_line(line):

    global failed_logins, system_errors

    if "Failed password" in line:

        failed_logins += 1

        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)

        if ip_match:
            ip = ip_match.group()
            ip_attempts[ip] += 1

    if "error" in line.lower():
        system_errors += 1


# -----------------------------
# Analyze Files
# -----------------------------
def analyze_files(files):

    for file in files:

        if not os.path.exists(file):
            console.print(f"[red]Warning:[/red] {file} not found")
            continue

        with open(file, "r", errors="ignore") as f:
            for line in f:
                process_line(line)


# -----------------------------
# Build Dashboard Table
# -----------------------------
def generate_dashboard():

    table = Table(title="🚨 Live SSH Attack Monitor")

    table.add_column("IP Address", style="cyan")
    table.add_column("Attempts", style="magenta")
    table.add_column("Country", style="green")

    sorted_ips = sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:10]:

        geo = get_geoip(ip)

        table.add_row(
            ip,
            str(count),
            geo["country"]
        )

    return table


# -----------------------------
# Real-Time Monitoring
# -----------------------------
def monitor_file(file):

    if not os.path.exists(file):
        console.print("[red]File not found[/red]")
        return

    console.print("\n[bold green]Real-Time Monitoring Started[/bold green]")
    console.print("Press CTRL+C to stop\n")

    last_size = os.path.getsize(file)

    with Live(generate_dashboard(), refresh_per_second=2, console=console) as live:

        while True:

            try:

                current_size = os.path.getsize(file)

                if current_size > last_size:

                    with open(file, "r", errors="ignore") as f:

                        f.seek(last_size)
                        new_lines = f.readlines()

                    last_size = current_size

                    for line in new_lines:

                        process_line(line)

                        if "Failed password" in line:

                            ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)

                            if ip_match:

                                ip = ip_match.group()

                                console.print(f"[yellow]ALERT[/yellow] Failed login from {ip}")

                                if ip_attempts[ip] >= 5:
                                    console.print(f"[red]BRUTE FORCE SUSPECTED[/red] {ip}")

                live.update(generate_dashboard())

            except FileNotFoundError:
                pass

            time.sleep(1)


# -----------------------------
# Run Analysis
# -----------------------------
analyze_files(args.file)


# -----------------------------
# Summary Mode
# -----------------------------
if args.summary:

    console.print("\n[bold]Security Summary[/bold]")

    console.print(f"Failed Logins: {failed_logins}")
    console.print(f"Unique IPs: {len(ip_attempts)}")

    exit()


# -----------------------------
# Standard Output
# -----------------------------
console.print("\n[bold]===== Linux Log Analysis =====[/bold]")

console.print(f"\nFailed Login Attempts: {failed_logins}")
console.print(f"System Errors: {system_errors}")

console.print("\nLogin Attempts by IP")

for ip, count in ip_attempts.items():
    console.print(f"{ip} -> {count}")


# -----------------------------
# Suspicious IP Detection
# -----------------------------
console.print("\n[bold]Suspicious IPs[/bold]")

for ip, count in ip_attempts.items():

    if count >= 3:
        console.print(f"[yellow]⚠ {ip}[/yellow]")


# -----------------------------
# Top Attackers
# -----------------------------
sorted_ips = sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)

console.print("\n[bold]Top Attackers[/bold]")

for ip, count in sorted_ips[:5]:
    console.print(f"{ip} -> {count}")


# -----------------------------
# GeoIP Tracking
# -----------------------------
console.print("\n[bold]Attacker GeoIP[/bold]")

for ip, count in sorted_ips:

    geo = get_geoip(ip)

    console.print(
        f"{ip} -> {geo['country']} | {geo['city']} | {geo['isp']}"
    )

    country_stats[geo["country"]] += count


# -----------------------------
# Country Summary
# -----------------------------
console.print("\n[bold]Attack Origin Countries[/bold]")

for c, count in country_stats.items():
    console.print(f"{c} -> {count}")


# -----------------------------
# JSON Report
# -----------------------------
report = {
    "failed_logins": failed_logins,
    "errors": system_errors,
    "ip_attempts": dict(ip_attempts),
    "countries": dict(country_stats)
}

with open("report.json", "w") as f:
    json.dump(report, f, indent=4)

console.print("\nJSON report saved")


# -----------------------------
# CSV Report
# -----------------------------
with open("attack_report.csv", "w", newline="") as f:

    writer = csv.writer(f)

    writer.writerow(["IP", "Attempts"])

    for ip, count in ip_attempts.items():
        writer.writerow([ip, count])

console.print("CSV report saved")


# -----------------------------
# Start Monitoring
# -----------------------------
try:

    if args.monitor:
        monitor_file(args.file[0])

except KeyboardInterrupt:
    console.print("\nMonitoring stopped")