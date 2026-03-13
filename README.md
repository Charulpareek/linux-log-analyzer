# Linux SSH Log Analyzer

A Python CLI tool that analyzes Linux SSH authentication logs to detect suspicious login attempts and brute-force attacks.

## Features
- Detect failed SSH login attempts
- Identify suspicious IP addresses
- GeoIP attacker tracking
- Real-time monitoring dashboard
- Generate JSON and CSV reports

## Technologies Used
- Python
- Regex
- Rich (terminal dashboard)
- GeoIP API

## Usage

Analyze logs:

python log_analyzer.py --file sample_logs/auth.log

Real-time monitoring:

python log_analyzer.py --file sample_logs/auth.log --monitor
