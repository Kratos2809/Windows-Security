# Windows Log Analyzer

A forensic tool to analyze Windows event logs and detect suspicious activities.

## Features

- Analysis of failed login attempts
- Detection of user account modifications
- Monitoring of service changes
- Command-line interface with colored output
- Configurable analysis period

## Prerequisites

- Python 3.8+
- Windows Administrator access (to read security logs)
- Python libraries listed in requirements.txt

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

To run the analysis with default parameters (last 24 hours):
```bash
python windows_log_analyzer.py
```

To analyze a specific time period:
```bash
python windows_log_analyzer.py --hours 48
```

## Output

The tool will display:
- Total number of events analyzed
- Failed login attempts
- User account modifications
- Suspicious service changes

Results are displayed with color coding for better readability.

## Security Note

This tool requires administrator privileges to access Windows security logs. Use it responsibly and only on systems you have permission to analyze.
