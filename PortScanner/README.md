# Port Scanner

A powerful and customizable port scanner written in Python.

## Features

- TCP port scanning
- Open and closed ports detection
- Common services identification
- User-friendly command-line interface
- Multithreading support for fast scanning

## Prerequisites

- Python 3.x

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python port_scanner.py -h                    # Show help
python port_scanner.py -t 192.168.1.1        # Scan a target
python port_scanner.py -t 192.168.1.1 -p 80  # Scan a specific port
```

## Security Note

Use this tool only on networks for which you have permission to perform testing.
