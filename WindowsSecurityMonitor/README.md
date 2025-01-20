# Windows Security Monitor

A comprehensive Windows security monitoring tool that tracks critical events, services, system files, and security policies in real-time.

## Features

### 1. Windows Event Monitoring
- Analysis of critical security events
- Detection of failed login attempts
- Tracking of privilege modifications
- Custom event filtering

### 2. Service Monitoring
- Monitoring of critical services (Windows Defender, Firewall, etc.)
- Detection of unauthorized service stops
- Automatic restart of critical services
- Service state analysis

### 3. System File Monitoring
- Detection of changes in system directories
- File signature verification (MD5/SHA256)
- Alert on suspicious modifications
- Real-time change tracking

### 4. Security Policy Monitoring
- Password settings verification
- Account lockout policy tracking
- Policy modification detection
- Security recommendations

### 5. Reports and Alerts
- Real-time interface with Rich
- Detailed report generation
- Instant alerts
- Automatic recommendations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/WindowsSecurityMonitor.git
cd WindowsSecurityMonitor
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Launch the monitoring tool:
```bash
python main.py
```

2. The interface will display in real-time:
- Recent security events
- Critical service status
- System file modifications
- Policy changes

3. Reports are automatically generated in the `reports/` folder

## Configuration

Monitoring parameters can be adjusted in the configuration files:

- `monitor/event_monitor.py`: Configuration of events to monitor
- `monitor/service_monitor.py`: List of critical services
- `monitor/file_monitor.py`: Directories and files to monitor
- `monitor/policy_monitor.py`: Security policy thresholds

## Dependencies

- Python 3.8+
- pywin32
- wmi
- psutil
- rich
- cryptography

## Security

This tool requires administrator privileges to function properly. It is recommended to:

1. Run the tool with an administrator account
2. Restrict access to configuration files
3. Secure generated reports
4. Regularly check tool logs

## Contributing

Contributions are welcome! To contribute:

1. Fork the project
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is under the MIT License. See the `LICENSE` file for more details.

## Support

For questions or issues:

1. Open an issue on GitHub
2. Check the documentation
3. Contact the support team

---

Developed with ❤️ for Windows security
