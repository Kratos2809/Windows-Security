# Windows Login Brute Force Simulator

This PowerShell script simulates brute force attacks on Windows login for security testing purposes. It helps understand how Windows responds to repeated failed login attempts.

⚠️ **WARNING: This tool is for educational and testing purposes only. Use it only on test systems with proper authorization.**

## Features

- Simulates login attempts using a password list
- Configurable delay between attempts
- Detailed logging of all attempts
- System security policy analysis
- Customizable maximum attempts
- Progress monitoring and statistics

## Prerequisites

- Windows 10 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrative privileges
- A test system (never use on production systems)

## Usage

1. Create a wordlist file (wordlist.txt) with passwords to test
2. Run the script with desired parameters:

```powershell
.\WindowsLoginBruteForceSimulator.ps1 -Username "testuser" -PasswordList ".\wordlist.txt" -DelaySeconds 2 -MaxAttempts 10
```

### Parameters

- `-Username`: Target username (default: current user)
- `-PasswordList`: Path to password list file (default: .\wordlist.txt)
- `-DelaySeconds`: Delay between attempts in seconds (default: 2)
- `-MaxAttempts`: Maximum number of attempts (default: 10)

## Output

The script generates:
- Real-time console output
- Detailed log file (bruteforce_log.txt)
- System security policy information
- Statistics about the simulation

## Security Notes

- This tool is for educational purposes only
- Always obtain proper authorization before testing
- Use only on test systems
- Never use on production or critical systems
- Be aware of local security policies and regulations

## Legal Disclaimer

This tool is provided for educational purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.
