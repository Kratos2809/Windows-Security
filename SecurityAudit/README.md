# Windows Security Audit Script

This PowerShell script automates the security audit of your Windows system by checking:
- Windows firewall status
- Critical system file permissions
- Users with administrative rights

## Prerequisites

- Windows 10 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrative rights to run the script

## Usage

1. Open PowerShell as administrator
2. Navigate to the script directory
3. Run the script with the command:
   ```powershell
   .\SecurityAudit.ps1
   ```

## Results

The script generates a detailed HTML report in the "Reports" subfolder containing:
- A summary of the firewall status for each profile
- Critical system folder permissions
- List of users with administrative rights

The report is timestamped and easily viewable in a web browser.

## Security Notes

- Always run this script with administrative privileges
- Regularly check the results to identify potential security issues
- Keep reports in a secure location for historical tracking
