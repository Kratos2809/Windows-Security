# Windows Security Audit Script
# Creation date: 2025-01-17

# Function to create report folder if it doesn't exist
function Create-ReportFolder {
    $reportPath = ".\Reports"
    if (-not (Test-Path -Path $reportPath)) {
        New-Item -ItemType Directory -Path $reportPath | Out-Null
    }
    return $reportPath
}

# Function to check firewall status
function Get-FirewallStatus {
    Write-Host "Checking firewall status..." -ForegroundColor Yellow
    $firewallProfiles = Get-NetFirewallProfile
    $firewallReport = foreach ($profile in $firewallProfiles) {
        [PSCustomObject]@{
            Profile = $profile.Name
            Enabled = $profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction
            DefaultOutboundAction = $profile.DefaultOutboundAction
        }
    }
    return $firewallReport
}

# Function to check critical file permissions
function Get-CriticalFilePermissions {
    Write-Host "Checking critical file permissions..." -ForegroundColor Yellow
    $criticalPaths = @(
        "$env:windir\System32",
        "$env:windir\System32\config",
        "$env:ProgramFiles"
    )
    
    $permissionsReport = foreach ($path in $criticalPaths) {
        try {
            $acl = Get-Acl -Path $path
            [PSCustomObject]@{
                Path = $path
                Owner = $acl.Owner
                AccessRules = ($acl.Access | Select-Object IdentityReference, FileSystemRights)
            }
        }
        catch {
            [PSCustomObject]@{
                Path = $path
                Owner = "Access Error"
                AccessRules = "Not accessible"
            }
        }
    }
    return $permissionsReport
}

# Function to check users with administrative rights
function Get-AdminUsers {
    Write-Host "Checking administrator users..." -ForegroundColor Yellow
    try {
        # Try with French group name first
        $adminUsers = Get-LocalGroupMember -Group "Administrateurs"
    }
    catch {
        try {
            # Fallback to English group name
            $adminUsers = Get-LocalGroupMember -Group "Administrators"
        }
        catch {
            Write-Host "Error accessing administrator group: $_" -ForegroundColor Red
            return @()
        }
    }
    
    $adminReport = foreach ($user in $adminUsers) {
        [PSCustomObject]@{
            Name = $user.Name
            Type = $user.ObjectClass
            Source = $user.PrincipalSource
        }
    }
    return $adminReport
}

# Main function to generate the report
function Generate-SecurityReport {
    $reportPath = Create-ReportFolder
    $date = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $reportFile = Join-Path $reportPath "SecurityAudit_$date.html"

    # Data collection
    $firewallStatus = Get-FirewallStatus
    $filePermissions = Get-CriticalFilePermissions
    $adminUsers = Get-AdminUsers

    # Creating HTML report
    $htmlReport = @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Windows Security Audit Report - $date</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2 { color: #2c3e50; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f5f5f5; }
            tr:nth-child(even) { background-color: #f9f9f9; }
        </style>
    </head>
    <body>
        <h1>Windows Security Audit Report</h1>
        <p>Report Date: $date</p>

        <h2>Firewall Status</h2>
        <table>
            <tr>
                <th>Profile</th>
                <th>Enabled</th>
                <th>Default Inbound Action</th>
                <th>Default Outbound Action</th>
            </tr>
            $(
                $firewallStatus | ForEach-Object {
                    "<tr><td>$($_.Profile)</td><td>$($_.Enabled)</td><td>$($_.DefaultInboundAction)</td><td>$($_.DefaultOutboundAction)</td></tr>"
                }
            )
        </table>

        <h2>Critical File Permissions</h2>
        $(
            $filePermissions | ForEach-Object {
                "<h3>$($_.Path)</h3>
                <p>Owner: $($_.Owner)</p>
                <table>
                    <tr><th>User/Group</th><th>Rights</th></tr>
                    $(
                        if ($_.AccessRules -ne 'Not accessible') {
                            $_.AccessRules | ForEach-Object {
                                "<tr><td>$($_.IdentityReference)</td><td>$($_.FileSystemRights)</td></tr>"
                            }
                        } else {
                            "<tr><td colspan='2'>Not accessible</td></tr>"
                        }
                    )
                </table>"
            }
        )

        <h2>Users with Administrative Rights</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Source</th>
            </tr>
            $(
                $adminUsers | ForEach-Object {
                    "<tr><td>$($_.Name)</td><td>$($_.Type)</td><td>$($_.Source)</td></tr>"
                }
            )
        </table>
    </body>
    </html>
"@

    # Save report
    $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "Report generated successfully: $reportFile" -ForegroundColor Green
}

# Script execution
try {
    Write-Host "Starting security audit..." -ForegroundColor Green
    Generate-SecurityReport
    Write-Host "Audit completed successfully." -ForegroundColor Green
}
catch {
    Write-Host "An error occurred during the audit: $_" -ForegroundColor Red
}
