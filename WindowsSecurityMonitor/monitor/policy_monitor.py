#!/usr/bin/env python3
"""
Windows Security Policy Monitor
Monitors and analyzes Windows security policies
"""

import win32security
import win32net
import win32netcon
import win32api
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from rich.console import Console
from rich.table import Table

@dataclass
class PolicyChange:
    """Represents a change in security policy"""
    policy_name: str
    old_value: str
    new_value: str
    timestamp: datetime

class PolicyMonitor:
    """Windows Security Policy Monitor"""
    
    def __init__(self):
        self.console = Console()
        self.critical_policies = {
            "MinimumPasswordLength": "Minimum password length",
            "MaximumPasswordAge": "Maximum password age",
            "PasswordHistoryLength": "Password history length",
            "LockoutDuration": "Account lockout duration",
            "LockoutThreshold": "Account lockout threshold",
            "ResetLockoutCount": "Reset lockout counter after",
        }
        self.policy_values: Dict[str, str] = {}
        self.policy_changes: List[PolicyChange] = []
    
    def get_password_policy(self) -> Dict:
        """
        Get current password policy settings
        
        Returns:
            Dict: Password policy settings
        """
        try:
            return win32net.NetUserModalsGet(None, 1)
        except Exception as e:
            self.console.print(f"[red]Error getting password policy: {str(e)}[/red]")
            return {}
    
    def get_lockout_policy(self) -> Dict:
        """
        Get current account lockout policy settings
        
        Returns:
            Dict: Lockout policy settings
        """
        try:
            return win32net.NetUserModalsGet(None, 3)
        except Exception as e:
            self.console.print(f"[red]Error getting lockout policy: {str(e)}[/red]")
            return {}
    
    def initialize_policies(self):
        """Initialize current policy values"""
        password_policy = self.get_password_policy()
        lockout_policy = self.get_lockout_policy()
        
        if password_policy:
            self.policy_values["MinimumPasswordLength"] = str(password_policy["min_passwd_len"])
            self.policy_values["MaximumPasswordAge"] = str(password_policy["max_passwd_age"])
            self.policy_values["PasswordHistoryLength"] = str(password_policy["passwd_hist_len"])
        
        if lockout_policy:
            self.policy_values["LockoutDuration"] = str(lockout_policy["lockout_duration"])
            self.policy_values["LockoutThreshold"] = str(lockout_policy["lockout_threshold"])
            self.policy_values["ResetLockoutCount"] = str(lockout_policy["lockout_observation_window"])
    
    def check_policy_changes(self) -> List[PolicyChange]:
        """
        Check for changes in security policies
        
        Returns:
            List[PolicyChange]: List of detected policy changes
        """
        changes = []
        
        # Check password policy
        password_policy = self.get_password_policy()
        if password_policy:
            current_values = {
                "MinimumPasswordLength": str(password_policy["min_passwd_len"]),
                "MaximumPasswordAge": str(password_policy["max_passwd_age"]),
                "PasswordHistoryLength": str(password_policy["passwd_hist_len"])
            }
            
            for policy_name, current_value in current_values.items():
                old_value = self.policy_values.get(policy_name)
                if old_value and old_value != current_value:
                    changes.append(PolicyChange(
                        policy_name=policy_name,
                        old_value=old_value,
                        new_value=current_value,
                        timestamp=datetime.now()
                    ))
                self.policy_values[policy_name] = current_value
        
        # Check lockout policy
        lockout_policy = self.get_lockout_policy()
        if lockout_policy:
            current_values = {
                "LockoutDuration": str(lockout_policy["lockout_duration"]),
                "LockoutThreshold": str(lockout_policy["lockout_threshold"]),
                "ResetLockoutCount": str(lockout_policy["lockout_observation_window"])
            }
            
            for policy_name, current_value in current_values.items():
                old_value = self.policy_values.get(policy_name)
                if old_value and old_value != current_value:
                    changes.append(PolicyChange(
                        policy_name=policy_name,
                        old_value=old_value,
                        new_value=current_value,
                        timestamp=datetime.now()
                    ))
                self.policy_values[policy_name] = current_value
        
        return changes
    
    def analyze_policies(self) -> Dict:
        """
        Analyze current security policies and generate report
        
        Returns:
            Dict: Analysis results
        """
        analysis = {
            "current_policies": {},
            "policy_changes": self.policy_changes,
            "issues": [],
            "recommendations": []
        }
        
        # Analyze password policy
        password_policy = self.get_password_policy()
        if password_policy:
            min_length = password_policy["min_passwd_len"]
            max_age = password_policy["max_passwd_age"]
            history_len = password_policy["passwd_hist_len"]
            
            analysis["current_policies"].update({
                "Minimum Password Length": str(min_length),
                "Maximum Password Age": str(max_age),
                "Password History Length": str(history_len)
            })
            
            # Check for weak settings
            if min_length < 8:
                analysis["issues"].append({
                    "policy": "Minimum Password Length",
                    "current": str(min_length),
                    "recommended": "8 or more"
                })
                analysis["recommendations"].append(
                    "Increase minimum password length to at least 8 characters"
                )
            
            if max_age > 90 * 24 * 3600:  # 90 days in seconds
                analysis["issues"].append({
                    "policy": "Maximum Password Age",
                    "current": f"{max_age//(24*3600)} days",
                    "recommended": "90 days or less"
                })
                analysis["recommendations"].append(
                    "Reduce maximum password age to 90 days or less"
                )
            
            if history_len < 5:
                analysis["issues"].append({
                    "policy": "Password History Length",
                    "current": str(history_len),
                    "recommended": "5 or more"
                })
                analysis["recommendations"].append(
                    "Increase password history length to prevent password reuse"
                )
        
        # Analyze lockout policy
        lockout_policy = self.get_lockout_policy()
        if lockout_policy:
            duration = lockout_policy["lockout_duration"]
            threshold = lockout_policy["lockout_threshold"]
            reset_count = lockout_policy["lockout_observation_window"]
            
            analysis["current_policies"].update({
                "Lockout Duration": str(duration),
                "Lockout Threshold": str(threshold),
                "Reset Lockout Count": str(reset_count)
            })
            
            # Check for weak settings
            if threshold == 0 or threshold > 5:
                analysis["issues"].append({
                    "policy": "Lockout Threshold",
                    "current": str(threshold),
                    "recommended": "3-5 attempts"
                })
                analysis["recommendations"].append(
                    "Configure account lockout threshold between 3-5 failed attempts"
                )
            
            if duration < 15 * 60:  # 15 minutes in seconds
                analysis["issues"].append({
                    "policy": "Lockout Duration",
                    "current": f"{duration//60} minutes",
                    "recommended": "15 minutes or more"
                })
                analysis["recommendations"].append(
                    "Increase account lockout duration to at least 15 minutes"
                )
        
        return analysis
    
    def display_analysis(self, analysis: Dict):
        """
        Display policy analysis results
        
        Args:
            analysis: Analysis results to display
        """
        # Display current policies
        table = Table(title="Current Security Policies")
        table.add_column("Policy", style="cyan")
        table.add_column("Value", style="magenta")
        
        for policy, value in analysis["current_policies"].items():
            table.add_row(policy, value)
        
        self.console.print(table)
        
        # Display policy changes
        if analysis["policy_changes"]:
            self.console.print("\n[bold yellow]Recent Policy Changes:[/bold yellow]")
            changes_table = Table()
            changes_table.add_column("Policy")
            changes_table.add_column("Old Value")
            changes_table.add_column("New Value")
            changes_table.add_column("Timestamp")
            
            for change in analysis["policy_changes"]:
                changes_table.add_row(
                    self.critical_policies.get(change.policy_name, change.policy_name),
                    change.old_value,
                    change.new_value,
                    change.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            self.console.print(changes_table)
        
        # Display issues
        if analysis["issues"]:
            self.console.print("\n[bold red]Security Policy Issues:[/bold red]")
            issues_table = Table()
            issues_table.add_column("Policy")
            issues_table.add_column("Current Setting")
            issues_table.add_column("Recommended")
            
            for issue in analysis["issues"]:
                issues_table.add_row(
                    issue["policy"],
                    issue["current"],
                    issue["recommended"]
                )
            
            self.console.print(issues_table)
        
        # Display recommendations
        if analysis["recommendations"]:
            self.console.print("\n[bold green]Recommendations:[/bold green]")
            for recommendation in analysis["recommendations"]:
                self.console.print(f"[yellow]• {recommendation}[/yellow]")

if __name__ == "__main__":
    monitor = PolicyMonitor()
    monitor.initialize_policies()
    
    # Check for changes
    changes = monitor.check_policy_changes()
    if changes:
        monitor.policy_changes.extend(changes)
    
    # Analyze and display results
    analysis = monitor.analyze_policies()
    monitor.display_analysis(analysis)
