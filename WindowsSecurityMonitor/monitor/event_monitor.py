#!/usr/bin/env python3
"""
Windows Event Log Monitor
Monitors and analyzes Windows event logs for security-related events
"""

import win32evtlog
import win32evtlogutil
import win32security
import win32con
import wmi
import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

@dataclass
class SecurityEvent:
    """Represents a security-related event from Windows Event Log"""
    event_id: int
    time_generated: datetime.datetime
    source_name: str
    event_type: str
    event_category: int
    description: str
    computer_name: str
    sid: Optional[str] = None
    data: Dict = None

class EventMonitor:
    """Windows Event Log Monitor for security events"""
    
    def __init__(self):
        self.console = Console()
        self.wmi = wmi.WMI()
        self.critical_events = {
            4624: "Successful logon",
            4625: "Failed logon attempt",
            4648: "Explicit credentials logon",
            4719: "System audit policy was changed",
            4732: "A member was added to a security-enabled local group",
            4735: "A security-enabled local group was changed",
            4740: "A user account was locked out",
            4756: "A member was added to a security-enabled universal group",
        }
    
    def get_event_description(self, event) -> str:
        """Get human-readable description of an event"""
        try:
            return win32evtlogutil.SafeFormatMessage(event, 'Security')
        except:
            return f"Event ID: {event.EventID}"
    
    def get_sid_string(self, event) -> Optional[str]:
        """Convert SID to string representation"""
        try:
            if event.Sid is not None:
                sid = win32security.ConvertSidToStringSid(event.Sid)
                return sid
            return None
        except:
            return None
    
    def monitor_security_events(
        self, hours_back: int = 1
    ) -> List[SecurityEvent]:
        """
        Monitor security events from Windows Event Log
        
        Args:
            hours_back: Number of hours to look back
            
        Returns:
            List[SecurityEvent]: List of security events
        """
        events = []
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        try:
            while True:
                events_batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events_batch:
                    break
                
                for event in events_batch:
                    # Check if event is within time range
                    if (datetime.datetime.now() - event.TimeGenerated).total_seconds() > hours_back * 3600:
                        continue
                    
                    if event.EventID in self.critical_events:
                        security_event = SecurityEvent(
                            event_id=event.EventID,
                            time_generated=event.TimeGenerated,
                            source_name=event.SourceName,
                            event_type=event.EventType,
                            event_category=event.EventCategory,
                            description=self.get_event_description(event),
                            computer_name=event.ComputerName,
                            sid=self.get_sid_string(event),
                            data=event.StringInserts if event.StringInserts else {}
                        )
                        events.append(security_event)
        
        finally:
            win32evtlog.CloseEventLog(handle)
        
        return events
    
    def analyze_events(self, events: List[SecurityEvent]) -> Dict:
        """
        Analyze security events and generate statistics
        
        Args:
            events: List of security events to analyze
            
        Returns:
            Dict: Analysis results
        """
        analysis = {
            "total_events": len(events),
            "events_by_type": {},
            "failed_logins": 0,
            "successful_logins": 0,
            "policy_changes": 0,
            "group_changes": 0,
            "account_lockouts": 0,
            "suspicious_activity": []
        }
        
        for event in events:
            # Count events by type
            event_type = self.critical_events.get(event.event_id, "Other")
            analysis["events_by_type"][event_type] = analysis["events_by_type"].get(event_type, 0) + 1
            
            # Analyze specific events
            if event.event_id == 4625:  # Failed login
                analysis["failed_logins"] += 1
                # Check for potential brute force
                if analysis["failed_logins"] >= 5:
                    analysis["suspicious_activity"].append({
                        "type": "Potential brute force attack",
                        "details": f"Multiple failed login attempts ({analysis['failed_logins']})"
                    })
            
            elif event.event_id == 4624:  # Successful login
                analysis["successful_logins"] += 1
            
            elif event.event_id == 4719:  # Policy change
                analysis["policy_changes"] += 1
                analysis["suspicious_activity"].append({
                    "type": "Security policy modified",
                    "details": event.description
                })
            
            elif event.event_id in [4732, 4735, 4756]:  # Group changes
                analysis["group_changes"] += 1
                analysis["suspicious_activity"].append({
                    "type": "Security group modified",
                    "details": event.description
                })
            
            elif event.event_id == 4740:  # Account lockout
                analysis["account_lockouts"] += 1
        
        return analysis
    
    def display_analysis(self, analysis: Dict):
        """
        Display analysis results in a formatted table
        
        Args:
            analysis: Analysis results to display
        """
        # Create summary table
        table = Table(title="Security Event Analysis")
        
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Events", str(analysis["total_events"]))
        table.add_row("Failed Logins", str(analysis["failed_logins"]))
        table.add_row("Successful Logins", str(analysis["successful_logins"]))
        table.add_row("Policy Changes", str(analysis["policy_changes"]))
        table.add_row("Group Changes", str(analysis["group_changes"]))
        table.add_row("Account Lockouts", str(analysis["account_lockouts"]))
        
        self.console.print(table)
        
        # Display suspicious activity
        if analysis["suspicious_activity"]:
            self.console.print("\n[bold red]Suspicious Activity Detected:[/bold red]")
            for activity in analysis["suspicious_activity"]:
                self.console.print(f"[red]• {activity['type']}[/red]")
                self.console.print(f"  {activity['details']}")
        
        # Display recommendations
        self.console.print("\n[bold green]Recommendations:[/bold green]")
        if analysis["failed_logins"] > 5:
            self.console.print("[yellow]• Review failed login attempts and consider implementing account lockout policies[/yellow]")
        if analysis["policy_changes"] > 0:
            self.console.print("[yellow]• Verify all security policy changes were authorized[/yellow]")
        if analysis["group_changes"] > 0:
            self.console.print("[yellow]• Audit security group modifications[/yellow]")
        if analysis["account_lockouts"] > 0:
            self.console.print("[yellow]• Investigate account lockouts for potential security breaches[/yellow]")

if __name__ == "__main__":
    monitor = EventMonitor()
    events = monitor.monitor_security_events(hours_back=24)
    analysis = monitor.analyze_events(events)
    monitor.display_analysis(analysis)
