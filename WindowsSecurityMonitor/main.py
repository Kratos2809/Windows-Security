#!/usr/bin/env python3
"""
Windows Security Monitoring Tool
Main interface for the security monitoring suite
"""

import sys
import time
import threading
from typing import Dict, List
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from monitor.event_monitor import EventMonitor
from monitor.service_monitor import ServiceMonitor
from monitor.file_monitor import FileMonitor
from monitor.policy_monitor import PolicyMonitor

class SecurityMonitor:
    """Main class for the Windows Security Monitor"""
    
    def __init__(self):
        self.console = Console()
        self.event_monitor = EventMonitor()
        self.service_monitor = ServiceMonitor()
        self.file_monitor = FileMonitor()
        self.policy_monitor = PolicyMonitor()
        
        # Initialize monitors
        self.policy_monitor.initialize_policies()
        self.running = True
        
        # Create report directory
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_layout(self) -> Layout:
        """Generate the layout for the monitoring dashboard"""
        layout = Layout()
        
        # Split into sections
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        # Split main section into panels
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="events"),
            Layout(name="services")
        )
        
        layout["right"].split_column(
            Layout(name="files"),
            Layout(name="policies")
        )
        
        return layout
    
    def create_header(self) -> Panel:
        """Create header panel"""
        return Panel(
            f"Windows Security Monitor - Running since {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            style="bold white on blue"
        )
    
    def create_footer(self) -> Panel:
        """Create footer panel"""
        return Panel(
            "Press Ctrl+C to exit",
            style="bold white on blue"
        )
    
    def create_event_panel(self, events: List) -> Panel:
        """Create event monitoring panel"""
        table = Table(title="Security Events")
        table.add_column("Time")
        table.add_column("Event")
        table.add_column("Details")
        
        for event in events[-5:]:  # Show last 5 events
            table.add_row(
                event.time_generated.strftime("%H:%M:%S"),
                str(event.event_id),
                event.description[:50] + "..." if len(event.description) > 50 else event.description
            )
        
        return Panel(table, title="Event Monitor", border_style="green")
    
    def create_service_panel(self, services: List) -> Panel:
        """Create service monitoring panel"""
        table = Table(title="Critical Services")
        table.add_column("Service")
        table.add_column("Status")
        
        for service in services:
            status_color = "green" if service.status == "Running" else "red"
            table.add_row(
                service.display_name,
                f"[{status_color}]{service.status}[/{status_color}]"
            )
        
        return Panel(table, title="Service Monitor", border_style="blue")
    
    def create_file_panel(self, changes: List) -> Panel:
        """Create file monitoring panel"""
        table = Table(title="File Changes")
        table.add_column("Time")
        table.add_column("Action")
        table.add_column("File")
        
        for change in changes[-5:]:  # Show last 5 changes
            table.add_row(
                change.timestamp.strftime("%H:%M:%S"),
                change.type,
                str(Path(change.path).name)
            )
        
        return Panel(table, title="File Monitor", border_style="yellow")
    
    def create_policy_panel(self, policies: Dict) -> Panel:
        """Create policy monitoring panel"""
        table = Table(title="Security Policies")
        table.add_column("Policy")
        table.add_column("Value")
        
        for policy, value in policies.items():
            table.add_row(policy, str(value))
        
        return Panel(table, title="Policy Monitor", border_style="red")
    
    def update_dashboard(self, layout: Layout):
        """Update the monitoring dashboard"""
        # Get current state from all monitors
        events = self.event_monitor.monitor_security_events(hours_back=1)
        services = self.service_monitor.monitor_services()
        file_changes = self.file_monitor.changes
        policy_analysis = self.policy_monitor.analyze_policies()
        
        # Update layout
        layout["header"].update(self.create_header())
        layout["events"].update(self.create_event_panel(events))
        layout["services"].update(self.create_service_panel(services))
        layout["files"].update(self.create_file_panel(file_changes))
        layout["policies"].update(self.create_policy_panel(policy_analysis["current_policies"]))
        layout["footer"].update(self.create_footer())
    
    def generate_report(self):
        """Generate a comprehensive security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.report_dir / f"security_report_{timestamp}.txt"
        
        with open(report_file, "w") as f:
            f.write("Windows Security Monitor Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Events
            f.write("Security Events\n")
            f.write("-" * 20 + "\n")
            events = self.event_monitor.monitor_security_events(hours_back=24)
            event_analysis = self.event_monitor.analyze_events(events)
            f.write(f"Total Events: {event_analysis['total_events']}\n")
            f.write(f"Failed Logins: {event_analysis['failed_logins']}\n")
            f.write(f"Policy Changes: {event_analysis['policy_changes']}\n\n")
            
            # Services
            f.write("Critical Services\n")
            f.write("-" * 20 + "\n")
            services = self.service_monitor.monitor_services()
            service_analysis = self.service_monitor.analyze_services(services)
            f.write(f"Total Services: {service_analysis['total_services']}\n")
            f.write(f"Running: {service_analysis['running']}\n")
            f.write(f"Stopped: {service_analysis['stopped']}\n\n")
            
            # File Changes
            f.write("File Changes\n")
            f.write("-" * 20 + "\n")
            file_analysis = self.file_monitor.analyze_changes()
            f.write(f"Total Changes: {file_analysis['total_changes']}\n")
            for change_type, count in file_analysis["changes_by_type"].items():
                f.write(f"{change_type}: {count}\n")
            f.write("\n")
            
            # Policies
            f.write("Security Policies\n")
            f.write("-" * 20 + "\n")
            policy_analysis = self.policy_monitor.analyze_policies()
            for policy, value in policy_analysis["current_policies"].items():
                f.write(f"{policy}: {value}\n")
            f.write("\n")
            
            # Issues and Recommendations
            f.write("Security Issues and Recommendations\n")
            f.write("-" * 20 + "\n")
            all_recommendations = (
                event_analysis.get("recommendations", []) +
                service_analysis.get("recommendations", []) +
                file_analysis.get("recommendations", []) +
                policy_analysis.get("recommendations", [])
            )
            for recommendation in all_recommendations:
                f.write(f"• {recommendation}\n")
        
        self.console.print(f"[green]Report generated: {report_file}[/green]")
    
    def start_monitoring(self):
        """Start the security monitoring dashboard"""
        try:
            # Start file monitoring in background
            self.file_monitor.start_monitoring()
            
            # Create and update dashboard
            layout = self.generate_layout()
            
            with Live(layout, refresh_per_second=1) as live:
                while self.running:
                    self.update_dashboard(layout)
                    time.sleep(1)
                    
                    # Generate report every hour
                    if datetime.now().minute == 0 and datetime.now().second == 0:
                        self.generate_report()
        
        except KeyboardInterrupt:
            self.running = False
            self.file_monitor.stop_monitoring()
            self.console.print("[yellow]Stopping security monitor...[/yellow]")
            self.generate_report()
            self.console.print("[green]Final report generated. Goodbye![/green]")
            sys.exit(0)

if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.start_monitoring()
