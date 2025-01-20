#!/usr/bin/env python3
"""
Windows Service Monitor
Monitors and manages critical Windows services
"""

import wmi
import win32serviceutil
import win32service
import psutil
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

@dataclass
class ServiceStatus:
    """Represents the status of a Windows service"""
    name: str
    display_name: str
    status: str
    start_type: str
    description: str
    path: str
    account: str
    is_critical: bool = False

class ServiceMonitor:
    """Windows Service Monitor for critical services"""
    
    def __init__(self):
        self.console = Console()
        self.wmi = wmi.WMI()
        self.critical_services = {
            "WinDefend": "Windows Defender",
            "MpsSvc": "Windows Firewall",
            "EventLog": "Windows Event Log",
            "Schedule": "Task Scheduler",
            "Netlogon": "Network Logon",
            "LanmanServer": "Server",
            "BITS": "Background Intelligent Transfer",
            "wuauserv": "Windows Update"
        }
    
    def get_service_status(self, service_name: str) -> Optional[ServiceStatus]:
        """
        Get detailed status of a Windows service
        
        Args:
            service_name: Name of the service
            
        Returns:
            Optional[ServiceStatus]: Service status details if found
        """
        try:
            service = win32serviceutil.SmartOpenService(
                None, service_name,
                win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
            )
            
            config = win32service.QueryServiceConfig(service)
            status = win32service.QueryServiceStatus(service)
            
            # Get status string
            status_map = {
                win32service.SERVICE_STOPPED: "Stopped",
                win32service.SERVICE_START_PENDING: "Starting",
                win32service.SERVICE_STOP_PENDING: "Stopping",
                win32service.SERVICE_RUNNING: "Running",
                win32service.SERVICE_CONTINUE_PENDING: "Continuing",
                win32service.SERVICE_PAUSE_PENDING: "Pausing",
                win32service.SERVICE_PAUSED: "Paused"
            }
            
            # Get start type string
            start_type_map = {
                win32service.SERVICE_AUTO_START: "Automatic",
                win32service.SERVICE_DEMAND_START: "Manual",
                win32service.SERVICE_DISABLED: "Disabled",
                win32service.SERVICE_BOOT_START: "Boot",
                win32service.SERVICE_SYSTEM_START: "System"
            }
            
            return ServiceStatus(
                name=service_name,
                display_name=win32serviceutil.QueryServiceDisplayName(None, service_name),
                status=status_map.get(status[1], "Unknown"),
                start_type=start_type_map.get(config[1], "Unknown"),
                description=win32serviceutil.QueryServiceDescription(None, service_name) or "",
                path=config[3],
                account=config[7],
                is_critical=service_name in self.critical_services
            )
        
        except Exception as e:
            self.console.print(f"[red]Error getting status for service {service_name}: {str(e)}[/red]")
            return None
    
    def monitor_services(self) -> List[ServiceStatus]:
        """
        Monitor status of all critical services
        
        Returns:
            List[ServiceStatus]: List of service status details
        """
        services = []
        
        for service_name in self.critical_services:
            status = self.get_service_status(service_name)
            if status:
                services.append(status)
        
        return services
    
    def restart_service(self, service_name: str) -> bool:
        """
        Restart a Windows service
        
        Args:
            service_name: Name of the service to restart
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            win32serviceutil.RestartService(service_name)
            return True
        except Exception as e:
            self.console.print(f"[red]Error restarting service {service_name}: {str(e)}[/red]")
            return False
    
    def analyze_services(self, services: List[ServiceStatus]) -> Dict:
        """
        Analyze service status and generate report
        
        Args:
            services: List of service status to analyze
            
        Returns:
            Dict: Analysis results
        """
        analysis = {
            "total_services": len(services),
            "running": 0,
            "stopped": 0,
            "issues": [],
            "recommendations": []
        }
        
        for service in services:
            if service.status == "Running":
                analysis["running"] += 1
            elif service.status == "Stopped":
                analysis["stopped"] += 1
                analysis["issues"].append({
                    "service": service.display_name,
                    "issue": "Service is stopped",
                    "severity": "High" if service.is_critical else "Medium"
                })
            
            # Check for disabled critical services
            if service.is_critical and service.start_type == "Disabled":
                analysis["issues"].append({
                    "service": service.display_name,
                    "issue": "Critical service is disabled",
                    "severity": "High"
                })
            
            # Generate recommendations
            if service.status == "Stopped" and service.is_critical:
                analysis["recommendations"].append(
                    f"Start the {service.display_name} service immediately"
                )
            elif service.start_type == "Disabled" and service.is_critical:
                analysis["recommendations"].append(
                    f"Enable and configure {service.display_name} to start automatically"
                )
        
        return analysis
    
    def display_analysis(self, analysis: Dict):
        """
        Display service analysis results
        
        Args:
            analysis: Analysis results to display
        """
        # Create summary table
        table = Table(title="Service Status Summary")
        
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Services", str(analysis["total_services"]))
        table.add_row("Running", str(analysis["running"]))
        table.add_row("Stopped", str(analysis["stopped"]))
        
        self.console.print(table)
        
        # Display issues
        if analysis["issues"]:
            self.console.print("\n[bold red]Service Issues:[/bold red]")
            issues_table = Table()
            issues_table.add_column("Service")
            issues_table.add_column("Issue")
            issues_table.add_column("Severity")
            
            for issue in analysis["issues"]:
                severity_color = "red" if issue["severity"] == "High" else "yellow"
                issues_table.add_row(
                    issue["service"],
                    issue["issue"],
                    f"[{severity_color}]{issue['severity']}[/{severity_color}]"
                )
            
            self.console.print(issues_table)
        
        # Display recommendations
        if analysis["recommendations"]:
            self.console.print("\n[bold green]Recommendations:[/bold green]")
            for recommendation in analysis["recommendations"]:
                self.console.print(f"[yellow]• {recommendation}[/yellow]")

if __name__ == "__main__":
    monitor = ServiceMonitor()
    services = monitor.monitor_services()
    analysis = monitor.analyze_services(services)
    monitor.display_analysis(analysis)
