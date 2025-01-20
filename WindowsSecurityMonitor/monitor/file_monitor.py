#!/usr/bin/env python3
"""
Windows File Monitor
Monitors critical system files for modifications
"""

import os
import hashlib
import time
import win32file
import win32con
import threading
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from datetime import datetime
from rich.console import Console
from rich.table import Table
from pathlib import Path

@dataclass
class FileChange:
    """Represents a change to a monitored file"""
    path: str
    type: str
    timestamp: datetime
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None

class FileMonitor:
    """Windows File Monitor for critical system files"""
    
    def __init__(self):
        self.console = Console()
        self.critical_directories = [
            os.path.join(os.environ['SystemRoot'], 'System32'),
            os.path.join(os.environ['SystemRoot'], 'SysWOW64'),
            os.path.join(os.environ['SystemRoot'], 'security'),
        ]
        self.critical_extensions = {'.exe', '.dll', '.sys', '.drv'}
        self.file_hashes: Dict[str, str] = {}
        self.changes: List[FileChange] = []
        self._stop_monitoring = threading.Event()
    
    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            filepath: Path to the file
            
        Returns:
            Optional[str]: File hash if successful, None otherwise
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.console.print(f"[red]Error calculating hash for {filepath}: {str(e)}[/red]")
            return None
    
    def initialize_file_hashes(self):
        """Initialize hashes for all monitored files"""
        for directory in self.critical_directories:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        if Path(file).suffix.lower() in self.critical_extensions:
                            filepath = os.path.join(root, file)
                            file_hash = self.calculate_file_hash(filepath)
                            if file_hash:
                                self.file_hashes[filepath] = file_hash
    
    def monitor_directory(self, directory: str):
        """
        Monitor a directory for file changes
        
        Args:
            directory: Directory to monitor
        """
        try:
            handle = win32file.CreateFile(
                directory,
                win32con.FILE_LIST_DIRECTORY,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            while not self._stop_monitoring.is_set():
                results = win32file.ReadDirectoryChangesW(
                    handle,
                    1024,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                )
                
                for action, file in results:
                    filepath = os.path.join(directory, file)
                    
                    # Only monitor files with critical extensions
                    if Path(filepath).suffix.lower() not in self.critical_extensions:
                        continue
                    
                    action_type = {
                        1: "Created",
                        2: "Deleted",
                        3: "Updated",
                        4: "Renamed from",
                        5: "Renamed to"
                    }.get(action, "Unknown")
                    
                    # Get file hash before and after change
                    hash_before = self.file_hashes.get(filepath)
                    hash_after = None
                    
                    if action != 2:  # If file wasn't deleted
                        hash_after = self.calculate_file_hash(filepath)
                        self.file_hashes[filepath] = hash_after
                    
                    change = FileChange(
                        path=filepath,
                        type=action_type,
                        timestamp=datetime.now(),
                        hash_before=hash_before,
                        hash_after=hash_after
                    )
                    self.changes.append(change)
                    
                    # Alert if hash changed
                    if hash_before and hash_after and hash_before != hash_after:
                        self.console.print(f"[red]WARNING: File hash changed for {filepath}[/red]")
        
        except Exception as e:
            self.console.print(f"[red]Error monitoring directory {directory}: {str(e)}[/red]")
    
    def start_monitoring(self):
        """Start monitoring all critical directories"""
        self.initialize_file_hashes()
        
        # Start a monitoring thread for each directory
        self.monitor_threads = []
        for directory in self.critical_directories:
            if os.path.exists(directory):
                thread = threading.Thread(
                    target=self.monitor_directory,
                    args=(directory,)
                )
                thread.daemon = True
                thread.start()
                self.monitor_threads.append(thread)
    
    def stop_monitoring(self):
        """Stop all monitoring threads"""
        self._stop_monitoring.set()
        for thread in self.monitor_threads:
            thread.join()
    
    def analyze_changes(self) -> Dict:
        """
        Analyze file changes and generate report
        
        Returns:
            Dict: Analysis results
        """
        analysis = {
            "total_changes": len(self.changes),
            "changes_by_type": {},
            "suspicious_changes": [],
            "recommendations": []
        }
        
        for change in self.changes:
            # Count changes by type
            analysis["changes_by_type"][change.type] = analysis["changes_by_type"].get(change.type, 0) + 1
            
            # Check for suspicious changes
            if change.type in ["Created", "Updated"]:
                if change.hash_before and change.hash_after and change.hash_before != change.hash_after:
                    analysis["suspicious_changes"].append({
                        "file": change.path,
                        "type": change.type,
                        "time": change.timestamp
                    })
            elif change.type == "Deleted":
                analysis["suspicious_changes"].append({
                    "file": change.path,
                    "type": "Deleted",
                    "time": change.timestamp
                })
        
        # Generate recommendations
        if analysis["suspicious_changes"]:
            analysis["recommendations"].append(
                "Verify all file modifications with system administrator"
            )
            analysis["recommendations"].append(
                "Consider restoring critical files from known good backups"
            )
        
        return analysis
    
    def display_analysis(self, analysis: Dict):
        """
        Display file monitoring analysis results
        
        Args:
            analysis: Analysis results to display
        """
        # Create summary table
        table = Table(title="File Changes Summary")
        
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Changes", str(analysis["total_changes"]))
        for change_type, count in analysis["changes_by_type"].items():
            table.add_row(f"{change_type} Files", str(count))
        
        self.console.print(table)
        
        # Display suspicious changes
        if analysis["suspicious_changes"]:
            self.console.print("\n[bold red]Suspicious File Changes:[/bold red]")
            suspicious_table = Table()
            suspicious_table.add_column("File")
            suspicious_table.add_column("Change Type")
            suspicious_table.add_column("Timestamp")
            
            for change in analysis["suspicious_changes"]:
                suspicious_table.add_row(
                    change["file"],
                    change["type"],
                    change["time"].strftime("%Y-%m-%d %H:%M:%S")
                )
            
            self.console.print(suspicious_table)
        
        # Display recommendations
        if analysis["recommendations"]:
            self.console.print("\n[bold green]Recommendations:[/bold green]")
            for recommendation in analysis["recommendations"]:
                self.console.print(f"[yellow]• {recommendation}[/yellow]")

if __name__ == "__main__":
    monitor = FileMonitor()
    monitor.start_monitoring()
    
    try:
        while True:
            time.sleep(1)
            analysis = monitor.analyze_changes()
            monitor.display_analysis(analysis)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
