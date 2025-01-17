import win32evtlog
import win32evtlogutil
import win32security
import win32con
from datetime import datetime, timedelta
from colorama import init, Fore, Style

init()  # Initialize colorama

class WindowsLogAnalyzer:
    def __init__(self):
        self.server = 'localhost'
        self.logtype = 'Security'
        self.events = []

    def collect_events(self, hours_back=24):
        """Collect events from the last X hours"""
        try:
            hand = win32evtlog.OpenEventLog(self.server, self.logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            
            print(f"{Fore.BLUE}[*] Collecting events from the last {hours_back} hours...{Style.RESET_ALL}")
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    # Convert timestamp
                    event_time = datetime.fromtimestamp(int(event.TimeGenerated))
                    if datetime.now() - event_time > timedelta(hours=hours_back):
                        continue
                        
                    event_dict = {
                        'TimeGenerated': event_time,
                        'EventID': event.EventID,
                        'EventType': event.EventType,
                        'SourceName': event.SourceName,
                        'EventCategory': event.EventCategory,
                        'Message': str(win32evtlogutil.SafeFormatMessage(event, self.logtype))
                    }
                    self.events.append(event_dict)
                    
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error collecting events: {str(e)}{Style.RESET_ALL}")

    def analyze_failed_logins(self):
        """Analyze failed login attempts"""
        failed_logins = [e for e in self.events if e['EventID'] == 4625]
        if failed_logins:
            print(f"\n{Fore.YELLOW}[!] Failed login attempts detected:{Style.RESET_ALL}")
            for login in failed_logins:
                print(f"Time: {login['TimeGenerated']}")
                print(f"Details: {login['Message']}\n")
            print(f"{Fore.RED}Total failed attempts: {len(failed_logins)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No failed login attempts detected{Style.RESET_ALL}")

    def analyze_account_changes(self):
        """Analyze account modifications"""
        account_changes = [e for e in self.events if e['EventID'] in [4720, 4722, 4723, 4724, 4725, 4726, 4738]]
        if account_changes:
            print(f"\n{Fore.YELLOW}[!] Account modifications detected:{Style.RESET_ALL}")
            for change in account_changes:
                print(f"Time: {change['TimeGenerated']}")
                print(f"Event ID: {change['EventID']}")
                print(f"Details: {change['Message']}\n")
        else:
            print(f"{Fore.GREEN}[+] No account modifications detected{Style.RESET_ALL}")

    def analyze_suspicious_services(self):
        """Analyze service modifications"""
        service_changes = [e for e in self.events if e['EventID'] in [7034, 7035, 7036, 7040]]
        if service_changes:
            print(f"\n{Fore.YELLOW}[!] Service modifications detected:{Style.RESET_ALL}")
            for change in service_changes:
                print(f"Time: {change['TimeGenerated']}")
                print(f"Event ID: {change['EventID']}")
                print(f"Details: {change['Message']}\n")
        else:
            print(f"{Fore.GREEN}[+] No suspicious service modifications detected{Style.RESET_ALL}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Windows Log Analyzer')
    parser.add_argument('--hours', type=int, default=24, help='Number of hours to analyze (default: 24)')
    args = parser.parse_args()

    print(f"{Fore.CYAN}=== Windows Log Analyzer ==={Style.RESET_ALL}")
    analyzer = WindowsLogAnalyzer()
    
    analyzer.collect_events(hours_back=args.hours)
    print(f"\n{Fore.CYAN}[+] {len(analyzer.events)} events collected{Style.RESET_ALL}")
    
    analyzer.analyze_failed_logins()
    analyzer.analyze_account_changes()
    analyzer.analyze_suspicious_services()

if __name__ == '__main__':
    main()
