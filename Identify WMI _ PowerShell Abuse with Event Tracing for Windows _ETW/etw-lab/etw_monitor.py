#!/usr/bin/env python3
import json
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import init, Fore, Style

init(autoreset=True)

class ETWMonitor(FileSystemEventHandler):
    def __init__(self):
        self.suspicious_keywords = [
            'IEX', 'DownloadString', 'Invoke-Expression', 'New-Object',
            'SELECT * FROM Win32_Process', 'cmd.exe', 'SYSTEM'
        ]
        self.alert_count = 0
    
    def on_modified(self, event):
        if event.src_path.endswith('etw_events.json'):
            self.analyze_new_events()
    
    def analyze_new_events(self):
        try:
            with open('etw_events.json', 'r') as f:
                lines = f.readlines()
                if lines:
                    # Analyze the last event
                    last_event = json.loads(lines[-1])
                    self.analyze_event(last_event)
        except Exception as e:
            print(f"Error analyzing events: {e}")
    
    def analyze_event(self, event):
        if event.get('suspicious', False):
            self.alert_count += 1
            print(f"\n{Fore.RED}🚨 SUSPICIOUS ACTIVITY DETECTED #{self.alert_count}")
            print(f"{Fore.YELLOW}Timestamp: {event['timestamp']}")
            print(f"{Fore.YELLOW}Provider: {event['provider']}")
            print(f"{Fore.YELLOW}Event ID: {event['event_id']}")
            print(f"{Fore.YELLOW}Process: {event['process_name']}")
            print(f"{Fore.YELLOW}User: {event['user']}")
            
            if 'command_line' in event:
                print(f"{Fore.RED}Command: {event['command_line']}")
            if 'script_block' in event:
                print(f"{Fore.RED}Script: {event['script_block']}")
            
            print(f"{Fore.CYAN}Indicators: {', '.join(event['indicators'])}")
            print(f"{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ Normal activity: {event['provider']} - {event['event_id']}")

def main():
    print("Starting ETW Real-time Monitor...")
    print("Monitoring etw_events.json for suspicious activity...")
    
    monitor = ETWMonitor()
    observer = Observer()
    observer.schedule(monitor, path='.', recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\nMonitoring stopped. Total alerts: {monitor.alert_count}")
    
    observer.join()

if __name__ == "__main__":
    main()
