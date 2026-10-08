# windows_service.py (Updated with proper paths)
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os

# Get the absolute path to the project directory
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

class ThreatClusterService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ThreatClusterAutoUpdate"
    _svc_display_name_ = "ThreatCluster Auto Update Service"
    _svc_description_ = "Automatically updates threat feeds every 5 minutes"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()
        
    def main(self):
        """Main service function"""
        # Change to project directory
        os.chdir(PROJECT_DIR)
        
        # Set up Django
        sys.path.insert(0, PROJECT_DIR)
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatintel.settings')
        
        import django
        django.setup()
        
        from django.core.management import call_command
        
        # Import schedule for running at intervals
        import time
        import schedule
        
        def run_ingestion():
            """Run the feed ingestion command"""
            try:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Running feed ingestion...")
                call_command('ingest_feed', limit=20)
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Ingestion completed")
            except Exception as e:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error: {e}")
        
        # Schedule every 5 minutes
        schedule.every(5).minutes.do(run_ingestion)
        
        # Run immediately
        run_ingestion()
        
        # Main service loop
        while self.is_running:
            schedule.run_pending()
            time.sleep(1)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ThreatClusterService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(ThreatClusterService)