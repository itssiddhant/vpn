from firebase_details import db
from datetime import datetime
import pytz
import platform
import traceback
import json
import socket
import psutil
import os

class FirebaseLogger:
    def __init__(self, user_id=None):
        self.user_id = user_id
        
    def set_user_id(self, user_id):
        self.user_id = user_id
    
    def _get_system_info(self):
        """Gather system information for logging"""
        try:
            system_info = {
                'device': platform.platform(),
                'python_version': platform.python_version(),
                # 'processor': platform.processor(),
                'hostname': socket.gethostname(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                # 'memory_total': psutil.virtual_memory().total,
                # 'memory_available': psutil.virtual_memory().available,
                # 'disk_usage': psutil.disk_usage('/').percent,
                # 'cpu_usage': psutil.cpu_percent(interval=1),
                'battery': None
            }
            
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    system_info['battery'] = {
                        'percent': battery.percent,
                        'power_plugged': battery.power_plugged
                    }
            
            return system_info
        except Exception as e:
            return {'error': f"Failed to gather system info: {str(e)}"}
    
    def _create_log_entry(self, log_type, message, additional_data=None):
        """Create a standardized log entry"""
        timestamp = datetime.now(pytz.utc)
        
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'timestamp_readable': timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'type': log_type,
            'message': message,
            'system_info': self._get_system_info()
        }
        
        if additional_data:
            log_entry['additional_data'] = additional_data
            
        return log_entry
    
    def log_login(self, email, success=True, error_message=None):
        """Log login attempts"""
        if not self.user_id:
            print("Warning: No user_id set for logging")
            return
            
        log_entry = self._create_log_entry(
            'login',
            'Login successful' if success else 'Login failed',
            {
                'email': email,
                'success': success,
                'error_message': error_message
            }
        )
        
        try:
            # Store in user's login history
            db.reference(f'users/{self.user_id}/activity_logs').push(log_entry)
            
            # Store in global login attempts (for security monitoring)
            db.reference('security_logs/login_attempts').push({
                'timestamp': log_entry['timestamp'],
                'email': email,
                'success': success,
                'device': log_entry['system_info']['device']
            })
            
        except Exception as e:
            print(f"Failed to log login: {str(e)}")
    
    def log_logout(self, reason="user_initiated"):
        """Log logout events"""
        if not self.user_id:
            return
            
        log_entry = self._create_log_entry(
            'logout',
            f'User logged out: {reason}'
        )
        
        try:
            db.reference(f'users/{self.user_id}/activity_logs').push(log_entry)
        except Exception as e:
            print(f"Failed to log logout: {str(e)}")
    
    def log_crash(self, error, stack_trace=None):
        """Log application crashes"""
        if not stack_trace:
            stack_trace = traceback.format_exc()
            
        log_entry = self._create_log_entry(
            'crash',
            str(error),
            {
                'stack_trace': stack_trace,
                'error_type': error.__class__.__name__
            }
        )
        
        try:
            # Store in user's crash logs if user_id exists
            if self.user_id:
                db.reference(f'users/{self.user_id}/crash_logs').push(log_entry)
            
            # Store in global crash logs
            db.reference('app_logs/crashes').push(log_entry)
        except Exception as e:
            print(f"Failed to log crash: {str(e)}")
    
    def log_error(self, error_message, error_type="error", additional_info=None):
        """Log general errors"""
        log_entry = self._create_log_entry(
            error_type,
            error_message,
            additional_info
        )
        
        try:
            if self.user_id:
                db.reference(f'users/{self.user_id}/error_logs').push(log_entry)
            db.reference('app_logs/errors').push(log_entry)
        except Exception as e:
            print(f"Failed to log error: {str(e)}")
    
    def log_activity(self, activity_type, description, additional_info=None):
        """Log user activities"""
        if not self.user_id:
            return
            
        log_entry = self._create_log_entry(
            activity_type,
            description,
            additional_info
        )
        
        try:
            db.reference(f'users/{self.user_id}/activity_logs').push(log_entry)
        except Exception as e:
            print(f"Failed to log activity: {str(e)}")