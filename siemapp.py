#!/usr/bin/env python3
"""
Advanced SIEM System with GUI - Modern Dark Theme
Security Information and Event Management with Professional Interface
"""

import re
import json
import yaml
import time
import sqlite3
import smtplib
import threading
import socketserver
import random
import winsound
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from collections import defaultdict, deque
import signal
import sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# =============================================================================
# MODELS AND ENUMS
# =============================================================================

class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class EventType(Enum):
    AUTH_SUCCESS = "authentication_success"
    AUTH_FAILURE = "authentication_failure"
    CONNECTION_ATTEMPT = "connection_attempt"
    PORT_SCAN = "port_scan"
    MALICIOUS_IP = "malicious_ip"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    event_type: EventType
    log_level: LogLevel
    message: str
    raw_log: str
    source: str
    user: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    additional_data: Dict[str, Any] = None

    def __post_init__(self):
        if self.additional_data is None:
            self.additional_data = {}

@dataclass
class Alert:
    timestamp: datetime
    rule_name: str
    description: str
    severity: str
    source_ip: str
    event_count: int
    details: Dict[str, Any]

# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_CONFIG = {
    'log_sources': [
        {
            'type': 'file',
            'path': './sample_auth.log',
            'format': 'syslog',
            'enabled': True
        },
        {
            'type': 'file',
            'path': './sample_apache.log',
            'format': 'apache',
            'enabled': True
        }
    ],
    'analysis_rules': [
        {
            'name': 'failed_login_attempts',
            'description': 'Multiple failed login attempts from same IP',
            'condition': "event_type == 'authentication_failure'",
            'threshold': 5,
            'time_window': 300,
            'severity': 'high'
        },
        {
            'name': 'brute_force_detection',
            'description': 'Possible brute force attack',
            'condition': "event_type == 'authentication_failure'",
            'threshold': 10,
            'time_window': 60,
            'severity': 'critical'
        },
        {
            'name': 'suspicious_activity',
            'description': 'Multiple event types from same IP',
            'condition': "event_type in ['authentication_failure', 'connection_attempt']",
            'threshold': 15,
            'time_window': 180,
            'severity': 'medium'
        }
    ],
    'alert_channels': {
        'email': {
            'enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'username': 'your-email@gmail.com',
            'password': 'your-password',
            'to': 'security@company.com'
        },
        'slack': {
            'enabled': False,
            'webhook_url': 'your-slack-webhook'
        },
        'console': {
            'enabled': True
        }
    },
    'storage': {
        'database': {
            'type': 'sqlite',
            'path': './siem.db'
        },
        'retention_days': 30
    }
}

def create_sample_logs():
    """Create sample log files for testing"""
    sample_auth_log = """Dec 10 14:23:45 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22
Dec 10 14:23:46 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22
Dec 10 14:23:47 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22
Dec 10 14:23:48 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22
Dec 10 14:23:49 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22
Dec 10 14:23:50 server sshd[12345]: Accepted password for user john from 192.168.1.101 port 22
Dec 10 14:23:51 server sshd[12345]: Failed password for root from 10.0.0.50 port 22
Dec 10 14:23:52 server sshd[12345]: Failed password for root from 10.0.0.50 port 22
Dec 10 14:23:53 server sshd[12345]: Connection closed by 192.168.1.100 port 22
Dec 10 14:23:54 server sshd[12345]: Accepted password for user alice from 192.168.1.102 port 22
"""
    
    sample_apache_log = """192.168.1.100 - - [10/Dec/2023:14:23:45 +0000] "GET /admin HTTP/1.1" 403 1234
192.168.1.100 - - [10/Dec/2023:14:23:46 +0000] "GET /admin HTTP/1.1" 403 1234
192.168.1.100 - - [10/Dec/2023:14:23:47 +0000] "POST /login HTTP/1.1" 200 512
192.168.1.101 - - [10/Dec/2023:14:23:48 +0000] "GET /index.html HTTP/1.1" 200 1024
10.0.0.50 - - [10/Dec/2023:14:23:49 +0000] "GET /wp-admin HTTP/1.1" 404 2345
192.168.1.200 - - [10/Dec/2023:14:23:50 +0000] "GET /api/data HTTP/1.1" 200 2048
10.0.0.50 - - [10/Dec/2023:14:23:51 +0000] "POST /wp-login.php HTTP/1.1" 200 512
192.168.1.100 - - [10/Dec/2023:14:23:52 +0000] "GET /.env HTTP/1.1" 404 1234
"""
    
    with open('sample_auth.log', 'w') as f:
        f.write(sample_auth_log)
    
    with open('sample_apache.log', 'w') as f:
        f.write(sample_apache_log)
    
    print("Sample log files created: sample_auth.log, sample_apache.log")

# =============================================================================
# COLOR THEME - MODERN DARK BLUE
# =============================================================================

class ColorTheme:
    # Dark background colors
    BG_PRIMARY = "#0a1929"      # Dark blue background
    BG_SECONDARY = "#132f4c"    # Slightly lighter blue
    BG_TERTIARY = "#1e3a5c"     # Medium blue for cards
    
    # Text colors
    TEXT_PRIMARY = "#e1f5fe"    # Light blue text
    TEXT_SECONDARY = "#b3e5fc"  # Medium blue text
    TEXT_MUTED = "#81d4fa"      # Muted blue text
    
    # Accent colors
    ACCENT_PRIMARY = "#00b0ff"  # Bright blue
    ACCENT_SECONDARY = "#0091ea" # Darker blue
    ACCENT_SUCCESS = "#00e676"  # Green
    ACCENT_WARNING = "#ff9100"  # Orange
    ACCENT_DANGER = "#ff1744"   # Red
    ACCENT_INFO = "#00b8d4"     # Cyan
    
    # Alert severity colors
    CRITICAL = "#ff5252"        # Bright red
    HIGH = "#ff9800"            # Orange
    MEDIUM = "#ffeb3b"          # Yellow
    LOW = "#4caf50"             # Green
    
    # Chart colors
    CHART_COLORS = ['#00b0ff', '#0091ea', '#0066cc', '#004ba0', '#003f7f']

# =============================================================================
# LOG PARSER
# =============================================================================

class LogParser:
    def __init__(self):
        self.syslog_pattern = re.compile(
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)'
        )
        self.apache_pattern = re.compile(
            r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)'
        )
    
    def parse_syslog(self, log_line: str, source: str = "syslog") -> Optional[LogEntry]:
        match = self.syslog_pattern.match(log_line)
        if not match:
            return None
            
        timestamp_str, host, process, pid, message = match.groups()
        
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except:
            timestamp = datetime.now()
        
        event_type = self._classify_syslog_event(message)
        log_level = self._extract_log_level(message)
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_matches = re.findall(ip_pattern, message)
        source_ip = ip_matches[0] if ip_matches else "unknown"
        
        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            event_type=event_type,
            log_level=log_level,
            message=message,
            raw_log=log_line,
            source=source,
            user=self._extract_username(message)
        )
    
    def parse_apache(self, log_line: str, source: str = "apache") -> Optional[LogEntry]:
        match = self.apache_pattern.match(log_line)
        if not match:
            return None
            
        ip, ident, user, timestamp_str, request, status, size = match.groups()
        
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except:
            timestamp = datetime.now()
        
        event_type = self._classify_apache_event(int(status), request)
        
        return LogEntry(
            timestamp=timestamp,
            source_ip=ip,
            destination_ip=None,
            event_type=event_type,
            log_level=LogLevel.INFO if status.startswith('2') else LogLevel.WARNING,
            message=f"{request} - {status}",
            raw_log=log_line,
            source=source,
            user=user if user != '-' else None,
            additional_data={
                "http_status": int(status),
                "request": request,
                "response_size": int(size)
            }
        )
    
    def _classify_syslog_event(self, message: str) -> EventType:
        message_lower = message.lower()
        if "failed password" in message_lower or "authentication failure" in message_lower:
            return EventType.AUTH_FAILURE
        elif "accepted password" in message_lower or "authentication success" in message_lower:
            return EventType.AUTH_SUCCESS
        elif "connection" in message_lower:
            return EventType.CONNECTION_ATTEMPT
        else:
            return EventType.SUSPICIOUS_ACTIVITY
    
    def _classify_apache_event(self, status: int, request: str) -> EventType:
        if status == 401 or status == 403:
            return EventType.AUTH_FAILURE
        elif status >= 400:
            return EventType.SUSPICIOUS_ACTIVITY
        else:
            return EventType.CONNECTION_ATTEMPT
    
    def _extract_log_level(self, message: str) -> LogLevel:
        message_lower = message.lower()
        if "error" in message_lower:
            return LogLevel.ERROR
        elif "warning" in message_lower:
            return LogLevel.WARNING
        elif "critical" in message_lower or "emergency" in message_lower:
            return LogLevel.CRITICAL
        else:
            return LogLevel.INFO
    
    def _extract_username(self, message: str) -> Optional[str]:
        user_pattern = r'for\s+(\S+)\s+from|user\s+(\S+)'
        match = re.search(user_pattern, message.lower())
        if match:
            return match.group(1) or match.group(2)
        return None

# =============================================================================
# DATA STORAGE
# =============================================================================

class DataStorage:
    def __init__(self, db_path: str = "siem.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                destination_ip TEXT,
                event_type TEXT,
                log_level TEXT,
                message TEXT,
                raw_log TEXT,
                source TEXT,
                user TEXT,
                port INTEGER,
                protocol TEXT,
                additional_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                rule_name TEXT,
                description TEXT,
                severity TEXT,
                source_ip TEXT,
                event_count INTEGER,
                details TEXT
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_entries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_source_ip ON log_entries(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_event_type ON log_entries(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp)')
        
        conn.commit()
        conn.close()
    
    def store_log_entry(self, log_entry: LogEntry):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO log_entries 
            (timestamp, source_ip, destination_ip, event_type, log_level, message, raw_log, source, user, port, protocol, additional_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_entry.timestamp,
            log_entry.source_ip,
            log_entry.destination_ip,
            log_entry.event_type.value,
            log_entry.log_level.value,
            log_entry.message,
            log_entry.raw_log,
            log_entry.source,
            log_entry.user,
            log_entry.port,
            log_entry.protocol,
            json.dumps(log_entry.additional_data) if log_entry.additional_data else None
        ))
        
        conn.commit()
        conn.close()
    
    def store_alert(self, alert: Alert):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts 
            (timestamp, rule_name, description, severity, source_ip, event_count, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.timestamp,
            alert.rule_name,
            alert.description,
            alert.severity,
            alert.source_ip,
            alert.event_count,
            json.dumps(alert.details, default=str)
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, source_ip, event_type, log_level, message, source 
            FROM log_entries 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'timestamp': row[0],
                'source_ip': row[1],
                'event_type': row[2],
                'log_level': row[3],
                'message': row[4],
                'source': row[5]
            }
            for row in rows
        ]
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, rule_name, description, severity, source_ip, event_count 
            FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'timestamp': row[0],
                'rule_name': row[1],
                'description': row[2],
                'severity': row[3],
                'source_ip': row[4],
                'event_count': row[5]
            }
            for row in rows
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total logs today
        cursor.execute('''
            SELECT COUNT(*) FROM log_entries 
            WHERE date(timestamp) = date('now')
        ''')
        total_today = cursor.fetchone()[0]
        
        # Alerts today
        cursor.execute('''
            SELECT COUNT(*) FROM alerts 
            WHERE date(timestamp) = date('now')
        ''')
        alerts_today = cursor.fetchone()[0]
        
        # Top source IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM log_entries 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_ips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Event type distribution
        cursor.execute('''
            SELECT event_type, COUNT(*) as count 
            FROM log_entries 
            GROUP BY event_type 
            ORDER BY count DESC
        ''')
        event_distribution = [{'type': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total_logs_today': total_today,
            'alerts_today': alerts_today,
            'top_source_ips': top_ips,
            'event_distribution': event_distribution
        }
    
    def cleanup_old_data(self, retention_days: int = 30):
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM log_entries WHERE timestamp < ?', (cutoff_date,))
        cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_date,))
        
        conn.commit()
        conn.close()

# =============================================================================
# ANALYSIS ENGINE
# =============================================================================

class AnalysisEngine:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or DEFAULT_CONFIG
        self.rules = self.config['analysis_rules']
        self.event_buffer = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.Lock()
        self.alerts_generated = []
    
    def process_log_entry(self, log_entry: LogEntry):
        with self.lock:
            key = f"{log_entry.event_type.value}_{log_entry.source_ip}"
            self.event_buffer[key].append({
                'timestamp': log_entry.timestamp,
                'entry': log_entry
            })
            
            self._check_rules(log_entry)
    
    def _check_rules(self, log_entry: LogEntry):
        current_time = datetime.now()
        
        for rule in self.rules:
            if self._evaluate_rule_condition(log_entry, rule['condition']):
                time_window = timedelta(seconds=rule['time_window'])
                threshold = rule['threshold']
                
                event_count = self._count_events_in_window(
                    log_entry.event_type, 
                    log_entry.source_ip, 
                    current_time - time_window, 
                    current_time,
                    rule['condition']
                )
                
                if event_count >= threshold:
                    alert = Alert(
                        timestamp=current_time,
                        rule_name=rule['name'],
                        description=rule['description'],
                        severity=rule['severity'],
                        source_ip=log_entry.source_ip,
                        event_count=event_count,
                        details={
                            'time_window': rule['time_window'],
                            'threshold': threshold,
                            'recent_events': [
                                {
                                    'timestamp': event['timestamp'],
                                    'message': event['entry'].message
                                }
                                for event in list(self.event_buffer[
                                    f"{log_entry.event_type.value}_{log_entry.source_ip}"
                                ])[-5:]
                            ]
                        }
                    )
                    self.alerts_generated.append(alert)
    
    def _evaluate_rule_condition(self, log_entry: LogEntry, condition: str) -> bool:
        try:
            return eval(condition, {}, {
                'event_type': log_entry.event_type.value,
                'log_level': log_entry.log_level.value,
                'source_ip': log_entry.source_ip
            })
        except:
            return False
    
    def _count_events_in_window(self, event_type, source_ip, start_time, end_time, condition) -> int:
        key = f"{event_type.value}_{source_ip}"
        if key not in self.event_buffer:
            return 0
        
        count = 0
        for event in self.event_buffer[key]:
            if start_time <= event['timestamp'] <= end_time:
                if self._evaluate_rule_condition(event['entry'], condition):
                    count += 1
        
        return count
    
    def get_recent_alerts(self, count: int = 10) -> List[Alert]:
        with self.lock:
            return self.alerts_generated[-count:]

# =============================================================================
# ALERT SYSTEM
# =============================================================================

class AlertSystem:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or DEFAULT_CONFIG
        self.alert_channels = self.config.get('alert_channels', {})
    
    def send_alert(self, alert: Alert):
        if self.alert_channels.get('email', {}).get('enabled', False):
            self._send_email_alert(alert)
        
        if self.alert_channels.get('slack', {}).get('enabled', False):
            self._send_slack_alert(alert)
    
    def _send_email_alert(self, alert: Alert):
        email_config = self.alert_channels['email']
        
        try:
            msg = MIMEMultipart()
            msg['From'] = email_config['username']
            msg['To'] = email_config['to']
            msg['Subject'] = f"SIEM Alert: {alert.rule_name} - {alert.severity.upper()}"
            
            body = f"""
            Security Alert Detected!
            
            Rule: {alert.rule_name}
            Description: {alert.description}
            Severity: {alert.severity}
            Source IP: {alert.source_ip}
            Event Count: {alert.event_count}
            Timestamp: {alert.timestamp}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def _send_slack_alert(self, alert: Alert):
        slack_config = self.alert_channels['slack']
        
        try:
            message = {
                "text": f"🚨 SIEM Security Alert - {alert.rule_name}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 Security Alert: {alert.severity.upper()}"
                        }
                    }
                ]
            }
            
            response = requests.post(
                slack_config['webhook_url'],
                json=message,
                headers={'Content-Type': 'application/json'}
            )
            
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")

# =============================================================================
# LOG COLLECTOR
# =============================================================================

class LogCollector:
    def __init__(self, callback: Callable):
        self.parser = LogParser()
        self.callback = callback
        self.running = False
        self.threads = []
    
    def start_file_monitoring(self, file_path: str, log_format: str):
        thread = threading.Thread(
            target=self._monitor_file,
            args=(file_path, log_format),
            daemon=True
        )
        thread.start()
        self.threads.append(thread)
    
    def start_syslog_server(self, port: int = 514):
        thread = threading.Thread(
            target=self._start_syslog_server,
            args=(port,),
            daemon=True
        )
        thread.start()
        self.threads.append(thread)
    
    def _monitor_file(self, file_path: str, log_format: str):
        file = Path(file_path)
        if not file.exists():
            return
        
        with open(file_path, 'r') as f:
            f.seek(0, 2)
        
        while self.running:
            try:
                with open(file_path, 'r') as f:
                    line = f.readline()
                    while line:
                        self._process_log_line(line.strip(), log_format, f"file:{file_path}")
                        line = f.readline()
                time.sleep(1)
            except Exception as e:
                time.sleep(5)
    
    def _start_syslog_server(self, port: int):
        class SyslogUDPHandler(socketserver.BaseRequestHandler):
            def handle(handler):
                data = handler.request[0].strip()
                self._process_log_line(data.decode('utf-8'), 'syslog', f"syslog:{port}")
        
        try:
            with socketserver.UDPServer(('0.0.0.0', port), SyslogUDPHandler) as server:
                server.serve_forever()
        except Exception as e:
            print(f"Syslog server error: {e}")
    
    def _process_log_line(self, log_line: str, log_format: str, source: str):
        if not log_line:
            return
        
        try:
            if log_format == 'syslog':
                log_entry = self.parser.parse_syslog(log_line, source)
            elif log_format == 'apache':
                log_entry = self.parser.parse_apache(log_line, source)
            else:
                return
            
            if log_entry:
                self.callback(log_entry)
        
        except Exception as e:
            print(f"Error processing log line: {e}")
    
    def start(self):
        self.running = True
    
    def stop(self):
        self.running = False
        for thread in self.threads:
            thread.join(timeout=1)

# =============================================================================
# MAIN SIEM SYSTEM
# =============================================================================

class SIEMSystem:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or DEFAULT_CONFIG
        self.running = False
        
        self.storage = DataStorage(self.config['storage']['database']['path'])
        self.analysis_engine = AnalysisEngine(self.config)
        self.alert_system = AlertSystem(self.config)
        self.log_collector = LogCollector(self._process_log_entry)
        
        self.alert_callbacks = []
    
    def add_alert_callback(self, callback: Callable):
        """Add callback for GUI alert notifications"""
        self.alert_callbacks.append(callback)
    
    def _process_log_entry(self, log_entry):
        self.storage.store_log_entry(log_entry)
        self.analysis_engine.process_log_entry(log_entry)
        
        # Notify GUI about new log
        for callback in self.alert_callbacks:
            callback('log', log_entry)
    
    def _process_alerts(self):
        while self.running:
            recent_alerts = self.analysis_engine.get_recent_alerts(10)
            for alert in recent_alerts:
                self.storage.store_alert(alert)
                self.alert_system.send_alert(alert)
                
                # Notify GUI about new alert
                for callback in self.alert_callbacks:
                    callback('alert', alert)
                
                self.analysis_engine.alerts_generated.remove(alert)
            
            time.sleep(1)
    
    def start(self):
        self.running = True
        
        self.log_collector.start()
        
        for source in self.config['log_sources']:
            if source['enabled']:
                if source['type'] == 'file':
                    self.log_collector.start_file_monitoring(
                        source['path'], 
                        source['format']
                    )
                elif source['type'] == 'syslog':
                    self.log_collector.start_syslog_server(
                        source.get('port', 514)
                    )
        
        alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
        alert_thread.start()
        
        cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def stop(self):
        self.running = False
        self.log_collector.stop()
    
    def _cleanup_worker(self):
        while self.running:
            retention_days = self.config['storage'].get('retention_days', 30)
            self.storage.cleanup_old_data(retention_days)
            time.sleep(3600)

# =============================================================================
# CUSTOM STYLED GUI WITH MODERN DARK THEME
# =============================================================================

class StyledSIEMGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ CyberShield SIEM - Security Dashboard")
        self.root.geometry("1400x900")
        
        # Configure theme colors
        self.setup_theme()
        
        # Initialize SIEM system
        self.siem = SIEMSystem()
        self.siem.add_alert_callback(self.on_new_event)
        
        # Statistics
        self.stats = {
            'total_logs': 0,
            'total_alerts': 0,
            'critical_alerts': 0,
            'high_alerts': 0
        }
        
        # Auto-response rules
        self.setup_auto_response()
        
        self.setup_gui()
        self.start_system()
        self.start_gui_updates()
    
    def setup_theme(self):
        """Configure the modern dark theme"""
        style = ttk.Style()
        
        # Configure theme
        style.theme_use('clam')
        
        # Configure colors for different elements
        style.configure('TFrame', background=ColorTheme.BG_PRIMARY)
        style.configure('TLabel', background=ColorTheme.BG_PRIMARY, foreground=ColorTheme.TEXT_PRIMARY)
        style.configure('TButton', background=ColorTheme.BG_TERTIARY, foreground=ColorTheme.TEXT_PRIMARY)
        style.configure('TLabelframe', background=ColorTheme.BG_SECONDARY, foreground=ColorTheme.TEXT_PRIMARY)
        style.configure('TLabelframe.Label', background=ColorTheme.BG_SECONDARY, foreground=ColorTheme.ACCENT_PRIMARY)
        style.configure('TNotebook', background=ColorTheme.BG_PRIMARY)
        style.configure('TNotebook.Tab', background=ColorTheme.BG_TERTIARY, foreground=ColorTheme.TEXT_SECONDARY)
        style.configure('Treeview', 
                       background=ColorTheme.BG_TERTIARY,
                       foreground=ColorTheme.TEXT_PRIMARY,
                       fieldbackground=ColorTheme.BG_TERTIARY)
        style.configure('Treeview.Heading', 
                       background=ColorTheme.BG_SECONDARY,
                       foreground=ColorTheme.ACCENT_PRIMARY)
        
        # Configure the root window background
        self.root.configure(bg=ColorTheme.BG_PRIMARY)
    
    def setup_auto_response(self):
        """Setup automated response rules"""
        self.auto_responses = {
            'critical': [
                {'action': 'block_ip', 'duration': 3600},
                {'action': 'notify_admin', 'method': 'email'}
            ],
            'high': [
                {'action': 'notify_admin', 'method': 'console'}
            ]
        }
    
    def setup_gui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.setup_header(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_logs_tab()
        self.setup_alerts_tab()
        self.setup_statistics_tab()
        self.setup_config_tab()
        
        # Status bar
        self.setup_status_bar()
    
    def setup_header(self, parent):
        """Create a modern header"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = tk.Label(header_frame, 
                              text="🛡️ CyberShield SIEM System",
                              font=('Arial', 20, 'bold'),
                              bg=ColorTheme.BG_PRIMARY,
                              fg=ColorTheme.ACCENT_PRIMARY)
        title_label.pack(side=tk.LEFT)
        
        # Stats overview
        stats_frame = ttk.Frame(header_frame)
        stats_frame.pack(side=tk.RIGHT)
        
        self.header_stats_var = tk.StringVar(value="📊 Monitoring Active | 🟢 System Online")
        stats_label = tk.Label(stats_frame,
                              textvariable=self.header_stats_var,
                              font=('Arial', 10),
                              bg=ColorTheme.BG_PRIMARY,
                              fg=ColorTheme.ACCENT_SUCCESS)
        stats_label.pack()
    
    def setup_dashboard_tab(self):
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Top stats cards
        self.setup_stats_cards(dashboard_frame)
        
        # Recent activity frame
        activity_frame = ttk.Frame(dashboard_frame)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Recent logs
        logs_frame = ttk.LabelFrame(activity_frame, text="📋 Live Log Stream", padding=10)
        logs_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=15, width=60, 
                                                  font=('Consolas', 9),
                                                  bg=ColorTheme.BG_TERTIARY,
                                                  fg=ColorTheme.TEXT_PRIMARY,
                                                  insertbackground=ColorTheme.ACCENT_PRIMARY)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        # Recent alerts
        alerts_frame = ttk.LabelFrame(activity_frame, text="🚨 Security Alerts", padding=10)
        alerts_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=15, width=60,
                                                    font=('Consolas', 9),
                                                    bg=ColorTheme.BG_TERTIARY,
                                                    fg=ColorTheme.TEXT_PRIMARY,
                                                    insertbackground=ColorTheme.ACCENT_PRIMARY)
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_stats_cards(self, parent):
        """Create modern stats cards"""
        cards_frame = ttk.Frame(parent)
        cards_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Stats cards data
        cards_data = [
            {"title": "Total Logs", "value": "total_logs", "color": ColorTheme.ACCENT_PRIMARY, "icon": "📈"},
            {"title": "Total Alerts", "value": "total_alerts", "color": ColorTheme.ACCENT_WARNING, "icon": "🚨"},
            {"title": "Critical", "value": "critical_alerts", "color": ColorTheme.ACCENT_DANGER, "icon": "🔴"},
            {"title": "High Severity", "value": "high_alerts", "color": ColorTheme.ACCENT_WARNING, "icon": "🟠"}
        ]
        
        self.stats_vars = {}
        self.stats_labels = {}
        
        for i, card in enumerate(cards_data):
            card_frame = tk.Frame(cards_frame, bg=ColorTheme.BG_SECONDARY, relief=tk.RAISED, bd=1)
            card_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            
            # Icon and title
            title_frame = tk.Frame(card_frame, bg=ColorTheme.BG_SECONDARY)
            title_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
            
            icon_label = tk.Label(title_frame, text=card["icon"], font=('Arial', 14),
                                 bg=ColorTheme.BG_SECONDARY, fg=card["color"])
            icon_label.pack(side=tk.LEFT)
            
            title_label = tk.Label(title_frame, text=card["title"], font=('Arial', 10, 'bold'),
                                  bg=ColorTheme.BG_SECONDARY, fg=ColorTheme.TEXT_PRIMARY)
            title_label.pack(side=tk.LEFT, padx=(5, 0))
            
            # Value
            self.stats_vars[card["value"]] = tk.StringVar(value="0")
            value_label = tk.Label(card_frame, textvariable=self.stats_vars[card["value"]],
                                  font=('Arial', 18, 'bold'),
                                  bg=ColorTheme.BG_SECONDARY, fg=card["color"])
            value_label.pack(pady=(0, 10))
            
            self.stats_labels[card["value"]] = value_label
    
    def setup_logs_tab(self):
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📋 Logs")
        
        # Toolbar
        toolbar = ttk.Frame(logs_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons with icons
        buttons = [
            ("🔄 Refresh", self.refresh_logs),
            ("🗑️ Clear", self.clear_logs),
            ("📤 Export", self.export_logs)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(toolbar, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Search frame
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT)
        self.log_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.log_search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', self.filter_logs)
        
        # Logs table
        columns = ('Timestamp', 'Source IP', 'Event Type', 'Level', 'Message', 'Source')
        self.logs_tree = ttk.Treeview(logs_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.logs_tree.heading(col, text=col)
            self.logs_tree.column(col, width=100)
        
        self.logs_tree.column('Message', width=300)
        self.logs_tree.column('Timestamp', width=150)
        
        scrollbar = ttk.Scrollbar(logs_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=scrollbar.set)
        
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def setup_alerts_tab(self):
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="🚨 Alerts")
        
        # Toolbar
        toolbar = ttk.Frame(alerts_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        buttons = [
            ("🔄 Refresh", self.refresh_alerts),
            ("✅ Acknowledge All", self.acknowledge_alerts),
            ("📊 Export Report", self.export_report)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(toolbar, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Alerts table
        columns = ('Timestamp', 'Rule', 'Severity', 'Source IP', 'Count', 'Description')
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=100)
        
        self.alerts_tree.column('Description', width=250)
        self.alerts_tree.column('Timestamp', width=150)
        
        # Configure tags for severity colors
        self.alerts_tree.tag_configure('critical', background=ColorTheme.CRITICAL)
        self.alerts_tree.tag_configure('high', background=ColorTheme.HIGH)
        self.alerts_tree.tag_configure('medium', background=ColorTheme.MEDIUM)
        self.alerts_tree.tag_configure('low', background=ColorTheme.LOW)
        
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
    
    def setup_statistics_tab(self):
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📈 Analytics")
        
        # Create matplotlib figure with dark theme
        plt.style.use('dark_background')
        self.fig = Figure(figsize=(10, 8), dpi=100, facecolor=ColorTheme.BG_PRIMARY)
        self.canvas = FigureCanvasTkAgg(self.fig, stats_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def setup_config_tab(self):
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="⚙️ Configuration")
        
        title_label = tk.Label(config_frame, text="SIEM System Configuration", 
                              font=('Arial', 14, 'bold'),
                              bg=ColorTheme.BG_PRIMARY,
                              fg=ColorTheme.ACCENT_PRIMARY)
        title_label.pack(pady=10)
        
        # Configuration controls
        control_frame = ttk.Frame(config_frame)
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        buttons = [
            ("▶ Start Monitoring", self.start_monitoring),
            ("⏹ Stop Monitoring", self.stop_monitoring),
            ("📁 Generate Sample Logs", self.generate_sample_logs),
            ("🔄 Reload Rules", self.reload_rules)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(control_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=5)
        
        # Rules configuration
        rules_frame = ttk.LabelFrame(config_frame, text="Detection Rules", padding=10)
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.rules_text = scrolledtext.ScrolledText(rules_frame, height=15, 
                                                   font=('Consolas', 9),
                                                   bg=ColorTheme.BG_TERTIARY,
                                                   fg=ColorTheme.TEXT_PRIMARY,
                                                   insertbackground=ColorTheme.ACCENT_PRIMARY)
        self.rules_text.pack(fill=tk.BOTH, expand=True)
        self.rules_text.insert(tk.END, json.dumps(DEFAULT_CONFIG['analysis_rules'], indent=2))
    
    def setup_status_bar(self):
        status_frame = tk.Frame(self.root, bg=ColorTheme.BG_SECONDARY, height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        self.status_var = tk.StringVar(value="🟢 Status: System Ready - Monitoring Active")
        status_label = tk.Label(status_frame, textvariable=self.status_var, 
                               font=('Arial', 9),
                               bg=ColorTheme.BG_SECONDARY,
                               fg=ColorTheme.ACCENT_SUCCESS)
        status_label.pack(side=tk.LEFT, padx=10)
        
        self.time_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        time_label = tk.Label(status_frame, textvariable=self.time_var,
                             font=('Arial', 9),
                             bg=ColorTheme.BG_SECONDARY,
                             fg=ColorTheme.TEXT_SECONDARY)
        time_label.pack(side=tk.RIGHT, padx=10)
    
    def on_new_event(self, event_type, data):
        """Handle new events from SIEM system"""
        if event_type == 'log':
            self.add_log_to_display(data)
        elif event_type == 'alert':
            self.add_alert_to_display(data)
            self.show_alert_notification(data)
            self.execute_auto_response(data)
    
    def add_log_to_display(self, log_entry):
        timestamp = log_entry.timestamp.strftime("%H:%M:%S")
        
        # Color code based on log level
        color_map = {
            LogLevel.INFO: ColorTheme.ACCENT_INFO,
            LogLevel.WARNING: ColorTheme.ACCENT_WARNING,
            LogLevel.ERROR: ColorTheme.ACCENT_DANGER,
            LogLevel.CRITICAL: ColorTheme.CRITICAL
        }
        
        color = color_map.get(log_entry.log_level, ColorTheme.TEXT_PRIMARY)
        log_line = f"[{timestamp}] {log_entry.source_ip} - {log_entry.event_type.value}: {log_entry.message}\n"
        
        # Update dashboard with colored text
        self.logs_text.insert(tk.END, log_line)
        self.logs_text.see(tk.END)
        
        # Update stats
        self.stats['total_logs'] += 1
        self.update_stats_display()
    
    def add_alert_to_display(self, alert):
        # Color code based on severity
        color_map = {
            'critical': ColorTheme.CRITICAL,
            'high': ColorTheme.HIGH,
            'medium': ColorTheme.MEDIUM,
            'low': ColorTheme.LOW
        }
        
        color = color_map.get(alert.severity, ColorTheme.TEXT_PRIMARY)
        alert_line = f"[{alert.timestamp.strftime('%H:%M:%S')}] {alert.severity.upper()}: {alert.rule_name} from {alert.source_ip}\n"
        
        # Update dashboard
        self.alerts_text.insert(tk.END, alert_line)
        self.alerts_text.see(tk.END)
        
        # Update stats
        self.stats['total_alerts'] += 1
        if alert.severity == 'critical':
            self.stats['critical_alerts'] += 1
        elif alert.severity == 'high':
            self.stats['high_alerts'] += 1
        
        self.update_stats_display()
    
    def show_alert_notification(self, alert):
        """Show popup notification for critical alerts"""
        if alert.severity in ['critical', 'high']:
            # Play alert sound
            try:
                winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS)
            except:
                pass  # Sound not available
            
            # Show popup
            messagebox.showwarning(
                "🚨 Security Alert!",
                f"Rule: {alert.rule_name}\n"
                f"Severity: {alert.severity.upper()}\n"
                f"Source IP: {alert.source_ip}\n"
                f"Event Count: {alert.event_count}\n"
                f"Time: {alert.timestamp.strftime('%H:%M:%S')}"
            )
    
    def execute_auto_response(self, alert):
        """Execute automated responses based on alert severity"""
        responses = self.auto_responses.get(alert.severity, [])
        
        for response in responses:
            if response['action'] == 'block_ip':
                self.block_ip(alert.source_ip, response.get('duration', 3600))
            elif response['action'] == 'notify_admin':
                self.notify_admin(alert, response.get('method', 'console'))
    
    def block_ip(self, ip, duration):
        """Block IP address (simulated)"""
        print(f"🚫 Blocking IP {ip} for {duration} seconds")
        # In real implementation, you would add to firewall rules
    
    def notify_admin(self, alert, method):
        """Notify administrator"""
        print(f"📧 Notifying admin about {alert.rule_name} via {method}")
    
    def update_stats_display(self):
        # Update header stats
        self.stats_vars['total_logs'].set(str(self.stats['total_logs']))
        self.stats_vars['total_alerts'].set(str(self.stats['total_alerts']))
        self.stats_vars['critical_alerts'].set(str(self.stats['critical_alerts']))
        self.stats_vars['high_alerts'].set(str(self.stats['high_alerts']))
        
        # Update header status
        status_text = f"📊 Logs: {self.stats['total_logs']} | 🚨 Alerts: {self.stats['total_alerts']} | 🟢 System Online"
        self.header_stats_var.set(status_text)
    
    def refresh_logs(self):
        """Refresh logs table"""
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        
        logs = self.siem.storage.get_recent_logs(100)
        for log in logs:
            self.logs_tree.insert('', tk.END, values=(
                log['timestamp'],
                log['source_ip'],
                log['event_type'],
                log['log_level'],
                log['message'][:100] + '...' if len(log['message']) > 100 else log['message'],
                log['source']
            ))
    
    def refresh_alerts(self):
        """Refresh alerts table"""
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        alerts = self.siem.storage.get_recent_alerts(50)
        for alert in alerts:
            tags = (alert['severity'],)
            self.alerts_tree.insert('', tk.END, values=(
                alert['timestamp'],
                alert['rule_name'],
                alert['severity'],
                alert['source_ip'],
                alert['event_count'],
                alert['description']
            ), tags=tags)
    
    def filter_logs(self, event=None):
        search_term = self.log_search_var.get().lower()
        
        for item in self.logs_tree.get_children():
            values = self.logs_tree.item(item)['values']
            if search_term in str(values).lower():
                self.logs_tree.item(item, tags=('match',))
            else:
                self.logs_tree.item(item, tags=())
        
        self.logs_tree.tag_configure('match', background=ColorTheme.ACCENT_WARNING)
    
    def clear_logs(self):
        self.logs_text.delete(1.0, tk.END)
    
    def export_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.logs_text.get(1.0, tk.END))
            messagebox.showinfo("Export", "Logs exported successfully!")
    
    def export_report(self):
        """Export comprehensive security report"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            stats = self.siem.storage.get_statistics()
            recent_alerts = self.siem.storage.get_recent_alerts(50)
            
            report_content = f"""
SECURITY REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

SUMMARY:
- Total Logs Today: {stats['total_logs_today']}
- Total Alerts Today: {stats['alerts_today']}
- Critical Alerts: {self.stats['critical_alerts']}
- High Alerts: {self.stats['high_alerts']}

TOP THREAT SOURCES:
"""
            for ip_stat in stats['top_source_ips'][:10]:
                report_content += f"- {ip_stat['ip']}: {ip_stat['count']} events\n"

            report_content += "\nRECENT ALERTS:\n"
            for alert in recent_alerts[:20]:
                report_content += f"- [{alert['severity']}] {alert['rule_name']} from {alert['source_ip']}\n"

            with open(filename, 'w') as f:
                f.write(report_content)
            
            messagebox.showinfo("Export", f"Report exported to {filename}")
    
    def acknowledge_alerts(self):
        self.alerts_text.delete(1.0, tk.END)
        messagebox.showinfo("Alerts", "All alerts acknowledged!")
    
    def start_monitoring(self):
        self.siem.start()
        self.status_var.set("🟢 Status: Monitoring Active - System Running")
        messagebox.showinfo("Monitoring", "SIEM monitoring started!")
    
    def stop_monitoring(self):
        self.siem.stop()
        self.status_var.set("🟡 Status: Monitoring Stopped - System Idle")
        messagebox.showinfo("Monitoring", "SIEM monitoring stopped!")
    
    def generate_sample_logs(self):
        create_sample_logs()
        messagebox.showinfo("Sample Logs", "Sample log files generated!")
    
    def reload_rules(self):
        try:
            new_rules = json.loads(self.rules_text.get(1.0, tk.END))
            self.siem.analysis_engine.rules = new_rules
            messagebox.showinfo("Rules", "Detection rules reloaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid rules format: {e}")
    
    def start_system(self):
        """Start the SIEM system"""
        self.siem.start()
        self.status_var.set("🟢 Status: System Running - Monitoring Active")
    
    def start_gui_updates(self):
        """Start periodic GUI updates"""
        self.update_time()
        self.refresh_logs()
        self.refresh_alerts()
        self.update_charts()
        
        # Schedule next update
        self.root.after(5000, self.start_gui_updates)
    
    def update_time(self):
        self.time_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def update_charts(self):
        """Update statistics charts with dark theme"""
        self.fig.clear()
        stats = self.siem.storage.get_statistics()
        
        # Set dark background for all subplots
        for ax in self.fig.axes:
            ax.set_facecolor(ColorTheme.BG_TERTIARY)
        
        # Event distribution pie chart
        ax1 = self.fig.add_subplot(221)
        ax1.set_facecolor(ColorTheme.BG_TERTIARY)
        if stats['event_distribution']:
            event_types = [e['type'] for e in stats['event_distribution']]
            event_counts = [e['count'] for e in stats['event_distribution']]
            ax1.pie(event_counts, labels=event_types, autopct='%1.1f%%', startangle=90,
                   colors=ColorTheme.CHART_COLORS)
            ax1.set_title('Event Distribution', color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        else:
            ax1.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax1.transAxes,
                    color=ColorTheme.TEXT_SECONDARY)
            ax1.set_title('Event Distribution', color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        
        # Top IPs bar chart
        ax2 = self.fig.add_subplot(222)
        ax2.set_facecolor(ColorTheme.BG_TERTIARY)
        if stats['top_source_ips']:
            top_ips = [ip['ip'] for ip in stats['top_source_ips'][:5]]
            ip_counts = [ip['count'] for ip in stats['top_source_ips'][:5]]
            bars = ax2.bar(top_ips, ip_counts, color=ColorTheme.ACCENT_PRIMARY)
            ax2.set_title('Top Source IPs', color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
            ax2.tick_params(axis='x', rotation=45, colors=ColorTheme.TEXT_SECONDARY)
            ax2.tick_params(axis='y', colors=ColorTheme.TEXT_SECONDARY)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom',
                        color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        else:
            ax2.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax2.transAxes,
                    color=ColorTheme.TEXT_SECONDARY)
            ax2.set_title('Top Source IPs', color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        
        # Alert severity chart
        ax3 = self.fig.add_subplot(223)
        ax3.set_facecolor(ColorTheme.BG_TERTIARY)
        severities = ['Critical', 'High', 'Medium', 'Low']
        severity_counts = [
            self.stats['critical_alerts'],
            self.stats['high_alerts'],
            0, 0  # You can track these too
        ]
        colors = [ColorTheme.CRITICAL, ColorTheme.HIGH, ColorTheme.MEDIUM, ColorTheme.LOW]
        bars = ax3.bar(severities, severity_counts, color=colors)
        ax3.set_title('Alert Severity Distribution', color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        ax3.tick_params(axis='x', colors=ColorTheme.TEXT_SECONDARY)
        ax3.tick_params(axis='y', colors=ColorTheme.TEXT_SECONDARY)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom',
                    color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        
        # Timeline chart (simulated)
        ax4 = self.fig.add_subplot(224)
        ax4.set_facecolor(ColorTheme.BG_TERTIARY)
        hours = list(range(24))
        # Simulate hourly data
        hourly_data = [random.randint(0, 50) for _ in hours]
        ax4.plot(hours, hourly_data, marker='o', color=ColorTheme.ACCENT_SUCCESS, linewidth=2)
        ax4.set_title('Events per Hour (Simulated)', color=ColorTheme.TEXT_PRIMARY, fontweight='bold')
        ax4.set_xlabel('Hour of Day', color=ColorTheme.TEXT_SECONDARY)
        ax4.set_ylabel('Number of Events', color=ColorTheme.TEXT_SECONDARY)
        ax4.grid(True, alpha=0.3)
        ax4.tick_params(axis='x', colors=ColorTheme.TEXT_SECONDARY)
        ax4.tick_params(axis='y', colors=ColorTheme.TEXT_SECONDARY)
        
        self.fig.tight_layout()
        self.canvas.draw()
    
    def on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Do you want to stop monitoring and quit?"):
            self.siem.stop()
            self.root.destroy()

# =============================================================================
# MAIN APPLICATION
# =============================================================================

def main():
    """Main function to run the SIEM GUI application"""
    # Create sample logs if they don't exist
    if not Path('sample_auth.log').exists() or not Path('sample_apache.log').exists():
        create_sample_logs()
        print("📁 Sample log files created!")
    
    # Create and run GUI
    root = tk.Tk()
    
    # Set window icon and title
    root.title("🛡️ CyberShield SIEM - Security Dashboard")
    root.geometry("1400x900")
    
    # Create the application
    app = StyledSIEMGUI(root)
    
    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    print("✅ SIEM System started successfully!")
    print("🎨 Modern dark theme applied!")
    print("📊 GUI is running...")
    print("🔍 Monitoring log files for security events...")
    
    # Start the GUI
    root.mainloop()

if __name__ == "__main__":
    main()