import os
import re
import time
import threading
from collections import defaultdict

class IDSEngine:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.running = False
        self.threads = []
        self.stop_event = threading.Event()
        self.alert_callback = None

        self.log_files = {
            "ssh": os.path.join(self.log_dir, "auth.log"),
            "apache": os.path.join(self.log_dir, "apache.log"),
            "firewall": os.path.join(self.log_dir, "firewall.log")
        }

        self.ssh_failures = defaultdict(list)
        self.fw_blocks = defaultdict(set)
        self.last_alerts = {}

    def log_alert(self, source, severity, message, attacker_ip=None):
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": source.upper(),
            "severity": severity.upper(),
            "message": message,
            "ip": attacker_ip or "unknown"
        }
        
        # 10 seconds anti-flood
        alert_key = f"{source}_{severity}_{attacker_ip}_{message}"
        now = time.time()
        if alert_key in self.last_alerts and (now - self.last_alerts[alert_key]) < 10:
            return
        
        self.last_alerts[alert_key] = now
        
        if self.alert_callback:
            self.alert_callback(alert)

    def parse_ssh_line(self, line):
        if "Failed password" in line or "authentication failure" in line:
            ip_match = re.search(r"from\s+([0-9a-fA-F\.:]+)", line)
            user_match = re.search(r"for\s+(?:invalid\s+user\s+)?(\S+)\s+from", line)
            
            ip = ip_match.group(1) if ip_match else "unknown"
            username = user_match.group(1) if user_match else "unknown"
            
            now = time.time()
            self.ssh_failures[ip].append(now)
            
            # keep only failures in the last 30 seconds
            self.ssh_failures[ip] = [t for t in self.ssh_failures[ip] if now - t <= 30]
            
            count = len(self.ssh_failures[ip])
            if count >= 5:
                self.log_alert(
                    source="SSH",
                    severity="CRITICAL",
                    message=f"SSH brute force detected: {count} failures in 30s targeting '{username}'",
                    attacker_ip=ip
                )
            else:
                self.log_alert(
                    source="SSH",
                    severity="WARNING",
                    message=f"Failed SSH login for '{username}' (attempt {count}/5)",
                    attacker_ip=ip
                )

    def parse_apache_line(self, line):
        parts = line.split('"')
        if len(parts) < 2:
            return
            
        request_line = parts[1]
        
        ip_match = re.match(r"^(\S+)", line)
        ip = ip_match.group(1) if ip_match else "unknown"
        
        sql_pattern = re.compile(r"(union\s+select|select\s+.*\s+from|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|['\"]?\s*--|xp_cmdshell)", re.IGNORECASE)
        xss_pattern = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<img\s+src)", re.IGNORECASE)
        traversal_pattern = re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|/bin/sh)", re.IGNORECASE)

        if sql_pattern.search(request_line):
            self.log_alert(
                source="Apache",
                severity="CRITICAL",
                message=f"SQL injection detected: '{request_line.strip()}'",
                attacker_ip=ip
            )
        elif xss_pattern.search(request_line):
            self.log_alert(
                source="Apache",
                severity="CRITICAL",
                message=f"XSS attack detected: '{request_line.strip()}'",
                attacker_ip=ip
            )
        elif traversal_pattern.search(request_line):
            self.log_alert(
                source="Apache",
                severity="CRITICAL",
                message=f"Path traversal detected: '{request_line.strip()}'",
                attacker_ip=ip
            )

    def parse_firewall_line(self, line):
        if "BLOCK" in line or "DROP" in line:
            src_match = re.search(r"SRC=([0-9a-fA-F\.:]+)", line)
            port_match = re.search(r"DPT=(\d+)", line)
            
            if src_match and port_match:
                ip = src_match.group(1)
                port = int(port_match.group(1))
                now = time.time()
                
                self.fw_blocks[ip].add((port, now))
                
                # keep only blocks in the last 15 seconds
                self.fw_blocks[ip] = {(p, t) for (p, t) in self.fw_blocks[ip] if now - t <= 15}
                
                unique_ports = {p for (p, t) in self.fw_blocks[ip]}
                port_count = len(unique_ports)
                
                if port_count >= 5:
                    self.log_alert(
                        source="Firewall",
                        severity="CRITICAL",
                        message=f"Port scan detected: {port_count} ports blocked in 15s. Ports: {sorted(list(unique_ports))}",
                        attacker_ip=ip
                    )
                else:
                    self.log_alert(
                        source="Firewall",
                        severity="WARNING",
                        message=f"Packet blocked on port {port} (scanned {port_count}/5)",
                        attacker_ip=ip
                    )

    def _tail_file(self, service_name, filepath, parser_func):
        if not os.path.exists(filepath):
            with open(filepath, "w", encoding="utf-8") as f:
                pass
            
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            
            while not self.stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                line = line.strip()
                if line:
                    try:
                        parser_func(line)
                    except Exception as e:
                        self.log_alert(
                            source="system",
                            severity="WARNING",
                            message=f"Error parsing {service_name}: {str(e)}"
                        )

    def start_monitoring(self, callback):
        if self.running:
            return
            
        self.alert_callback = callback
        self.running = True
        self.stop_event.clear()
        
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.threads = []
        
        ssh_thread = threading.Thread(
            target=self._tail_file, 
            args=("SSH", self.log_files["ssh"], self.parse_ssh_line),
            daemon=True
        )
        self.threads.append(ssh_thread)
        
        apache_thread = threading.Thread(
            target=self._tail_file, 
            args=("Apache", self.log_files["apache"], self.parse_apache_line),
            daemon=True
        )
        self.threads.append(apache_thread)
        
        fw_thread = threading.Thread(
            target=self._tail_file, 
            args=("Firewall", self.log_files["firewall"], self.parse_firewall_line),
            daemon=True
        )
        self.threads.append(fw_thread)
        
        for t in self.threads:
            t.start()
            
        self.log_alert("system", "INFO", "IDS started. monitoring logs...")

    def stop_monitoring(self):
        if not self.running:
            return
            
        self.stop_event.set()
        self.running = False
        
        for t in self.threads:
            t.join(timeout=0.5)
            
        self.threads = []
        self.log_alert("system", "INFO", "IDS stopped. monitoring suspended.")
