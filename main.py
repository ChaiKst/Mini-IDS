import os
import sys
import time
import random
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from ids_core import IDSEngine

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("intrusion detection system")
        self.root.geometry("900x650")
        self.root.minsize(800, 550)
        
        self.engine = IDSEngine()
        self.attacker_ip = "198.51.100.42"
        self.normal_ip = "192.168.1.15"

        self.setup_ui()
        self.setup_text_tags()
        self.toggle_monitoring()

    def setup_ui(self):
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame, 
            text="intrusion detection system", 
            font=("Segoe UI", 14, "bold"), 
            fg="white", 
            bg="#2c3e50"
        )
        title_label.pack(side=tk.LEFT, padx=15, pady=15)

        self.status_var = tk.StringVar(value="status: stopped")
        self.status_label = tk.Label(
            header_frame, 
            textvariable=self.status_var, 
            font=("Segoe UI", 11, "bold"),
            fg="#e74c3c", 
            bg="#2c3e50"
        )
        self.status_label.pack(side=tk.RIGHT, padx=15, pady=15)

        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.LabelFrame(main_paned, text=" real-time alerts ", font=("Segoe UI", 10, "bold"), labelanchor="nw")
        main_paned.add(left_frame, weight=3)

        self.console = scrolledtext.ScrolledText(
            left_frame, 
            wrap=tk.WORD, 
            font=("Consolas", 10), 
            bg="#1e1e1e", 
            fg="#ffffff", 
            insertbackground="white"
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        console_buttons = tk.Frame(left_frame)
        console_buttons.pack(fill=tk.X, pady=5)
        
        self.btn_toggle = tk.Button(
            console_buttons, 
            text="start monitoring", 
            font=("Segoe UI", 9, "bold"), 
            bg="#2ecc71", 
            fg="white", 
            relief=tk.FLAT, 
            command=self.toggle_monitoring,
            padx=10, pady=5
        )
        self.btn_toggle.pack(side=tk.LEFT, padx=5)

        btn_clear = tk.Button(
            console_buttons, 
            text="clear history", 
            font=("Segoe UI", 9), 
            bg="#95a5a6", 
            fg="white", 
            relief=tk.FLAT, 
            command=self.clear_console,
            padx=10, pady=5
        )
        btn_clear.pack(side=tk.LEFT, padx=5)

        btn_open_logs = tk.Button(
            console_buttons, 
            text="open logs folder", 
            font=("Segoe UI", 9), 
            bg="#34495e", 
            fg="white", 
            relief=tk.FLAT, 
            command=self.open_log_folder,
            padx=10, pady=5
        )
        btn_open_logs.pack(side=tk.RIGHT, padx=5)

        right_frame = tk.LabelFrame(main_paned, text=" attack simulator ", font=("Segoe UI", 10, "bold"), labelanchor="nw")
        main_paned.add(right_frame, weight=1)

        sim_desc = tk.Label(
            right_frame, 
            text="inject simulated log entries to test detection rules.", 
            font=("Segoe UI", 9, "italic"),
            wraplength=220, 
            justify=tk.LEFT
        )
        sim_desc.pack(fill=tk.X, padx=10, pady=10)

        ssh_group = tk.LabelFrame(right_frame, text=" ssh log simulation ", padx=5, pady=5)
        ssh_group.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(
            ssh_group, 
            text="failed ssh login attempt", 
            bg="#f39c12", fg="white", relief=tk.GROOVE,
            command=lambda: self.simulate_ssh_fail(count=1)
        ).pack(fill=tk.X, pady=2)

        tk.Button(
            ssh_group, 
            text="ssh brute force attack (5 failures)", 
            bg="#c0392b", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.GROOVE,
            command=lambda: self.simulate_ssh_fail(count=5)
        ).pack(fill=tk.X, pady=2)

        tk.Button(
            ssh_group, 
            text="successful ssh login", 
            bg="#27ae60", fg="white", relief=tk.GROOVE,
            command=self.simulate_ssh_success
        ).pack(fill=tk.X, pady=2)

        web_group = tk.LabelFrame(right_frame, text=" apache web log simulation ", padx=5, pady=5)
        web_group.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(
            web_group, 
            text="standard web traffic", 
            bg="#27ae60", fg="white", relief=tk.GROOVE,
            command=self.simulate_web_normal
        ).pack(fill=tk.X, pady=2)

        tk.Button(
            web_group, 
            text="sql injection attack", 
            bg="#c0392b", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.GROOVE,
            command=self.simulate_web_sql
        ).pack(fill=tk.X, pady=2)

        tk.Button(
            web_group, 
            text="xss attack", 
            bg="#c0392b", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.GROOVE,
            command=self.simulate_web_xss
        ).pack(fill=tk.X, pady=2)

        tk.Button(
            web_group, 
            text="path traversal attack", 
            bg="#c0392b", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.GROOVE,
            command=self.simulate_web_traversal
        ).pack(fill=tk.X, pady=2)

        fw_group = tk.LabelFrame(right_frame, text=" firewall log simulation ", padx=5, pady=5)
        fw_group.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(
            fw_group, 
            text="blocked packet (port 80)", 
            bg="#f39c12", fg="white", relief=tk.GROOVE,
            command=lambda: self.simulate_fw_block(ports=[80])
        ).pack(fill=tk.X, pady=2)

        tk.Button(
            fw_group, 
            text="port scan (5 ports)", 
            bg="#c0392b", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.GROOVE,
            command=lambda: self.simulate_fw_block(ports=[21, 22, 23, 80, 443])
        ).pack(fill=tk.X, pady=2)

        footer = tk.Frame(self.root, bd=1, relief=tk.SUNKEN)
        footer.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=2)
        
        info_label = tk.Label(footer, text="simulator ips: normal = 192.168.1.15 | attacker = 198.51.100.42", font=("Segoe UI", 8))
        info_label.pack(side=tk.LEFT)

        help_label = tk.Label(footer, text="python native intrusion detection system", font=("Segoe UI", 8, "italic"))
        help_label.pack(side=tk.RIGHT)

    def setup_text_tags(self):
        self.console.tag_config("CRITICAL", foreground="#ff6b6b", font=("Consolas", 10, "bold"))
        self.console.tag_config("WARNING", foreground="#f39c12", font=("Consolas", 10))
        self.console.tag_config("INFO", foreground="#2ecc71")
        self.console.tag_config("SYSTEM", foreground="#9b59b6")
        self.console.tag_config("TIMESTAMP", foreground="#7f8c8d")

    def toggle_monitoring(self):
        if self.engine.running:
            self.engine.stop_monitoring()
            self.status_var.set("status: stopped")
            self.status_label.config(fg="#e74c3c")
            self.btn_toggle.config(text="start monitoring", bg="#2ecc71")
        else:
            self.engine.start_monitoring(self.handle_incoming_alert)
            self.status_var.set("status: listening")
            self.status_label.config(fg="#2ecc71")
            self.btn_toggle.config(text="stop monitoring", bg="#e74c3c")

    def handle_incoming_alert(self, alert):
        self.root.after(0, self.append_alert_to_console, alert)

    def append_alert_to_console(self, alert):
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, f"[{alert['timestamp']}] ", "TIMESTAMP")
        
        severity = alert["severity"]
        self.console.insert(tk.END, f"[{alert['source']}] [IP: {alert['ip']}] ", "SYSTEM")
        self.console.insert(tk.END, f"{severity}", severity)
        self.console.insert(tk.END, f" : {alert['message']}\n")
        
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

    def clear_console(self):
        self.console.configure(state=tk.NORMAL)
        self.console.delete("1.0", tk.END)
        self.console.configure(state=tk.DISABLED)

    def open_log_folder(self):
        log_dir_absolute = os.path.abspath(self.engine.log_dir)
        os.makedirs(log_dir_absolute, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(log_dir_absolute)
        else:
            messagebox.showinfo("logs folder", f"logs are located at:\n{log_dir_absolute}")

    def _write_log(self, filepath, line):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        try:
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "write error", f"unable to write to {os.path.basename(filepath)}: {e}")

    def simulate_ssh_fail(self, count=1):
        filepath = self.engine.log_files["ssh"]
        
        def run():
            users = ["admin", "root", "user", "guest", "mysql"]
            for i in range(count):
                user = random.choice(users)
                now_str = time.strftime("%b %d %H:%M:%S")
                pid = random.randint(1000, 30000)
                port = random.randint(30000, 65000)
                log_line = f"{now_str} server sshd[{pid}]: Failed password for {user} from {self.attacker_ip} port {port} ssh2"
                self._write_log(filepath, log_line)
                if count > 1:
                    time.sleep(0.2)

        threading.Thread(target=run, daemon=True).start()

    def simulate_ssh_success(self):
        filepath = self.engine.log_files["ssh"]
        now_str = time.strftime("%b %d %H:%M:%S")
        pid = random.randint(1000, 30000)
        port = random.randint(30000, 65000)
        log_line = f"{now_str} server sshd[{pid}]: Accepted password for admin from {self.normal_ip} port {port} ssh2"
        self._write_log(filepath, log_line)

    def simulate_web_normal(self):
        filepath = self.engine.log_files["apache"]
        now_str = time.strftime("%d/%b/%Y:%H:%M:%S +0200")
        urls = ["/index.php", "/about.html", "/contact.php", "/assets/logo.png", "/css/style.css"]
        url = random.choice(urls)
        log_line = f'{self.normal_ip} - - [{now_str}] "GET {url} HTTP/1.1" 200 {random.randint(500, 10000)}'
        self._write_log(filepath, log_line)

    def simulate_web_sql(self):
        filepath = self.engine.log_files["apache"]
        now_str = time.strftime("%d/%b/%Y:%H:%M:%S +0200")
        sql_payloads = [
            "/products.php?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users",
            "/login.php?user=admin'%20OR%20'1'='1",
            "/search.php?q=test'%20OR%201=1%20--"
        ]
        url = random.choice(sql_payloads)
        log_line = f'{self.attacker_ip} - - [{now_str}] "GET {url} HTTP/1.1" 200 {random.randint(100, 500)}'
        self._write_log(filepath, log_line)

    def simulate_web_xss(self):
        filepath = self.engine.log_files["apache"]
        now_str = time.strftime("%d/%b/%Y:%H:%M:%S +0200")
        xss_payloads = [
            "/comment.php?msg=<script>alert('hacked')</script>",
            "/profile.php?name=guest<img%20src=x%20onerror=alert(1)>",
            "/index.php?search=javascript:alert(document.cookie)"
        ]
        url = random.choice(xss_payloads)
        log_line = f'{self.attacker_ip} - - [{now_str}] "GET {url} HTTP/1.1" 200 {random.randint(100, 500)}'
        self._write_log(filepath, log_line)

    def simulate_web_traversal(self):
        filepath = self.engine.log_files["apache"]
        now_str = time.strftime("%d/%b/%Y:%H:%M:%S +0200")
        traversal_payloads = [
            "/download.php?file=../../../../etc/passwd",
            "/view.php?page=..\\..\\..\\windows\\win.ini",
            "/cgi-bin/test.cgi?file=/bin/sh"
        ]
        url = random.choice(traversal_payloads)
        log_line = f'{self.attacker_ip} - - [{now_str}] "GET {url} HTTP/1.1" 200 {random.randint(100, 500)}'
        self._write_log(filepath, log_line)

    def simulate_fw_block(self, ports=[80]):
        filepath = self.engine.log_files["firewall"]
        
        def run():
            for port in ports:
                log_line = f"BLOCK: SRC={self.attacker_ip} DST=10.0.0.1 PROTO=TCP DPT={port}"
                self._write_log(filepath, log_line)
                if len(ports) > 1:
                    time.sleep(0.15)

        threading.Thread(target=run, daemon=True).start()

    def on_closing(self):
        self.engine.stop_monitoring()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
