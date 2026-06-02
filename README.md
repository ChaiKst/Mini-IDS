# Mini-IDS

This **Mini-IDS** is a lightweight, standalone intrusion detection system written in **pure Python** (no third-party libraries, no heavy frameworks, just good old standard library code).

It monitors system log files in real-time (SSH, Apache, Firewall) similar to `tail -f`, analyzes the content line-by-line, and triggers color-coded alerts in a minimalist yet extremely practical graphical user interface.

---

## Implemented detection rules

The IDS uses two types of analysis: **signature-based** (regex matching suspicious patterns) and **time-based heuristics** (tracking activity per IP address).

### 1. SSH brute force (`logs/auth.log`)

- **Detection:** The IDS scans for authentication failures (`Failed password` or `authentication failure`).
- **Threshold:** If the same IP address experiences **5 or more failures in under 30 seconds**, the alert level is set to **CRITICAL** (SSH brute force detected). Intermediate attempts raise **WARNING** alerts.

### 2. Apache web injections (`logs/apache.log`)

- **Detection:** Analysis of HTTP requests (GET/POST methods, URL, query strings).
- **Signatures (Regex):**
  - **SQL Injection:** Looks for patterns like `UNION SELECT`, `OR 1=1`, `SELECT ... FROM`, `--`.
  - **Cross-Site Scripting (XSS):** Looks for tags like `<script>`, `javascript:`, `onerror`, or `onload` attributes.
  - **Path Traversal:** Looks for directory traversal attempts (`../../`) or access to sensitive files (`/etc/passwd`, `win.ini`).
- **Severity:** Instantly classified as **CRITICAL** with details about the suspicious request.

### 3. Firewall port scan (`logs/firewall.log`)

- **Detection:** Scans for packets blocked by the firewall (`BLOCK` or `DROP`).
- **Threshold:** If the same IP address generates blocked packets on **5 or more different ports in under 15 seconds**, the IDS triggers a **CRITICAL** alert for a Port Scan, listing all targeted ports. Single blocks are flagged as **WARNING**.

---

## How to launch the application?

It's extremely simple! The application only uses Python's standard library. **Zero external dependencies to install via pip.**

1. Open a terminal in the project directory:
   ```powershell
   cd c:\Users\sltce\mon_ids
   ```
2. Run the main script:
   ```powershell
   python main.py
   ```

A Tkinter graphical interface window will open. Monitoring automatically starts on the three files located in the `logs/` directory.

---

## How to test (the attack simulator)

To save you from having to run actual attack tools (such as Hydra, Nmap, or Sqlmap) or configuring real log servers, **an interactive simulator is built directly into the right panel of the GUI**!

Here is how to test the different scenarios:

### Scenario A: SSH brute force

1. Click the **"failed ssh login attempt"** button: the IDS displays a warning in yellow (`WARNING : Failed SSH login for 'admin' (attempt 1/5)`).
2. Click the **"ssh brute force attack (5 failures)"** button: the simulator quickly injects 5 consecutive failures. The IDS aggregates these events and instantly triggers a red alert (`CRITICAL : SSH brute force detected: 5 failures in 30s targeting '...'`).
3. Click **"successful ssh login"**: the IDS ignores the line (no alert) because the connection succeeded.

### Scenario B: web injections

- Click **"sql injection attack"**, **"xss attack"**, or **"path traversal attack"**: the IDS analyzes the requested URL and immediately triggers a critical alert describing the injection.
- Click **"standard web traffic"**: no alert is triggered (normal traffic).

### Scenario C: port scan

- Click **"port scan (5 ports)"**: the simulator injects blocked packets on 5 different ports (21, 22, 23, 80, 443). The IDS detects the scanning behavior and triggers a red alert (`CRITICAL : Port scan detected: 5 ports blocked in 15s. Ports: [...]`).

---

## Real integration

If you want to use this IDS on a real machine to monitor your actual logs:

1. Modify the log file paths in the `IDSEngine` constructor in `ids_core.py`:
   ```python
   self.log_files = {
       "ssh": "/var/log/auth.log",
       "apache": "/var/log/apache2/access.log",
       "firewall": "/var/log/ufw.log"
   }
   ```
2. Ensure that the user running the Python script has read permissions for these files.
