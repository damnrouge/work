### **Anti-Debugging Techniques**

| Technique            | How it Works                              | Example Scenario                                |
|----------------------|-------------------------------------------|--------------------------------------------------|
| System API Calls     | Uses Windows API like `IsDebuggerPresent` | If `IsDebuggerPresent` returns true, malware shuts down to prevent analysis. |
| Code Modification Detection | Checks code checksum at startup and periodically for tampering. | Starts with checksum `0x1234ABCD`. If changed, stops malicious activities. |
| Timing Checks        | Measures time to execute instructions. Longer times may indicate debugging. | Executes a 1ms loop. If longer, assumes debugger is present. |
| Hardware Breakpoints | Checks CPU registers (DR0-DR7) for hardware breakpoints. | Scans debug registers. If non-zero, avoids critical code. |
| Exception Handling   | Triggers exceptions to detect debuggers. | Divides by zero. If program continues, likely being debugged. |
| Process & Thread Blocks | Enumerates processes/threads for debuggers. | Looks for `ollydbg.exe`. If found, suspends operations. |
| Memory Checks        | Checks if code relocated in memory. | Starts at `0x00400000`. If different, assumes debugger present. |
| IDT Monitoring       | Monitors Interrupt Descriptor Table for changes. | Checks interrupt handler addresses. If modified, deactivates. |
| LDT Checks          | Checks Local Descriptor Table for debugger modifications. | Verifies segment selectors for anomalies. |
| GDT Monitoring      | Monitors Global Descriptor Table alterations. | If base address changes, stops execution. |

<!-- -->

<!-- -->
### **Anti-Sandboxing Techniques**

| Technique            | Definition                           | Example Scenario                          |
|----------------------|--------------------------------------|-------------------------------------------|
| Encryption           | Encrypts payload to hinder analysis. | Ransomware remains inert in sandbox without decryption key. |
| Environment Scanners | Detects virtual machine artifacts. | Checks for VM drivers (e.g., VirtualBox). If found, exits. |
| User Activity Monitoring | Watches for human interactions. | Only activates after detecting mouse movements/keystrokes. |
| AI Algorithms        | Uses machine learning to detect sandboxes. | Analyzes system behavior patterns to identify analysis environments. |
| Sleep Loops          | Delays execution with long sleeps. | Sleeps for 10 minutes (longer than sandbox timeout). |
| Fast Flux            | Rapidly changes network addresses. | Botnet changes C2 server IPs every 5 minutes. |
| Stalling Code        | Requires specific conditions to run. | Checks for `C:\real_user\documents` before executing. |
| Resource Checks      | Profiles system resources. | Detects low CPU cores/RAM (common in VMs). |
| Hook Detection       | Scans for API hooks. | Avoids calling hooked functions like `CreateProcess`. |
| Time Bomb            | Delays activation. | Only runs after 30 days (post-sandbox analysis). |

<!-- -->

<!-- -->

### **Anti-Sandboxing for URLs**

| Technique            | Definition                           | Example Scenario                          |
|----------------------|--------------------------------------|-------------------------------------------|
| System API Calls     | Hides code from analysis. | Encrypted payload avoids sandbox inspection. |
| Environment Scanners | Detects VM environments. | Exits if VMware tools detected. |
| User Activity Monitoring | Requires human interaction. | Waits for mouse clicks before connecting to C2. |
| AI Algorithms        | Behavioral analysis evasion. | Mimics legitimate browser traffic patterns. |
| Sleep Loops          | Delays malicious actions. | JavaScript sleeps for 1 hour before phishing redirect. |
| Fast Flux            | Rotates domain names/IPs. | Changes malicious domain every 10 minutes. |
| Stalling Code        | Conditional execution. | Only loads payload if visited from specific referrer. |
| Resource Checks      | Detects headless browsers. | Checks for Chrome `--headless` flag. |
| Hook Detection       | Avoids monitored APIs. | Skips `XMLHttpRequest` if hooked. |
| Time Bomb            | Scheduled activation. | Malicious iframe loads after 14 days. |
