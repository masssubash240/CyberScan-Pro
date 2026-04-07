import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socket
import subprocess
import threading
import ipaddress
import time
import csv
from datetime import datetime
from queue import Queue
import platform
import sys

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberScan Pro - Network Scanner for Ethical Use")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0a0a1a')
        
        # Initialize variables
        self.scanning = False
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.results_queue = Queue()
        self.hosts_discovered = []
        
        # Set up GUI
        self.setup_gui()
        
        # Start queue processor for real-time updates
        self.process_queue()
        
        # Display disclaimer
        self.show_disclaimer()
    
    def setup_gui(self):
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        bg_color = '#0a0a1a'
        fg_color = '#00ff00'
        entry_bg = '#1a1a2e'
        button_bg = '#162447'
        accent_color = '#00ff00'
        
        # Create main frames
        header_frame = tk.Frame(self.root, bg=bg_color, height=80)
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        main_frame = tk.Frame(self.root, bg=bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        output_frame = tk.Frame(self.root, bg=bg_color)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        # Header
        title_label = tk.Label(header_frame, 
                              text="CyberScan Pro - Network Security Scanner", 
                              font=('Courier', 24, 'bold'),
                              bg=bg_color, 
                              fg=accent_color)
        title_label.pack(pady=10)
        
        subtitle_label = tk.Label(header_frame, 
                                 text="For Educational and Authorized Use Only", 
                                 font=('Courier', 10),
                                 bg=bg_color, 
                                 fg='#cccccc')
        subtitle_label.pack()
        
        # Configure grid for main_frame
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # Left panel - Target Configuration
        left_panel = tk.LabelFrame(main_frame, text=" Target Configuration ", 
                                   font=('Courier', 12, 'bold'),
                                   bg=bg_color, fg=accent_color,
                                   relief=tk.GROOVE, bd=2)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=5)
        
        # IP Range Input
        ip_frame = tk.Frame(left_panel, bg=bg_color)
        ip_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(ip_frame, text="IP Address or Range:", 
                bg=bg_color, fg='white', font=('Arial', 10)).pack(anchor='w')
        
        ip_example = tk.Label(ip_frame, 
                             text="Examples: 192.168.1.1  or  192.168.1.1-192.168.1.254  or  192.168.1.0/24",
                             bg=bg_color, fg='#999999', font=('Arial', 8))
        ip_example.pack(anchor='w', pady=(0, 5))
        
        self.ip_entry = tk.Entry(ip_frame, bg=entry_bg, fg='white', 
                                insertbackground='white', font=('Courier', 10))
        self.ip_entry.pack(fill=tk.X, pady=5)
        self.ip_entry.insert(0, "192.168.1.1-192.168.1.10")
        
        # Port Configuration
        port_frame = tk.Frame(left_panel, bg=bg_color)
        port_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(port_frame, text="Port Configuration:", 
                bg=bg_color, fg='white', font=('Arial', 10)).pack(anchor='w')
        
        # Common ports checkbox
        self.common_ports_var = tk.BooleanVar(value=True)
        common_check = tk.Checkbutton(port_frame, text="Scan Common Ports (21,22,23,25,53,80,110,143,443,445,3389)",
                                     variable=self.common_ports_var,
                                     bg=bg_color, fg='white', selectcolor=bg_color,
                                     activebackground=bg_color, activeforeground='white')
        common_check.pack(anchor='w', pady=5)
        
        # Custom ports
        custom_port_frame = tk.Frame(port_frame, bg=bg_color)
        custom_port_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(custom_port_frame, text="Custom Ports/Range:", 
                bg=bg_color, fg='white', font=('Arial', 10)).pack(side=tk.LEFT)
        
        self.custom_ports_entry = tk.Entry(custom_port_frame, bg=entry_bg, fg='white',
                                          insertbackground='white', width=30)
        self.custom_ports_entry.pack(side=tk.LEFT, padx=5)
        self.custom_ports_entry.insert(0, "1-1024")
        
        # Scan options
        options_frame = tk.Frame(left_panel, bg=bg_color)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Timeout
        timeout_frame = tk.Frame(options_frame, bg=bg_color)
        timeout_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(timeout_frame, text="Timeout (seconds):", 
                bg=bg_color, fg='white').pack(side=tk.LEFT)
        
        self.timeout_var = tk.StringVar(value="1")
        timeout_spin = tk.Spinbox(timeout_frame, from_=1, to=10, textvariable=self.timeout_var,
                                 bg=entry_bg, fg='white', width=5)
        timeout_spin.pack(side=tk.LEFT, padx=5)
        
        # Max threads
        threads_frame = tk.Frame(options_frame, bg=bg_color)
        threads_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(threads_frame, text="Max Threads:", 
                bg=bg_color, fg='white').pack(side=tk.LEFT)
        
        self.threads_var = tk.StringVar(value="50")
        threads_spin = tk.Spinbox(threads_frame, from_=1, to=200, textvariable=self.threads_var,
                                 bg=entry_bg, fg='white', width=5)
        threads_spin.pack(side=tk.LEFT, padx=5)
        
        # Right panel - Scan Control & Results
        right_panel = tk.LabelFrame(main_frame, text=" Scan Control & Results ", 
                                    font=('Courier', 12, 'bold'),
                                    bg=bg_color, fg=accent_color,
                                    relief=tk.GROOVE, bd=2)
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=5)
        
        # Control buttons
        button_frame = tk.Frame(right_panel, bg=bg_color)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_btn = tk.Button(button_frame, text="▶ START SCAN", 
                                  command=self.start_scan,
                                  bg='#006600', fg='white', font=('Arial', 10, 'bold'),
                                  padx=20, pady=5, cursor="hand2")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="⏹ STOP SCAN", 
                                 command=self.stop_scan,
                                 bg='#990000', fg='white', font=('Arial', 10, 'bold'),
                                 padx=20, pady=5, state=tk.DISABLED, cursor="hand2")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = tk.Button(button_frame, text="🗑 CLEAR", 
                                  command=self.clear_results,
                                  bg=button_bg, fg='white', font=('Arial', 10),
                                  padx=20, pady=5, cursor="hand2")
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = tk.Button(button_frame, text="💾 EXPORT", 
                                   command=self.export_results,
                                   bg=button_bg, fg='white', font=('Arial', 10),
                                   padx=20, pady=5, cursor="hand2")
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = tk.Frame(right_panel, bg=bg_color)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Treeview for hosts
        columns = ('IP', 'Status', 'Hostname', 'Open Ports')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=8)
        
        # Define headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure treeview style
        style.configure("Treeview", 
                       background=entry_bg,
                       foreground="white",
                       fieldbackground=entry_bg,
                       font=('Arial', 9))
        style.configure("Treeview.Heading", 
                       background=button_bg,
                       foreground=accent_color,
                       font=('Arial', 10, 'bold'))
        
        # Output console
        console_frame = tk.LabelFrame(output_frame, text=" Scan Output Console ", 
                                      font=('Courier', 12, 'bold'),
                                      bg=bg_color, fg=accent_color,
                                      relief=tk.GROOVE, bd=2)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(console_frame, 
                                                    bg='#1a1a1a', 
                                                    fg=accent_color,
                                                    font=('Courier', 9),
                                                    height=12)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to scan. Enter target IP or range.")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                             bg=bg_color, fg='#cccccc', font=('Arial', 9),
                             relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def show_disclaimer(self):
        disclaimer = """
        ⚠️  ETHICAL AND LEGAL NOTICE  ⚠️
        
        This tool is for educational and authorized network scanning purposes only.
        
        IMPORTANT:
        1. Only scan networks you own or have explicit permission to test
        2. Unauthorized scanning is illegal and unethical
        3. Use responsibly for learning cybersecurity concepts
        4. The developer is not responsible for misuse
        
        By using this tool, you agree to use it ethically and legally.
        """
        
        # Add to output console
        self.log_output("="*60)
        self.log_output(disclaimer)
        self.log_output("="*60)
        self.log_output("")
    
    def log_output(self, message, color=None):
        """Add message to output console"""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def process_queue(self):
        """Process messages from the queue for real-time updates"""
        try:
            while not self.results_queue.empty():
                message_type, data = self.results_queue.get_nowait()
                
                if message_type == "log":
                    self.log_output(data)
                elif message_type == "status":
                    self.update_status(data)
                elif message_type == "host":
                    self.add_host_to_tree(data)
                elif message_type == "port":
                    self.update_host_ports(data)
        
        except:
            pass
        
        # Schedule next queue processing
        self.root.after(100, self.process_queue)
    
    def add_host_to_tree(self, host_data):
        """Add a host to the results tree"""
        ip, status, hostname, ports = host_data
        ports_str = ", ".join(str(p) for p in ports) if ports else "None"
        
        # Determine tag based on status
        tag = 'online' if status == "Online" else 'offline'
        
        # Insert into tree
        item_id = self.results_tree.insert('', tk.END, 
                                          values=(ip, status, hostname, ports_str),
                                          tags=(tag,))
        
        # Configure tags
        self.results_tree.tag_configure('online', foreground='#00ff00')
        self.results_tree.tag_configure('offline', foreground='#ff3333')
    
    def update_host_ports(self, port_data):
        """Update ports for a specific host"""
        ip, port, service = port_data
        
        # Find the item with matching IP
        for item in self.results_tree.get_children():
            values = self.results_tree.item(item)['values']
            if values and values[0] == ip:
                # Update ports column
                current_ports = values[3]
                if current_ports == "None":
                    new_ports = f"{port} ({service})"
                else:
                    new_ports = current_ports + f", {port} ({service})"
                
                self.results_tree.item(item, values=(values[0], values[1], values[2], new_ports))
                break
    
    def validate_ip_range(self, ip_input):
        """Parse and validate IP address or range input"""
        try:
            # Check for single IP
            if '-' in ip_input:
                # IP range like 192.168.1.1-192.168.1.10
                start_ip, end_ip = ip_input.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                
                if start > end:
                    return None, "Start IP must be less than or equal to end IP"
                
                ips = [str(ipaddress.IPv4Address(ip)) 
                      for ip in range(int(start), int(end) + 1)]
                return ips, None
                
            elif '/' in ip_input:
                # CIDR notation
                network = ipaddress.IPv4Network(ip_input, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                return ips, None
                
            else:
                # Single IP
                ip = ipaddress.IPv4Address(ip_input)
                return [str(ip)], None
                
        except ValueError as e:
            return None, f"Invalid IP format: {str(e)}"
    
    def parse_ports(self):
        """Parse port configuration from UI"""
        ports_to_scan = set()
        
        # Add common ports if selected
        if self.common_ports_var.get():
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 3306, 5432]
            ports_to_scan.update(common_ports)
        
        # Parse custom ports
        custom_input = self.custom_ports_entry.get().strip()
        if custom_input:
            try:
                for part in custom_input.split(','):
                    part = part.strip()
                    if '-' in part:
                        # Port range
                        start, end = map(int, part.split('-'))
                        ports_to_scan.update(range(start, end + 1))
                    else:
                        # Single port
                        ports_to_scan.add(int(part))
            except ValueError:
                return None, "Invalid port format. Use comma-separated ports or ranges (e.g., '80,443,1000-2000')"
        
        return list(ports_to_scan), None
    
    def ping_host(self, ip):
        """Ping a host to check if it's online"""
        try:
            # Platform-specific ping command
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout = int(self.timeout_var.get())
            
            # Build command
            command = ['ping', param, '1', '-w', str(timeout * 1000), ip]
            
            # Execute ping
            result = subprocess.run(command, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, timeout=timeout + 1)
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def scan_port(self, ip, port, timeout):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            return result == 0
            
        except:
            return False
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 3306: 'MySQL',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        return service_map.get(port, 'Unknown')
    
    def get_hostname(self, ip):
        """Attempt to get hostname for IP"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "N/A"
    
    def start_scan(self):
        """Start the network scan in a separate thread"""
        if self.scanning:
            return
        
        # Get IP range
        ip_input = self.ip_entry.get().strip()
        if not ip_input:
            messagebox.showerror("Input Error", "Please enter an IP address or range")
            return
        
        ips, error = self.validate_ip_range(ip_input)
        if error:
            messagebox.showerror("IP Error", error)
            return
        
        # Limit the number of IPs for demo purposes
        if len(ips) > 100:
            if not messagebox.askyesno("Warning", 
                                      f"You're about to scan {len(ips)} hosts. This may take a while. Continue?"):
                return
        
        # Get ports to scan
        ports, error = self.parse_ports()
        if error:
            messagebox.showerror("Port Error", error)
            return
        
        if not ports:
            messagebox.showerror("Port Error", "Please select at least one port to scan")
            return
        
        # Reset state
        self.scanning = True
        self.stop_event.clear()
        self.hosts_discovered = []
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Log scan start
        self.log_output(f"\n{'='*60}")
        self.log_output(f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log_output(f"Target: {ip_input}")
        self.log_output(f"Ports to scan: {len(ports)} ports")
        self.log_output(f"Timeout: {self.timeout_var.get()} seconds")
        self.log_output(f"{'='*60}\n")
        
        # Start scan thread
        self.scan_thread = threading.Thread(
            target=self.perform_scan,
            args=(ips, ports),
            daemon=True
        )
        self.scan_thread.start()
    
    def perform_scan(self, ips, ports):
        """Perform the actual network scan"""
        total_hosts = len(ips)
        online_hosts = 0
        
        # Host discovery phase
        self.results_queue.put(("status", "Performing host discovery..."))
        
        for i, ip in enumerate(ips):
            if self.stop_event.is_set():
                break
            
            self.results_queue.put(("status", 
                                   f"Scanning hosts: {i+1}/{total_hosts} | Online: {online_hosts}"))
            
            # Ping host
            is_online = self.ping_host(ip)
            
            # Get hostname
            hostname = self.get_hostname(ip) if is_online else "N/A"
            
            # Add to results
            status = "Online" if is_online else "Offline"
            self.results_queue.put(("host", (ip, status, hostname, [])))
            
            if is_online:
                online_hosts += 1
                self.hosts_discovered.append(ip)
                self.results_queue.put(("log", f"[+] {ip} is ONLINE ({hostname})"))
            else:
                self.results_queue.put(("log", f"[-] {ip} is OFFLINE"))
        
        # Port scanning phase for online hosts
        if self.hosts_discovered and not self.stop_event.is_set():
            self.results_queue.put(("status", 
                                   f"Starting port scan on {len(self.hosts_discovered)} online hosts..."))
            
            total_ports = len(ports) * len(self.hosts_discovered)
            scanned_ports = 0
            
            timeout = int(self.timeout_var.get())
            max_threads = int(self.threads_var.get())
            
            # Use threading for port scanning
            for host_ip in self.hosts_discovered:
                if self.stop_event.is_set():
                    break
                
                self.results_queue.put(("log", f"\nScanning ports on {host_ip}..."))
                
                # Create thread pool for ports
                threads = []
                for port in ports:
                    if self.stop_event.is_set():
                        break
                    
                    # Limit concurrent threads
                    while threading.active_count() > max_threads:
                        time.sleep(0.01)
                        if self.stop_event.is_set():
                            break
                    
                    # Start port scan thread
                    t = threading.Thread(
                        target=self.scan_single_port,
                        args=(host_ip, port, timeout, scanned_ports, total_ports),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)
                    scanned_ports += 1
                
                # Wait for all threads to complete
                for t in threads:
                    if self.stop_event.is_set():
                        break
                    t.join(timeout=timeout + 1)
            
            self.results_queue.put(("log", "\n" + "="*60))
            self.results_queue.put(("log", f"Scan completed: {online_hosts} online hosts found"))
        
        # Scan complete
        self.scanning = False
        self.results_queue.put(("status", 
                               f"Scan complete. Found {online_hosts} online hosts out of {total_hosts}"))
        
        # Update UI
        self.root.after(0, self.scan_complete)
    
    def scan_single_port(self, ip, port, timeout, scanned, total):
        """Scan a single port and report results"""
        if self.stop_event.is_set():
            return
        
        # Update status
        if scanned % 10 == 0:  # Update every 10 ports
            self.results_queue.put(("status", 
                                   f"Scanning ports: {scanned}/{total}"))
        
        # Perform port scan
        is_open = self.scan_port(ip, port, timeout)
        
        if is_open:
            service = self.get_service_name(port)
            self.results_queue.put(("log", f"  [+] {ip}:{port} is OPEN ({service})"))
            self.results_queue.put(("port", (ip, port, service)))
    
    def scan_complete(self):
        """Called when scan completes"""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        if not self.stop_event.is_set():
            self.log_output("\n✅ Scan completed successfully!")
            self.update_status("Scan completed successfully!")
        else:
            self.log_output("\n⚠️ Scan stopped by user")
            self.update_status("Scan stopped by user")
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.stop_event.set()
            self.scanning = False
            self.update_status("Stopping scan...")
            self.log_output("\n⚠️ Stopping scan...")
    
    def clear_results(self):
        """Clear all scan results"""
        if self.scanning:
            messagebox.showwarning("Scan in Progress", 
                                  "Please stop the scan before clearing results")
            return
        
        # Clear treeview
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Clear output console
        self.output_text.delete(1.0, tk.END)
        
        # Show disclaimer again
        self.show_disclaimer()
        
        self.update_status("Results cleared. Ready to scan.")
    
    def export_results(self):
        """Export scan results to file"""
        if not self.results_tree.get_children():
            messagebox.showwarning("No Data", "No scan results to export")
            return
        
        # Ask for file location
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if not filename:
            return
        
        try:
            if filename.endswith('.csv'):
                # Export as CSV
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['IP Address', 'Status', 'Hostname', 'Open Ports', 'Scan Time'])
                    
                    # Write data
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        writer.writerow(values + [datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                
                self.log_output(f"\n📁 Results exported to CSV: {filename}")
                
            else:
                # Export as text
                with open(filename, 'w') as f:
                    f.write("CyberScan Pro - Scan Results\n")
                    f.write("="*50 + "\n")
                    f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    f.write("Hosts Discovered:\n")
                    f.write("-"*50 + "\n")
                    
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        f.write(f"IP: {values[0]}\n")
                        f.write(f"  Status: {values[1]}\n")
                        f.write(f"  Hostname: {values[2]}\n")
                        f.write(f"  Open Ports: {values[3]}\n\n")
            
            self.log_output(f"✅ Export completed successfully!")
            self.update_status(f"Results exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")
    
    def on_closing(self):
        """Handle window closing"""
        if self.scanning:
            if messagebox.askokcancel("Quit", "Scan is in progress. Are you sure you want to quit?"):
                self.stop_event.set()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """Main entry point"""
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()