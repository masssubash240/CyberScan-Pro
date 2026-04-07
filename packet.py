#!/usr/bin/env python3
"""
Packet Sniffer Tool with Tkinter GUI
Run as Administrator on Windows
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import sys
import os

# Check if running as administrator (Windows)
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("[!] This tool requires Administrator privileges!")
    print("[!] Please run this script as Administrator")
    print("\nTo fix:")
    print("1. Close VS Code")
    print("2. Right-click VS Code → Run as administrator")
    print("3. Open project and run this script")
    sys.exit(1)

# Now import other modules
import socket
import struct
import binascii
from datetime import datetime
import time

class PacketSniffer:
    def __init__(self):
        self.socket = None
        self.running = False
        self.packet_count = 0
        self.packet_queue = queue.Queue()
        self.filter_protocol = None
        self.filter_ip = None
        self.filter_port = None
        
    def start(self, interface_ip="0.0.0.0"):
        """Start packet sniffing"""
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.socket.bind((interface_ip, 0))
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.running = True
            self.packet_count = 0
            
            # Start sniffing thread
            sniff_thread = threading.Thread(target=self.sniff_packets)
            sniff_thread.daemon = True
            sniff_thread.start()
            
            return True
            
        except Exception as e:
            return str(e)
    
    def sniff_packets(self):
        """Main sniffing loop"""
        while self.running:
            try:
                packet_data, address = self.socket.recvfrom(65535)
                self.packet_count += 1
                
                # Process packet
                packet_info = self.process_packet(packet_data, address)
                if packet_info:
                    # Add timestamp
                    packet_info['timestamp'] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    packet_info['number'] = self.packet_count
                    
                    # Apply filters
                    if self.apply_filters(packet_info):
                        self.packet_queue.put(packet_info)
                        
            except:
                if self.running:  # Only ignore errors if we're still running
                    pass
    
    def apply_filters(self, packet_info):
        """Apply filters to packet"""
        if self.filter_protocol and packet_info['protocol'] != self.filter_protocol:
            return False
            
        if self.filter_ip:
            if self.filter_ip not in [packet_info['src_ip'], packet_info['dst_ip']]:
                return False
                
        if self.filter_port:
            if self.filter_port not in [packet_info.get('src_port', 0), packet_info.get('dst_port', 0)]:
                return False
                
        return True
    
    def process_packet(self, raw_data, address):
        """Process raw packet data"""
        try:
            if len(raw_data) < 34:
                return None
                
            # Parse Ethernet header
            eth_header = raw_data[:14]
            eth_type = struct.unpack("!H", eth_header[12:14])[0]
            
            # Only process IP packets
            if eth_type != 0x0800:
                return None
                
            # Parse IP header
            ip_header = raw_data[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Get protocol name
            protocol_name = self.get_protocol_name(protocol)
            
            packet_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol_name,
                'protocol_num': protocol,
                'ttl': ttl,
                'size': len(raw_data),
                'raw': raw_data[:100]  # First 100 bytes
            }
            
            # Process TCP
            if protocol == 6:
                tcp_info = self.process_tcp(raw_data, ip_header_length)
                packet_info.update(tcp_info)
                
            # Process UDP
            elif protocol == 17:
                udp_info = self.process_udp(raw_data, ip_header_length)
                packet_info.update(udp_info)
                
            # Process ICMP
            elif protocol == 1:
                packet_info['type'] = 'ICMP'
                
            return packet_info
            
        except Exception as e:
            return None
    
    def process_tcp(self, raw_data, ip_header_length):
        """Extract TCP information"""
        try:
            tcp_header_start = 14 + ip_header_length
            if len(raw_data) >= tcp_header_start + 20:
                tcp_header = raw_data[tcp_header_start:tcp_header_start+20]
                tcph = struct.unpack("!HHLLBBHHH", tcp_header)
                
                src_port = tcph[0]
                dst_port = tcph[1]
                flags = tcph[5]
                
                # Get service name
                service = self.get_service_name(dst_port, 'tcp')
                
                # Get flag names
                flag_names = []
                if flags & 0x01: flag_names.append("FIN")
                if flags & 0x02: flag_names.append("SYN")
                if flags & 0x04: flag_names.append("RST")
                if flags & 0x08: flag_names.append("PSH")
                if flags & 0x10: flag_names.append("ACK")
                if flags & 0x20: flag_names.append("URG")
                
                return {
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'flags': ', '.join(flag_names),
                    'service': service,
                    'type': 'TCP'
                }
        except:
            pass
        return {}
    
    def process_udp(self, raw_data, ip_header_length):
        """Extract UDP information"""
        try:
            udp_header_start = 14 + ip_header_length
            if len(raw_data) >= udp_header_start + 8:
                udp_header = raw_data[udp_header_start:udp_header_start+8]
                udph = struct.unpack("!HHHH", udp_header)
                
                src_port = udph[0]
                dst_port = udph[1]
                
                # Get service name
                service = self.get_service_name(dst_port, 'udp')
                
                return {
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'service': service,
                    'type': 'UDP'
                }
        except:
            pass
        return {}
    
    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            89: "OSPF"
        }
        return protocols.get(protocol_num, f"Proto-{protocol_num}")
    
    def get_service_name(self, port, proto):
        """Get service name for port"""
        services = {
            # TCP services
            'tcp': {
                20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
                25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
                143: "IMAP", 443: "HTTPS", 3389: "RDP",
                3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"
            },
            # UDP services
            'udp': {
                53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
                69: "TFTP", 123: "NTP", 161: "SNMP", 162: "SNMP-Trap",
                500: "IKE", 514: "Syslog", 1900: "UPnP"
            }
        }
        return services.get(proto, {}).get(port, "")
    
    def set_filter(self, protocol=None, ip=None, port=None):
        """Set packet filters"""
        self.filter_protocol = protocol
        self.filter_ip = ip
        self.filter_port = port
    
    def stop(self):
        """Stop sniffing"""
        self.running = False
        if self.socket:
            try:
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket.close()
            except:
                pass
    
    def get_stats(self):
        """Get statistics"""
        return {
            'packet_count': self.packet_count,
            'is_running': self.running
        }


class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize sniffer
        self.sniffer = PacketSniffer()
        self.is_sniffing = False
        
        # Configure style
        self.setup_styles()
        
        # Build GUI
        self.setup_gui()
        
        # Start update thread
        self.update_thread()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        bg_color = '#2b2b2b'
        fg_color = '#ffffff'
        accent_color = '#007acc'
        
        style.configure('TLabel', background=bg_color, foreground=fg_color, font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10), padding=6)
        style.configure('TCheckbutton', background=bg_color, foreground=fg_color)
        style.configure('TEntry', font=('Segoe UI', 10))
        style.configure('TCombobox', font=('Segoe UI', 10))
        
        # Configure custom styles
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'))
        style.configure('Status.TLabel', font=('Segoe UI', 10, 'bold'))
        style.configure('Accent.TButton', background=accent_color, foreground='white')
        
    def setup_gui(self):
        """Setup the GUI layout"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="📡 Packet Sniffer Tool", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Start/Stop button
        self.control_button = ttk.Button(control_frame, text="▶ Start Sniffing", 
                                        command=self.toggle_sniffing, width=15)
        self.control_button.grid(row=0, column=0, padx=(0, 10))
        
        # Clear button
        ttk.Button(control_frame, text="🗑️ Clear", 
                  command=self.clear_display).grid(row=0, column=1, padx=(0, 10))
        
        # Save button
        ttk.Button(control_frame, text="💾 Save to File", 
                  command=self.save_packets).grid(row=0, column=2)
        
        # Filter Panel
        filter_frame = ttk.LabelFrame(main_frame, text="Filters", padding="10")
        filter_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Protocol filter
        ttk.Label(filter_frame, text="Protocol:").grid(row=0, column=0, padx=(0, 5))
        self.protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(filter_frame, textvariable=self.protocol_var, 
                                     values=["All", "TCP", "UDP", "ICMP"], width=10, state="readonly")
        protocol_combo.set("All")
        protocol_combo.grid(row=0, column=1, padx=(0, 20))
        
        # IP filter
        ttk.Label(filter_frame, text="IP Address:").grid(row=0, column=2, padx=(0, 5))
        self.ip_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.ip_var, width=15).grid(row=0, column=3, padx=(0, 20))
        
        # Port filter
        ttk.Label(filter_frame, text="Port:").grid(row=0, column=4, padx=(0, 5))
        self.port_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.port_var, width=10).grid(row=0, column=5, padx=(0, 20))
        
        # Apply filter button
        ttk.Button(filter_frame, text="Apply Filters", 
                  command=self.apply_filters).grid(row=0, column=6)
        
        # Statistics Panel
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Stats labels
        self.packet_count_label = ttk.Label(stats_frame, text="Packets: 0", style='Status.TLabel')
        self.packet_count_label.grid(row=0, column=0, padx=(0, 20))
        
        self.status_label = ttk.Label(stats_frame, text="Status: Stopped", style='Status.TLabel')
        self.status_label.grid(row=0, column=1, padx=(0, 20))
        
        # Packet display area
        display_frame = ttk.LabelFrame(main_frame, text="Captured Packets", padding="10")
        display_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for expansion
        main_frame.rowconfigure(4, weight=1)
        display_frame.columnconfigure(0, weight=1)
        display_frame.rowconfigure(0, weight=1)
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(display_frame)
        text_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        
        # Create scrollbars
        y_scrollbar = ttk.Scrollbar(text_frame)
        y_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        x_scrollbar = ttk.Scrollbar(text_frame, orient='horizontal')
        x_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Create text widget
        self.packet_text = tk.Text(text_frame, wrap=tk.NONE, 
                                  yscrollcommand=y_scrollbar.set,
                                  xscrollcommand=x_scrollbar.set,
                                  bg='#1e1e1e', fg='#ffffff',
                                  font=('Consolas', 10),
                                  insertbackground='white')
        self.packet_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure scrollbars
        y_scrollbar.config(command=self.packet_text.yview)
        x_scrollbar.config(command=self.packet_text.xview)
        
        # Configure tags for syntax highlighting
        self.packet_text.tag_configure('timestamp', foreground='#569cd6')
        self.packet_text.tag_configure('ip', foreground='#4ec9b0')
        self.packet_text.tag_configure('port', foreground='#dcdcaa')
        self.packet_text.tag_configure('protocol', foreground='#c586c0')
        self.packet_text.tag_configure('service', foreground='#ce9178')
        self.packet_text.tag_configure('size', foreground='#9cdcfe')
        
        # Packet details frame
        details_frame = ttk.LabelFrame(main_frame, text="Packet Details", padding="10")
        details_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Details text
        self.details_text = scrolledtext.ScrolledText(details_frame, height=5,
                                                     bg='#1e1e1e', fg='#ffffff',
                                                     font=('Consolas', 9))
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        details_frame.columnconfigure(0, weight=1)
        
        # Bind click event on packet display
        self.packet_text.bind('<ButtonRelease-1>', self.show_packet_details)
    
    def toggle_sniffing(self):
        """Toggle sniffing on/off"""
        if not self.is_sniffing:
            # Start sniffing
            result = self.sniffer.start()
            if result is True:
                self.is_sniffing = True
                self.control_button.config(text="⏹ Stop Sniffing")
                self.status_label.config(text="Status: Running")
                messagebox.showinfo("Success", "Packet sniffing started!")
            else:
                messagebox.showerror("Error", f"Failed to start sniffing:\n{result}")
        else:
            # Stop sniffing
            self.sniffer.stop()
            self.is_sniffing = False
            self.control_button.config(text="▶ Start Sniffing")
            self.status_label.config(text="Status: Stopped")
            messagebox.showinfo("Info", "Packet sniffing stopped!")
    
    def apply_filters(self):
        """Apply filters to packet capture"""
        protocol = self.protocol_var.get()
        ip = self.ip_var.get().strip()
        port = self.port_var.get().strip()
        
        # Convert protocol to filter format
        protocol_filter = None
        if protocol != "All":
            protocol_filter = protocol
        
        # Convert port to integer if provided
        port_filter = None
        if port:
            try:
                port_filter = int(port)
            except ValueError:
                messagebox.showerror("Error", "Port must be a number!")
                return
        
        # Set filters
        self.sniffer.set_filter(protocol_filter, ip if ip else None, port_filter)
        messagebox.showinfo("Filters Applied", "Filters have been applied!")
    
    def clear_display(self):
        """Clear the packet display"""
        self.packet_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
    
    def save_packets(self):
        """Save captured packets to file"""
        from tkinter import filedialog
        import json
        
        # Get packets from text widget
        packets_text = self.packet_text.get(1.0, tk.END)
        if not packets_text.strip():
            messagebox.showwarning("Warning", "No packets to save!")
            return
        
        # Ask for file location
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Save as JSON (simplified)
                    packets = []
                    lines = packets_text.split('\n')
                    for line in lines:
                        if line.strip():
                            packets.append({"packet": line})
                    
                    with open(filename, 'w') as f:
                        json.dump(packets, f, indent=2)
                else:
                    # Save as text
                    with open(filename, 'w') as f:
                        f.write(packets_text)
                
                messagebox.showinfo("Success", f"Packets saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{e}")
    
    def show_packet_details(self, event):
        """Show details of selected packet"""
        try:
            # Get the line at cursor position
            index = self.packet_text.index(f"@{event.x},{event.y}")
            line_num = int(index.split('.')[0])
            
            # Get the line text
            line_text = self.packet_text.get(f"{line_num}.0", f"{line_num}.end")
            
            # Parse packet info from line
            if '|' in line_text:
                parts = line_text.split('|')
                if len(parts) >= 6:
                    details = f"""
Packet Details:
----------------
Time: {parts[0].strip()}
From: {parts[1].strip()}
To: {parts[2].strip()}
Protocol: {parts[3].strip()}
Ports: {parts[4].strip()}
Size: {parts[5].strip()}
Service: {parts[6].strip() if len(parts) > 6 else 'N/A'}
                    """
                    self.details_text.delete(1.0, tk.END)
                    self.details_text.insert(1.0, details.strip())
        except:
            pass
    
    def format_packet(self, packet_info):
        """Format packet information for display"""
        # Format timestamp
        timestamp = packet_info['timestamp']
        
        # Format IP addresses
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        
        # Format protocol
        protocol = packet_info['protocol']
        
        # Format ports
        src_port = packet_info.get('src_port', '')
        dst_port = packet_info.get('dst_port', '')
        ports = f"{src_port} → {dst_port}" if src_port and dst_port else "N/A"
        
        # Format size
        size = f"{packet_info['size']} bytes"
        
        # Get service
        service = packet_info.get('service', '')
        
        # Create formatted line
        line = f"{timestamp:15} | {src_ip:15} → {dst_ip:15} | {protocol:6} | {ports:15} | {size:12} | {service}"
        
        return line, {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'ports': ports,
            'size': size,
            'service': service
        }
    
    def update_display(self):
        """Update the display with new packets"""
        try:
            # Process all packets in queue
            while not self.sniffer.packet_queue.empty():
                packet_info = self.sniffer.packet_queue.get()
                
                # Format packet
                line, formatted_info = self.format_packet(packet_info)
                
                # Insert with tags for syntax highlighting
                start_pos = self.packet_text.index(tk.END)
                self.packet_text.insert(tk.END, line + "\n")
                
                # Apply tags
                end_pos = self.packet_text.index(tk.END)
                
                # Tag timestamp
                ts_start = f"{start_pos}+{0}c"
                ts_end = f"{start_pos}+{15}c"
                self.packet_text.tag_add('timestamp', ts_start, ts_end)
                
                # Tag source IP
                ip_start = f"{start_pos}+{18}c"
                ip_end = f"{start_pos}+{33}c"
                self.packet_text.tag_add('ip', ip_start, ip_end)
                
                # Tag destination IP
                ip_start = f"{start_pos}+{37}c"
                ip_end = f"{start_pos}+{52}c"
                self.packet_text.tag_add('ip', ip_start, ip_end)
                
                # Tag protocol
                proto_start = f"{start_pos}+{55}c"
                proto_end = f"{start_pos}+{61}c"
                self.packet_text.tag_add('protocol', proto_start, proto_end)
                
                # Tag ports
                port_start = f"{start_pos}+{64}c"
                port_end = f"{start_pos}+{79}c"
                self.packet_text.tag_add('port', port_start, port_end)
                
                # Tag size
                size_start = f"{start_pos}+{82}c"
                size_end = f"{start_pos}+{94}c"
                self.packet_text.tag_add('size', size_start, size_end)
                
                # Tag service
                if formatted_info['service']:
                    service_start = f"{start_pos}+{97}c"
                    self.packet_text.tag_add('service', service_start, end_pos)
                
                # Auto-scroll to bottom
                self.packet_text.see(tk.END)
            
            # Update statistics
            stats = self.sniffer.get_stats()
            self.packet_count_label.config(text=f"Packets: {stats['packet_count']}")
            
        except Exception as e:
            print(f"Update error: {e}")
    
    def update_thread(self):
        """Thread for updating GUI"""
        self.update_display()
        self.root.after(100, self.update_thread)
    
    def on_closing(self):
        """Handle window closing"""
        if self.is_sniffing:
            self.sniffer.stop()
        self.root.destroy()


def main():
    """Main function"""
    # Check admin privileges
    if not is_admin():
        print("[!] ERROR: This tool requires Administrator privileges!")
        print("\nHow to run as Administrator:")
        print("1. Close ALL VS Code windows")
        print("2. Find Visual Studio Code in Start Menu")
        print("3. RIGHT-CLICK and select 'Run as administrator'")
        print("4. Open this project folder")
        print("5. Run this script again")
        input("\nPress Enter to exit...")
        return
    
    # Create and run GUI
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()