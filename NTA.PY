import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import struct
import textwrap
import time
from datetime import datetime

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Ethical Network Traffic Analyzer")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.is_sniffing = False
        self.socket = None
        self.packet_count = 0
        self.start_time = None
        
        # Create GUI
        self.setup_gui()
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Interface selection
        ttk.Label(main_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_var = tk.StringVar()
        interface_combo = ttk.Combobox(main_frame, textvariable=self.interface_var, width=30)
        interface_combo['values'] = self.get_network_interfaces()
        if interface_combo['values']:
            interface_combo.current(0)
        interface_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Filter selection
        ttk.Label(main_frame, text="Filter:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.filter_var = tk.StringVar()
        filter_combo = ttk.Combobox(main_frame, textvariable=self.filter_var, width=30)
        filter_combo['values'] = ('All traffic', 'TCP', 'UDP', 'ICMP', 'HTTP', 'DNS')
        filter_combo.current(0)
        filter_combo.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="5")
        stats_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(stats_frame, text="Packets Captured:").grid(row=0, column=0, sticky=tk.W)
        self.packets_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.packets_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(stats_frame, text="Capture Time:").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        self.time_var = tk.StringVar(value="00:00:00")
        ttk.Label(stats_frame, textvariable=self.time_var).grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(stats_frame, text="TCP:").grid(row=1, column=0, sticky=tk.W)
        self.tcp_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.tcp_var).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(stats_frame, text="UDP:").grid(row=1, column=2, sticky=tk.W, padx=(20, 0))
        self.udp_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.udp_var).grid(row=1, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(stats_frame, text="ICMP:").grid(row=2, column=0, sticky=tk.W)
        self.icmp_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.icmp_var).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(stats_frame, text="Other:").grid(row=2, column=2, sticky=tk.W, padx=(20, 0))
        self.other_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.other_var).grid(row=2, column=3, sticky=tk.W, padx=5)
        
        # Packet list with scrollbar
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('timestamp', 'source', 'destination', 'protocol', 'length', 'info')
        self.packet_list = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Define headings
        self.packet_list.heading('timestamp', text='Timestamp')
        self.packet_list.heading('source', text='Source')
        self.packet_list.heading('destination', text='Destination')
        self.packet_list.heading('protocol', text='Protocol')
        self.packet_list.heading('length', text='Length')
        self.packet_list.heading('info', text='Info')
        
        # Define columns
        self.packet_list.column('timestamp', width=120)
        self.packet_list.column('source', width=150)
        self.packet_list.column('destination', width=150)
        self.packet_list.column('protocol', width=80)
        self.packet_list.column('length', width=80)
        self.packet_list.column('info', width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_list.yview)
        self.packet_list.configure(yscrollcommand=scrollbar.set)
        
        self.packet_list.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Packet details
        ttk.Label(main_frame, text="Packet Details:").grid(row=5, column=0, sticky=tk.W, pady=(10, 5))
        
        details_frame = ttk.Frame(main_frame)
        details_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.details_text = scrolledtext.ScrolledText(details_frame, width=80, height=15, wrap=tk.WORD)
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Bind selection event
        self.packet_list.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        main_frame.rowconfigure(6, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        
        # Initialize statistics
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        
    def get_network_interfaces(self):
        """Get available network interfaces"""
        # This is a simplified version - in a real application, 
        # you would use more sophisticated methods to list interfaces
        interfaces = []
        try:
            # Try to get interface names
            import netifaces
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    interfaces.append(interface)
        except:
            # Fallback if netifaces is not available
            interfaces = ['eth0', 'wlan0', 'lo', 'en0', 'en1']
        return interfaces
    
    def start_capture(self):
        """Start packet capture"""
        self.is_sniffing = True
        self.packet_count = 0
        self.start_time = time.time()
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        
        # Clear previous packets
        for item in self.packet_list.get_children():
            self.packet_list.delete(item)
        
        self.details_text.delete(1.0, tk.END)
        
        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.packets_var.set("0")
        self.time_var.set("00:00:00")
        self.update_stats()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Start timer thread
        self.timer_thread = threading.Thread(target=self.update_timer)
        self.timer_thread.daemon = True
        self.timer_thread.start()
        
    def stop_capture(self):
        """Stop packet capture"""
        self.is_sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
    def clear_log(self):
        """Clear the packet list and details"""
        for item in self.packet_list.get_children():
            self.packet_list.delete(item)
        self.details_text.delete(1.0, tk.END)
        
    def export_results(self):
        """Export results to a file"""
        # This would typically save to a file
        messagebox.showinfo("Export", "Packet data would be exported to a file in a real implementation.")
        
    def update_timer(self):
        """Update the capture timer"""
        while self.is_sniffing:
            elapsed = time.time() - self.start_time
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_var.set(f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
            time.sleep(1)
            
    def update_stats(self):
        """Update statistics display"""
        self.tcp_var.set(str(self.protocol_stats['TCP']))
        self.udp_var.set(str(self.protocol_stats['UDP']))
        self.icmp_var.set(str(self.protocol_stats['ICMP']))
        self.other_var.set(str(self.protocol_stats['Other']))
        
    def on_packet_select(self, event):
        """Handle packet selection event"""
        selection = self.packet_list.selection()
        if selection:
            item = selection[0]
            details = self.packet_list.item(item, 'values')
            # In a real implementation, this would show the full packet details
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, f"Packet details for {details[0]}\n")
            self.details_text.insert(tk.END, f"Source: {details[1]}\n")
            self.details_text.insert(tk.END, f"Destination: {details[2]}\n")
            self.details_text.insert(tk.END, f"Protocol: {details[3]}\n")
            self.details_text.insert(tk.END, f"Length: {details[4]} bytes\n")
            
    def capture_packets(self):
        """Main packet capture method (simulated)"""
        # In a real implementation, this would use raw sockets or a library like scapy
        # This is a simulation for demonstration purposes
        
        # Simulate packet capture
        import random
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']
        sources = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.0.3']
        destinations = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1']
        
        while self.is_sniffing:
            # Simulate packet arrival
            time.sleep(random.uniform(0.1, 1.0))
            
            protocol = random.choice(protocols)
            src = random.choice(sources)
            dst = random.choice(destinations)
            length = random.randint(40, 1500)
            
            # Update statistics
            self.packet_count += 1
            if protocol in ['TCP', 'UDP', 'ICMP']:
                self.protocol_stats[protocol] += 1
            else:
                self.protocol_stats['Other'] += 1
                
            # Add to packet list
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            self.packet_list.insert('', 'end', values=(
                timestamp, src, dst, protocol, length, f"{protocol} packet"
            ))
            
            # Update UI
            self.packets_var.set(str(self.packet_count))
            self.update_stats()

# Disclaimer window
def show_disclaimer():
    disclaimer = tk.Toplevel()
    disclaimer.title("Important Disclaimer")
    disclaimer.geometry("600x400")
    disclaimer.resizable(False, False)
    
    text = """
    ETHICAL HACKING DISCLAIMER AND TERMS OF USE
    
    This Network Traffic Analyzer is designed for educational purposes 
    and ethical security testing only.
    
    BY USING THIS SOFTWARE, YOU AGREE TO THE FOLLOWING:
    
    1. You will only use this tool on networks you own or have explicit 
       permission to test.
    
    2. You will not use this tool for any malicious or illegal activities.
    
    3. You understand that unauthorized network monitoring may violate 
       laws and regulations in your jurisdiction.
    
    4. The developers of this tool are not responsible for any misuse 
       or damage caused by this software.
    
    5. This tool is provided for educational purposes only to help 
       network administrators and security professionals improve 
       network security.
    
    I understand and agree to these terms.
    """
    
    text_widget = scrolledtext.ScrolledText(disclaimer, wrap=tk.WORD, width=70, height=20)
    text_widget.insert(1.0, text)
    text_widget.config(state=tk.DISABLED)
    text_widget.pack(padx=10, pady=10)
    
    agree_btn = ttk.Button(disclaimer, text="I Agree", command=disclaimer.destroy)
    agree_btn.pack(pady=10)
    
    # Make the disclaimer modal
    disclaimer.transient(root)
    disclaimer.grab_set()
    root.wait_window(disclaimer)

if __name__ == "__main__":
    root = tk.Tk()
    
    # Show disclaimer first
    show_disclaimer()
    
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()
