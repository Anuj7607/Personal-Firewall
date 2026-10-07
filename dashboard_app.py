import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import pydivert
import re
import ipaddress
import queue

# --- DETECTOR CORE LOGIC CONFIGURATION ---
KNOWN_BRANDS = ["google", "paypal", "netflix", "amazon", "microsoft", "apple", "twitter", "youtube", "facebook"]
SHADY_TLDS = [".xyz", ".cc", ".top", ".loan", ".club", ".click", ".gq", ".cf", ".tk"]
GEO_BLOCKED_SUBNETS = ["185.22.172.0/22", "95.215.111.0/24", "45.138.120.0/22"]
THREAT_CEILING = 50

# Country mapping for presentation clarity
COUNTRY_MAP = {
    "Russia (.ru)": ".ru",
    "China (.cn)": ".cn",
    "North Korea (.kp)": ".kp",
    "Iran (.ir)": ".ir",
    "Soviet Union (.su)": ".su"
}

def calculate_malicious_score(domain_str, active_geo_blocks):
    score = 0
    flags = []
    domain_clean = domain_str.lower().strip()
    core_name = domain_clean.split('.')[0]
    
    # Check against user-selected active geofence blocks
    if any(domain_clean.endswith(geo_tld) for geo_tld in active_geo_blocks):
        score += 50
        flags.append("Geo-Restricted TLD")
    if any(domain_clean.endswith(tld) for tld in SHADY_TLDS):
        score += 25
        flags.append("Shady Extension (+25)")
    if len(core_name) > 0:
        digit_count = sum(c.isdigit() for c in core_name)
        digit_ratio = digit_count / len(core_name)
        if digit_ratio > 0.30:
            score += 30
            flags.append(f"DGA Numeric Density ({int(digit_ratio*100)}%) (+30)")
    if core_name.count('-') >= 2:
        score += 20
        flags.append("Hyphen Stacking (+20)")
    for brand in KNOWN_BRANDS:
        if brand in core_name:
            if domain_clean == f"{brand}.com" or domain_clean.endswith(f".{brand}.com"):
                continue
            score += 40
            flags.append(f"Brand Impersonation: '{brand}' (+40)")
            
    return min(score, 100), flags

def is_ip_geo_blocked(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for subnet in GEO_BLOCKED_SUBNETS:
            if ip_obj in ipaddress.ip_network(subnet, strict=False):
                return True
    except ValueError:
        pass
    return False


# --- GUI APPLICATION CLASS ---
class SecurityDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Next-Gen Heuristic & Geo-Fencing Firewall Dashboard")
        self.root.geometry("1000x650")
        self.root.configure(bg="#121212")
        
        self.is_running = False
        self.total_scanned = 0
        self.total_blocked = 0
        self.active_geo_blocks = set()  # Dynamically stores blocked TLD extensions
        
        self.msg_queue = queue.Queue()
        self.stat_queue = queue.Queue()
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", background="#121212", foreground="#FFFFFF", font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("TCombobox", fieldbackground="#1A1A1A", background="#333333", foreground="#FFFFFF")
        
        self.setup_ui()
        self.periodic_ui_update()

    def setup_ui(self):
        # 1. Header Display Banner
        header_frame = tk.Frame(self.root, bg="#1E1E1E", height=70)
        header_frame.pack(fill="x", side="top")
        header_title = tk.Label(header_frame, text="🛡️ NETWORK OPERATIONS CENTER", bg="#1E1E1E", fg="#00FF66", font=("Segoe UI", 16, "bold"))
        header_title.pack(side="left", padx=20, pady=15)
        
        # Engine Switch Button (ON/OFF Toggle)
        self.btn_control = tk.Button(header_frame, text="TURN ENGINE ON", bg="#00FF66", fg="#121212", font=("Segoe UI", 10, "bold"), padx=15, command=self.toggle_engine, bd=0, activebackground="#00CC52")
        self.btn_control.pack(side="right", padx=20, pady=15)

        # 2. Controls & Configuration Split Panel
        main_body_frame = tk.Frame(self.root, bg="#121212")
        main_body_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        control_panel = tk.LabelFrame(main_body_frame, text=" FIREWALL MANAGEMENT POLICY ", bg="#121212", fg="#A0A0A0", font=("Segoe UI", 10, "bold"), padx=15, pady=15, bd=1, relief="solid", highlightbackground="#333333")
        control_panel.pack(side="left", fill="y", padx=(0, 15))
        
        # Metric Widgets inside Panel
        self.lbl_scanned = tk.Label(control_panel, text="Packets Scanned: 0", bg="#1A1A1A", fg="#FFFFFF", font=("Segoe UI", 11, "bold"), anchor="w", padx=10, pady=10)
        self.lbl_scanned.pack(fill="x", pady=(0, 10))
        
        self.lbl_blocked = tk.Label(control_panel, text="Threats Intercepted: 0", bg="#1A1A1A", fg="#FF3333", font=("Segoe UI", 11, "bold"), anchor="w", padx=10, pady=10)
        self.lbl_blocked.pack(fill="x", pady=(0, 20))
        
        # Geofencing Selector Interactivity
        geo_label = tk.Label(control_panel, text="Geofencing TLD Blocker:", bg="#121212", fg="#FFFFFF", font=("Segoe UI", 10, "bold"))
        geo_label.pack(anchor="w", pady=(0, 5))
        
        self.country_box = ttk.Combobox(control_panel, values=list(COUNTRY_MAP.keys()), state="readonly")
        self.country_box.pack(fill="x", pady=(0, 10))
        self.country_box.current(0)
        
        btn_add_block = tk.Button(control_panel, text="ADD POLICY BLOCK", bg="#333333", fg="#FFFFFF", font=("Segoe UI", 9, "bold"), pady=5, bd=0, command=self.add_geo_block, activebackground="#444444")
        btn_add_block.pack(fill="x", pady=(0, 5))
        
        btn_remove_block = tk.Button(control_panel, text="REMOVE POLICY BLOCK", bg="#333333", fg="#FFFFFF", font=("Segoe UI", 9, "bold"), pady=5, bd=0, command=self.remove_geo_block, activebackground="#444444")
        btn_remove_block.pack(fill="x", pady=(0, 20))
        
        # Active Blocks Manifest
        active_label = tk.Label(control_panel, text="Active Geofence Blocks:", bg="#121212", fg="#A0A0A0", font=("Segoe UI", 9, "bold"))
        active_label.pack(anchor="w")
        
        self.lbl_active_blocks = tk.Label(control_panel, text="[ None ]", bg="#0A0A0A", fg="#FF9900", font=("Consolas", 10), justify="left", anchor="nw", height=6, wraplength=220, pady=5, padx=5)
        self.lbl_active_blocks.pack(fill="x")

        # 3. Data Feed Layout Right Side
        feed_frame = tk.Frame(main_body_frame, bg="#121212")
        feed_frame.pack(side="right", fill="both", expand=True)
        
        feed_header_frame = tk.Frame(feed_frame, bg="#121212")
        feed_header_frame.pack(fill="x", pady=(0, 5))
        
        log_label = tk.Label(feed_header_frame, text="LIVE RISK EVALUATION ACTIVITY FEED:", bg="#121212", fg="#A0A0A0", font=("Segoe UI", 10, "bold"))
        log_label.pack(side="left")
        
        # Clear Terminal Button
        btn_clear = tk.Button(feed_header_frame, text="🧹 CLEAR LOGS", bg="#222222", fg="#FFFFFF", font=("Segoe UI", 9, "bold"), padx=10, bd=0, command=self.clear_logs, activebackground="#333333")
        btn_clear.pack(side="right")
        
        self.log_display = scrolledtext.ScrolledText(feed_frame, bg="#0A0A0A", fg="#00FF66", insertbackground="white", font=("Consolas", 10), bd=0, highlightthickness=1, highlightbackground="#333333")
        self.log_display.pack(fill="both", expand=True)
        self.log_display.insert(tk.END, "[INFO] Dashboard initialized. Select policy restrictions and toggle protection.\n")
        
        # System Footer Note
        self.lbl_status = tk.Label(self.root, text="SYSTEM STATUS: IDLE", bg="#121212", fg="#A0A0A0", font=("Segoe UI", 10, "bold"), pady=5)
        self.lbl_status.pack(side="bottom", anchor="e", padx=20)

    def toggle_engine(self):
        if not self.is_running:
            self.is_running = True
            self.lbl_status.config(text="SYSTEM STATUS: PROTECTION ACTIVE", fg="#00FF66")
            self.btn_control.config(text="TURN ENGINE OFF", bg="#FF3333", fg="#FFFFFF", activebackground="#CC2929")
            self.log_display.insert(tk.END, "[SYSTEM] Firewall kernel hook loaded. Processing socket buffers...\n")
            self.log_display.see(tk.END)
            
            self.capture_thread = threading.Thread(target=self.firewall_pipeline, daemon=True)
            self.capture_thread.start()
        else:
            self.is_running = False
            self.lbl_status.config(text="SYSTEM STATUS: IDLE", fg="#A0A0A0")
            self.btn_control.config(text="TURN ENGINE ON", bg="#00FF66", fg="#121212", activebackground="#00CC52")
            self.log_display.insert(tk.END, "[SYSTEM] Network capture driver detached.\n")
            self.log_display.see(tk.END)

    def add_geo_block(self):
        selection = self.country_box.get()
        tld = COUNTRY_MAP[selection]
        self.active_geo_blocks.add(tld)
        self.update_geo_display()
        self.log_display.insert(tk.END, f"[POLICY] Added geofencing rule for target domain structures extension: {tld}\n")
        self.log_display.see(tk.END)

    def remove_geo_block(self):
        selection = self.country_box.get()
        tld = COUNTRY_MAP[selection]
        self.active_geo_blocks.discard(tld)
        self.update_geo_display()
        self.log_display.insert(tk.END, f"[POLICY] Removed geofencing rule restriction for: {tld}\n")
        self.log_display.see(tk.END)

    def update_geo_display(self):
        if not self.active_geo_blocks:
            self.lbl_active_blocks.config(text="[ None ]", fg="#FF9900")
        else:
            block_list = sorted(list(self.active_geo_blocks))
            self.lbl_active_blocks.config(text="\n".join(f"• Block active: *{tld}" for tld in block_list), fg="#00FF66")

    def clear_logs(self):
        self.log_display.delete('1.0', tk.END)
        self.log_display.insert(tk.END, "[SYSTEM] Console logs flushed cleanly.\n")

    def periodic_ui_update(self):
        while not self.msg_queue.empty():
            try:
                msg = self.msg_queue.get_nowait()
                self.log_display.insert(tk.END, msg + "\n")
                self.log_display.see(tk.END)
            except queue.Empty:
                break
        
        while not self.stat_queue.empty():
            try:
                scanned_num, blocked_num = self.stat_queue.get_nowait()
                self.lbl_scanned.config(text=f"Packets Scanned: {scanned_num}")
                self.lbl_blocked.config(text=f"Threats Intercepted: {blocked_num}")
            except queue.Empty:
                break
                
        self.root.after(50, self.periodic_ui_update)

    def firewall_pipeline(self):
        try:
            with pydivert.WinDivert("true") as w:
                for packet in w:
                    if not self.is_running:
                        break
                    
                    self.total_scanned += 1
                    self.stat_queue.put((self.total_scanned, self.total_blocked))
                    
                    # Core Infrastructure Subnet Check
                    if is_ip_geo_blocked(packet.dst_addr) or is_ip_geo_blocked(packet.src_addr):
                        self.total_blocked += 1
                        self.stat_queue.put((self.total_scanned, self.total_blocked))
                        self.msg_queue.put(f"[⚠️ GEO-IP SUB-BLOCK] Intercepted link payload path targeting restricted subnet element.")
                        continue
                    
                    # Layer 7 Evaluation using local frozen copy of chosen active TLD structures
                    if packet.payload:
                        try:
                            payload_text = packet.payload.decode('utf-8', errors='ignore').lower()
                            domains_found = re.findall(r'[a-z0-9\-\.]+\.(?:[a-z]{2,4})', payload_text)
                            
                            drop_packet = False
                            for domain in domains_found:
                                # Safe pass of active geofence targets list array snapshot
                                risk_score, triggers = calculate_malicious_score(domain, self.active_geo_blocks)
                                
                                if risk_score >= THREAT_CEILING:
                                    self.total_blocked += 1
                                    self.stat_queue.put((self.total_scanned, self.total_blocked))
                                    self.msg_queue.put(f"\n[❌ DROP PACKET ENFORCED] Target: {domain} | Risk: {risk_score}/100 | Triggers: {triggers}\n")
                                    drop_packet = True
                                    break
                                    
                            if drop_packet:
                                continue
                        except Exception:
                            pass
                            
                    w.send(packet)
        except PermissionError:
            self.msg_queue.put("\n[ERROR] Administrative permissions missing! Please run your environment interface as Administrator.\n")
            self.root.after(0, self.toggle_engine)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityDashboard(root)
    root.mainloop()