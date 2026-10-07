import tkinter as tk
from tkinter import messagebox, ttk
import json
import os

RULES_FILE = "rules.json"

def load_rules():
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"blocked_ips": [], "blocked_ports": []}

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Management Console")
        self.root.geometry("450x400")
        
        self.rules = load_rules()
        
        # IP Input Section
        tk.Label(root, text="Block a New IP Address:", font=("Arial", 10, "bold")).pack(pady=5)
        self.ip_entry = tk.Entry(root, width=30)
        self.ip_entry.pack(pady=2)
        tk.Button(root, text="Add to Blocklist", command=self.add_ip, bg="red", fg="white").pack(pady=5)
        
        # Active Rules Display
        tk.Label(root, text="Currently Blocked IPs:", font=("Arial", 10)).pack(pady=10)
        self.rules_listbox = tk.Listbox(root, width=40, height=8)
        self.rules_listbox.pack(pady=2)
        
        tk.Button(root, text="Remove Selected Rule", command=self.remove_ip, bg="gray", fg="white").pack(pady=10)
        
        self.refresh_list()

    def refresh_list(self):
        self.rules_listbox.delete(0, tk.END)
        for ip in self.rules.get("blocked_ips", []):
            self.rules_listbox.insert(tk.END, ip)

    def add_ip(self):
        ip = self.ip_entry.get().strip()
        if ip and ip not in self.rules["blocked_ips"]:
            self.rules["blocked_ips"].append(ip)
            save_rules(self.rules)
            self.refresh_list()
            self.ip_entry.delete(0, tk.END)
            messagebox.showinfo("Success", f"Blocked IP: {ip}\nRestart firewall script to apply instantly.")
        else:
            messagebox.showwarning("Error", "Invalid IP or IP already blocked.")

    def remove_ip(self):
        try:
            selected_index = self.rules_listbox.curselection()[0]
            ip_to_remove = self.rules_listbox.get(selected_index)
            self.rules["blocked_ips"].remove(ip_to_remove)
            save_rules(self.rules)
            self.refresh_list()
            messagebox.showinfo("Success", f"Allowed IP: {ip_to_remove}\nRestart firewall script to apply instantly.")
        except IndexError:
            messagebox.showwarning("Error", "Please select an IP from the list to remove.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()