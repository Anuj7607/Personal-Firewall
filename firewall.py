import pydivert
import re
import ipaddress


KNOWN_BRANDS = ["google", "paypal", "netflix", "amazon", "microsoft", "apple", "twitter", "youtube", "facebook"]
SHADY_TLDS = [".xyz", ".cc", ".top", ".loan", ".club", ".click", ".gq", ".cf", ".tk"]

GEO_BLOCKED_TLDS = [".ru", ".cn", ".su", ".ir", ".kp"]


GEO_BLOCKED_SUBNETS = [
    "185.22.172.0/22",   
    "95.215.111.0/24",   
    "45.138.120.0/22"    
]

THREAT_CEILING = 50 
def calculate_malicious_score(domain_str):
    """
    Algorithmic Threat Score Calculator.
    Evaluates 5 distinct architectural vectors without requiring machine learning models.
    """
    score = 0
    flags = []
    
    domain_clean = domain_str.lower().strip()
    core_name = domain_clean.split('.')[0]
    
    # VECTOR 1: Restricted Geographic Extension Check (Geo-Fencing)
    if any(domain_clean.endswith(geo_tld) for geo_tld in GEO_BLOCKED_TLDS):
        score += 50  # Automatically triggers the block threshold
        flags.append("Restricted Geographic Domain TLD")

    # VECTOR 2: Shady TLD Check (Known Malicious/Spam registrars)
    if any(domain_clean.endswith(tld) for tld in SHADY_TLDS):
        score += 25
        flags.append("Shady TLD extension (+25)")

    # VECTOR 3: Digit Density Check (Domain Generation Algorithm/Botnets)
    if len(core_name) > 0:
        digit_count = sum(c.isdigit() for c in core_name)
        digit_ratio = digit_count / len(core_name)
        if digit_ratio > 0.30:
            score += 30
            flags.append(f"High Digit Density ({int(digit_ratio*100)}%) (+30)")

    # VECTOR 4: Hyphen/Dash Stacking (Phishing URL structures)
    hyphen_count = core_name.count('-')
    if hyphen_count >= 2:
        score += 20
        flags.append(f"Hyphen Stacking ({hyphen_count} dashes) (+20)")

    # VECTOR 5: Typosquatting / Brand Spoofing Safeguard
    for brand in KNOWN_BRANDS:
        if brand in core_name:
            # If it's the exact valid brand domain, allow it to clear
            if domain_clean == f"{brand}.com" or domain_clean.endswith(f".{brand}.com"):
                continue
            else:
                score += 40
                flags.append(f"Brand Impersonation Layout: '{brand}' (+40)")

    return min(score, 100), flags

def is_ip_geo_blocked(ip_str):
    """Network Layer Geo-Fencing: Validates if an IP address resides in a blocked network."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for subnet in GEO_BLOCKED_SUBNETS:
            if ip_obj in ipaddress.ip_network(subnet, strict=False):
                return True
    except ValueError:
        pass
    return False

def main():
    print("=" * 70)
    print("   NEXT-GEN INTELLIGENT HEURISTIC & GEO-FENCING SECURITY PLATFORM")
    print(f"   [Stateful Risk Evaluation Active | Drop Threshold: {THREAT_CEILING}/100]")
    print("=" * 70)
    print("[*] Intercepting network adapters... Tracking metrics active.\n")

    try:
        with pydivert.WinDivert("true") as w:
            for packet in w:
                
                # --- LAYER 3/4: NETWORK GEO-FENCING ---
                if is_ip_geo_blocked(packet.dst_addr) or is_ip_geo_blocked(packet.src_addr):
                    print(f"[⚠️ GEO-IP BLOCK] Outbound block to restricted geographic IP: {packet.dst_addr}")
                    continue  # DROP ACTION

                # --- LAYER 7: APPLICATION INTELLIGENCE ENGINE ---
                if packet.payload:
                    try:
                        # Convert network packet payload data to readable text format
                        payload_text = packet.payload.decode('utf-8', errors='ignore').lower()
                        
                        # Isolate domain and web resource layouts matching .com, .net, .ru etc.
                        domains_found = re.findall(r'[a-z0-9\-\.]+\.(?:[a-z]{2,4})', payload_text)
                        
                        drop_packet = False
                        for domain in domains_found:
                            risk_score, triggers = calculate_malicious_score(domain)
                            
                            # Real-Time Visual Tracking Console
                            print(f"[TRACKING LOG] Domain Evaluated: {domain:<35} | Risk Score: {risk_score}/100")
                            
                            # Policy Execution Check
                            if risk_score >= THREAT_CEILING:
                                print(f"\n[❌ DROP PACKET - CRITICAL RISK DETECTED]")
                                print(f"    ↳ Target: {domain}")
                                print(f"    ↳ Final Threat Score: {risk_score}/100")
                                print(f"    ↳ Violation Trace:    {triggers}\n")
                                drop_packet = True
                                break # Stop analyzing other domains in this single packet
                                
                        if drop_packet:
                            continue  # DROP ACTION: Prevent re-injection into the OS
                            
                    except Exception:
                        pass

                # ALLOW STEP: Forward trusted traffic forward safely
                w.send(packet)
                
    except PermissionError:
        print("\n[ERROR] Administrative privileges missing! Please restart terminal as Admin.")
    except KeyboardInterrupt:
        print("\n[INFO] Security core shut down cleanly. Traffic routing restored.")

if __name__ == "__main__":
    main()