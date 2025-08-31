import os
import modules.psnifmdl as packet_sniffer
import modules.os1ntmdl as osint_module
import modules.nmpmdl as nmap_module
import modules.sysutlmdl as sys_utilities
import modules.rcnmdl as reconng_module
from modules.utlmdl import print_title
from modules.clgmdl import H0m3_Pa9e
from modules.unfmdl import UnifiedFramework

uf = UnifiedFramework()
# -------------------------
# CLI Commands Menu
# -------------------------
r0otcmds = [
    "1. System Information",
    "2. Network Forensics",
    "3. Data Infiltration",
    "4. WhoIS / GeoIP",
    "5. Recon-ng",
    "6. Packet Sniffer",
    "7. Unified Summary",
    "8. Exit"
]

def clr():
    os.system("cls" if os.name == "nt" else "clear")

def r0ot():
    while True:
        clr()
        print("=" * 60)
        print(H0m3_Pa9e)
        print("=" * 60)
        for cmd in r0otcmds:
            print(cmd)
        print("=" * 60)
        
        r0otcmd = input("\nR0ot:~$ ").strip()

        # -------------------------
        # System Information
        # -------------------------
        if r0otcmd == "1":
            print("[*] Gathering System Stats...")
            stats = uf.get_system_stats()
            print(stats)
            input("\nPress Enter to continue...")

        # -------------------------
        # Network Forensics (Connections & Routing)
        # -------------------------
        elif r0otcmd == "2":
            print("[*] Gathering Network Forensics...")
            conns = uf.get_connections()
            routing = uf.get_routing()
            print(conns)
            print(routing)
            input("\nPress Enter to continue...")

        # -------------------------
        # Data Infiltration / Host Discovery
        # -------------------------
        elif r0otcmd == "3":
            target = input("Target IP/Subnet (e.g., 192.168.1.0/24): ")
            print(f"[*] Running Nmap scan on {target} ...")
            hosts = uf.discover_hosts(target)
            print(hosts)
            input("\nPress Enter to continue...")

        # -------------------------
        # GeoIP / OSINT
        # -------------------------
        elif r0otcmd == "4":
            ip = input("Enter Public IP: ")
            geo = uf.geo_lookup(ip)
            print(geo)
            input("\nPress Enter to continue...")

        # -------------------------
        # Recon-ng
        # -------------------------
        elif r0otcmd == "5":
            script = input("Recon-ng script (leave blank to skip): ").strip() or None
            recon = uf.run_recon(script)
            print(recon)
            input("\nPress Enter to continue...")

        # -------------------------
        # Packet Sniffer
        # -------------------------
        elif r0otcmd == "6":
            action = input("Start or Stop Sniffer? (start/stop): ").strip().lower()
            if action == "start":
                interface = input("Network Interface (e.g., eth0): ").strip()
                uf.start_sniffer(interface)
            elif action == "stop":
                uf.stop_sniffer()
            input("\nPress Enter to continue...")

        # -------------------------
        # Unified Summary
        # -------------------------
        elif r0otcmd == "7":
            uf.query("summary")
            input("\nPress Enter to continue...")

        # -------------------------
        # Exit
        # -------------------------
        elif r0otcmd == "8":
            print("[*] Exiting...")
            uf.stop_sniffer()  # Ensure sniffer thread is stopped
            break

        else:
            print("[!] Unknown command.")
            input("\nPress Enter to continue...")

# Run CLI
if __name__ == "__main__":
    r0ot()
