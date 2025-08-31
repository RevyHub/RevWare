import threading
import queue

import modules.psnifmdl as packet_sniffer
import modules.os1ntmdl as osint_module
import modules.nmpmdl as nmap_module
import modules.sysutlmdl as sys_utilities
import modules.rcnmdl as reconng_module
from modules.utlmdl import print_title

class UnifiedFramework:
    def __init__(self):
        # Network scanning
        self.hosts = []

        # Packet sniffing
        self.sniffed_packets = []
        self._sniffer_thread = None
        self._sniffer_queue = queue.Queue()
        self._stop_sniffer = False

        # OSINT / GeoIP
        self.geo_info = {}

        # System utilities
        self.connections = None
        self.routing = None
        self.system_stats_data = None

        # Recon-ng
        self.recon_output = None

    # -------------------------
    # Packet Sniffer Methods
    # -------------------------
    def _packet_callback(self, packet):
        summary = packet_sniffer.packet_summary(packet)
        if summary:
            self.sniffed_packets.append(summary)
            self._sniffer_queue.put(summary)
        return summary

    def start_sniffer(self, interface="eth0"):
        from scapy.all import sniff

        def sniffer():
            sniff(iface=interface, prn=self._packet_callback,
                  store=False, stop_filter=lambda x: self._stop_sniffer)

        self._stop_sniffer = False
        self._sniffer_thread = threading.Thread(target=sniffer, daemon=True)
        self._sniffer_thread.start()
        print(f"[*] Sniffer running on {interface}")

    def stop_sniffer(self):
        self._stop_sniffer = True
        if self._sniffer_thread:
            self._sniffer_thread.join()
        print("[*] Sniffer stopped.")

    # -------------------------
    # Nmap Methods
    # -------------------------
    def discover_hosts(self, target="127.0.0.1", args="-sV -T4"):
        self.hosts = nmap_module.nmap_scan(target, args)
        return self.hosts

    # -------------------------
    # OSINT / GeoIP Methods
    # -------------------------
    def geo_lookup(self, ip):
        info = osint_module.geo_ip(ip)
        self.geo_info[ip] = info
        return info

    # -------------------------
    # System Utilities Methods
    # -------------------------
    def get_connections(self):
        self.connections = sys_utilities.net_connections()
        return self.connections

    def get_routing(self):
        self.routing = sys_utilities.routing_table()
        return self.routing

    def get_system_stats(self):
        self.system_stats_data = sys_utilities.system_stats()
        return self.system_stats_data

    # -------------------------
    # Recon-ng Methods
    # -------------------------
    def run_recon(self, script=None):
        self.recon_output = reconng_module.run_recon_ng(script)
        return self.recon_output

    # -------------------------
    # Unified Query
    # -------------------------
    def query(self, command):
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return "No command given"

        cmd = cmd_parts[0].lower()

        if cmd == "hosts":
            return self.hosts
        elif cmd == "connections":
            return self.connections
        elif cmd == "routing":
            return self.routing
        elif cmd == "sysstats":
            return self.system_stats_data
        elif cmd == "packets":
            return self.sniffed_packets[-10:]
        elif cmd == "geo" and len(cmd_parts) > 1:
            return self.geo_lookup(cmd_parts[1])
        elif cmd == "recon":
            script = cmd_parts[1] if len(cmd_parts) > 1 else None
            return self.run_recon(script)

        elif cmd == "summary":
            dashboard = {
                "Hosts (Nmap)": self.hosts,
                "Connections": self.connections,
                "Routing Table": self.routing,
                "System Stats": self.system_stats_data,
                "Recent Packets": self.sniffed_packets[-10:],
                "OSINT / GeoIP": self.geo_info,
                "Recon-ng Output": self.recon_output
            }

            print_title("=== Unified Cybersecurity Summary ===")
            for section, data in dashboard.items():
                print(f"\n[{section}]")
                if isinstance(data, list):
                    for item in data:
                        print(item)
                elif isinstance(data, dict):
                    for k, v in data.items():
                        print(f"{k}: {v}")
                else:
                    print(data)
            print_title("=== End of Summary ===")

            return dashboard

        else:
            return f"[!] Unknown command: {command}"
