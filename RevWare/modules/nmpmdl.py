import subprocess
import xml.etree.ElementTree as ET
from modules.utlmdl import save_log, print_title

def nmap_scan(target="127.0.0.1", args="-sV -T4"):
    """
    Runs an Nmap scan on the target and parses XML output.
    Requires Nmap installed.
    """
    print(f"[*] Running Nmap scan on {target} ...")
    xml_output = "nmap_temp.xml"
    cmd = f"sudo nmap {args} -oX {xml_output} {target}"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)

    # Parse XML output
    tree = ET.parse(xml_output)
    root = tree.getroot()
    results = []
    for host in root.findall("host"):
        ip_tag = host.find("address[@addrtype='ipv4']")
        ip = ip_tag.attrib["addr"] if ip_tag is not None else None
        hostname_tag = host.find("hostnames/hostname")
        hostname = hostname_tag.attrib["name"] if hostname_tag is not None else None
        ports = []
        for port in host.findall("ports/port"):
            port_id = port.attrib["portid"]
            proto = port.attrib["protocol"]
            state_tag = port.find("state")
            state = state_tag.attrib["state"] if state_tag is not None else None
            service_tag = port.find("service")
            service = service_tag.attrib["name"] if service_tag is not None else None
            ports.append({"port": port_id, "protocol": proto, "state": state, "service": service})
        results.append({"ip": ip, "hostname": hostname, "ports": ports})

    print_title(f"Nmap Scan Results for {target}")
    for host in results:
        print(f"IP: {host['ip']} | Hostname: {host['hostname']}")
        for p in host["ports"]:
            print(f"  {p['protocol']} {p['port']} {p['state']} ({p['service']})")

    save_log(f"nmap_{target}", results)
    return results
