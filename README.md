# RevWare

![Python](https://img.shields.io/badge/python-3.x-blue) ![Status](https://img.shields.io/badge/status-active%20development-yellow)

A modular Python CLI that unifies several network and system utilities behind a single menu: system stats, network forensics, host discovery, OSINT/GeoIP lookups, recon-ng integration, and live packet capture.

## Features

| Module | File | Capability |
|---|---|---|
| System utilities | `sysutlmdl.py` | Active network connections and routing table |
| Host discovery | `nmpmdl.py` | Nmap scan of a target/subnet, with parsed XML results |
| OSINT / GeoIP | `os1ntmdl.py` | IP geolocation and ISP/org lookup via ipinfo.io |
| Recon-ng bridge | `rcnmdl.py` | Launches recon-ng, optionally running a provided script |
| Packet sniffer | `psnifmdl.py` | Live packet capture and per-packet summaries via scapy |
| Unified framework | `unfmdl.py` | Combines all modules behind one `UnifiedFramework` class, including background-thread sniffing |
| Utilities | `utlmdl.py` | Shared logging (JSON, under `logs/`) and CLI formatting helpers |
| Banner | `clgmdl.py` | Home-screen ASCII art |

## Requirements

- Python 3.x
- [Nmap](https://nmap.org/) installed and on your `PATH`
- [recon-ng](https://github.com/lanmaster53/recon-ng) installed and on your `PATH` (optional — only needed for the recon-ng bridge)
- Administrator/root privileges for packet capture

```bash
pip install psutil requests scapy
```

## Usage

```bash
python root.py
```

```
1. System Information
2. Network Forensics
3. Host Discovery (Nmap scan of a target/subnet)
4. WhoIS / GeoIP
5. Recon-ng
6. Packet Sniffer
7. Unified Summary
8. Exit

R0ot:~$
```

Selecting **Packet Sniffer** prompts for `start` or `stop`; sniffing runs on a background thread so the menu stays responsive, and is automatically stopped on exit.

## Logging

Lookups and scan results are written as JSON under a local `logs/` directory via `utlmdl.save_log()`, so past results can be reviewed without re-running a scan.

## Project Structure

```
RevWare/
  root.py
  modules/
    sysutlmdl.py
    nmpmdl.py
    os1ntmdl.py
    rcnmdl.py
    psnifmdl.py
    unfmdl.py
    utlmdl.py
    clgmdl.py
  README.md
```

## Legal & Ethical Use

RevWare is intended for use on networks and systems you own or have explicit, documented authorization to test. Nmap scanning, packet capture, and recon-ng activity should only be run against authorized targets. You are responsible for compliance with applicable laws and network policies.
