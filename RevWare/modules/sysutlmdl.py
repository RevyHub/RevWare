import subprocess
import platform
import psutil
from modules.utlmdl import save_log, print_title

# -----------------------------
# Network Connections
# -----------------------------
def net_connections():
    """
    Shows current network connections using OS utilities.
    """
    print_title("Active Network Connections")
    try:
        if platform.system() == "Windows":
            cmd = ["netstat", "-ano"]
        else:
            cmd = ["netstat", "-tunap"]
        output = subprocess.check_output(cmd, text=True)
        print(output)
        save_log("net_connections", output)
        return output
    except Exception as e:
        print(f"[!] Error getting connections: {e}")
        return None

# -----------------------------
# Routing Table
# -----------------------------
def routing_table():
    """
    Displays the system routing table.
    """
    print_title("Routing Table")
    try:
        if platform.system() == "Windows":
            cmd = ["route", "print"]
        else:
            cmd = ["netstat", "-rn"]
        output = subprocess.check_output(cmd, text=True)
        print(output)
        save_log("routing_table", output)
        return output
    except Exception as e:
        print(f"[!] Error getting routing table: {e}")
        return None

# -----------------------------
# System Stats
# -----------------------------
def system_stats():
    """
    Returns CPU, memory, disk, and network I/O stats.
    """
    print_title("System Stats")
    stats = {
        "CPU_Usage": psutil.cpu_percent(interval=1),
        "Memory_Usage": psutil.virtual_memory().percent,
        "Disk_Usage": psutil.disk_usage('/').percent,
        "Network_IO": psutil.net_io_counters()._asdict()
    }
    print(stats)
    save_log("system_stats", stats)
    return stats
