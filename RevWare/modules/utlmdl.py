import os
import json
from datetime import datetime

LOG_DIR = "logs"

def clr():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")

def print_title(title):
    """Print a nicely formatted section title."""
    print("=" * 60)
    print(title)
    print("=" * 60)

def save_log(filename, data):
    """
    Save data to JSON (or fallback to text) in the logs folder.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(LOG_DIR, f"{filename}_{ts}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=4, default=str)
    except Exception:
        # fallback to plain text if json fails
        path = path.replace(".json", ".txt")
        with open(path, "w") as f:
            f.write(str(data))
    return path
