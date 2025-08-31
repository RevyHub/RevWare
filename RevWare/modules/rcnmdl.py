import subprocess
from modules.utlmdl import save_log, print_title

def run_recon_ng(script=None):
    """
    Launches recon-ng in console mode.
    Optionally, run a recon-ng script if provided.
    Requires recon-ng installed and in PATH.
    """
    try:
        print_title("Recon-ng")
        if script:
            # Run recon-ng with a script file
            cmd = ["recon-ng", "-r", script]
            print(f"[*] Running recon-ng script: {script}")
        else:
            # Just launch recon-ng console
            cmd = ["recon-ng", "-c", "exit"]  # starts and immediately exits for automation

        output = subprocess.check_output(cmd, text=True)
        print(output)
        save_log("recon-ng_output", output)
        return output

    except FileNotFoundError:
        print("[!] recon-ng not installed. Install via package manager.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] Recon-ng error: {e}")
        return None
