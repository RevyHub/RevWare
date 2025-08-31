import requests
from modules.utlmdl import save_log, print_title

def geo_ip(ip):
    """
    Query ipinfo.io for public IP geolocation and network info.
    Returns JSON with country, city, region, ISP, etc.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        print_title(f"OSINT / GeoIP for {ip}")
        for k in ["ip", "city", "region", "country", "org", "loc"]:
            print(f"{k.capitalize()}: {data.get(k, 'N/A')}")
        save_log(f"osint_{ip}", data)
        return data
    except requests.RequestException as e:
        print(f"[!] OSINT Error: {e}")
        return {"error": str(e)}
