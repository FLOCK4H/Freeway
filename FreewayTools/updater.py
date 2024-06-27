import requests
import subprocess
from FreewayTools.colors import *
import time, os

GITHUB_REPO = "FLOCK4H/Freeway"

def get_latest_version():
    try:
        # This is an API created & hosted by github, not by me, 
        # it's the safest way of checking the most recent version of Freeway

        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        response = requests.get(url)
        response.raise_for_status()
        latest_release = response.json()
        return latest_release["tag_name"]
    except ConnectionError:
        pass
    except Exception as e:
        wprint(str(e))

def get_current_version():
    return "1.3.0"

def update():
    cprint("Checking for updates..")
    
    current_version = get_current_version()
    latest_version = get_latest_version()
    if latest_version is None:
        wprint("You are not connected to any network, I can't fetch updates...")
        time.sleep(2)
        return
    
    if current_version != latest_version:
        cprint(f"New version available: {latest_version}")
        if cinput("Update Freeway? (y/n)") == "y":
            if os.path.exists("FreewayTools"):
                subprocess.run(["git", "pull", "origin", "main"], check=True)
            else:
                subprocess.run(["sudo", "pip", "install", "--upgrade", "3way"])
            iprint("Update completed. Please restart Freeway.")
    else:
        iprint("You are using the latest version of Freeway.")
    time.sleep(0.8)

if __name__ == "__main__":
    update()
