"""
    Simple script that downloads github files
"""

import os
import requests
import base64
import sys
import time

try:
    from FreewayTools.colors import cprint, iprint, wprint, cinput, ColorCodes

except ModuleNotFoundError:
    from colors import cprint, iprint, wprint, cinput, ColorCodes

def download_folder_from_github(owner, repo, path, local_dir, token=None):
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            files = response.json()
            for file in files:
                if file['type'] == 'file':
                    download_url = file['download_url']
                    file_response = requests.get(download_url)
                    local_file_path = os.path.join(local_dir, file['name'])
                    with open(local_file_path, 'wb') as local_file:
                        local_file.write(file_response.content)
                    cprint(f"Downloaded: {file['name']}")
                else:
                    # If there are subdirectories, call the function recursively
                    download_folder_from_github(owner, repo, file['path'], os.path.join(local_dir, file['name']), token)
        else:
            wprint(f"Failed to get contents of directory: STATUS_CODE {response.status_code}")
    except Exception as e:
        wprint(f"Failed to download {path}! You may need to download manually or check for your internet connection.")
        time.sleep(3)