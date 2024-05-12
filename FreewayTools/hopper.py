"""
    This script was developed only because the rich live table 
    is introducing weird output to the console when 
    trying to execute any of iwconfig and iw commands.
    Otherwise there is no need for the hopper.py,
    as channel hopping would be implemented into the modules.
"""

import argparse
import subprocess
import time
import sys
import threading

try:
    from FreewayTools.colors import cprint, oneline, iprint, wprint, cinput, ColorCodes

except ModuleNotFoundError:
    from colors import cprint, oneline, iprint, wprint, cinput, ColorCodes

cc = ColorCodes()

def channel_hopper(interface, delay, channels):
    for inf in interface:
        threading.Thread(target=_channel_hopper_thread_, args=(inf, delay, parse_channel_range(channels)), daemon=True).start()
    while True:
        pass

def _channel_hopper_thread_(interface, delay, channels):
    current_index = 0
    while True:
        subprocess.run(["sudo", "iw", "dev", interface, "set", "channel", str(channels[current_index])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        current_index = (current_index + 1) % len(channels)
        oneline(f"Current channel: {channels[current_index]}", sys)
        time.sleep(delay)


def parse_channel_range(range_str):
    if '-' in range_str:
        start, end = map(int, range_str.split('-'))
        return list(range(start, end + 1))
    else:
        return [int(ch) for ch in range_str.split(',')]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to use for channel hopping")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay (in seconds) between channel hops")
    parser.add_argument("-r", "--range", default="1-11", help="Comma-separated list of channels to hop on or a range e.g. 1-11")
    args = parser.parse_args()

    channel_hopper(list(args.interface), args.delay, args.range)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)