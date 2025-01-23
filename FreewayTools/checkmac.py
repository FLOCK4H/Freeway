#!/usr/bin/env python3
from netaddr import EUI
from netaddr.core import NotRegisteredError
import argparse

def check_manufacturer(mac_address):
    try:
        mac = EUI(mac_address)
        manufacturer = mac.oui.registration().org
        return manufacturer
    except NotRegisteredError:
        return "Unknown/Random MAC"
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get the manufacturer of a given MAC address.')
    parser.add_argument('-m', '--mac', type=str, required=True, help='The MAC address to look up')
    args = parser.parse_args()
    manufacturer = check_manufacturer(args.mac)
    print(f'\033[34mManufacturer: {manufacturer}')