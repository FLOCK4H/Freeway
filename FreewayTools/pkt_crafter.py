# pkt_crafter.py
from scapy.all import *
import threading

try:
    from FreewayTools.colors import cprint, wprint, cinput, iprint, ColorCodes

except ModuleNotFoundError:
    from colors import cprint, wprint, cinput, iprint, ColorCodes

packet_types = [
    Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp,
    Dot11Auth, Dot11Deauth, Dot11Disas, Dot11QoS, Dot11Elt, EAPOL
]

packet_names = sorted(set(pt.__name__ for pt in packet_types))

# Packets not included in Scapy package
packet_names.extend(["Dot11RTS", "Dot11CTS", "Dot11Ack", "Dot11CFEnd"])

packet_names_str = ', '.join(packet_names)

def random_mac():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    return ':'.join(map(lambda x: format(x, '02x'), mac))

def list_packets():
    print(packet_names_str)

class CraftingTable:
    def __init__(self, interface, to_craft, addr1, addr2, addr3, ssid=None, threads=1, count=1, interval=0.1, loop=False):
        self.interface = interface
        self.to_craft = to_craft # packet_name
        self.addr1 = addr1 if addr1 != "" else random_mac()
        self.addr2 = addr2 if addr2 != "" else random_mac()
        self.addr3 = addr3 if addr3 != "" else random_mac()
        self.ssid = ssid
        self.threads = threads
        self.count = count
        self.interval = interval
        self.loop = loop
        self.global_event = threading.Event()

    def craft_packet(self):
        iprint(f"Crafting {self.to_craft} packet...")
        if self.to_craft not in packet_names:
            wprint(f"Packet type {self.to_craft} not supported.")
            return None

        packet = Dot11(addr1=self.addr1, addr2=self.addr2, addr3=self.addr3)
        radiotap = RadioTap()

        if self.to_craft == 'Dot11Beacon':
            iprint("This packet type requires only two addresses to be specified, overriding addr3 to addr2...")
            broadcast = cinput("I assume you want to broadcast (visible to all devices) (enter/n)")
            self.addr1 = self.addr1 if broadcast == "n" else "FF:FF:FF:FF:FF:FF"
            cap = cinput("Encryption code (default: ESS+privacy)") or "ESS+privacy"
            rates = cinput("Enter byte sequence of supported rates (default: \\x82\\x84\\x8b\\x96\\x0c\\x12\\x18\\x24)") or b'\x82\x84\x8b\x96\x0c\x12\x18\x24'
            packet = radiotap / Dot11(type=0, subtype=8, addr1=self.addr1, addr2=self.addr2, addr3=self.addr2) / Dot11Beacon(cap=cap)
            packet /= Dot11Elt(ID="SSID", info=self.ssid)
            packet /= Dot11Elt(ID="Rates", info=rates)
            packet /= Dot11Elt(ID="DSset", info=chr(random.randint(1, 14)))

            # RSNinfo is necessary for the beacon to appear as valid
            packet /= Dot11Elt(ID='RSNinfo', info=(
            b'\x01\x00'              # RSN Version 1
            b'\x00\x0f\xac\x04'      # Group Cipher Suite: AES (CCMP)
            b'\x01\x00'              # 1 Pairwise Cipher Suite
            b'\x00\x0f\xac\x04'      # Pairwise Cipher Suite: AES (CCMP)
            b'\x01\x00'              # 1 Authentication Key Management Suite (AKM)
            b'\x00\x0f\xac\x02'      # AKM Suite: PSK
            b'\xac\x00'              # RSN Capabilities (MFP capable)
        ))
        elif self.to_craft == 'Dot11ProbeReq':
            iprint("This packet type requires only two addresses to be specified, overriding addr3 to addr2...")
            broadcast = cinput("I assume you want to broadcast (visible to all devices) (enter/n)")
            self.addr1 = self.addr1 if broadcast == "n" else "FF:FF:FF:FF:FF:FF"
            dot11 = Dot11(type=0, subtype=4, addr1=self.addr1, addr2=self.addr2, addr3=self.addr2)
            probe_req = Dot11ProbeReq()
            ssid = Dot11Elt(ID="SSID", info=self.ssid, len=len(self.ssid))
            packet = radiotap / dot11 / probe_req / ssid
        elif self.to_craft == 'Dot11ProbeResp':
            iprint("This packet type requires only two addresses to be specified, overriding addr3 to addr2...")
            dot11 = Dot11(type=0, subtype=5, addr1=self.addr1, addr2=self.addr2, addr3=self.addr2)
            cap = cinput("Encryption code (default: ESS+privacy)") or "ESS+privacy"
            rates = cinput("Enter byte sequence of supported rates (default: \\x82\\x84\\x8b\\x96\\x0c\\x12\\x18\\x24)") or b'\x82\x84\x8b\x96\x0c\x12\x18\x24'
            probe_resp = Dot11ProbeResp(timestamp=int(time.time()*1000000), beacon_interval=0x0064, cap=cap)
            ssid_elt = Dot11Elt(ID='SSID', info=self.ssid.encode())
            rates_elt = Dot11Elt(ID='Rates', info=rates)
            dsset_elt = Dot11Elt(ID='DSset', info=chr(1))
            packet = radiotap / dot11 / probe_resp / ssid_elt / rates_elt / dsset_elt
        elif self.to_craft == 'Dot11AssoReq':
            # 1 - AP Mac
            # 2 - Client Mac
            # 3 - AP Mac
            iprint("This packet type requires only two addresses to be specified, where addr1/3 is AP Mac, and addr2 is Client Mac, overriding addr3 to addr1...")
            ssid = Dot11Elt(ID="SSID", info=self.ssid, len=len(str(self.ssid)))
            packet = radiotap / Dot11(type=0, subtype=0, addr1=self.addr1, addr2=self.addr2, addr3=self.addr1) / Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / ssid
        elif self.to_craft == 'Dot11AssoResp':
            # 1 - Client Mac
            # 2 - AP Mac
            # 3 - AP Mac
            iprint("This packet type requires only two addresses to be specified, where addr2/3 is AP Mac, and addr1 is Client Mac, overriding addr3 to addr2...")
            status = cinput("Association Response status code (default: 0)") or 0
            aid = cinput("Association ID (AID) (default: 1)") or 1
            cap = cinput("Encryption code (default: ESS+privacy)") or "ESS+privacy"
            dot11 = Dot11(addr1=self.addr1, addr2=self.addr2, addr3=self.addr2)
            packet = radiotap / dot11 / Dot11AssoResp(cap=cap, status=int(status), AID=int(aid))
        elif self.to_craft == 'Dot11Auth':
            # 1 - AP Mac
            # 2 - Client Mac
            # 3 - AP Mac
            iprint("This packet type requires only two addresses to be specified, where addr1/3 is AP Mac, and addr2 is Client Mac, overriding addr3 to addr1...")
            status = cinput("Auth status code (default: 0)") or 0
            algo = cinput("Algo (Authentication algorithm) code (default: 0)") or 0
            seqnum = cinput("Seqnum (which auth message is this one) code (default: 1)") or 1
            packet = radiotap / Dot11(type=0, subtype=11, addr1=self.addr1, addr2=self.addr2, addr3=self.addr1) / Dot11Auth(algo=int(algo), seqnum=int(seqnum), status=int(status))
        elif self.to_craft == 'Dot11Deauth':
            # 1 - Client Mac
            # 2 - AP Mac
            # 3 - AP Mac
            iprint("This packet type requires only two addresses to be specified, where addr2/3 is AP Mac, and addr1 is Client Mac, overriding addr3 to addr2...")
            dot11 = Dot11(addr1=self.addr1, addr2=self.addr2, addr3=self.addr2)
            deauth = Dot11Deauth(reason=7)
            packet = radiotap / dot11 / deauth
        elif self.to_craft == 'Dot11Disas':
            # 1 - Client Mac
            # 2 - AP Mac
            # 3 - AP Mac
            reason = cinput("Disassociation reason code (default: 7)") or 7
            dot11 = Dot11(addr1=self.addr1, addr2=self.addr2, addr3=self.addr2)
            disas = Dot11Disas(reason=int(reason))
            packet = radiotap / dot11 / disas
        elif self.to_craft == 'Dot11QoS':
            TID = cinput("Traffic Identifier (TID) code (default: 0)") or 0
            EOSP = cinput("End of Service Period (EOSP) code (default: 0)") or 0
            Acks = cinput("Acknowledge policy (default: 0)") or 0
            dot11 = Dot11(addr1=self.addr1, addr2=self.addr2, addr3=self.addr3)
            qos = Dot11QoS(TID=int(TID), EOSP=int(EOSP), Ack_Policy=int(Acks))
            packet = radiotap / dot11 / qos
        elif self.to_craft == 'Dot11RTS':
            # 1 - Receiver address
            # 2 - Transmitter address
            packet = radiotap / Dot11(type=1, subtype=11, addr1=self.addr1, addr2=self.addr2)
        elif self.to_craft == 'Dot11CTS':
            # 1 - Receiver address
            packet = radiotap / Dot11(type=1, subtype=12, addr1=self.addr1)
        elif self.to_craft == 'Dot11Ack':
            # 1 - Receiver address
            packet = radiotap / Dot11(type=1, subtype=13, addr1=self.addr1)
        elif self.to_craft == 'Dot11CFEnd':
            # 1 - Receiver address
            # 2 - BSSID
            packet = radiotap / Dot11(type=1, subtype=14, addr1=self.addr1, addr2=self.addr2)
        elif self.to_craft == 'EAPOL':
            eapol_type = cinput("Enter EAPOL packet type (Start, Logoff, Key, ASF-Alert) (default: Start)") or "Start"
            packet = self.create_eapol_packet(eapol_type)

        return packet

    def create_eapol_packet(self, eapol_type):
        eapol_type = eapol_type.lower()
        
        if eapol_type == 'start':
            iprint("Constructing an EAPOL-Start packet...")
            packet = EAPOL(type=1)
        elif eapol_type == 'logoff':
            iprint("Constructing an EAPOL-Logoff packet...")
            packet = EAPOL(type=2)
        elif eapol_type == 'key':
            iprint("Constructing an EAPOL-Key packet...")
            key_descriptor_type = cinput("Enter Key Descriptor Type (default: 2)") or 2
            key_info = cinput("Enter Key Information (default: 0x8a02)") or 0x8a02
            key_length = cinput("Enter Key Length (default: 16)") or 16
            key_replay_counter = cinput("Enter Key Replay Counter (default: 1)") or 1
            key_nonce = cinput("Enter Key Nonce (default: '00' * 32)") or '00' * 32
            key_iv = cinput("Enter Key IV (default: '00' * 16)") or '00' * 16
            key_rsc = cinput("Enter Key RSC (default: '00' * 8)") or '00' * 8
            key_id = cinput("Enter Key ID (default: '00' * 8)") or '00' * 8
            key_mic = cinput("Enter Key MIC (default: '00' * 16)") or '00' * 16
            key_data_length = cinput("Enter Key Data Length (default: 0)") or 0
            key_data = cinput("Enter Key Data (default: '')") or ''
            
            packet = EAPOL(type=3) / EAPOL.Key(
                key_descriptor_type=int(key_descriptor_type),
                key_info=int(key_info, 16),
                key_length=int(key_length),
                replay_counter=int(key_replay_counter),
                nonce=bytes.fromhex(key_nonce),
                key_iv=bytes.fromhex(key_iv),
                key_rsc=bytes.fromhex(key_rsc),
                key_id=bytes.fromhex(key_id),
                mic=bytes.fromhex(key_mic),
                wpa_key_length=int(key_data_length),
                wpa_key=bytes.fromhex(key_data)
            )
        elif eapol_type == 'asf-alert':
            iprint("Constructing an EAPOL-Encapsulated-ASF-Alert packet...")
            asf_data = cinput("Enter ASF Data (default: '00' * 32)") or '00' * 32
            packet = EAPOL(type=0) / Raw(bytes.fromhex(asf_data))
        else:
            wprint(f"Unknown EAPOL packet type: {eapol_type}. Defaulting to EAPOL-Start.")
            packet = EAPOL(type=1)
        
        return packet

    def send_packet(self, packet):
        sent = 0
        while not self.global_event.is_set():
            if self.count >= sent and not self.loop:
                self.global_event.set()
                break
            try:
                for interface in self.interface:
                    sendp(packet, iface=interface, count=1, inter=self.interval, verbose=0)
                    sent += 1
            except OSError:
                wprint("The network interface is down, but who cares? Trying to put it up...")

    def start_sending(self):
        self.global_event.clear()
        packet = self.craft_packet()
        if packet:
            iprint(f"Sending {self.count if not self.loop else 'infinite'} {self.to_craft} packet(s)...")
            iprint(f"Packet format: ADDR1 {self.addr1} / ADDR2 {self.addr2} / ADDR3 {self.addr3} / SSID {self.ssid}")
            threads = []
            for _ in range(self.threads):
                t = threading.Thread(target=self.send_packet, args=(packet,))
                t.start()
                threads.append(t)
            try:
                while not self.global_event.is_set():
                    pass
            except KeyboardInterrupt:
                self.global_event.set()
                iprint("Stopping all threads...")
            for t in threads:
                t.join()
        else:
            wprint("Failed to craft packet.")

if __name__ == "__main__":
    interface = "wlan0"
    to_craft = cinput("Specify packet to craft")
    addr1 = cinput("Enter address1 (or leave empty for random)") or random_mac()
    addr2 = cinput("Enter address2 (or leave empty for random)") or random_mac()
    addr3 = cinput("Enter address3 (or leave empty for random)") or random_mac()
    ssid = cinput("Enter SSID (optional)") or "Freeway"
    threads = 2
    count = 10
    interval = 0.1

    crafting_table = CraftingTable(interface, to_craft, addr1, addr2, addr3, ssid, threads, count, interval, loop=True)
    crafting_table.start_sending()

