"""
    IEEE 802.11 Packet Monitor using curses module as display,
    + captures PMKIDs & Handshakes + catches most clients
    + checks manufacturer + has filter options
    27.09.24 -> You can now summarize your hunt
"""

import curses
import os
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, Dot11, Dot11Deauth, RadioTap, Dot11AssoResp, Dot11Disas, Dot11QoS
from scapy.layers.eap import EAPOL
import logging
from FreewayTools.checkmac import check_manufacturer

log_dir = "/usr/local/share/3way/"

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(filename=os.path.join(log_dir, 'debug.log'), level=logging.DEBUG)

def init_colors():
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_BLUE, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_WHITE) 

def get_signal_strength(packet):
    """
    Extracts signal strength in dBm from the packet if available
    """
    if packet.haslayer(RadioTap):
        radiotap_fields = packet[RadioTap].fields
        if 'dBm_AntSignal' in radiotap_fields:
            return radiotap_fields['dBm_AntSignal']
    return None

def save_hash_file(path, content):
    try:
        with open(path + ".hash", "w") as f:
            f.write(content)
    except Exception as e:
        logging.debug(str(e))

class PacketHandler:
    def __init__(self, aps, clients, script_dir: str = "/usr/local/share/3way"):
        self.script_dir = script_dir
        self.APs = aps
        self.Clients = clients
        self.handshake_dir = os.path.join(self.script_dir, "caps/handshakes")
        self.pmkids_dir = os.path.join(self.script_dir, "caps/pmkids")
        os.makedirs(self.handshake_dir, exist_ok=True)
        os.makedirs(self.pmkids_dir, exist_ok=True)
        self.handshakes = {}
        self.pmkids = {}

    def determine_encryption(self, packet):
        """Determines encryption type of the AP"""
        encryption = "Open"
        if packet.haslayer(Dot11Elt):
            rsn_found = packet.getlayer(Dot11Elt, ID=48)
            wpa_found = packet.getlayer(Dot11Elt, ID=221)
            
            if rsn_found:
                encryption = self.parse_rsn_element(rsn_found)

            elif wpa_found and b'\x00P\xf2\x01\x01\x00' in wpa_found.info:
                encryption = "WPA"

        return encryption

    def parse_rsn_element(self, rsn_elt):
        """Determines encryption type included in RSN"""
        encryption = "WPA2"

        if len(rsn_elt.info) > 2:
            asc = int.from_bytes(rsn_elt.info[10:12], byteorder='little')

            if asc > 0:
                akm_offset = 12
                for _ in range(asc):
                    akm_suite = rsn_elt.info[akm_offset:akm_offset+4]
                    if akm_suite in [b'\x00\x0F\xAC\x02', b'\x00\x0F\xAC\x05']:
                        encryption += " (Personal)"
                    elif akm_suite in [b'\x00\x0F\xAC\x01', b'\x00\x0F\xAC\x05']:
                        encryption = "WPA2 Enterprise"
                    elif akm_suite in [b'\x00\x0F\xAC\x08', b'\x00\x0F\xAC\x09', b'\x00\x0F\xAC\x12']:
                        encryption = "WPA3 Enterprise"
                    elif akm_suite == b'\x00\x0F\xAC\x04':
                        encryption = "WPA3"

                    akm_offset += 4

        return encryption

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

    def packet_breathalyzer(self, ap_mac, client_mac, types):
        """
            The author of this function needs a breathalyzer himself (me) 
            *Sorry for such a mess
        """
        if types in ["Association", "Authentication", "QoS Data", "RTS", "Block Ack"]:
            if client_mac in self.APs or ap_mac in self.APs:
                self.APs[ap_mac if ap_mac in self.APs else client_mac]["Clients"].add(client_mac if client_mac not in self.APs else ap_mac)
                logging.debug(f"PB-{types}: Current client list for {ap_mac}: {self.APs[ap_mac if ap_mac in self.APs else client_mac]['Clients']}")
            if client_mac in self.Clients:
                self.Clients[client_mac]["AP_MAC"] = ap_mac
            elif ap_mac in self.Clients:
                self.Clients[ap_mac]["AP_MAC"] = client_mac

        elif types in ["Deauthentication", "Disassociation"]:
            if client_mac in self.APs or ap_mac in self.APs:
                if client_mac in self.APs[ap_mac if ap_mac in self.APs else client_mac]["Clients"] or ap_mac in self.APs[ap_mac if ap_mac in self.APs else client_mac]["Clients"]:
                    self.APs[ap_mac if ap_mac in self.APs else client_mac]["Clients"].remove(client_mac if client_mac not in self.APs else ap_mac)

    def extract_channel(self, packet):
        channel = "N/A"
        if packet.haslayer(RadioTap):
            try:
                channel = ord(packet[Dot11Elt:3].info)
            except Exception as e:
                logging.debug(f"In function extract_channel: {type(e).__name__}: {str(e)}")
        return channel

    def handle_dot11_beacon(self, packet, timestamp):
        mac_address = packet[Dot11].addr2
        channel = self.extract_channel(packet)
        ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet[Dot11Elt].info else "Hidden SSID"
        enc = self.determine_encryption(packet)
        signal_strength = get_signal_strength(packet)
        manufacturer = check_manufacturer(mac_address)

        if mac_address not in self.APs:
            self.APs[mac_address] = {"SSID": ssid, "Clients": set(), "PMKIDs": set(), "Handshakes": set(), "Last Beacon": timestamp, "ENC": enc, "Signal": signal_strength, "Channel": channel, "Manufacturer": manufacturer}
        else:
            self.APs[mac_address]["ENC"] = enc
            self.APs[mac_address]["Signal"] = signal_strength
            self.APs[mac_address]["Channel"] = channel
            self.APs[mac_address]["Manufacturer"] = manufacturer
        self._handle_client_activity(packet, timestamp, update_ap=True)

    def handle_dot11_probe_req(self, packet, timestamp):
        mac_address = packet[Dot11].addr2

        signal = get_signal_strength(packet)

        if packet.haslayer(Dot11Elt):
            for element in packet[Dot11Elt]:
                if element.ID == 0 and element.info: # ID 0 == SSID
                    if mac_address in self.Clients:
                        ssid = element.info.decode('utf-8', 'ignore')
                        self.Clients[mac_address]["Name"].add(ssid)
                        logging.debug(f"Current probes list for {mac_address}: {self.Clients[mac_address]['Name']}")
                        return
        self._handle_client_activity(packet, timestamp, update_ap=True)

    def handle_dot11_probe_resp(self, packet, timestamp):
        ap_mac = packet[Dot11].addr2
        enc = self.determine_encryption(packet)
        if ap_mac in self.APs:
            self.APs[ap_mac]["ENC"] = enc
        self._handle_client_activity(packet, timestamp, update_ap=True)

    def handle_dot11_asso_req(self, packet, timestamp):
        self._handle_client_activity(packet, timestamp, update_ap=True)

    def handle_dot11_auth(self, packet, timestamp):
        self._handle_client_activity(packet, timestamp, update_ap=True)

    def handle_eapol_frame(self, packet, timestamp):
        """
            Capture WPA 2/3 handshakes and PMKIDs for all sessions.
        """

        src_mac = packet[Dot11].addr2
        dst_mac = packet[Dot11].addr1
        session_id = f"{src_mac}-{dst_mac}"
        session_id_reversed = f"{dst_mac}-{src_mac}"
        logging.debug(f"{timestamp}--Detected EAPOL Packet! Logging session-id: {session_id}")

        if session_id not in self.handshakes or session_id not in self.pmkids:
            self.handshakes[session_id] = {'to_frames': 0, 'from_frames': 0, 'packets': []}
            self.pmkids[session_id] = {'num_frame': 0, 'first_eapol_frame': None, 'pmkid': None, 'mac_ap': None, 'mac_cl': None, 'packets': []} 

        # PMKIDs
        if session_id_reversed in self.pmkids:
            temp_data = self.pmkids[session_id]
            del self.pmkids[session_id]
            self.pmkids[session_id_reversed]['num_frame'] = temp_data['num_frame']
            session_id = session_id_reversed

        self.pmkids[session_id]['num_frame'] += 1

        if self.pmkids[session_id]['num_frame'] == 1:
            self.pmkids[session_id]['first_eapol_frame'] = bytes(packet[EAPOL])
            self.pmkids[session_id]['pmkid'] = self.pmkids[session_id]['first_eapol_frame'][-16:].hex()
            self.pmkids[session_id]['mac_ap'] = packet.addr2
            self.pmkids[session_id]['mac_cl'] = packet.addr1
            logging.debug(f"Detected 1st EAPOL PMKID packet for {self.pmkids[session_id]}")

        if self.pmkids[session_id]['num_frame'] == 2:
            if not src_mac in self.APs:
                logging.debug(f"Detected second EAPOL PMKID packet but we didnt catch the SSID yet! Session: {self.pmkids[session_id]}")
                return
            self.APs[src_mac]["PMKIDs"].add(timestamp)
            logging.debug("\n1st EAPoL Frame:   \n" + str(self.pmkids[session_id]['first_eapol_frame']) + "\n")
            logging.debug("Possible PMKID:        ", self.pmkids[session_id]['pmkid'])
            ssid_hex = bytes(self.APs[src_mac]["SSID"], 'utf-8').hex()
            logging.debug("SSID:                  ", self.APs[src_mac]["SSID"])
            mac_ap_formatted = self.pmkids[session_id]['mac_ap'].replace(":", "").lower()
            mac_cl_formatted = self.pmkids[session_id]['mac_cl'].replace(":", "").lower()
            logging.debug("MAC AP:                ", mac_ap_formatted)
            logging.debug("MAC Client:            ", mac_cl_formatted)
            logging.debug("\nEncoded PMKID compatible with Hashcat hc22000:")
            hash_line = f"{self.pmkids[session_id]['pmkid']}*{mac_ap_formatted}*{mac_cl_formatted}*{ssid_hex}"
            logging.debug(hash_line)
            save_hash_file(os.path.join(self.pmkids_dir, "pmkid_" + timestamp), hash_line)

        # Handshakes
        to_ds = packet.FCfield & 0x1 != 0
        from_ds = packet.FCfield & 0x2 != 0

        if to_ds and not from_ds:
            self.handshakes[session_id]['to_frames'] += 1
        elif not to_ds and from_ds:
            self.handshakes[session_id]['from_frames'] += 1

        self.handshakes[session_id]['packets'].append(packet)

        filename = os.path.join(self.handshake_dir, f"{session_id}_handshake.pcap")
        dump = PcapWriter(filename, append=True, sync=True)
        dump.write(packet)

        if self.handshakes[session_id]['to_frames'] >= 2 and self.handshakes[session_id]['from_frames'] >= 2:
            if self.APs[src_mac]:
                self.APs[src_mac]["Handshakes"].add(timestamp)
            logging.debug(f"Captured complete WPA handshake for session {session_id}")
            self.handshakes[session_id] = {'to_frames': 0, 'from_frames': 0, 'packets': []}
        self._handle_client_activity(packet, timestamp, update_ap=True)

    def _handle_client_activity(self, packet, timestamp, update_ap=False):
        ptype = self.get_packet_type(packet)
        ap_mac = packet[Dot11].addr2
        mac_address = packet[Dot11].addr1 if ptype not in ["Probe Request", "CTS", "RTS"] else packet[Dot11].addr2

        if ap_mac in self.APs:
            for mac, ap_info in self.APs.items():
                if mac_address in ap_info['Clients']:
                    self.APs[mac]['Clients'].remove(mac_address)
                    self.APs[ap_mac]['Clients'].add(mac_address)

        self.packet_breathalyzer(ap_mac, mac_address, ptype)

        signal = get_signal_strength(packet)

        if mac_address in self.APs and mac_address in self.Clients:
            del self.Clients[mac_address]
        elif ap_mac in self.APs and ap_mac in self.Clients:
            del self.Clients[ap_mac]

        if update_ap and ap_mac in self.APs and mac_address in self.Clients:
            ssid = self.APs[ap_mac]["SSID"]
            if ssid not in self.Clients[mac_address]["Name"]:
                self.Clients[mac_address]["Name"].add(ssid)
        else:
            if mac_address not in ["ff:ff:ff:ff:ff:ff", None]:
                if mac_address not in self.Clients and mac_address not in self.APs:
                    self.Clients[mac_address] = {"Name": set(), "AP_MAC": "Not Associated", "Last Beacon": timestamp, "Signal": signal, "Manufacturer": check_manufacturer(mac_address)}
                    for mac, ap_info in self.APs.items():
                        if mac_address in ap_info['Clients']:
                            self.Clients[mac_address]['AP_MAC'] = mac