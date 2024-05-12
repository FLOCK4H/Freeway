"""
    IEEE 802.11 Packet Monitor using curses module as display,
    + captures PMKIDs & Handshakes + catches most clients
    + checks manufacturer + filter options
"""
import curses
import time
from datetime import datetime, timedelta
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, Dot11, Dot11Deauth, RadioTap, Dot11AssoResp, Dot11Disas, Dot11QoS
from scapy.layers.eap import EAPOL
import logging

try:
    from FreewayTools.checkmac import check_manufacturer
except ModuleNotFoundError:
    from checkmac import check_manufacturer

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
    def __init__(self, aps, clients, parms, script_dir):
        self.script_dir = script_dir
        self.APs = aps
        self.Clients = clients
        self.parms = parms
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

class Monitor:
    def __init__(self, interface, script_dir=None, parms=None, filters=None):
        self.script_dir = script_dir
        self.interface = interface
        self.parms = parms or {}
        self.filters = filters or {}
        self.save = True if "f" in self.filters else False
        self.caps_dir = os.path.join(self.script_dir, "caps")
        self.save_dir = os.path.join(self.script_dir, "caps/saved")
        self.session = self.new_session_number()
        os.makedirs(self.caps_dir, exist_ok=True)
        os.makedirs(self.save_dir, exist_ok=True)
        self.APs = {}
        self.Clients = {}
        self.run_time = time.time()
        self.packet_handler = PacketHandler(self.APs, self.Clients, self.parms, self.script_dir)

    def new_session_number(self):
        session_time = datetime.now().strftime('%m%d_%H%M%S')
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 12)))
        unique_id = f"{session_time}_{random_string}"
        return unique_id

    def process_packet(self, packet):
        timestamp = datetime.now().strftime('%m-%d %H:%M:%S')
        if self.save:
            PcapWriter(f"{self.save_dir}/{self.session}", append=True, sync=True).write(packet)
        if EAPOL in packet or packet.haslayer(EAPOL):
            self.packet_handler.handle_eapol_frame(packet, timestamp)
        elif packet.haslayer(Dot11):
            if packet.haslayer(Dot11Beacon):
                self.packet_handler.handle_dot11_beacon(packet, timestamp)
            elif packet.haslayer(Dot11ProbeReq):
                self.packet_handler.handle_dot11_probe_req(packet, timestamp)
            elif packet.haslayer(Dot11ProbeResp):
                self.packet_handler.handle_dot11_probe_resp(packet, timestamp)
            elif packet.haslayer(Dot11AssoReq):
                self.packet_handler.handle_dot11_asso_req(packet, timestamp)
            elif packet.haslayer(Dot11Auth):
                self.packet_handler.handle_dot11_auth(packet, timestamp)
            else:
                self.packet_handler._handle_client_activity(packet, timestamp, update_ap=True)
    
    def determine_columns_count(self):
        column_names = ["SSID", "MAC", "CLIENTS", "ENC", "PMKIDs", "HANDSHAKES", "LAST BEACON", "SIGNAL"]
        if 'channel' in self.parms:
            column_names.append("CH.")
        if 'manu' in self.parms:
            column_names.append("MANUFACTURER")

        return len(column_names)

    def get_dynamic_widths(self, stdscr, padding=2):
        _, width = stdscr.getmaxyx() 
        num_columns = self.determine_columns_count()
        available_width = width - (padding * (num_columns - 1))
        ssid_width = int(available_width * 0.17)
        mac_width = int(available_width * 0.2) if num_columns == 8 else int(available_width * 0.17)
        clients_width = int(available_width * 0.1) if num_columns == 8 else int(available_width * 0.08)
        enc_width = int(available_width * 0.1) if num_columns == 8 else int(available_width * 0.08)
        pmkids_width = int(available_width * 0.08) 
        handshakes_width = int(available_width * 0.12) if num_columns == 8 else int(available_width * 0.1)
        last_beacon_width = int(available_width * 0.16) if num_columns == 8 else int(available_width * 0.10)
        signal_width = int(available_width * 0.05)
        channel_width = int(available_width * 0.05) if 'channel' in self.parms else 0
        manu_width = int(available_width * 0.12) if 'manu' in self.parms else 0
        return ssid_width, mac_width, clients_width, enc_width, pmkids_width, handshakes_width, last_beacon_width, signal_width, channel_width, manu_width

    def safe_addstr(self, stdscr, y, x, text, attr=None):
        """ 
            Ensures the text can be added to the view
            basing on terminal width and height
        """
        max_y, max_x = stdscr.getmaxyx()
        if attr is None:
            attr = curses.A_NORMAL

        if y < max_y and x < max_x:
            try:
                stdscr.addstr(y, x, text, attr)
            except curses.error:
                pass
            except ValueError:
                pass

    def calc_time(self, elapsed_seconds):
        """Calculate the time passed"""
        elapsed_time = timedelta(seconds=elapsed_seconds)
        
        days, remainder = divmod(elapsed_time.total_seconds(), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes = remainder // 60

        runtime_parts = []
        if days > 0:
            runtime_parts.append(f"{int(days)}d")
        if hours > 0:
            runtime_parts.append(f"{int(hours)}h")
        if minutes > 0 or (days == 0 and hours == 0):
            runtime_parts.append(f"{int(minutes)}m")

        return runtime_parts

    def show_captured_data(self, stdscr):
        """
            Streams all the captured beacon packets onto the curses view,
            initializes and calculates banners and other styling elements
        """
        current_time = time.time()
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        display_aps = True if not "c" in self.filters else False
        display_clients = True if not "a" in self.filters else False
        display_no_empty_aps = True if "e" in self.filters else False
        display_stack_ssids = True if "s" in self.filters else False
        display_no_lonely_clients = True if "n" in self.filters else False

        banner = [
            " ______                       ",
            "|__    |.--.--.--.---.-.--.--.",
            "|__    ||  |  |  |  _  |  |  |",
            "|______||________|___._|___  |",
            "                       |_____|"
        ]

        start_row_banner = 0
        start_col = 0
        
        # freeway banner setup
        for line in banner:
            start_col = max(0, (width // 2) - (len(line) // 2))
            end_col = start_col + len(line)

            part_length = len(line) // 3
            part1 = line[:part_length]
            part2 = line[part_length:2*part_length]
            part3 = line[2*part_length:]

            self.safe_addstr(stdscr, start_row_banner, start_col, part1, curses.color_pair(1) | curses.A_BOLD)
            self.safe_addstr(stdscr, start_row_banner, start_col + len(part1), part2, curses.color_pair(2) | curses.A_BOLD)
            self.safe_addstr(stdscr, start_row_banner, start_col + len(part1) + len(part2), part3, curses.color_pair(5) | curses.A_BOLD)
            
            start_row_banner += 1

        stdscr.refresh()

        elapsed_seconds = int(current_time - self.run_time)
        runtime_parts = self.calc_time(elapsed_seconds)

        runtime_str = " ".join(runtime_parts)
        rtheader = f"running for {runtime_str}"
        
        runtime_col = max(0, (width // 2) - (len(rtheader) // 2))

        self.safe_addstr(stdscr, start_row_banner, runtime_col + 23, rtheader, curses.color_pair(4) | curses.A_BOLD)
        self.row = start_row_banner + 1

        ssid_width, mac_width, clients_width, enc_width, pmkids_width, handshakes_width, last_beacon_width, signal_width, channel_width, manu_width = self.get_dynamic_widths(stdscr)
        if display_aps:
            header_elements = ["SSID", "MAC", "CLIENTS", "ENC", "PMKIDs", "HANDSHAKES", "LAST BEACON", "SIGNAL"]
            ap_header_format = " ".join(["{:<" + str(width) + "}" for width in (ssid_width, mac_width, clients_width, enc_width, pmkids_width, handshakes_width, last_beacon_width, signal_width)])

            if 'channel' in self.parms:
                header_elements.append("CH.")
                ap_header_format += " {:<" + str(channel_width) + "}"

            if 'manu' in self.parms:
                header_elements.append("MANUFACTURER")
                ap_header_format += " {:<" + str(manu_width) + "}"            

            ap_header = ap_header_format.format(*header_elements)

            self.safe_addstr(stdscr, self.row, 0, "[>]   Access Points", curses.color_pair(2))
            self.row += 1
            self.safe_addstr(stdscr, self.row + 1, 0, ap_header, curses.color_pair(3))
            self.row += 2

            self.known_ssids = set()

            # APs data
            for mac, info in self.APs.items():
                if (display_no_empty_aps and len(info['Clients']) == 0) or (display_stack_ssids and 
                info['SSID'] in self.known_ssids):
                    continue

                signal = info.get("Signal", 0)
                if signal < -50:
                    color_pair = curses.color_pair(2)
                else:
                    color_pair = curses.color_pair(1)

                ssid = (info['SSID'][:ssid_width - 3] + '...') if len(info['SSID']) > ssid_width else info['SSID']
                self.known_ssids.add(info['SSID'])
                enc = (info['ENC'][:enc_width - 3] + '...') if len(info['ENC']) > enc_width else info['ENC']
                signal_str = str(signal) + " dBm"

                ap_line = "{:<{}} {:<{}} {:<{}} {:<{}} {:<{}} {:<{}} {:<{}} {:<{}} ".format(ssid, ssid_width, mac, mac_width, str(len(info['Clients'])), clients_width, enc, enc_width, str(len(info['PMKIDs'])), pmkids_width, str(len(info['Handshakes'])), handshakes_width, info['Last Beacon'], last_beacon_width, signal_str, signal_width)
                
                if "channel" in self.parms:
                    ap_line += "{:<{}}".format(info.get("Channel", "N/A"), channel_width)
                if "manu" in self.parms:
                    ap_line += "{:<{}}".format(info.get("Manufacturer"), manu_width)

                self.safe_addstr(stdscr, self.row, 0, ap_line, color_pair)
                self.row += 1

        if display_clients:
            self.row += 1
            client_header_format = "{:<" + str(ssid_width) + "} {:<" + str(mac_width) + "} {:<" + str(mac_width) + "} {:<" + str(last_beacon_width) + "} {:<" + str(signal_width) + "} {:<" + str(manu_width) + "}"
            self.safe_addstr(stdscr, self.row, 0, "[+]   Clients", curses.color_pair(5))
            self.row += 2
            client_header = client_header_format.format("NAME (Probe)", "MAC", "AP MAC", "LAST BEACON", "SIGNAL", "MANUFACTURER")
            self.safe_addstr(stdscr, self.row, 0, client_header, curses.color_pair(3))
            self.row += 1

            # Clients data
            for mac, info in self.Clients.items():
                if (display_no_lonely_clients and len(info['AP_MAC']) < 16):
                    continue

                full_names = ', '.join(info['Name']) if 'Name' in info else " "
                if len(full_names) > ssid_width:
                    full_names = full_names[:ssid_width - 3] + '...'

                ap_mac = info['AP_MAC'] or ''
                last_beacon = info['Last Beacon']
                signal_str = str(info['Signal']) + "dbm"
                manufacturer = info['Manufacturer']
                client_line = client_header_format.format(full_names, mac, ap_mac, last_beacon, signal_str, manufacturer)
                self.safe_addstr(stdscr, self.row, 0, client_line, curses.color_pair(4))
                self.row += 1

        stdscr.refresh()

    def start_sniffing(self, stdscr):
        self.mod_curses('enter', stdscr)

        running = True
        network_down_message_displayed = False
        counter = 0
        while running:
            try:
                sniff(iface=self.interface, count=4, prn=self.process_packet, store=0, monitor=True)
                if network_down_message_displayed and counter <= 10:
                    counter += 1
                    self.safe_addstr(stdscr, self.row + 3, 0, "Network is down..", curses.color_pair(5))
                    stdscr.refresh()                    

                    if counter == 10:
                        network_down_message_displayed = False
                        counter = 0
                        
            except OSError as e:
                if e.errno == 100:
                    if not network_down_message_displayed:
                        self.safe_addstr(stdscr, self.row + 3, 0, "Network is down..", curses.color_pair(5))
                        stdscr.refresh()
                        network_down_message_displayed = True
                        time.sleep(3)
                else:
                    raise

            self.show_captured_data(stdscr)
            self.safe_addstr(stdscr, self.row + 2, 0, " Press q to stop monitoring", curses.color_pair(1))
            stdscr.refresh()

            if stdscr.getch() == ord('q'):
                running = False

        # Results Screen
        self.show_captured_data(stdscr)
        self.safe_addstr(stdscr, self.row + 4 if network_down_message_displayed else self.row + 3, 0, " Press anything to exit", curses.color_pair(1))
        stdscr.refresh()

        self.mod_curses('leave', stdscr)

    def mod_curses(self, mod, stdscr):
        if mod == "enter":
            curses.curs_set(0)
            init_colors()
            stdscr.nodelay(1)
            stdscr.clear()
            return

        stdscr.nodelay(0)
        stdscr.getch()
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()  

if __name__ == "__main__":
    interface = "wlan0mon"
    curses.wrapper(Monitor(interface).start_sniffing)