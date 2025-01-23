# audit.py
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, RadioTap, Dot11AssoResp, Dot11Ack, Dot11QoS 
from scapy.layers.eap import EAPOL
import os
import time
import curses

from rich.console import Console
from datetime import timedelta

try:
    from FreewayTools.colors import wprint
    from FreewayTools.monitor import get_signal_strength, save_hash_file, init_colors
    from FreewayTools.checkmac import check_manufacturer

except ModuleNotFoundError:
    from colors import wprint
    from monitor import get_signal_strength, save_hash_file, init_colors
    from checkmac import check_manufacturer

def get_ap_uptime(packet):
    if packet.haslayer(Dot11Beacon):
        timestamp = packet[Dot11Beacon].timestamp
        uptime_seconds = timestamp / 1000000
        uptime_delta = timedelta(seconds=int(uptime_seconds))
        days = uptime_delta.days
        hours = uptime_delta.seconds // 3600
        return f"{days}d {hours}h"
    return None

class Sniffer:
    def __init__(self, interface, console, script_dir=None, target=None, ssid=None, results=None, clients=None, debug=False):
        self.script_dir = script_dir
        self.interface = interface
        self.target = target
        self.ssid = ssid
        self.console = console
        self.results = results
        self.clients = clients
        self.debug = debug
        self.handshakes = {}
        self.pmkids = {}
        self.handshake_dir = os.path.join(self.script_dir or "/usr/local/share/3way", "caps/audit/handshakes")
        self.pmkids_dir = os.path.join(self.script_dir or "/usr/local/share/3way", "caps/audit/pmkids")
        os.makedirs(self.handshake_dir, exist_ok=True)
        os.makedirs(self.pmkids_dir, exist_ok=True)

    def debugprint(self, text, style="white"):
        if self.debug:
            self.console.print(text, style=style)

    def packet_handler(self, packet):
        if EAPOL in packet:
            timestamp = datetime.now().strftime('%m-%d %H:%M:%S')
            self.handle_eapol_frame(packet, timestamp)
            self.packet_analyzer(packet, types="eapol")
        elif packet.haslayer(Dot11):
            self.debugprint(f"ADDR1: {packet.addr1} <-> ADDR2: {packet.addr2} || {packet}", style="blue")
            if packet.haslayer(Dot11Beacon):
                self.packet_analyzer(packet, types="beacon")
            elif packet.haslayer(Dot11ProbeReq):
                self.packet_analyzer(packet, types="probereq")
            elif packet.haslayer(Dot11ProbeResp):
                self.packet_analyzer(packet, types="proberesp")
            elif packet.haslayer(Dot11Auth):
                self.packet_analyzer(packet, types="auth")
            elif packet.haslayer(Dot11AssoReq):
                self.packet_analyzer(packet, types="asso_req")
            elif packet.haslayer(Dot11AssoResp):
                self.packet_analyzer(packet, types="asso_resp")
            elif packet.haslayer(Dot11Ack):
                self.packet_analyzer(packet, types="ack")
            elif packet.haslayer(Dot11QoS):
                self.packet_analyzer(packet, types="qos_data")
            else:
                if packet.type == 1:
                    subtype = packet.subtype
                    if subtype == 0x09:
                        self.packet_analyzer(packet, types="block_ack_req")
                    elif subtype == 0x0b:
                        self.packet_analyzer(packet, types="block_ack")
                    elif subtype == 0x0B:
                        self.packet_analyzer(packet, types="rts")
                    elif subtype == 0x0C:
                        self.packet_analyzer(packet, types="cts")

    def handle_eapol_frame(self, packet, timestamp):
        """
            Capture WPA 2/3 handshakes and PMKIDs for all sessions.
        """

        if not self.target:
            return

        src_mac = packet.addr2
        dst_mac = packet.addr1

        if src_mac == self.target or dst_mac == self.target:
            session_id = f"{src_mac}-{dst_mac}"
            session_id_reversed = f"{dst_mac}-{src_mac}"
            self.debugprint(f"{timestamp}--Detected EAPOL Packet! Logging session-id: {session_id}", style='red')

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
                self.debugprint(f"Detected 1st EAPOL PMKID packet for {self.pmkids[session_id]}")

            if self.pmkids[session_id]['num_frame'] == 2:
                if not self.ssid:
                    self.debugprint(f"Detected second EAPOL PMKID packet but we didnt catch the SSID yet! Session: {self.pmkids[session_id]}")
                    return
                self.results[src_mac]["PMKIDs"].add(timestamp)
                self.debugprint("\n1st EAPoL Frame:   \n" + str(self.pmkids[session_id]['first_eapol_frame']) + "\n")
                self.debugprint("Possible PMKID:        ", self.pmkids[session_id]['pmkid'])
                ssid_hex = bytes(self.ssid, 'utf-8').hex()
                self.debugprint("SSID:                  ", self.ssid)
                mac_ap_formatted = self.pmkids[session_id]['mac_ap'].replace(":", "").lower()
                mac_cl_formatted = self.pmkids[session_id]['mac_cl'].replace(":", "").lower()
                self.debugprint("MAC AP:                ", mac_ap_formatted)
                self.debugprint("MAC Client:            ", mac_cl_formatted)
                self.debugprint("\nEncoded PMKID compatible with Hashcat hc22000:")
                hash_line = f"{self.pmkids[session_id]['pmkid']}*{mac_ap_formatted}*{mac_cl_formatted}*{ssid_hex}"
                self.debugprint(hash_line)
                save_hash_file(os.path.join(self.pmkids_dir,"pmkid_" + timestamp), hash_line)

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
                if src_mac in self.results:
                    self.results[src_mac]["Handshakes"].add(timestamp)
                self.debugprint(f"Captured complete WPA handshake for session {session_id}")
                self.handshakes[session_id] = {'to_frames': 0, 'from_frames': 0, 'packets': []}

    def get_ssid(self, packet):
        if packet.haslayer(Dot11Elt) and (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
            ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet[Dot11Elt].info else "Hidden SSID"
            return ssid
        return "0"

    def get_macs(self, packet, types):
        if types == "probereq":
            mac_cl = packet.addr2
            mac_ap = packet.addr1 # Usually ff:ff:ff:ff:ff:ff
        elif types == "rts":
            mac_cl = packet.addr2
            mac_ap = packet.addr1
        elif types == "qos_data": # This can have either AP or station as addr1 & addr2
            mac_cl = packet.addr2
            mac_ap = packet.addr1
        elif types == "cts":
            mac_cl = packet.addr2
            mac_ap = packet.addr1
        elif types == "block_ack_req": # This can have either AP or station as addr1 & addr2
            mac_cl = packet.addr1
            mac_ap = packet.addr2
        elif types == "block_ack": # This can have either AP or station as addr1 & addr2
            mac_cl = packet.addr1
            mac_ap = packet.addr2
        else:
            mac_cl = packet.addr1
            mac_ap = packet.addr2

        return mac_cl, mac_ap

    def packet_analyzer(self, packet, types):
        mac_cl, mac_ap = self.get_macs(packet, types)
        old_mac_ap = mac_ap
        if self.target and mac_cl == self.target:
            mac_ap = mac_cl
            mac_cl = old_mac_ap

        enc = self.determine_encryption(packet)
        ssid = self.get_ssid(packet)
        channel = self.extract_channel(packet)
        signal = get_signal_strength(packet)
        uptime = get_ap_uptime(packet)
        timestamp = datetime.now().strftime('%m-%d %H:%M')

        updated = False
        if (mac_ap == self.target or ssid == self.ssid) and (self.target not in self.results):
            self.debugprint(f"Friendly packet detected!")
            self.target = mac_ap
            self.ssid = ssid
            self.results[self.target] = {"SSID(s)": set(), "CHANNEL(s)": set(), "SIGNAL": signal, "CLIENTS": set(), 
            "KNOWN_TO": set(), "ENC": enc, "FRAMES": 0, "DATA(QoS)": 0, "EAPOLS": 0, "PMKIDs": set(), "Handshakes": set(),
            "MANUFACTURER": check_manufacturer(self.target) if self.target else "Not Yet", "UPTIME": uptime, "LAST SEEN": timestamp}
            updated = True

        if self.target in self.results:
            if not updated and mac_ap == self.target:
                if types == "beacon":
                    self.results[self.target]['UPTIME'] = uptime
                elif types == "qos_data":
                    self.results[self.target]['DATA(QoS)'] += 1 
                elif types == "auth" and types == "eapol":
                    self.results[self.target]['EAPOLS'] += 1
                if packet.haslayer(RadioTap) and packet.haslayer(Dot11Elt):
                    if channel != "N/A":
                        self.results[self.target]['CHANNEL(s)'].add(channel)
                    self.results[self.target]['SIGNAL'] = signal
                    if ssid != "0":
                        self.results[self.target]['SSID(s)'].add(ssid)
                    self.results[self.target]['ENC'] = enc
                self.results[self.target]['FRAMES'] += 1

            if types == "auth" or types == "asso_req" or types == "asso_resp" and ssid == self.ssid:
                if mac_cl not in self.results[self.target]['CLIENTS']:
                    self.results[self.target]['CLIENTS'].add(mac_cl)
                    self.results[self.target]['KNOWN_TO'].add(mac_cl)
                self.clients[mac_cl] = {"SIGNAL": signal,"MANUFACTURER": check_manufacturer(mac_cl), "LAST SEEN": timestamp}

            elif types == "auth" or types == "asso_req" or types == "asso_resp" and ssid != self.ssid:
                self.debugprint(f"Check passed. Not target SSID!", style="red")
                if mac_cl in self.results[self.target]['CLIENTS']:
                    self.results[self.target]['CLIENTS'].remove(mac_cl)
                    del self.clients[mac_cl]
                    self.debugprint(f"I removed the client {mac_cl} from target!", style="red")

            if (types == "rts" or types == "qos_data" or types == "block_ack") and mac_ap == self.target:
                if mac_cl not in self.results[self.target]['CLIENTS']:
                    self.results[self.target]['CLIENTS'].add(mac_cl)
                    self.results[self.target]['KNOWN_TO'].add(mac_cl)
                self.clients[mac_cl] = {"SIGNAL": signal,"MANUFACTURER": check_manufacturer(mac_cl), "LAST SEEN": timestamp}


    def extract_channel(self, packet):
        channel = "N/A"
        if packet.haslayer(RadioTap) and packet.haslayer(Dot11Elt):
            try:
                channel = ord(packet[Dot11Elt:3].info)
            except TypeError:
                pass
            except IndexError:
                pass
            except Exception as e:
                self.debugprint(f"In function extract_channel: {type(e).__name__}: {str(e)}")
        return channel

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

    def run_sniff(self):
        while True:
            try:
                sniff(iface=self.interface, prn=self.packet_handler, store=0, monitor=True)
                time.sleep(1)
            except OSError as e:
                wprint(f"Network error: {e}")

class Audit:
    def __init__(self, interface, mac, ssid, script_dir=None, debug=False):
        self.debug = debug
        self.script_dir = script_dir or "/usr/local/share/3way"
        self.interface = interface
        self.target_mac = mac
        self.ssid = ssid
        self.console = Console()
        self.clients = {}
        self.results = {}
        self.sniffer = Sniffer(interface=self.interface, console=self.console, script_dir=self.script_dir, target=self.target_mac, ssid=self.ssid, results=self.results, clients=self.clients, debug=self.debug)

    def init_monitor_mode(self):
        try:
            for interface in self.interface:
                os.system(f'sudo iwconfig {interface} mode monitor')
        except Exception as e:
            wprint(f"Error while putting interface in monitor mode: {e}")

    def run_audit(self):
        self.init_monitor_mode()
        threading.Thread(target=self.sniffer.run_sniff, daemon=True).start()
        if not self.debug:
            curses.wrapper(setup_curses, self)
        else:
    
            last_print_time = time.time()

            while True:
                cur_time = time.time()
                if cur_time - last_print_time >= 10:
                    self.sniffer.debugprint(f"Results: {self.results}")
                    self.sniffer.debugprint(f"Clients: {self.clients}")
                    
                    last_print_time = cur_time

def setup_curses(stdscr, audit_instance):
    curses.curs_set(0)
    init_colors()
    stdscr.nodelay(1)
    display_results(stdscr, audit_instance)

def safe_addstr(stdscr, y, x, text, attr=None):
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

def display_results(stdscr, audit_instance):
    running = True
    last_refreshed = time.time()
    while running:
        current_time = time.time()
        if current_time - last_refreshed >= 10:
            stdscr.clear()
            stdscr.refresh()
            last_refreshed = current_time

        stdscr.refresh()
        max_y, max_x = stdscr.getmaxyx()
        mid_point_y = max_y // 2
        mid_point_x = max_x // 2

        results_window = curses.newwin(mid_point_y, max_x, 0, 0)
        clients_window = curses.newwin(mid_point_y, max_x, mid_point_y, 0)

        results_window.border()
        clients_window.border()

        safe_addstr(results_window, 0, 2, " Network Results ", curses.color_pair(2) | curses.A_BOLD)
        safe_addstr(results_window, 2, 30, "Press 'q' or 's' to stop audit", curses.color_pair(3) | curses.A_BOLD)

        safe_addstr(clients_window, 0, 2, " Client Details ", curses.color_pair(1) | curses.A_BOLD)

        display_data(results_window, audit_instance.results, mid_point_y)
        display_data(clients_window, audit_instance.clients, mid_point_y, True)

        stdscr.refresh()
        results_window.refresh()
        clients_window.refresh()

        if stdscr.getch() in [ord('q'), ord('s')]:
            safe_addstr(results_window, 2, 30, " " * (max_x - 30))
            safe_addstr(results_window, 2, 30, " Press anything to quit ", curses.color_pair(3) | curses.A_BOLD)
            results_window.refresh()
            running = False

    stdscr.nodelay(False)
    stdscr.getch()

def display_data(window, data, max_lines, is_client=False):
    y = 2
    x_offset = 1
    
    column_width = max(40, window.getmaxyx()[1] // 3)
    max_possible_columns = window.getmaxyx()[1] // column_width
    columns = min(max_possible_columns, len(data)) if max_possible_columns > 0 else 1

    for index, (mac, details) in enumerate(data.items()):
        current_col = index % columns
        x_position = x_offset + (current_col * column_width)

        if current_col == 0 and index != 0:
            y += 1
        
        if y + 5 >= max_lines: 
            safe_addstr(window, max_lines - 1, 3, "+ more...", curses.A_BOLD)
            break

        safe_addstr(window, y, x_position, f"MAC: {mac}", curses.A_BOLD)
        detail_y = y + 1
        for key, value in details.items():
            if detail_y >= max_lines - 1:
                safe_addstr(window, max_lines - 1, 3, "+ more...", curses.A_BOLD)
                return

            if key in ['CLIENTS', 'KNOWN_TO']:
                value_str = str(len(value))
            elif key == "MANUFACTURER":
                value_str = value if len(value) <= 26 else value[:23] + '...'
            else:
                value_str = ', '.join(str(v) for v in value) if isinstance(value, set) else str(value)
            
            safe_addstr(window, detail_y, x_position + 2, f"{key}: {value_str}")
            detail_y += 1

        if current_col == columns - 1:
            y = detail_y

def main():
    audit_instance = Audit(interface=["wlan0"], mac="a4:2b:4c:23:ad:e6", ssid="Test", debug=False)
    audit_instance.init_monitor_mode()
    threading.Thread(target=audit_instance.sniffer.run_sniff, daemon=True).start()
    curses.wrapper(setup_curses, audit_instance)

if __name__ == "__main__":
    main()
