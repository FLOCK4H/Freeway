<div align="center">
  <img src="https://github.com/FLOCK4H/Freeway/assets/161654571/85eb939d-0154-4767-8aab-c3a5e29b1d6f" alt="Freeway logo" />

  <h6>Freeway for Network Penetration</h6>
</div>

> [!NOTE]
> Before using the software, the user must agree to the EULA when prompted.

<h2><strong>1. Overview</strong></h2>
Freeway is a Python scapy-based tool for WiFi penetration that aim to help ethical hackers and pentesters develop their skills and knowledge in auditing and securing home or enterprise networks.

<h2><strong>2. Features</strong></h2>

- IEEE 802.11 Packet Monitoring
- Deauthentication Attack
- Beacon Flood
- Packet Fuzzer
- Network Audit
- Channel Hopper

<h6>Description of the features can be found in Section 6.</h6>

<h2><strong>3. Preparation</strong></h2>

It is **necessary** to have:
- A network adapter supporting monitor mode and frame injection.
- An operating system running a Linux distribution.
- Python 3+ installed.

<h6>Optionally, install Scapy and Rich packages for Python if not installing via pip (see Section 4).</h6>

<h2><strong>4. Setup</strong></h2>

First, clone the repository:

    git clone https://github.com/FLOCK4H/Freeway

Navigate to the cloned repository:

    cd Freeway

<strong>A:</strong> Install dependencies and Freeway.

<h6>This will allow launching the tool from anywhere.</h6>

    sudo pip install .

<strong>B:</strong> Run without installation using Python.

<h6>Must be called from the /Freeway directory.</h6>

    sudo pip install scapy rich
    sudo python Freeway

<h2><strong>5. Usage</strong></h2>

This tool comes with its own **command line interface (CLI)** and can be run without specifying any additional arguments.

<details>
<summary>Click to expand</summary>
<br />

    sudo Freeway

Follow the prompt to select the network adapter (see Section 3):

![image](https://github.com/FLOCK4H/Freeway/assets/161654571/653c9304-3256-4444-8f3f-0677134c8af8)

Select the feature and parameter(s):

![image](https://github.com/FLOCK4H/Freeway/assets/161654571/2444922e-6f1b-4958-99ea-df7463b912cb)
![image](https://github.com/FLOCK4H/Freeway/assets/161654571/757b5d77-be12-4dda-a957-3c305789bba7)

</details>

...and it can also be run with them:

<details>
<summary>Click to expand</summary>
<br />

    sudo Freeway -i wlan2 -a monitor -p 1,2,a

<h6>'-p' is not required with '-a', e.g., this will prompt for parameters to specify in the CLI:</h6>

    sudo Freeway -i wlan2 -a deauth

**All arguments, actions, and parameters:**

<div>
<pre>
  Arguments:
  -h, --help     Show the help message. <br />
  -i, --inf      Specify the WLAN interface (e.g., wlan0, wlan1). <br />
  -a, --action   Action number or alias (e.g., 1 or monitor). <br />
  -p, --params   Parameter identifiers (e.g., 1,2,a or 3rtv, depends on action). <br />

  Actions:
  1 or monitor,
  2 or deauth,
  3 or beacon_spam,
  4 or fuzzer,
  5 or audit,
  6 or hopper

  Parameters must be provided in the same format as in the CLI, specific for every action.
  To list all parameters for a given action, just provide -a argument without -p.
</pre>
</div>
</details>

<h2><strong>6. Details</strong></h2>

- **Packet Monitor** - Sniffs the WiFi packets in the air, analyze them and return the result onto the python's curses display. Catches SSIDs, MACs, Clients, Uptime, Channel, Signal (dBm), Encryption and resolves manufacturer. Catches PMKIDs in hashcat crackable format, and 4-way Handshakes, as well as other EAPOL packets. Logs the captured session to the **/caps** folder or every captured packet if _Save output_ was selected.
- **Deauthentication Attack (Deauthing)** - Disconnects a device from the network by sending a packet containing AP<sup>1<sup> address, device address (or broadcast for _Mass Deauthing_) and the deauthentication frame with a reason of kicking the client(s). In case where a device address is a broadcast address, the AP will in most cases disconnect all clients at once. Freeway creates separate thread for every AP or client found in order to make deauthing maximally efficient.
- **Beacon Flood Attack** - Floods the nearby WiFi scanners with fake or malformed APs 
