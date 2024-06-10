<div align="center">
  <img src="https://github.com/FLOCK4H/Freeway/assets/161654571/85eb939d-0154-4767-8aab-c3a5e29b1d6f" alt="Freeway logo" />

  $${\color{red}Freeway\ for\ Network\ Pentesting}$$
</div>

<div align="center">


<strong>Read the article about Freeway, now on</strong>
<a href="https://medium.com/@flytechoriginal/freeway-for-network-pentesting-e97e69e481fc">Medium</a>
</div>
<br />

> [!NOTE]
> Before using the software, the user must agree to the EULA when prompted

<h2><strong>1. Overview</strong></h2>

**Freeway** is a Python scapy-based tool for WiFi penetration that aim to help ethical hackers and pentesters develop their skills and knowledge in auditing and securing home or enterprise networks.

<h2><strong>2. Features</strong></h2>

- IEEE 802.11 Packet Monitoring
- Deauthentication Attack
- Beacon Flood
- Packet Fuzzer
- Network Audit
- Channel Hopper
- Evil Twin

<sub>Description of the features can be found in Section 6</sub>

<h2><strong>3. Preparation</strong></h2>

It is **necessary** to have:
- A network adapter supporting monitor mode and frame injection.
- An operating system running a Linux distribution.
- Python 3+ installed.

<sub>Optionally, install Scapy and Rich packages for Python if not installing via pip (see Section 4)</sub>

<h2><strong>4. Setup</strong></h2>

**Option A**: Install via PyPi (**RECOMMENDED**)

```
  $ sudo pip install 3way
```

**Option B**: Install or run manually

First, clone the repository:

    git clone https://github.com/FLOCK4H/Freeway

Navigate to the cloned repository:

    cd Freeway

<strong>Option 1:</strong> Install dependencies, folders, and Freeway. (RECOMMENDED)

<sub>This will allow to launch the tool from anywhere</sub>

    sudo pip install .

<strong>Option 2:</strong> Run without installation using Python.

<sub>Must be called from the /Freeway directory</sub>

    sudo pip install scapy rich
    sudo python Freeway

<h2><strong>5. Usage</strong></h2>

This tool comes with its own **command line interface (CLI)** and can be run without specifying any additional arguments.

<details>
<summary><strong>Click to expand the CLI usage</strong></summary>
<br />

    sudo Freeway

Follow the prompt to select the network adapter (see Section 3):

![image](https://github.com/FLOCK4H/Freeway/assets/161654571/653c9304-3256-4444-8f3f-0677134c8af8)

Select the feature and parameter(s):

![image](https://github.com/FLOCK4H/Freeway/assets/161654571/2444922e-6f1b-4958-99ea-df7463b912cb)
![image](https://github.com/FLOCK4H/Freeway/assets/161654571/757b5d77-be12-4dda-a957-3c305789bba7)

</details>
<br />

And with the **additional arguments**, to skip the CLI partially or completely.

<details>
<summary><strong>Click to expand the arguments usage</strong></summary>
<br />

    sudo Freeway -i wlan2 -a monitor -p 1,2,a

<sub>'-p' is not required with '-a', e.g., this will prompt for parameters to specify in the CLI:</sub>

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
  6 or hopper,
  7 or eviltwin

  Parameters must be provided in the same format as in the CLI, specific for every action.
  To list all parameters for a given action, just provide -a argument without -p.
</pre>
</div>
</details>

<h2><strong>6. Details</strong></h2>

- **Packet Monitor** - Sniffs the WiFi packets in the air, analyze them and return the result onto the python's curses display. Catches SSIDs, MACs, Clients, Uptime, Channel, Signal (dBm), Encryption and resolves manufacturer. Catches PMKIDs in hashcat crackable format, and 4-way Handshakes, as well as other EAPOL packets. Logs the captured session to the **/caps** folder or every captured packet if _Save output_ was selected.
- **Deauthentication Attack (Deauthing)** - Disconnects a device from the network by sending a packet containing AP<sup>1</sup> address, device address (or broadcast for _Mass Deauthing_) and the deauthentication frame with a reason of kicking the client(s). In case where a device address is a broadcast address, the AP will in most cases disconnect all clients at once. Freeway creates separate thread for every AP or client found in order to make deauthing maximally efficient.
- **Beacon Flood Attack** - Floods the nearby WiFi scanners with fake or malformed APs. It can cause the devices looking for WiFi to behave abnormally (e.g. crash, freeze, drain the battery or run slower) and disrupt the nearby network traffic. User is able to specify his own ssid list, use the default one and generate correct (but random) or malformed beacon packets.
- **Packet Fuzzer** - Fuzzing is a technique of network vulnerability assesment by sending a wide array of malformed or semi-random data to network interfaces and observing the responses. Freeway covers: **Replay captured packets (RX&TX<sup>2</sup>)**, **Spam CTS/RTS or Probe requests** and **Flood an AP with Authentication or Association Frames**. Devices that will capture fuzzed packets will behave differently depending on vulnerability level of receiver (!USE WITH CAUTION!).
- **Network Audit** - Gathers all possible information about specific network and returns them onto the curses view. Tracks all clients signal and last activity, as well as resolve the manufacturer.
- **Channel Hopper** - Changes the current channel of the network adapter. Helpful in making specific attacks more successful.
- **Evil Twin** - Hosts a legitimate Access Point with Captive Portal, this 'legitimate' AP asks user for login/ bank credentials, or to download malware. First, there's a normal AP created, most times with an ESSID and MAC of existing network. Then, we host our captive portal (e.g., login website), so a normal web server, that reroutes users to our `index.html` trying to associate with the network we spoof.

<sup>1<sup>**Access Points**</sup></sup>

<sup>2<sup>**Transceive and receive at the same time**</sup></sup>

<h2><strong>7. Uninstall</strong></h2>

In case where Freeway doesn't meet the expectations and was installed via pip, the removal process is as easy:

    sudo pip uninstall 3way

<sub>The rename to 3way is done on purpose to 'reserve' the name for the future official pip release as Freeway is taken.</sub>

<h2>TODO</h2>

✅ Evil Twin attack

✅ Version & update checker

✅ PyPi Release

<h2>Changelog</h2>

> 19.05
> 1. Fixed rare RuntimeError in deauth.py caused by iterating on dynamicly changing size dictionary
> 2. Further improvements of beacon packet formatting in beacon_spam.py

> 27.05
> 1. Added `updater.py`
> 2. Added `evil_twin.py`
> 3. Added `/templates` folder
> 4. Added Evil Twin to actions list
> 5. Updated README.md
> 6. PyPi Release

> 3.05
> 1. Added `git_downloader.py`
> 2. Updated `beacon_spam`
> 3. Updated `evil_twin`

<h2>Known Issues</h2>

> 1. Android filters out fake beacon frames (works for Android 5, doesn't on Android 11+, versions below Android 11  and above Android 5 were not tested.)
> 2. EvilTwin needs a second adapter connected to the internet (Not really an issue), to be able to reroute traffic 

<h2><strong>Legal Note</strong></h2>

> [!IMPORTANT]
> Any malicious use of such features should be considered a crime, <br />
> always assert permission to perform the penetration testing.

<h2><strong>License</strong></h2>

The distribution of Freeway is regulated by the standard MIT license, users can feel free to use, share and contribute to the repository or report bugs.
