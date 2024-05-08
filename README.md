<div align="center">
  <img src="https://github.com/FLOCK4H/Freeway/assets/161654571/85eb939d-0154-4767-8aab-c3a5e29b1d6f" alt="Freeway logo" />

  <h6>Freeway for network pentesting</h6>
</div>

> [!NOTE]
> Before using the software user must agree to the EULA when prompted


<h2><strong>Overview<sup>1</sup></strong></h2>
Python's scapy based tool for WiFi penetration loaded with rich number of features that aims to help ethical hackers and pentesters in developing their skills and knowledge in auditing and securing home or enterprise networks.

<strong><h2>Features<sup>2</sup></h2>

- IEEE 802.11 Packet monitor
- Deauthentication attack
- Beacon Flood
- Packet Fuzzer
- Network Audit
- Channel Hopper
</strong>

<h6>Description of the features can be found below</h6>

<strong><h2>Preparation<sup>3</sup></h2></strong>
It's **necessary** to have:
  - Network Adapter supporting monitor mode and frame injection
  - Operating system running Linux distribution
  - Python 3+ installed

<h5>Optionally Scapy and Rich packages for Python if not installing via pip (see section 4)</h5>

<strong><h2>Setup<sup>4</sup></h2></strong>

Clone the repository first:

    git clone https://github.com/FLOCK4H/Freeway

Navigate to the cloned repository:

    cd Freeway

<strong>A:</strong> Install dependencies and Freeway
<h6>This will allow to launch the tool from anywhere</h6>

    sudo pip install .

<strong>B:</strong> Run without installation using Python
<h6>Must be called from /Freeway directory</h6>

    sudo python Freeway

<strong><h2>Usage<sup>5</sup></h2></strong>

This tool comes with it's own user-friendly **command line interface (CLI)**, and can be run without specifying any additional parameters:

`sudo Freeway`












