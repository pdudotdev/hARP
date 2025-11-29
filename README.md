![hARP](docs/hARP.png)
# 🕵️ hARP: Covert Communication via ARP Cache 🕵️‍♂️

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
[![Stable Release](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/pdudotdev/hARP/releases/tag/v0.1.0)
[![Last Commit](https://img.shields.io/github/last-commit/pdudotdev/hARP)](https://github.com/pdudotdev/hARP/commits/main/)

**hARP** is a covert communication tool that enables two hosts on the same network to exchange messages by manipulating their ARP caches. By embedding messages into static ARP entries, **hARP** allows for discreet data exchange without raising suspicions from standard network monitoring tools.

🍀 **NOTE:** This is an ongoing **research project** for educational purposes rather than a full-fledged production-ready tool, so treat it accordingly.

## 📋 Table of Contents

- [🕵️ hARP: Covert Communication via ARP Cache](#%EF%B8%8F-harp-covert-communication-via-arp-cache-%EF%B8%8F%EF%B8%8F)
  - [🎯 Advantages](#-advantages)
  - [🖥️ System Requirements](#%EF%B8%8F-system-requirements)
  - [⚙️ Installation and Setup](#%EF%B8%8F-installation-and-setup)
  - [🔠 Character Mapping](#-character-mapping)
  - [🛠️ How It Works - Steps and Example](#%EF%B8%8F-how-it-works---steps-and-example)
  - [⛑️ Security Considerations](#%EF%B8%8F-security-considerations)
  - [🎯 Planned Upgrades](#-planned-upgrades)
  - [⚠️ Disclaimer](#%EF%B8%8F%EF%B8%8F-disclaimer)
  - [📜 License](#-license)
  - [🙏 Special Thank You](#-special-thank-you)

## 🎯 Advantages

- **Stealthy Communication**: **hARP** leverages ARP cache entries to hide messages, making it difficult for traditional network security tools to detect the communication.
- **Minimal Network Footprint**: By using ARP cache manipulation and minimal ICMP pings, **hARP** avoids generating significant network traffic.
- **No Additional Network Services Required**: Operates without the need for extra network services or open ports, reducing exposure to network scans.
- **Customizable and Extensible**: Users can extend the character mapping to support additional characters or symbols as needed.

## 🖥️ System Requirements

- **Operating System**: Linux-based systems (tested on Kali Linux)
- **Python**: Python 3.8 or higher
- **Python Packages**:
  - `scapy`
  - `paramiko`
- **Network Configuration**:
  - Both hosts must be on the same subnet.
  - SSH server running on both hosts.
  - Mutual SSH access with appropriate credentials.
- **Privileges**:
  - Administrative (sudo) privileges to modify ARP cache entries and clear logs.

## ⚙️ Installation and Setup

### 1. Prepare the Environment
**hARP** consists of two main components: the **Initiator** and the **Responder** - Kali Linux hosts, physical or VMs. The configuration below should be applied to **both machines**.

```bash
mkdir hARP
cd hARP
python3 -m venv .harp
source .harp/bin/activate
git clone https://github.com/pdudotdev/hARP.git
```

### 2. Install Required Python Packages

```bash
pip install paramiko scapy colorama
```

### 3. Configure SSH Access
```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl start ssh
sudo systemctl enable ssh
sudo systemctl status ssh
```

### 4. Allow SSH Through Firewall
If any of the two hosts has a firewall running, it should either be disabled (not recommended) or configured to allow incoming SSH connections on port 22. Example for **ufw**:
```bash
sudo ufw allow ssh
```

🍀 **NOTE:** Default SSH username is the host's username, default SSH password is the host's password.

### 5. Update Character Mapping (Optional)
The **char_to_mac.json** file in the repo contains the character-to-hex mappings.
Modify or extend the mappings if you need to support additional characters.
The two machines should always have the same **char_to_mac.json** file.

## 🔠 Character Mapping

This example demonstrates the exact character-to-hexadecimal mapping and ARP table entries created for the message `"python is the best!"`. We’ll walk through how each character is encoded into MAC addresses, added to the ARP table, and decoded by the receiving party.

### Message: `"python is the best!"`

Each character is mapped to a hexadecimal code using a predefined mapping, allowing us to convert the message into MAC address segments.

#### Character Mapping for `"python is the best!"`

| Character | Hex Code |
|-----------|----------|
| `p`       | `19`     |
| `y`       | `22`     |
| `t`       | `1D`     |
| `h`       | `11`     |
| `o`       | `18`     |
| `n`       | `17`     |
| (space)   | `2E`     |
| `i`       | `12`     |
| `s`       | `1C`     |
| (space)   | `2E`     |
| `t`       | `1D`     |
| `h`       | `11`     |
| `e`       | `0E`     |
| (space)   | `2E`     |
| `b`       | `0B`     |
| `e`       | `0E`     |
| `s`       | `1C`     |
| `t`       | `1D`     |
| `!`       | `34`     |

### Building MAC Addresses

Each MAC address holds 6 bytes (12 hex characters). Here’s how the message "python is the best!" is split and padded into MAC addresses:

1. **Convert Characters to Hex**:
   - "python is the best!" → `19 22 1D 11 18 17 2E 12 1C 2E 1D 11 0E 2E 0B 0E 1C 1D 34`

2. **Construct MAC Addresses**:
   - MAC Address 1: `19:22:1D:11:18:17` (for `"python"`)
   - MAC Address 2: `2E:12:1C:2E:1D:11` (for `" is th"`)
   - MAC Address 3: `0E:2E:0B:0E:1C:1D` (for `"e best"`)
   - MAC Address 4: `34:00:00:00:00:00` (for `!` and padded with `00` bytes)

### ARP Table Entries

Each of these MAC addresses is paired with an IP address in the Initiator's ARP cache:

| IP Address      | MAC Address           | Message Segment |
|-----------------|-----------------------|-----------------|
| `192.168.56.201` | `19:22:1D:11:18:17`   | `"python"`      |
| `192.168.56.202` | `2E:12:1C:2E:1D:11`   | `" is th"`      |
| `192.168.56.203` | `0E:2E:0B:0E:1C:1D`   | `"e best"`      |
| `192.168.56.204` | `34:00:00:00:00:00`   | `"!"` (end)     |

### Retrieving and Decoding the Message

1. **Signal and Retrieval**:
   - The Initiator signals the Responder via ICMP that the message is ready to be extracted.
   - The Responder SSHes into the Initiator’s ARP cache and retrieves entries matching the specific IP range (`192.168.56.201` to `192.168.56.204`).

2. **Decoding MAC Addresses**:
   - The Responder collects the MAC addresses in the order of the IP addresses.
   - Each MAC address is split back into its original hex pairs and decoded according to the character mapping:
     - `19:22:1D:11:18:17` → `"python"`
     - `2E:12:1C:2E:1D:11` → `" is th"`
     - `0E:2E:0B:0E:1C:1D` → `"e best"`
     - `34:00:00:00:00:00` → `"!"` (end)

3. **Reassemble the Message**:
   - The decoded segments are combined to reconstruct the original message: `"python is the best!"`.

### Summary

- The Initiator encoded the message `"python is the best!"` as four MAC addresses, stored in the ARP cache.
- The Responder retrieves these entries, decodes them, and reassembles the complete message, successfully receiving the transmission without direct network packets being sent with the message data.

This example illustrates the complete process of encoding, transmitting, and decoding a simple message using hARP.

## 🛠️ How It Works - Steps and Example

Prior to initiating the scripts, the Initiator user and the Responder user should **securely share** their IP addresses and SSH credentials, as well as who's going to run the Initiator and Responder respectively. Once this initial exchange is done, they will be able to run hARP whenever they need without any prerequisites.

Let's assume we have two Linux hosts:
- **Responder**: `192.168.56.124`
- **Initiator**: `192.168.56.125`
- **SSH credentials**: `kali`:`kali`
- **Agreed IP range for fake ARP entries**: `192.168.56.201-.210`

### 1. Start the Responder
On the **Responder** host:

```bash
cd ~/hARP
sudo .harp/bin/python hARP/harp/responder.py
```

- Input Prompts:
  - Enter the Initiator's IP address.
  - Enter the SSH username and password.
- The Responder will wait for a ping from the Initiator.

![1-1](docs/1-1.png)

### 2. Start the Initiator
On the **Initiator** host:

```bash
cd ~/hARP
sudo .harp/bin/python hARP/harp/initiator.py
```

- Input Prompts:
  - Enter the Responder's IP address.
  - Enter the SSH username and password.
  - Enter the secret message (up to 60 characters).

![2-1](docs/2-1.png)

- The Initiator will embed the message in its own ARP cache entries. Notice the .201-.204 entries.

![2-2](docs/2-2.png)

- The Initiator sends a ping to the Responder to signal that the message is ready to be extracted.

![2-3](docs/2-3.png)

### 3. Message Exchange
- Responder:
  - Receives the ping from the Initiator.

![3-1](docs/3-1.png)

  - Connects via SSH to the Initiator and reads the MAC addresses its ARP cache.

![3-2](docs/3-2.png)

  - Displays the message to the user.

![3-3](docs/3-3.png)

  - Asks for input - a reply message.

![3-4](docs/3-4.png)

  - Embeds the reply as fake MAC addresses in its own ARP cache.

![3-5](docs/3-5.png)

  - Sends a ping back to the Initiator to signal that the reply is ready to be extracted.

![3-6](docs/3-6.png)

- Initiator:
  - Receives the ping and reads the reply message from the Responder's ARP cache, via SSH.

![3-7](docs/3-7.png)

  - Displays the reply message to the user.

![3-8](docs/3-8.png)

  - Sends a confirmation ping to the Responder.

![3-9](docs/3-9.png)

### 4. Cleanup
- Upon sending/receiving the confirmation ping, both hosts:
  - Remove the static ARP entries created during the session.

![4-1](docs/4-1.png)
![4-2](docs/4-2.png)

  - Finally, they both clear the terminal screen.

## ⛑️ Security Considerations
- **Administrative Privileges**: **hARP** requires sudo privileges, so ensure that only trusted users have access to the scripts.
- **Network Impact**: Manipulating ARP tables can have unintended consequences on network operations. Use **hARP** in controlled environments.
- **SSH Credentials**: Be cautious with SSH passwords. Always share sensitive data through a separate secure channel.
- **Log Clearing**: Clearing logs may violate organizational policies. Ensure compliance before using **hARP**.

## 🎯 Planned Upgrades
- [x] Improved CLI experience
- [ ] Increased message length
- [ ] More testing is needed

## ️⚠️ Disclaimer
**hARP** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **hARP** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
**hARP** is licensed under the [GNU GENERAL PUBLIC LICENSE Version 3](https://github.com/pdudotdev/hARP/blob/main/LICENSE).

## 🙏 Special Thank You
The idea behind creating **hARP** was inspired by the concept of **Network Dead Drops** pioneered by Tobias Schmidbauer, Steffen Wendzel, Aleksandra Mileva and Wojciech Mazurczyk in **Introducing Dead Drops to Network Steganography using ARP-Caches and SNMP-Walks** (more details [here](https://dl.acm.org/doi/10.1145/3339252.3341488)).

Main differences between the original approach and **hARP**:
- **hARP** introduces a new flavor of **Network Dead Drops**, named **Active Self-Hosted Network Dead Drops**.
- **Active** because there is an active connection established. **Self-Hosted** because the encoder stores the hidden message.
- Unlike the original **Network Dead Drops** concept, **hARP** does not use an unaware 3rd party to store hidden messages.
- Unlike the original **Network Dead Drops** concept, **hARP** uses *static* ARP entries that each host generates itself.
- Unlike the original **Network Dead Drops** concept, **hARP** uses ARP for storage and SSH for retrieval, instead of SNMP.
- **hARP** does not involve a 3rd party for the dead drop which may raise suspicions or be illegal. Also reduces complexity.
- Other differences in nuances of the overall logic and communication flow, as well as of the actual code implementation.