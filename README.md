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
  - [🛠️ How It Works](#%EF%B8%8F-how-it-works)
  - [🖥️ System Requirements](#%EF%B8%8F-system-requirements)
  - [⚙️ Installation and Setup](#%EF%B8%8F-installation-and-setup)
  - [📝 Usage](#-usage)
  - [⛑️ Security Considerations](#%EF%B8%8F-security-considerations)
  - [🎯 Planned Upgrades](#-planned-upgrades)
  - [⚠️ Disclaimer](#%EF%B8%8F%EF%B8%8F-disclaimer)
  - [📜 License](#-license)
  - [🙏 Special Thank You](#-special-thank-you)
  - [📧 Contact](#-professional-collaborations)

## 🎯 Advantages

- **Stealthy Communication**: **hARP** leverages ARP cache entries to hide messages, making it difficult for traditional network security tools to detect the communication.
- **Minimal Network Footprint**: By using ARP cache manipulation and minimal ICMP pings, **hARP** avoids generating significant network traffic.
- **No Additional Network Services Required**: Operates without the need for extra network services or open ports, reducing exposure to network scans.
- **Customizable and Extensible**: Users can extend the character mapping to support additional characters or symbols as needed.

## 🛠️ How It Works

**hARP** consists of two main components: the **Initiator** and the **Responder**. The communication flow between them involves the following steps:

1. **Initialization**:
   - The Initiator and Responder agree on a range of IP addresses within their shared subnet to use for ARP cache manipulation.
   - Both hosts ensure that they have SSH access to each other for reading ARP caches remotely.

2. **Message Encoding**:
   - **Initiator**:
     - The user inputs a message for the Responder to read.
     - The message is converted into a series of MAC addresses using a predefined character-to-hex mapping.
     - More specifically, each character is mapped to a MAC address octet as per **char_to_mac.json**.
     - Static ARP entries are created on the Initiator's host, associating each MAC address with a unique IP address within the agreed range.
   - **Responder**:
     - Waits for a signal (ping) from the Initiator.

3. **Communication Trigger**:
   - The Initiator sends an ICMP ping to the Responder, signaling that the message is ready to be read.

4. **Message Retrieval**:
   - **Responder**:
     - Upon receiving the ping, the Responder SSHes into the Initiator's host to read the ARP cache entries.
     - Extracts the MAC addresses associated with the agreed IP range and orders them by last IP octet.
     - Decodes the MAC addresses back into the original message using the reverse character mapping.
     - Displays the message to the user.

5. **Replying**:
   - **Responder**:
     - The Responder user can input a reply message following the same encoding process.
     - Static ARP entries are created on the Responder's host.
     - Sends an ICMP ping back to the Initiator to signal that the reply is ready.
   - **Initiator**:
     - Upon receiving the ping, the Initiator SSHes into the Responder's host to read the ARP cache and retrieve the reply message.

6. **Confirmation and Cleanup**:
   - Both the Initiator and Responder send confirmation pings after reading messages.
   - Upon receiving the confirmation, both hosts perform cleanup:
     - Remove the static ARP entries created in the ARP cache.
     - Clear SSH logs to minimize traces of the communication.
     - Clear the terminal screen.

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

### 1. Clone the Repository

```bash
git clone https://github.com/pdudotdev/hARP.git
cd hARP/harp
```

### 2. Install Required Python Packages

```bash
sudo apt install python3-scapy
sudo apt install python3-paramiko
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

🍀 **NOTE:** Default SSH username is host username, default SSH password is host password.

### 4. Update Character Mapping (Optional)
The **char_to_mac.json** file contains the character-to-hex mappings.
Modify or extend the mappings if you need to support additional characters.

## 📝 Usage
### 1. Start the Responder
Prior to initiating the scripts, the Initiator user and the Responder user should **securely share** their IP addresses and SSH username/password, as well as who's going to run the Initiator and Responder respectively. Once this initial exchange is done, they will be able to run hARP whenever they need without any prerequisites.

On the **Responder** host:

```bash
sudo python3 responder.py
```

- Input Prompts:
  - Enter the Initiator's IP address.
  - Enter the SSH username and password.
- The Responder will wait for a ping from the Initiator.

### 2. Start the Initiator
On the **Initiator** host:

```bash
sudo python3 initiator.py
```

- Input Prompts:
  - Enter the Responder's IP address.
  - Enter the SSH username and password.
  - Enter your message (up to 60 characters).
- The Initiator will embed the message in its own ARP cache entries and send a ping to the Responder.

### 3. Message Exchange
- Responder:
  - Receives the ping and reads the message from the Initiator's ARP cache.
  - Displays the message to the user.
  - Inputs a reply message.
  - Embeds the reply in its own ARP cache entries and sends a ping back to the Initiator.

- Initiator:
  - Receives the ping and reads the reply message from the Responder's ARP cache.
  - Displays the reply message to the user.
  - Sends a confirmation ping to the Responder.

### 4. Cleanup
- Upon receiving the confirmation ping, both hosts:
  - Remove the static ARP entries created during the session.
  - Clear SSH logs.
  - Clear the terminal screen.

## ⛑️ Security Considerations
- **Administrative Privileges**: **hARP** requires sudo privileges, so ensure that only trusted users have access to the scripts.
- **Network Impact**: Manipulating ARP tables can have unintended consequences on network operations. Use **hARP** in controlled environments.
- **SSH Credentials**: Be cautious with SSH passwords. Always share sensitive data through a separate secure channel.
- **Log Clearing**: Clearing logs may violate organizational policies. Ensure compliance before using **hARP**.

## 🎯 Planned Upgrades
- [x] Improved CLI experience
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
