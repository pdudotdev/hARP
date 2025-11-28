import os
import json
import time
import paramiko
import threading
import subprocess
from colorama import Fore, Style
from scapy.all import sniff, ICMP, IP

# Constants
ARP_START = 201
ARP_END = 210
MAX_MESSAGE_LENGTH = 60
MAC_ADDRESS_FORMAT = "{}:{}:{}:{}:{}:{}"
LISTEN_IFACE = "eth1"  # Host-only adapter if VMs

# Load character to MAC mapping
def load_mapping():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "char_to_mac.json")
    with open(json_path, "r") as file:
        return json.load(file)

# Determine subnet based on Responder's IP
def determine_subnet(responder_ip):
    octets = responder_ip.strip().split('.')
    if len(octets) != 4:
        raise ValueError(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid IP address format.")
    return '.'.join(octets[:3]) + '.'

# Validate and get user message
def get_user_message(mapping):
    allowed_chars = set(mapping.keys())
    while True:
        message = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + f"Enter a message (up to {MAX_MESSAGE_LENGTH} characters): ").lower()
        if len(message) > MAX_MESSAGE_LENGTH:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Message too long. Truncated to {MAX_MESSAGE_LENGTH} characters.")
            message = message[:MAX_MESSAGE_LENGTH]
        if all(char in allowed_chars for char in message):
            return message
        else:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Message contains invalid characters. Allowed characters are:")
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + ", ".join(sorted(allowed_chars)))

# Convert message to MAC addresses
def convert_message_to_mac(message, mapping):
    encoded = ''.join([mapping[char] for char in message])
    # Each MAC address requires 12 hex characters (6 octets)
    mac_addresses = []
    for i in range(0, len(encoded), 12):
        chunk = encoded[i:i+12]
        if len(chunk) < 12:
            chunk = chunk.ljust(12, '0')  # Pad with '0's
        mac = MAC_ADDRESS_FORMAT.format(*[chunk[j:j+2] for j in range(0, 12, 2)])
        mac_addresses.append(mac)
    return mac_addresses

# Add static ARP entries
def add_arp_entries(mac_addresses, subnet):
    for idx, mac in enumerate(mac_addresses, start=ARP_START):
        ip = f"{subnet}{idx}"
        command = f"sudo arp -s {ip} {mac}"
        os.system(command)
        # Suppress output as per your request

# Send ping to Responder
def send_ping(responder_ip):
    # Suppress ping output by redirecting stdout and stderr
    subprocess.run(["ping", "-c", "1", responder_ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Listen for incoming pings from Responder
def listen_for_ping(responder_ip, callback):
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[IP].src == responder_ip:
                callback()
    sniff(filter="icmp", prn=packet_callback, store=0, timeout=300, iface=LISTEN_IFACE)

# SSH into Responder to read its ARP cache
def read_responder_message(responder_ip, ssh_username, ssh_password, mapping, subnet):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(responder_ip, username=ssh_username, password=ssh_password)
        stdin, stdout, stderr = ssh.exec_command("arp -an")
        arp_output = stdout.read().decode()
        ssh.close()
        
        if not arp_output.strip():
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "No ARP entries found.")
            return
        
        arp_entries = []
        for line in arp_output.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip_part = parts[1]  # Should be (IP)
                ip_address = ip_part.strip('()')
                if ip_address.startswith(subnet):
                    last_octet = int(ip_address.split('.')[-1])
                    if ARP_START <= last_octet <= ARP_END:
                        mac = parts[3].replace(':', '').upper()
                        arp_entries.append((ip_address, mac))
        
        if not arp_entries:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "No ARP entries found for the specified subnet.")
            return

        # Sort arp_entries based on the last octet of the IP address
        arp_entries.sort(key=lambda x: int(x[0].split('.')[-1]))

        # Decode MAC addresses to message
        decoded = ""
        reverse_mapping = {v: k for k, v in mapping.items()}
        for _, mac in arp_entries:
            for i in range(0, len(mac), 2):
                pair = mac[i:i+2]
                if pair in reverse_mapping:
                    decoded += reverse_mapping[pair]
                else:
                    # Ignore unknown pairs or padding
                    pass
        print(Style.BRIGHT + Fore.GREEN + "\n[MESSAGE RECEIVED] " + Style.RESET_ALL + f"Message from Responder: {decoded}\n")
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Error reading Responder's message: {e}")

# Cleanup function
def cleanup(subnet):
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Performing cleanup...")
    # Clear ARP cache entries within the subnet and ARP_START to ARP_END
    for idx in range(ARP_START, ARP_END + 1):
        ip = f"{subnet}{idx}"
        command = ["sudo", "arp", "-d", ip]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "ARP cache entries cleared.")
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Clearing screen immediately.")
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Cleanup completed.")
    time.sleep(3)
    os.system('clear')

# Main function for Initiator
def main():
    mapping = load_mapping()
    
    # Step 1: Get Responder's IP
    responder_ip = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the Responder's IP address: ")
    try:
        subnet = determine_subnet(responder_ip)
    except ValueError as ve:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + ve)
        return

    # Get SSH credentials at the beginning
    ssh_username = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the SSH username for the Responder: ")
    ssh_password = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the SSH password for the Responder: ")
    
    # Step 2: Get user message
    message = get_user_message(mapping)
    
    # Step 3: Convert message to MAC addresses
    mac_addresses = convert_message_to_mac(message, mapping)
    
    # Step 4: Add ARP entries
    add_arp_entries(mac_addresses, subnet)
    
    # Step 5: Ask user to send ping
    send_ping_confirm = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Message embedded in ARP cache. Send ping to Responder? (y/n): ").lower()
    if send_ping_confirm == 'y':
        send_ping(responder_ip)
    
    # Step 6: Start listening for pings from Responder in a separate thread
    def on_message_ping():
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Received ping from {responder_ip}. Proceeding to read Responder's message.")
        read_responder_message(responder_ip, ssh_username, ssh_password, mapping, subnet)
        
        # Confirm reading
        confirm = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Did you read the message? (y/n): ").lower()
        if confirm == 'y':
            # Send ping to Responder to confirm message read
            send_ping(responder_ip)
            # Perform cleanup
            cleanup(subnet)
            exit(0)
        else:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "You chose not to read the message. Exiting.")
            cleanup(subnet)
            exit(0)

    listener_thread = threading.Thread(target=listen_for_ping, args=(responder_ip, on_message_ping))
    listener_thread.start()
    
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Listening for pings from Responder...")
    
    # Keep the main thread alive to continue listening
    try:
        while listener_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting Initiator.")
        cleanup(subnet)

if __name__ == "__main__":
    main()
