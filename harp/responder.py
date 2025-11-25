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

# Load character to MAC mapping
def load_mapping():
    with open('char_to_mac.json', 'r') as file:
        return json.load(file)

# Determine subnet based on Initiator's IP
def determine_subnet(initiator_ip):
    octets = initiator_ip.strip().split('.')
    if len(octets) != 4:
        raise ValueError(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid IP address format.")
    return '.'.join(octets[:3]) + '.'

# Validate and get user message
def get_user_message(mapping):
    allowed_chars = set(mapping.keys())
    while True:
        message = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + f"Enter a reply (up to {MAX_MESSAGE_LENGTH} characters): ").lower()
        if len(message) > MAX_MESSAGE_LENGTH:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Message too long. Truncated to {MAX_MESSAGE_LENGTH} characters.")
            message = message[:MAX_MESSAGE_LENGTH]
        if all(char in allowed_chars for char in message):
            return message
        else:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Message contains invalid characters. Allowed characters are:")
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

# Send ping to Initiator
def send_ping(initiator_ip):
    # Suppress ping output by redirecting stdout and stderr
    subprocess.run(["ping", "-c", "1", initiator_ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Listen for incoming pings from Initiator
def listen_for_ping(initiator_ip, callback):
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[IP].src == initiator_ip:
                callback()
    sniff(filter="icmp", prn=packet_callback, store=0, timeout=300)

# SSH into Initiator to read its ARP cache
def read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping, subnet):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(initiator_ip, username=ssh_username, password=ssh_password)
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
        print(Style.BRIGHT + Fore.GREEN + "\n[MESSAGE RECEIVED] " + Style.RESET_ALL + f"Message from Initiator: {decoded}\n")
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Error reading Initiator's message: {e}")

# Cleanup function
import subprocess

def cleanup(subnet):
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Performing cleanup...")
    # Clear ARP cache entries within the subnet and ARP_START to ARP_END
    for idx in range(ARP_START, ARP_END + 1):
        ip = f"{subnet}{idx}"
        command = ["sudo", "arp", "-d", ip]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "ARP cache entries cleared.")
    # Clear SSH auth logs (Linux specific)
    try:
        subprocess.run(["sudo", "truncate", "-s", "0", "/var/log/auth.log"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "SSH logs cleared.")
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to clear SSH logs: {e}")
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Cleanup completed.")
    time.sleep(3)
    os.system('clear')

# Main function for Responder
def main():
    mapping = load_mapping()
    
    # Step 1: Get Initiator's IP
    initiator_ip = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the Initiator's IP address: ")
    try:
        subnet = determine_subnet(initiator_ip)
    except ValueError as ve:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + ve)
        return
    
    # Step 2: Get SSH credentials
    ssh_username = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the SSH username for the Initiator: ")
    ssh_password = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the SSH password for the Initiator: ")
    
    # Step 3: Start listening for pings from Initiator in a separate thread
    def on_message_ping():
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Received ping from {initiator_ip}. Proceeding to read Initiator's message.")
        read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping, subnet)
        
        # Confirm reading
        confirm = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Did you read the message? (y/n): ").lower()
        if confirm == 'y':
            # Send reply without prompting for another message
            reply_message = get_user_message(mapping)
            reply_mac_addresses = convert_message_to_mac(reply_message, mapping)
            add_arp_entries(reply_mac_addresses, subnet)
            send_ping(initiator_ip)
            # Now wait for confirmation ping from Initiator
            def on_confirmation_ping():
                print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Received confirmation ping from Initiator. Performing cleanup.")
                cleanup(subnet)
                exit(0)
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Waiting for confirmation ping from Initiator...")
            confirmation_listener = threading.Thread(target=listen_for_ping, args=(initiator_ip, on_confirmation_ping))
            confirmation_listener.start()
            while confirmation_listener.is_alive():
                time.sleep(1)
        else:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "You chose not to read the message. Exiting.")
            cleanup(subnet)
            exit(0)

    listener_thread = threading.Thread(target=listen_for_ping, args=(initiator_ip, on_message_ping))
    listener_thread.start()
    
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Listening for pings from Initiator...")
    
    # Keep the main thread alive to continue listening
    try:
        while listener_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "\nExiting Responder.")
        cleanup(subnet)

if __name__ == "__main__":
    main()
