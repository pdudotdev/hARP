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

# Load character to MAC mapping from the JSON file
def load_mapping():
    base_dir = os.path.dirname(os.path.abspath(__file__)) # convert path to script into absolute and get the dir
    json_path = os.path.join(base_dir, "char_to_mac.json")
    with open(json_path, "r") as file:
        return json.load(file) # return json as dict

# Determine subnet based on Responder's IP
def determine_subnet(responder_ip):
    octets = responder_ip.strip().split('.')
    if len(octets) != 4:
        raise ValueError(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid IP address format.")
    return '.'.join(octets[:3]) + '.' # return only the first 3 octets in IP

# Validate and get user message
def get_user_message(mapping):
    allowed_chars = set(mapping.keys()) # no chars outside json map are allowed
    # Keep prompting if user enters invalid chars. Don't crash due to bad input
    while True:
        message = input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + f"Enter a message (up to {MAX_MESSAGE_LENGTH} characters): ").lower()
        if len(message) > MAX_MESSAGE_LENGTH:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Message too long. Truncated to {MAX_MESSAGE_LENGTH} characters.")
            message = message[:MAX_MESSAGE_LENGTH] # truncate message to MAX_MESSAGE_LENGTH
        if all(char in allowed_chars for char in message): # validate each character in user message
            return message
        else:
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Message contains invalid characters. Allowed characters are:")
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + ", ".join(sorted(allowed_chars)))

# Convert message to MAC addresses
def convert_message_to_mac(message, mapping):
    encoded = ''.join([mapping[char] for char in message]) # convert message chars to hex pairs, e.g. "hi" -> "1112"
    # Each MAC address requires 12 hex characters (6 octets)
    mac_addresses = []
    for i in range(0, len(encoded), 12): # loop through converted message with a step of 12 (6 octets x 2 hex chars)
        chunk = encoded[i:i+12]
        if len(chunk) < 12: # "110E1515182E34" results in chunk1 "110E1515182E" and chunk2 "34"
            chunk = chunk.ljust(12, '0')  # Pad with '0's -> chunk2 becomes "340000000000"
        mac = MAC_ADDRESS_FORMAT.format(*[chunk[j:j+2] for j in range(0, 12, 2)]) # unpacks ['34', '00', '00', '00', '00', '00'] to "34:00:00:00:00:00"
        mac_addresses.append(mac)
    return mac_addresses

# Add static ARP entries
def add_arp_entries(mac_addresses, subnet):
    for idx, mac in enumerate(mac_addresses, start=ARP_START): # idx=201 & first MAC, idx=202 & second MAC etc.
        ip = f"{subnet}{idx}" # reconstruct IPs from subnet+idx
        command = f"sudo arp -s {ip} {mac}"
        os.system(command)

# Send ping to Responder when ARP message is ready for extraction
def send_ping(responder_ip):
    # Suppress ping output by redirecting stdout and stderr
    subprocess.run(["ping", "-c", "1", responder_ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Listen for incoming pings from Responder when the Responder's reply is ready for extraction OR as confirmation for cleanup
def listen_for_ping(responder_ip, callback):
    # Defining packet_callback() here cause it's relevant only within listen_for_ping()
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[IP].src == responder_ip:
                # 'callback' becomes on_message_ping(); listen_for_ping calls it when the expected ping is detected.
                callback()
    sniff(filter="icmp", prn=packet_callback, store=0, timeout=300, iface=LISTEN_IFACE)

# SSH into Responder to read its ARP cache
def read_responder_message(responder_ip, ssh_username, ssh_password, mapping, subnet):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # auto-accepts host keys
        ssh.connect(responder_ip, username=ssh_username, password=ssh_password)
        stdin, stdout, stderr = ssh.exec_command("arp -an")
        arp_output = stdout.read().decode()
        ssh.close()
        
        # If ARP table is empty, exit gracefully
        if not arp_output.strip():
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "No ARP entries found.")
            return
        
        arp_entries = []
        for line in arp_output.splitlines(): # return ARP table rows as list elements
            # Example: ? (192.168.56.202) at 2E:15:00:00:00:00 PERM on eth0
            parts = line.split()
            if len(parts) >= 4:
                ip_part = parts[1]  # Should be the IP: "(192.168.56.201)"
                ip_address = ip_part.strip('()') # "192.168.56.201"
                if ip_address.startswith(subnet):
                    last_octet = int(ip_address.split('.')[-1])
                    if ARP_START <= last_octet <= ARP_END: # .201 - .210
                        mac = parts[3].replace(':', '').upper() # 2E:15:00:00:00:00 → "2E1500000000"
                        arp_entries.append((ip_address, mac))
        
        # If ARP table does not contain any entries for my subnet, exit gracefully
        if not arp_entries:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "No ARP entries found for the specified subnet.")
            return

        # Sort arp_entries based on the last octet of the IP address
        # Example: arp_entries = [("192.168.56.203", "c"), ("192.168.56.201", "a"), ("192.168.56.202", "b")]
        arp_entries.sort(key=lambda x: int(x[0].split('.')[-1]))
        # Result: [('192.168.56.201', 'a'), ('192.168.56.202', 'b'), ('192.168.56.203', 'c')]

        # Decode MAC addresses to message, e.g. "0A" -> 'a'
        decoded = ""
        reverse_mapping = {v: k for k, v in mapping.items()} # '0A': 'a' k-v pairs
        for _, mac in arp_entries:
            for i in range(0, len(mac), 2): # [0, 2, 4, 6, 8, 10] indexes from the MAC
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
    # Loading the character mapping from JSON
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

    # Make sure the sniffer is running in its own thread, otherwise it blocks execution
    listener_thread = threading.Thread(target=listen_for_ping, args=(responder_ip, on_message_ping))
    listener_thread.start()
    
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Listening for pings from Responder...")
    
    # Keep the main thread alive to continue listening
    try:
        while listener_thread.is_alive():
            time.sleep(1) # keeps the program alive until the listener finishes
    except KeyboardInterrupt:
        print("\nExiting Initiator.")
        cleanup(subnet)

if __name__ == "__main__":
    main()
