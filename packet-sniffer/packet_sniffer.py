from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from prettytable import PrettyTable
import socket
import psutil
import subprocess
import time
import re

total_packet = 100 #initialize a total number of packet and it is set by default to 100
packet_count = 0  # Initialize a packet counter
#Stop sniffing packets after total_packet number of  packets captured and stop the program
def stop_sniffing(packet):
    global packet_count
    packet_count += 1
    if packet_count >= total_packet:  # Stop after the specified total number of  packets
        print(f"Sniffing stopped after {total_packet} packets.")
        return True  # Stop sniffing
    return False


#get the MAC address of the given interface
def get_current_mac(interface):
    try:
        # Get the output of ipconfig and decode it
        output = subprocess.check_output("ipconfig /all", shell=True).decode()
        
        # Find the MAC address for the specified interface
        interface_section = re.search(rf"{interface}.*?Physical Address[^\n]*?:\s+([0-9A-Fa-f-]+)", output, re.DOTALL)
        if interface_section:
            return interface_section.group(1)
        else:
            return None
    except subprocess.CalledProcessError:
        return None

#get the IP address of the given interface
def get_current_ip(interface):
    try:
        output = subprocess.check_output("ipconfig", shell=True).decode()
        
        # Find the IP address for the specified interface
        interface_section = re.search(rf"{interface}.*?IPv4 Address[^\n]*?:\s+([\d\.]+)", output, re.DOTALL)
        if interface_section:
            return interface_section.group(1)
        else:
            return None
    except subprocess.CalledProcessError:
        return None


#get a table of the all interfaces with its MAC and IP address
def ip_table():   
    addrs = psutil.net_if_addrs()
    interfaces = []  # Array to hold interface names
    t = PrettyTable(['Interface','Mac Address','IP Address'])
    
    for k, v  in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        interfaces.append(k)  # Add interface name to the list
  
        if ip and mac:
            t.add_row([k,mac,ip])
        elif mac:
            t.add_row([k,mac,'No IP assigned'])
        elif ip:
            t.add_row([k,'No MAC assigned',ip])
    print(t)
    return interfaces  # Return the list of interfaces
 

# Function to get the raw data and decode it
def get_raw_data(packet):    
    raw_data = packet[Raw].load  # Get the raw data
    print(f"\n                              ------------------***Raw Data without Decoding***---------------- \n {raw_data}\n\n")
    
    # Try common encodings
    print("Trying to decode the data...")
    encodings = ['utf-8', 'latin-1', 'ascii','utf-16', 'utf-32', 'windows-1252','iso-8859-2', 'iso-8859-5', 'iso-8859-15', 'mac_roman','cp437',]
    for enc in encodings:   
        try:
            decoded_data = raw_data.decode(enc)
            print(f"Successfully decoded with {enc}")
            print(f"                              ------------------***Decoded Raw Data***------------------ \n {decoded_data}\n")

            #get the login information if it is in the decoded raw data
            keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
            for i in keywords:
                if i in decoded_data:
                     print(f"Username or Password detected >>> {decoded_data}")
                     
            break  # Stop trying once we succeed
        except UnicodeDecodeError:
                print(f"Failed to decode with {enc}. Trying next...")
        except Exception as e:
                print(f"An error occurred while decoding: {e}")
                

# Function to analyze sniffed packet
def analyzer(packet):
    print(f"The number of the order of this packet: {str(packet_count + 1)}\n")
    
    if packet.haslayer(IP):
        print(f"Source IP Address: {packet[IP].src}")
        print(f"Destination IP Address: {packet[IP].dst}")

        if packet.haslayer(Ether):
            print(f"Source MAC Address: {packet[Ether].src}")
            print(f"Destination MAC Address: {packet[Ether].dst}\n")

        protocol = packet[IP].proto
        if protocol == 6:  # TCP protocol
            print("I got a TCP packet")
            
            print(f"Source Port: {str(packet[TCP].sport)}")
            try:
                src_serv = socket.getservbyport(packet[TCP].sport)
                print(f"Source Service: {src_serv}")
            except:
                print("Source Service: Unknown")

            print(f"Destination Port: {str(packet[TCP].dport)}")
            try:
                dst_serv = socket.getservbyport(packet[TCP].dport)
                print(f"Destination  Service: {dst_serv}")
            except:
                print("Destination Service: Unknown")
                
        elif protocol == 17:  # UDP protocol
            print("I got a UDP packet")
            print(f"Source Port: {str(packet[UDP].sport)}")
            try:
                src_serv = socket.getservbyport(packet[UDP].sport)
                print(f"Source Service: {src_serv}")
            except:
                print("Source Service: Unknown")

            print(f"Destination Port: {str(packet[UDP].dport)}")
            try:
                dst_serv = socket.getservbyport(packet[UDP].dport)
                print(f"Destination Service: {dst_serv}")
            except:
                print("Destination Service: Unknown")
                
        elif protocol == 1:  # ICMP protocol
            print("I got an ICMP packet")
            
        else:
            print("I got another or unrecognized packet")


        print(f"TTL: {packet[IP].ttl}")
        print(f"Flags: {packet[IP].flags}")
        print(f"Fragment Offset: {packet[IP].frag}")
        print(f"Packet Length: {len(packet)}")
        print(f"Packet Time: {packet.time}")

        if packet.haslayer("Raw"):
            get_raw_data(packet)
            
            
    else:
        print("NO IP Packet")
    print("\n                           ##################################################################")
    time.sleep(0.5) # Adds a 0.5 second delay between each packet print


# Sniffing function
def main_sniff():
    global total_packet
    print("                                  [*][*][*] Welcome to Packet Sniffer [*][*][*]\n")
    try:
        print("These are the interface details on your PC:")
        interfaces = ip_table()  # Get the list of interfaces
        interface = input("\nPlease enter the interface name > ")
        
        # Validate user input for the interface
        while interface not in interfaces:
            print(f"'{interface}' is not a valid interface. Please try again.")
            interface = input("Please enter the interface name > ")
            
        # Ask the user how many packets to capture and handle invalid input
        while True:
            try:
                total_packet = int(input("How many packets do you want to capture? "))
                if total_packet <= 0:
                    print("Please enter a positive number of packets.")
                else:
                    break  # Exit the loop if a valid number is entered
            except ValueError:
                print("Invalid input. Please enter a valid integer.")
        
        print("\n Sniffing Packets...\n")
        
        sniff(iface = interface, prn = analyzer, store = False, stop_filter = stop_sniffing)
        
    except KeyboardInterrupt:
        print("\nExiting the program...")
        time.sleep(2)  # Wait 2 seconds before closing
        
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(2)
    

# Calling the sniffing function
if __name__ == "__main__":
    main_sniff()
              
 
