---
# Python Packet Sniffer

## Overview

This project implements a basic **packet sniffing** tool using Python and the Scapy library. The tool allows users to:
- Capture packets on a specified network interface.
- Analyze packet contents including IP addresses, MAC addresses, and transport layer protocols (TCP, UDP, ICMP).
- Display raw packet data and decode it using various encoding methods (e.g., UTF-8, Latin-1).
- Optionally specify the number of packets to capture before automatically stopping the sniffing process.

## Features

- **Interface Selection**: Users can select a network interface from the available interfaces on their machine.
- **Packet Analysis**: Captured packets are analyzed to display the source and destination IP addresses, MAC addresses, protocols, ports, and more.
- **Raw Data Decoding**: Any raw data in the packets is extracted and decoded using common encodings (e.g., UTF-8, Latin-1, ASCII).
- **Custom Packet Capture Limit**: Users can specify how many packets they want to capture.
- **Keyboard Interrupt Handling**: The program can be gracefully interrupted using `Ctrl + C`, exiting cleanly.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/NidaaChok/codeaplha_tasks/packet-sniffer.git
   cd packet-sniffer
   ```

2. **Install Dependencies**:
   Make sure you have the required Python libraries installed:
   ```bash
   pip install scapy prettytable psutil
   ```

3. **Run the Sniffer**:
   Start the packet sniffer with the following command:
   ```bash
   python packet_sniffer.py
   ```

## Usage

1. **Select an Interface**: When the program starts, it will display a list of network interfaces on your system. Enter the name of the interface you want to sniff traffic on.
   
2. **Set Packet Limit**: Enter how many packets you want to capture before the sniffing process stops automatically. If you do not provide a number, the default is 100 packets.

3. **View Packet Data**: As the packets are captured, information about the source and destination addresses, MAC addresses, protocols, and raw data is displayed.

## Example Output

Here’s an example of what the output might look like:

```
                                  [*][*][*] Welcome to Packet Sniffer [*][*][*]

These are the interface details on your PC:
+--------------------------------+-------------------+---------------+
|           Interface            |    Mac Address    |   IP Address  |
+--------------------------------+-------------------+---------------+
|            Ethernet            | 10-65-30-6A-01-F8 | 192.168.154.1 |
| VMware Network Adapter VMnet1  | 00-50-56-C0-00-01 | 192.168.154.1 |
| VMware Network Adapter VMnet8  | 00-50-56-C0-00-08 |  192.168.26.1 |
| VMware Network Adapter VMnet7  | 00-50-56-C0-00-07 |  192.168.10.1 |
| VMware Network Adapter VMnet19 | 00-50-56-C0-00-13 | 200.200.200.1 |
|             Wi-Fi              | 38-DE-AD-1B-25-48 |  192.168.1.11 |
+--------------------------------+-------------------+---------------+

Please enter the interface name > eee
'eee' is not a valid interface. Please try again.
Please enter the interface name > Wi-Fi
How many packets do you want to capture? -2
Please enter a positive number of packets.
How many packets do you want to capture? ee
Invalid input. Please enter a valid integer.
How many packets do you want to capture? 10

 Sniffing Packets...

The number of the order of this packet: 1

Source IP Address: 192.168.1.11
Destination IP Address: 142.251.37.238
Source MAC Address: 38:de:ad:1b:25:47
Destination MAC Address: 64:ee:b7:f0:0b:d3

I got a UDP packet
Source Port: 60151
Source Service: Unknown
Destination Port: 443
Destination Service: https
TTL: 128
Flags: DF
Fragment Offset: 0
Packet Length: 1292
Packet Time: 1729788791.218371

                              ------------------***Raw Data without Decoding***---------------- 
 b'\xc3\x009%\xf2b\x866\5\x18\xcaNCX\x87\xa9\xa3&\xc9\xe9\xed\xe0\xb8\x0bZ\x05'


Trying to decode the data...
Failed to decode with utf-8. Trying next...
Successfully decoded with latin-1
                              ------------------***Decoded Raw Data***------------------
ÃÃ.........

                           ##################################################################
The number of the order of this packet: 2

Source IP Address: 192.168.1.11
Destination IP Address: 142.251.37.238
Source MAC Address: 38:de:ad:1b:25:47
.....

                           ##################################################################
Sniffing stopped after 10 packets.
```

## Key Functions

- `ip_table()`: Displays the available network interfaces and their associated IP and MAC addresses.
- `stop_sniffing()`: Stops packet sniffing after the user-specified number of packets is captured.
- `analyzer(packet)`: Analyzes captured packets and displays details such as source and destination IPs, MAC addresses, ports, and raw data.
- `get_raw_data(packet)`: Decodes raw data from the packet using common encoding formats and searches for sensitive information such as usernames or passwords.

## Requirements

- Python 3.x
- Scapy
- PrettyTable
- psutil

## Future Enhancements

- Add support for filtering packets by protocol.
- Implement saving packet captures to a file (e.g., PCAP format).
- Allow for real-time analysis and alerts for specific packet types.
